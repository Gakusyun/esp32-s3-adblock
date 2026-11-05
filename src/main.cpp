// S3 AdBlock — DNS sinkhole + web dashboard for the ESP32-S3 (N16R8).
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://s3adblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "esp_heap_caps.h"     // PSRAM-backed arena for the on-device rules parser
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include <freertos/FreeRTOS.h> // the rule fetch runs in its own task so DNS never stalls
#include <freertos/task.h>
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
// AliDNS — low latency from mainland China. Override in secrets.h if needed.
#ifndef UPSTREAM_IP
#define UPSTREAM_IP 223, 5, 5, 5
#endif
#ifndef UPSTREAM_PORT
#define UPSTREAM_PORT 53
#endif

// Default rules source (used when /update.cfg doesn't exist yet).
#ifndef RULE_URL
#define RULE_URL "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-hosts.txt"
#endif
#ifndef RULE_URL_FALLBACK
#define RULE_URL_FALLBACK "https://gcore.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-hosts.txt"
#endif
// ---- upstream transport ----
// Plain UDP/53 to UPSTREAM_IP can be read, dropped and spoofed by anyone on the
// path, so an on-path attacker gets to answer *any* name and the blocklist never
// sees it. DoH (RFC 8484) carries the same DNS message inside an authenticated TLS
// stream and is the one part of this device's DNS path that can be made
// MITM-resistant (the dashboard and OTA stay plain HTTP by design).
//
// Point DOH_URL at an RFC 8484 endpoint to move the upstream to HTTPS:
//   #define DOH_URL "https://dns.alidns.com/dns-query"   // Alibaba, mainland CN
//   #define DOH_URL "https://doh.pub/dns-query"          // Tencent
// Empty = keep plain UDP. Enabling DoH holds ~45 KB of heap for the TLS session,
// which is kept alive across queries (a handshake per lookup would cost 0.3-1 s on
// an 80 MHz S3) and it needs a valid clock for certificate validation.
#ifndef DOH_URL
#define DOH_URL ""
#endif
// When the DoH endpoint is unreachable: 1 = fall back to plain UDP (the LAN stays
// online), 0 = fail the lookup (strict; do not silently downgrade). Whichever you
// pick, /stats.json counts the downgrades (dohFallback) so they are never invisible.
#ifndef DOH_UDP_FALLBACK
#define DOH_UDP_FALLBACK 1
#endif
// Automatic refresh runs once a day at a fixed LOCAL hour instead of "N hours after
// boot", so updates land at night and are deterministic across reboots.
#ifndef RULE_HOUR
#define RULE_HOUR 3            // 03:00 local time
#endif
#ifndef RULE_TZ
#define RULE_TZ 8              // UTC+8 (China); used for the update window and NTP
#endif
static const IPAddress UPSTREAM(UPSTREAM_IP);
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
// Blocklist staging paths (upload / remote fetch / the parked copy during a swap).
// Kept up here with the rest of the config so /stats.json can report them.
static const char* BL_TMP_UPLOAD = "/blocklist.new";   // written by /upload (browser)
static const char* BL_TMP_REMOTE = "/blupdate.new";    // written by the update task
static const char* BL_OLD        = "/bl.old";          // previous list, parked during a swap
// 11.75 MB LittleFS / 5 bytes per entry, minus metadata.
static const uint32_t FLASH_HASH_CAPACITY = 2400000;
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_MAX = 4096;         // upper bound on first-level buckets (20 KB)
static const int INDEX_PER_BUCKET = 8;     // aim for ~8 hashes per bucket
static const int CACHE_SIZE = 256;         // must be power of 2
static const int MAX_RANGE = 640;          // hashes read from flash per chunk (3.2 KB)
// Upstream-answer cache (Pi-hole style): a repeated lookup for the same question
// is answered from PSRAM instead of paying a ~40ms round trip to 223.5.5.5.
//
// Sizing is exact, not worst-case: every entry owns a heap_caps_malloc() of exactly
// (reply + key) bytes — a typical entry is ~110 bytes, not the 512 bytes a fixed
// per-slot layout would burn.
//
// DNS_CACHE_SLOTS is the only real ceiling. The table costs ~28 bytes per slot of
// static RAM and the largest possible entry is (512 + 288) bytes, so 1024 slots top
// out at ~800 KB (typically ~110 KB). There used to be a second, PSRAM-derived
// "byte budget" here: it could never be reached before the slot table filled up, so
// it was only pretending to be a limit. Raise DNS_CACHE_SLOTS if you want a bigger
// cache and watch dnsCacheBytes/heap in /stats.json. The eviction policy picks the
// victim closest to expiry, tie-broken by fewest hits and then least-recently-used.
static const int DNS_CACHE_SLOTS = 1024;        // entry table size (the only ceiling)
static const uint16_t DNS_CACHE_MAXLEN = 512;   // largest reply we are willing to cache
static const uint16_t DNS_CACHE_MAXQ = 288;     // largest key we build (question section)
static const uint32_t DNS_CACHE_MAX_TTL = 3600; // seconds; longer TTLs are clamped down

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache.
// The index lives in PSRAM (sized from the actual rule count) instead of a fixed 20 KB
// static array: internal SRAM is the scarce resource here (WiFi + TLS need it), and the
// index is only touched on a flash-cache miss.
static uint8_t* blArena = nullptr;       // one PSRAM block: [index][range buffer]
static uint8_t* blIndex = nullptr;       // -> blArena, indexEntries * HASH_BYTES
static uint8_t* rangeBuf = nullptr;      // -> after the index, MAX_RANGE * HASH_BYTES
static uint32_t blIndexErrors  = 0;      // flash reads that failed in buildFlashIndex()
static uint32_t blRangeStreams = 0;      // buckets that needed more than one chunk
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];

// Key = the question section lowercased + the client's DO bit. Deliberately NOT the
// whole query: EDNS COOKIE (a fresh random cookie per process — even per `dig` run),
// padding and UDP size differ between clients that are asking the same question, and
// keying on them produced a 0% hit rate. Cached replies are stored without their OPT
// record, so one entry is valid for EDNS and non-EDNS clients alike, and on a hit the
// question bytes are patched with the caller's own casing (0x20 clients stay happy).
struct DnsCacheEnt {
  uint32_t sig;       // hash of the key (bucket = sig & (CACHE_BUCKETS-1))
  uint32_t storedMs;  // millis() when the packet's TTLs were last correct
  uint32_t expireS;   // seconds of life left in the packet at storedMs
  uint16_t keyLen;    // key length (key is stored right after the reply)
  uint16_t len;       // reply length
  uint16_t cap;       // bytes actually allocated for this entry
  int16_t  hnext;     // next entry in the same bucket (-1 = end)
  int16_t  lprev;     // LRU list: previous (more recently used), -1 = MRU end
  int16_t  lnext;     // LRU list: next (less recently used)
  uint8_t* pkt;       // pkt[0..len) = reply, pkt[len..len+keyLen) = key; nullptr = free
};
// The table itself (~34 KB for 1024 slots) is allocated in PSRAM at boot: it used to be a
// static array and was the single biggest consumer of internal SRAM in this project.
static DnsCacheEnt* dnsCache = nullptr;
static const int CACHE_BUCKETS = 256;          // power of 2; hash chains (1024 slots)
static int16_t cacheHead[CACHE_BUCKETS];       // bucket heads, -1 = empty
static int16_t cacheMru = -1, cacheLru = -1;   // LRU list ends
static int16_t cacheFree = -1;                 // free-slot stack (linked through hnext)
static size_t   dnsCacheBytes = 0;      // sum of cap over all live entries
static uint32_t dnsCacheHits = 0, dnsCacheMiss = 0, dnsCacheEvicted = 0;
static uint8_t  dnsQSave[DNS_CACHE_MAXQ];   // copy of the current query's question section
static uint8_t  dnsKeyBuf[DNS_CACHE_MAXQ];  // key built from dnsQSave
static uint8_t  dnsQDo = 0;                 // DO bit of the current query's OPT record

// ---- DoH upstream state ----
static bool     dohAvail = false;       // DOH_URL was set and parsed
static String   dohHost, dohPath;       // e.g. "dns.alidns.com" + "/dns-query"
static uint16_t dohPort = 443;
static WiFiClientSecure dohTls;         // one long-lived TLS session, reused per query
static uint8_t  dohRx[1536];            // DoH replies land here: a failed attempt must not
                                        // clobber the query still sitting in buf (UDP fallback)
static bool     dohConnected = false;
static uint32_t dohFailAt = 0;          // last failure -> back off instead of stalling every query
static uint32_t dohOkCount = 0, dohFailCount = 0, dohFallbackCount = 0;
static const uint32_t DOH_BACKOFF_MS = 30000;
static const uint32_t DOH_TIMEOUT_MS = 5000;   // whole request (headers + body)
// Rule fetches are TLS too; they are only certificate-checked when the clock has
// been set by SNTP (a 1970 clock fails every validity check). Exposed in stats.
static bool     fetchSecure = true;
// Set when the last rules fetch was a chunked transfer, i.e. its length could not be
// verified (see fetchRuleText()). Exposed in stats as fetchChunked.
static bool     chunkedFetch = false;

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 512;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

// Hosts-style overrides: answer these names with a fixed IPv4 instead of forwarding.
// Exact match only (with the same "www." stripping the DNS parser applies, plus
// parent-domain matching, so `nas.home` also answers `foo.nas.home`).
struct HostEnt { String dom; uint64_t hash; uint32_t ip; };
static const int MAX_HOSTS = 128;
HostEnt hostEnt[MAX_HOSTS]; int numHosts = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "";              // URL of a rules file, or a prebuilt blocklist.bin
uint8_t updateHour = RULE_HOUR;     // local hour (0-23) of the nightly fetch
int8_t  updateTz   = RULE_TZ;       // local time = UTC + updateTz hours
int32_t lastUpdateDay = 0;          // local day number (epoch/86400) of the last successful fetch
uint32_t lastAttemptMs = 0;         // millis() of the last attempt (0 = none yet; drives the cooldown)
String updateStatus = "never";      // published status (written by the main task only)
// The fetch itself runs in updateTask (see "rule refresh runs in its own task"):
static volatile bool updRunning = false, updDone = false, updOk = false;
static int32_t updDay = 0;          // local day this fetch was started for (0 = manual fetch)
static String fetchStatus;          // owned by the fetch task, published once updDone is set

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// blocking pause (Pi-hole-style "disable for a while")
bool     blockingOn = true;
uint32_t resumeAt   = 0;            // millis() to auto-resume; 0 = paused indefinitely / not paused

// On-board RGB status LED (WS2812). Some clones wire it to GPIO38 instead of 48:
// override with -D LED_PIN=38 (or in secrets.h) if the panel switch does nothing.
#ifndef LED_PIN
#define LED_PIN 48
#endif
// On/off is a user setting (panel: 系统 → 指示灯), persisted in /led.cfg.
// When off the LED is driven to black; some boards also have a hardwired power
// LED that no firmware can switch off.
bool ledOn = true;

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static inline uint64_t unpackHash(const uint8_t* b) {
  uint64_t v = 0;
  for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
  return v;
}
static inline void packHash(uint64_t h, uint8_t* b) {
  for (int k = 0; k < HASH_BYTES; k++) { b[k] = (uint8_t)h; h >>= 8; }
}

// Number of index entries actually in use (0 = no blocklist). Sampling 4096 entries
// out of a 969-domain list would cost 4096 random flash reads at every boot for
// nothing, so the index is only as dense as the list.
static int indexEntries = 0;

// Read `n` bytes at hash position `pos` (pos is in *entries*, not bytes).
static bool blReadAt(uint32_t pos, uint8_t* dst, size_t n) {
  if (!blocklist) return false;
  blocklist.seek((size_t)pos * HASH_BYTES);
  size_t got = 0;
  while (got < n) { const int r = blocklist.read(dst + got, n - got); if (r <= 0) return false; got += (size_t)r; }
  return true;
}

static void buildFlashIndex() {
  if (blArena) { heap_caps_free(blArena); blArena = blIndex = rangeBuf = nullptr; }
  indexEntries = 0;
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
  if (!blocklist || numHashes == 0) return;

  int want = (int)(numHashes / INDEX_PER_BUCKET);
  if (want < 2) want = 2;                        // always keep [0] and [last]
  if (want > INDEX_MAX) want = INDEX_MAX;        // bounds the boot-time flash reads
  const size_t idxBytes = (size_t)want * HASH_BYTES;
  const size_t rangeBytes = (size_t)MAX_RANGE * HASH_BYTES;
  blArena = (uint8_t*)heap_caps_malloc(idxBytes + rangeBytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!blArena) { Serial.println("[bl] WARN no PSRAM for the index -> lookups go unfiltered"); return; }
  blIndex = blArena;
  rangeBuf = blArena + idxBytes;

  if (!blReadAt(0, blIndex, HASH_BYTES)) { blIndexErrors++; heap_caps_free(blArena); blArena = blIndex = rangeBuf = nullptr; return; }
  if (numHashes == 1) {                          // degenerate: one entry, duplicated as [0]/[1]
    memcpy(blIndex + HASH_BYTES, blIndex, HASH_BYTES);
    indexEntries = 2;
    return;
  }
  indexEntries = want;
  for (int i = 1; i < indexEntries; i++) {
    const uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (uint32_t)(indexEntries - 1));
    // Every read must be checked: a failed one leaves a zero/stale sample behind and
    // the binary search in inFlash() would then silently mis-route the whole bucket.
    if (!blReadAt(pos, blIndex + (size_t)i * HASH_BYTES, HASH_BYTES)) {
      blIndexErrors++;
      Serial.printf("[bl] WARN index read failed at %u -> blocking disabled this boot\n", (unsigned)pos);
      heap_caps_free(blArena); blArena = blIndex = rangeBuf = nullptr;
      indexEntries = 0;
      return;
    }
  }
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0 || indexEntries == 0 || !blIndex) return false;
  uint64_t first = unpackHash(blIndex);
  uint64_t last  = unpackHash(blIndex + (size_t)(indexEntries - 1) * HASH_BYTES);
  if (h < first || h > last) return false;

  int lo = 0, hi = indexEntries - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex + (size_t)mid * HASH_BYTES);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (uint32_t)(indexEntries - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (uint32_t)(indexEntries - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  if (endPos - startPos + 1 > (uint32_t)MAX_RANGE) blRangeStreams++;   // visible in stats

  // Stream the bucket in chunks. The old code clamped the count to MAX_RANGE and
  // returned false for anything past it, so with a very large list a few buckets were
  // silently unreachable — rules that never matched, reported only as a boot-time WARN.
  uint32_t pos = startPos;
  while (pos <= endPos) {
    uint32_t n = endPos - pos + 1;
    if (n > (uint32_t)MAX_RANGE) n = MAX_RANGE;
    const size_t want = (size_t)n * HASH_BYTES;
    blocklist.seek((size_t)pos * HASH_BYTES);
    size_t got = 0;
    while (got < want) { const int r = blocklist.read(rangeBuf + got, want - got); if (r <= 0) return false; got += (size_t)r; }
    for (uint32_t i = 0; i < n; i++) {
      const uint64_t v = unpackHash(rangeBuf + (size_t)i * HASH_BYTES);
      if (v == h) return true;
      if (v > h) return false;
    }
    pos += n;
  }
  return false;
}

// Open-addressed index over customHash[] so the per-query custom check is O(1) instead
// of a linear scan of up to MAX_CUSTOM entries on every parent-domain level.
// 1024 slots for 512 entries -> at most 2 probes, and probing always terminates at an
// empty slot because the table is at most half full.
static const int CUSTOM_SET = 1024;
static int16_t customSlot[CUSTOM_SET];    // entry index + 1, 0 = empty
static void customSetInsert(int i) {
  uint32_t p = (uint32_t)(customHash[i] ^ (customHash[i] >> 32)) & (CUSTOM_SET - 1);
  while (customSlot[p]) p = (p + 1) & (CUSTOM_SET - 1);
  customSlot[p] = (int16_t)(i + 1);
}
static void customSetRebuild() {
  memset(customSlot, 0, sizeof(customSlot));
  for (int i = 0; i < numCustom; i++) customSetInsert(i);
}
static bool inCustom(uint64_t h) {
  uint32_t p = (uint32_t)(h ^ (h >> 32)) & (CUSTOM_SET - 1);
  while (int16_t s = customSlot[p]) { if (customHash[s - 1] == h) return true; p = (p + 1) & (CUSTOM_SET - 1); }
  return false;
}

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached to avoid serving stale answers — but through customSlot[], not a
// linear scan (that was up to MAX_CUSTOM compares per parent-domain level, per query).
static bool isBlockedHash(uint64_t h) {
  if (inCustom(h)) return true;
  uint32_t slot = h & (CACHE_SIZE - 1);
  if (cacheValid[slot]) {
    uint8_t want[HASH_BYTES]; packHash(h, want);
    bool same = true;
    for (int k = 0; k < HASH_BYTES; k++) if (cacheKey[slot][k] != want[k]) { same = false; break; }
    if (same) return cacheRes[slot] != 0;
  }
  bool res = inFlash(h);
  cacheValid[slot] = 1;
  cacheRes[slot] = res ? 1 : 0;
  packHash(h, cacheKey[slot]);
  return res;
}

static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (isBlockedHash(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
// Lowercase + strip a leading "www.", the same normalisation the DNS query parser
// and the rule parser apply, so a user can paste any of those forms.
static bool normDomain(const String& in, String& out) {
  String s = in; s.trim(); s.toLowerCase();
  if (s.startsWith("http://")) s = s.substring(7);
  if (s.startsWith("https://")) s = s.substring(8);
  int slash = s.indexOf('/'); if (slash >= 0) s = s.substring(0, slash);
  while (s.length() && (s[0] == '*' || s[0] == '.')) s = s.substring(1);
  while (s.length() && s[s.length() - 1] == '.') s = s.substring(0, s.length() - 1);
  if (s.startsWith("www.") && s.length() > 8) s = s.substring(4);
  if (s.length() < 3 || s.length() > 253 || s.indexOf('.') < 0) return false;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return false;
  }
  out = s; return true;
}
static bool isIPv4Token(const String& t) {
  int dots = 0, octet = -1; if (!t.length()) return false;
  for (size_t i = 0; i < t.length(); i++) {
    const char c = t[i];
    if (c == '.') { if (octet < 0 || octet > 255) return false; dots++; octet = -1; continue; }
    if (c < '0' || c > '9') return false;
    octet = (octet < 0 ? 0 : octet * 10) + (c - '0');
    if (octet > 255) return false;
  }
  return dots == 3 && octet >= 0 && octet <= 255;
}
static void loadCustom() {
  numCustom = 0;
  memset(customSlot, 0, sizeof(customSlot));    // the set mirrors the list as it is built
  File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); String d;
    if (!normDomain(l, d)) continue;
    // De-duplicate on the 40-bit hash, not on the String: the hash is already the
    // comparison key at query time, and String comparison made this O(n^2) in
    // heap-allocating operator== calls (512^2 of them on every boot).
    const uint64_t h = fnv40(d.c_str(), d.length());
    if (inCustom(h)) continue;
    customDom[numCustom] = d; customHash[numCustom] = h;
    customSetInsert(numCustom); numCustom++;
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }

// ---------- on-board RGB LED ----------
// Status colours: blue = booting / no Wi-Fi, green = blocking, amber = paused.
// "Off" means the LED is driven dark (an LED has no black — it just goes out).
// rgbLedWrite() takes care of the pin setup (RMT), so no pinMode() is needed.
// Only re-drive the LED when the state actually changes: rgbLedWrite() is not free.
static uint8_t ledState = 255;   // 0 = off, 1 = blue, 2 = green, 3 = amber
static void applyLed() {
  uint8_t s = !ledOn ? 0 : (WiFi.status() != WL_CONNECTED ? 1 : (blockingOn ? 2 : 3));
  if (s == ledState) return;
  ledState = s;
  switch (s) {
    case 0:  rgbLedWrite(LED_PIN, 0, 0, 0); break;                                  // dark
    case 1:  rgbLedWrite(LED_PIN, 0, 0, RGB_BRIGHTNESS); break;                     // blue
    case 2:  rgbLedWrite(LED_PIN, 0, RGB_BRIGHTNESS, 0); break;                     // green
    default: rgbLedWrite(LED_PIN, RGB_BRIGHTNESS, RGB_BRIGHTNESS / 2, 0); break;    // amber
  }
}
static void loadLedCfg() {
  File f = LittleFS.open("/led.cfg", "r"); if (!f) return;
  String v = f.readStringUntil('\n'); v.trim(); f.close();
  if (v.length()) ledOn = v.toInt() != 0;
}
static void saveLedCfg() { File f = LittleFS.open("/led.cfg", "w"); if (!f) return; f.println(ledOn ? 1 : 0); f.close(); }
// Replace the whole list from the textarea contents. Accepts one domain per line,
// hosts-file lines ("0.0.0.0 a b c"), and # comments — anything that is not a
// domain token is ignored, so pasting a full hosts file just works.
// Build the list in place and return how many domains it holds, or -1 when the text
// holds more than MAX_CUSTOM *distinct* domains (the saved list is then reloaded and
// nothing is written to flash).
//
// This used to be a dry run followed by a real run, and the dry run counted every
// token including duplicates, so a pasted list with repeated names could be rejected
// while holding fewer than MAX_CUSTOM domains.
static int setCustomFromText(const String& text) {
  numCustom = 0;
  memset(customSlot, 0, sizeof(customSlot));    // the set mirrors the list being built
  bool overflow = false;
  int i = 0; const int n = text.length();
  while (i <= n && !overflow) {
    int e = text.indexOf('\n', i); if (e < 0) e = n;
    String line = text.substring(i, e); i = e + 1;
    int hash = line.indexOf('#'); if (hash >= 0) line = line.substring(0, hash);
    line.replace('\t', ' ');
    int p = 0;
    while (p < (int)line.length()) {
      while (p < (int)line.length() && line[p] == ' ') p++;
      int q = line.indexOf(' ', p); if (q < 0) q = line.length();
      String tok = line.substring(p, q); p = q;
      if (!tok.length() || isIPv4Token(tok) || tok == "::" || tok == "::1") continue;
      String d; if (!normDomain(tok, d)) continue;
      const uint64_t h = fnv40(d.c_str(), d.length());
      if (inCustom(h)) continue;                    // duplicate: does not count
      if (numCustom == MAX_CUSTOM) { overflow = true; break; }
      customDom[numCustom] = d; customHash[numCustom] = h;
      customSetInsert(numCustom); numCustom++;
    }
    if (e >= n) break;
  }
  if (!overflow) { customSetRebuild(); return numCustom; }
  loadCustom();                                    // restore what is still on flash (rebuilds the set)
  return -1;
}

// ---------- hosts overrides ----------
static uint32_t parseIPv4(const String& s) {
  IPAddress ip; if (!ip.fromString(s)) return 0;
  return (uint32_t)ip;      // 0.0.0.0 is rejected by the caller (0 = "no mapping")
}
static void loadHosts() {
  numHosts = 0; File f = LittleFS.open("/hosts.txt", "r"); if (!f) return;
  while (f.available() && numHosts < MAX_HOSTS) {
    String l = f.readStringUntil('\n');
    int hash = l.indexOf('#'); if (hash >= 0) l = l.substring(0, hash);
    l.replace('\t', ' '); l.trim();
    int sp = l.indexOf(' '); if (sp < 0) continue;
    String dom = l.substring(0, sp); String ip = l.substring(sp + 1); ip.trim();
    if (isIPv4Token(dom)) { String t = dom; dom = ip; ip = t; }   // "IP domain" too
    int cut = ip.indexOf(' '); if (cut >= 0) ip = ip.substring(0, cut);
    String d; uint32_t v = parseIPv4(ip);
    if (!v || !normDomain(dom, d)) continue;
    const uint64_t h = fnv40(d.c_str(), d.length());
    bool dup = false; for (int k = 0; k < numHosts; k++) if (hostEnt[k].hash == h) { dup = true; break; }
    if (dup) continue;
    hostEnt[numHosts].dom = d; hostEnt[numHosts].hash = h;
    hostEnt[numHosts].ip = v; numHosts++;
  }
  f.close();
}
static void saveHosts() {
  File f = LittleFS.open("/hosts.txt", "w"); if (!f) return;
  for (int i = 0; i < numHosts; i++) { IPAddress ip(hostEnt[i].ip); f.println(hostEnt[i].dom + " " + ip.toString()); }
  f.close();
}
// Same contract as setCustomFromText(): built in place, -1 (and the flash copy
// reloaded) when there are more than MAX_HOSTS distinct mappings.
static int setHostsFromText(const String& text) {
  numHosts = 0;
  bool overflow = false;
  int i = 0; const int n = text.length();
  while (i <= n && !overflow) {
    int e = text.indexOf('\n', i); if (e < 0) e = n;
    String line = text.substring(i, e); i = e + 1;
    int hash = line.indexOf('#'); if (hash >= 0) line = line.substring(0, hash);
    line.replace('\t', ' '); line.trim();
    int sp = line.indexOf(' '); if (sp < 0) continue;
    String dom = line.substring(0, sp); String ip = line.substring(sp + 1); ip.trim();
    if (isIPv4Token(dom)) { String t = dom; dom = ip; ip = t; }   // tolerate "IP domain"
    int cut = ip.indexOf(' '); if (cut >= 0) ip = ip.substring(0, cut);
    String d; uint32_t v = parseIPv4(ip);
    if (!v || !normDomain(dom, d)) continue;
    const uint64_t h = fnv40(d.c_str(), d.length());
    bool dup = false; for (int k = 0; k < numHosts; k++) if (hostEnt[k].hash == h) { dup = true; break; }
    if (dup) continue;
    if (numHosts == MAX_HOSTS) { overflow = true; break; }
    hostEnt[numHosts].dom = d; hostEnt[numHosts].hash = h; hostEnt[numHosts].ip = v;
    numHosts++;
  }
  if (!overflow) return numHosts;
  loadHosts();
  return -1;
}
// Walk the label suffixes (foo.nas.home -> nas.home -> home) so a hosts entry for a
// parent name also covers its subdomains, mirroring how the blocklist matches.
static uint32_t hostsLookup(const char* domain) {
  if (numHosts == 0) return 0;
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    for (int i = 0; i < numHosts; i++) if (hostEnt[i].hash == h) return hostEnt[i].ip;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return 0;
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  // A banned device that has not queried since boot is not in clients[], so
  // rebuilding the file from the client table alone (which is what this used to do)
  // silently dropped its ban on the next toggle in the UI. The client table is the
  // authority for IPs it knows about; bannedIP stays the authority for the rest.
  uint32_t out[MAX_BAN]; int n = 0;
  auto add = [&](uint32_t ip) {
    for (int i = 0; i < n; i++) if (out[i] == ip) return;
    if (n < MAX_BAN) out[n++] = ip;
  };
  for (int i = 0; i < numClients; i++) if (clients[i].banned) add(clients[i].ip);
  for (int i = 0; i < numBanned; i++) {
    bool inTable = false;
    for (int k = 0; k < numClients && !inTable; k++) if (clients[k].ip == bannedIP[i]) inTable = true;
    if (!inTable) add(bannedIP[i]);
  }
  if (n > numBanned) Serial.printf("[ban] %d bans (table was %d)\n", n, numBanned);
  numBanned = n;
  memcpy(bannedIP, out, (size_t)n * sizeof(uint32_t));
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  Dev* c;
  if (numClients < MAX_CLIENTS) {
    c = &clients[numClients++];
  } else {
    // Table full: reuse the least recently seen slot. DHCP churn used to fill the
    // table for good, after which new devices were invisible and could not even be
    // banned. Bans live in bannedIP, so evicting a slot never loses one.
    int worst = 0;
    for (int i = 1; i < numClients; i++)
      if ((int32_t)(clients[i].lastSeen - clients[worst].lastSeen) < 0) worst = i;
    c = &clients[worst];
  }
  c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis();
  c->banned = isBannedIP(ip);
  getMac(ip, c->mac);
  return c;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0;
  int i = 12; size_t o = 0;
  while (i < len) {
    uint8_t l = pkt[i++];
    if (l == 0) break;
    if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0;
    if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]);
  }
  out[o] = 0;
  if (i + 4 > len) return 0;
  *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
// Build the reply for a locally-answered name. ip==0 -> blocked (0.0.0.0); a hosts
// override passes the mapped address. Only A records get an answer; anything else
// (AAAA, MX, ...) becomes a NOERROR/NODATA reply so clients fall back to IPv4.
static int buildAnswer(int qend, uint16_t qtype, uint32_t ip) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  IPAddress addr(ip);                                   // round-trip keeps the octet order right
  for (int k = 0; k < 4; k++) ans[12 + k] = addr[k];
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int buildBlocked(int qend, uint16_t qtype) { return buildAnswer(qend, qtype, 0); }
// ---- upstream transport: DoH (RFC 8484) and plain UDP/53 -------------------
// Give the dashboard a slice while we wait on the network: forwarding used to block
// the whole loop for up to a second per unanswered query, which made the panel crawl
// exactly when the link was bad.
static void pumpWeb() { web.handleClient(); }

// Read one CRLF-terminated line with a deadline. NetworkClientSecure::read() blocks
// for up to the socket timeout (~600 ms here), so the deadline sits on top of it.
static bool httpReadLine(WiFiClient& c, char* out, size_t cap, uint32_t deadline) {
  size_t n = 0;
  uint32_t lastPump = millis();
  while ((int32_t)(deadline - millis()) > 0) {
    const int ch = c.read();
    if (ch < 0) {
      if (!c.connected() && !c.available()) return false;
      if (millis() - lastPump >= 20) { lastPump = millis(); pumpWeb(); }
      delay(1);
      continue;
    }
    if (ch == '\n') { if (n && out[n - 1] == '\r') n--; out[n] = 0; return true; }
    if (n + 1 < cap) out[n++] = (char)ch;
  }
  return false;
}

static bool dohParseUrl(const char* url) {
  String u(url);
  if (!u.startsWith("https://")) return false;   // plain-http "DoH" would defeat the point
  u = u.substring(8);
  const int slash = u.indexOf('/');
  const String hostPort = slash < 0 ? u : u.substring(0, slash);
  dohPath = slash < 0 ? String("/dns-query") : u.substring(slash);
  const int colon = hostPort.indexOf(':');
  dohPort = 443;
  dohHost = hostPort;
  if (colon >= 0) {
    dohHost = hostPort.substring(0, colon);
    const long p = hostPort.substring(colon + 1).toInt();
    if (p > 0 && p < 65536) dohPort = (uint16_t)p;
  }
  return dohHost.length() > 0 && dohPort > 0;
}

// Certificate validation needs a plausible clock; without SNTP every handshake
// fails the validity check. Reported once instead of silently per query.
static bool clockPlausible() { return time(nullptr) > 1600000000; }

static void dohClose() {
  if (dohConnected || dohTls.connected()) dohTls.stop();
  dohConnected = false;
}

static bool dohConnect() {
  dohClose();
  if (!clockPlausible()) {
    if (!dohFailAt) Serial.println("[doh] clock not set (no SNTP) -> cannot validate the DoH certificate");
    dohFailAt = millis() ? millis() : 1; dohFailCount++;
    return false;
  }
  dohTls.setTimeout(4000);            // TCP connect + TLS handshake budget
  dohTls.setHandshakeTimeout(8);
  dohTls.useBuiltinCACertBundle();    // the full Mozilla root set is compiled in
  if (!dohTls.connect(dohHost.c_str(), dohPort)) {
    Serial.printf("[doh] connect %s:%u failed\n", dohHost.c_str(), (unsigned)dohPort);
    dohFailAt = millis() ? millis() : 1; dohFailCount++;
    return false;
  }
  dohTls.setTimeout(600);             // per-read budget; the query deadline is below
  dohConnected = true;
  return true;
}

// POST the query to the DoH endpoint, read the DNS message back into buf and return
// its length (0 = failure, the caller may fall back to UDP). The TLS session is
// kept alive between queries: a handshake per lookup would cost 0.3-1 s here.
static int dohForward(int qlen, uint16_t wid, const uint8_t* q, int ql) {
  if (!dohAvail) return 0;
  if (!clockPlausible()) {                 // no SNTP yet: certificate dates can't be checked
    static bool warned = false;
    if (!warned) { warned = true; Serial.println("[doh] waiting for SNTP before using DoH"); }
    return 0;
  }
  if (dohFailAt && millis() - dohFailAt < DOH_BACKOFF_MS) return 0;   // endpoint down: don't burn seconds per lookup
  for (int attempt = 0; attempt < 2; attempt++) {  // 2nd try: the kept-alive session may have expired
    if (!dohConnected && !dohConnect()) return 0;
    String req = String("POST ") + dohPath + " HTTP/1.1\r\nHost: " + dohHost +
                 "\r\nAccept: application/dns-message\r\nContent-Type: application/dns-message\r\nContent-Length: " +
                 qlen + "\r\nConnection: keep-alive\r\n\r\n";
    const size_t rl = req.length();
    bool ok = dohTls.write((const uint8_t*)req.c_str(), rl) == rl &&
              dohTls.write(buf, qlen) == (size_t)qlen;
    int code = 0; long clen = -1;
    char line[128];
    const uint32_t deadline = millis() + DOH_TIMEOUT_MS;
    if (ok && (!httpReadLine(dohTls, line, sizeof(line), deadline) ||
               sscanf(line, "HTTP/%*d.%*d %d", &code) != 1)) ok = false;
    while (ok) {                                  // headers
      if (!httpReadLine(dohTls, line, sizeof(line), deadline)) { ok = false; break; }
      if (!line[0]) break;                        // blank line ends the headers
      if (!strncasecmp(line, "Content-Length:", 15)) clen = atol(line + 15);
      else if (!strncasecmp(line, "Transfer-Encoding:", 18)) ok = false;   // chunked: unsupported
    }
    if (ok && (code != 200 || clen < 12 || clen > (long)sizeof(dohRx))) ok = false;
    int got = 0;
    while (ok && got < (int)clen) {
      const int r = dohTls.read(dohRx + got, (size_t)(clen - got));
      if (r > 0) { got += r; continue; }
      if ((int32_t)(deadline - millis()) <= 0) { ok = false; break; }
      pumpWeb();
    }
    if (ok && (got < 12 || dohRx[0] != (uint8_t)(wid >> 8) || dohRx[1] != (uint8_t)wid ||
               (q && ql > 0 && (got < 12 + ql || memcmp(dohRx + 12, q, ql) != 0)))) ok = false;
    if (ok) { memcpy(buf, dohRx, (size_t)got); dohOkCount++; dohFailAt = 0; return got; }
    dohClose();                                   // the stream is out of sync now
    dohFailAt = millis() ? millis() : 1; dohFailCount++;
  }
  return 0;
}

// Plain UDP/53 path. Issue #10: after one timeout the late reply used to sit in the
// socket and get relayed to the next client (every answer shifted by one). Now:
// drain stale datagrams first, send with a fresh random txid, and only accept a
// reply whose txid, question section and source address/port all match.
static int udpForward(int qlen, uint16_t wid, const uint8_t* q, int ql) {
  upstreamCli.clear();                                        // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.clear();  // drop stale late replies
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  uint32_t lastPump = t0;
  while (millis() - t0 < 1000) {                              // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) {
      if (millis() - lastPump >= 20) { lastPump = millis(); pumpWeb(); }
      delay(1);
      continue;
    }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.clear();                                      // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (uint8_t)(wid >> 8) || buf[1] != (uint8_t)wid) continue;
    if (q && ql > 0 && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    return n;
  }
  return 0;
}

// Forward the current query (buf[0..qlen)) with a fresh txid and restore the
// client's txid on the way back.
//
// `q`/`ql` is the caller's question section (12 bytes in), used to verify the answer.
// It used to be a local uint8_t q[260], but the question section can be up to 271
// bytes, and for the longer ones the copy silently did not happen — which turned the
// anti-spoofing check off (only the 16-bit txid was left) for exactly those queries.
static int forwardUpstream(int qlen, const uint8_t* q, int ql) {
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  int n = 0;
  if (dohAvail) n = dohForward(qlen, wid, q, ql);
  if (n <= 0 && (!dohAvail || DOH_UDP_FALLBACK)) {
    if (dohAvail) dohFallbackCount++;   // visible in stats: a downgrade is never silent
    n = udpForward(qlen, wid, q, ql);
  }
  if (n > 0) { buf[0] = cid0; buf[1] = cid1; }
  return n;
}

// ---- upstream answer cache -------------------------------------------------
// Everything below works on a raw DNS message: skip a (possibly compressed) name,
// then walk every RR subtracting the elapsed time from its TTL. The packets we
// cache are the ones upstream already validated in forwardUpstream(), and every
// byte offset is bounds-checked because a malformed reply must never be trusted.
static int dnsSkipName(const uint8_t* p, int len, int i) {
  while (i < len) {
    const uint8_t l = p[i];
    if (l == 0) return i + 1;
    if ((l & 0xC0) == 0xC0) return (i + 2 <= len) ? i + 2 : -1;   // compression pointer
    if (l & 0xC0) return -1;                                      // 0x40/0x80: reserved label type
    i += 1 + l;
  }
  return -1;
}
// One walk over a DNS message, used for both the cache-hit and the cache-store path.
//
// - subtracts `age` seconds from every real record TTL (clamped at 0),
// - optionally drops a trailing OPT pseudo-RR (the cached copy must not echo another
//   client's EDNS cookie / advertised UDP size, and it has to stay trailing-safe),
// - optionally clamps every TTL down to `capTtl` (the store path keeps entries short).
//
// Returns the (possibly shortened) message length, or -1 if it cannot be parsed. Doing
// this in one pass replaced dnsStripOpt() + up to two dnsAgeTtls() calls, i.e. the same
// answer was previously walked three times.
static int dnsWalkTtls(uint8_t* p, int n, uint32_t age, bool dropOpt, uint32_t capTtl, int32_t* minTtl) {
  if (minTtl) *minTtl = -1;
  if (n < 12) return -1;
  const uint32_t qd = ((uint32_t)p[4] << 8) | p[5];
  const uint32_t an = ((uint32_t)p[6] << 8) | p[7];
  const uint32_t ns = ((uint32_t)p[8] << 8) | p[9];
  const uint32_t ar = ((uint32_t)p[10] << 8) | p[11];
  int i = 12;
  for (uint32_t k = 0; k < qd; k++) {                  // question section: name + 4
    i = dnsSkipName(p, n, i);
    if (i < 0 || i + 4 > n) return -1;
    i += 4;                                            // qtype + qclass
  }
  int32_t minT = -1;
  int optStart = -1, optEnd = -1;
  const uint32_t rrs = an + ns + ar;
  for (uint32_t k = 0; k < rrs; k++) {
    const int start = i;
    i = dnsSkipName(p, n, i);
    if (i < 0 || i + 10 > n) return -1;
    const uint16_t type = ((uint16_t)p[i] << 8) | p[i + 1];
    const uint16_t rdlen = ((uint16_t)p[i + 8] << 8) | p[i + 9];
    if (i + 10 + rdlen > n) return -1;
    if (k >= an + ns && type == 41) {                  // OPT: not a lifetime, never aged
      optStart = start; optEnd = i + 10 + rdlen;
    } else {
      const uint32_t ttl = ((uint32_t)p[i + 4] << 24) | ((uint32_t)p[i + 5] << 16) |
                           ((uint32_t)p[i + 6] << 8) | p[i + 7];
      uint32_t nt = ttl > age ? ttl - age : 0;
      if (capTtl && nt > capTtl) nt = capTtl;
      p[i + 4] = (uint8_t)(nt >> 24); p[i + 5] = (uint8_t)(nt >> 16);
      p[i + 6] = (uint8_t)(nt >> 8);  p[i + 7] = (uint8_t)nt;
      if (minT < 0 || (int32_t)nt < minT) minT = (int32_t)nt;
    }
    i += 10 + rdlen;
  }
  if (dropOpt && optStart >= 0) {
    if (optEnd != i || ar == 0) return -1;             // OPT not last: leave the packet alone
    p[10] = (uint8_t)((ar - 1) >> 8); p[11] = (uint8_t)(ar - 1);
    i = optStart;
  }
  if (minTtl) *minTtl = minT;
  return i;
}
static uint32_t qHash(const uint8_t* p, int n) {
  uint32_t h = 2166136261u;
  for (int i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
  return h ? h : 1;                            // 0 marks an empty slot
}
// Key = lowercased question section (name + qtype + qclass) + one DO-bit byte.
// Lowercasing means a client that randomises 0x20 case still shares the entry; the
// caller's own casing is written back into the reply on a hit.
static int dnsKeyBuild(int qend) {
  if (qend < 17 || qend > DNS_CACHE_MAXQ) return 0;      // 12 header + name + 4
  int k = 0;
  for (int i = 12; i < qend - 4; i++) dnsKeyBuf[k++] = (uint8_t)tolower(dnsQSave[i]);
  for (int i = qend - 4; i < qend; i++) dnsKeyBuf[k++] = dnsQSave[i];   // qtype + qclass
  dnsKeyBuf[k++] = dnsQDo;
  return k;
}
// DO bit from the query's OPT pseudo-RR (its "TTL" field holds the flags).
static uint8_t dnsQueryDo(const uint8_t* q, int qlen, int qend) {
  const uint32_t ar = ((uint32_t)q[10] << 8) | q[11];
  int i = qend;
  for (uint32_t r = 0; r < ar; r++) {
    i = dnsSkipName(q, qlen, i);
    if (i < 0 || i + 10 > qlen) return 0;
    const uint16_t type = ((uint16_t)q[i] << 8) | q[i + 1];
    const uint16_t rdlen = ((uint16_t)q[i + 8] << 8) | q[i + 9];
    if (type == 41) return (q[i + 6] & 0x80) ? 1 : 0;
    i += 10 + rdlen;
  }
  return 0;
}
// Full-byte comparison of the key (the hash alone is never trusted). Only the entries in
// this hash bucket are examined, so a lookup is O(1) instead of a 1024-slot scan.
static int dnsCacheFind(uint32_t h, int klen) {
  if (!dnsCache) return -1;
  for (int16_t i = cacheHead[h & (CACHE_BUCKETS - 1)]; i >= 0; i = dnsCache[i].hnext) {
    const DnsCacheEnt& e = dnsCache[i];
    if (!e.pkt || e.sig != h || e.keyLen != klen) continue;
    if (memcmp(e.pkt + e.len, dnsKeyBuf, klen) == 0) return i;
  }
  return -1;
}

// ---- table management: hash chains + intrusive LRU list, both O(1) ------------
// The eviction policy is plain LRU now. It used to be "closest to expiry, then fewest
// hits, then least recently used", which meant scanning all 1024 slots per eviction —
// and a full table evicts on every store. Expired entries end up at the LRU tail anyway.
static void cacheLruUnlink(int i) {
  DnsCacheEnt& e = dnsCache[i];
  if (e.lprev >= 0) dnsCache[e.lprev].lnext = e.lnext; else if (cacheMru == i) cacheMru = e.lnext;
  if (e.lnext >= 0) dnsCache[e.lnext].lprev = e.lprev; else if (cacheLru == i) cacheLru = e.lprev;
  e.lprev = e.lnext = -1;
}
static void cacheLruFront(int i) {
  DnsCacheEnt& e = dnsCache[i];
  e.lprev = -1; e.lnext = cacheMru;
  if (cacheMru >= 0) dnsCache[cacheMru].lprev = (int16_t)i; else cacheLru = (int16_t)i;
  cacheMru = (int16_t)i;
}
static void cacheHashUnlink(int i) {
  DnsCacheEnt& e = dnsCache[i];
  int16_t* pp = &cacheHead[e.sig & (CACHE_BUCKETS - 1)];
  while (*pp >= 0) {
    if (*pp == i) { *pp = e.hnext; return; }
    pp = &dnsCache[*pp].hnext;
  }
}
static void dnsCacheDrop(int i) {
  DnsCacheEnt& e = dnsCache[i];
  if (!e.pkt) return;
  cacheLruUnlink(i);
  cacheHashUnlink(i);
  heap_caps_free(e.pkt);
  dnsCacheBytes -= e.cap;
  e.pkt = nullptr;
  e.hnext = cacheFree;                // back on the free-slot stack
  cacheFree = (int16_t)i;
}
// A slot ready for a new entry, evicting the LRU tail when the table is full.
static int dnsCacheSlot() {
  if (!dnsCache) return -1;
  if (cacheFree < 0) {
    if (cacheLru < 0) return -1;
    dnsCacheDrop(cacheLru);
    dnsCacheEvicted++;
    if (cacheFree < 0) return -1;
  }
  const int i = cacheFree;
  cacheFree = dnsCache[i].hnext;
  dnsCache[i].hnext = -1;
  return i;
}
static uint32_t dnsCacheRemain(const DnsCacheEnt& e, uint32_t now) {
  const uint32_t ageS = (now - e.storedMs) / 1000;
  return ageS >= e.expireS ? 0 : e.expireS - ageS;      // 0 = already expired
}

// `h`/`klen` are the key hash and length already built by the caller (dnsKeyBuild()),
// so a miss does not build and hash the same key twice (lookup + store).
static int dnsCacheLookup(int qend, uint32_t h, int klen) {
  const int i = dnsCacheFind(h, klen);
  if (i < 0) return 0;
  DnsCacheEnt& e = dnsCache[i];
  const uint32_t now = millis();
  const uint32_t ageS = (now - e.storedMs) / 1000;
  // Expired entries are reclaimed here instead of lingering: they used to keep their
  // slot (and be re-parsed on every query) while always answering "miss".
  if (ageS >= e.expireS) { dnsCacheDrop(i); return 0; }
  int32_t left = 0;
  const int n2 = dnsWalkTtls(e.pkt, e.len, ageS, false, 0, &left);
  if (n2 <= 0 || left <= 0) { dnsCacheDrop(i); return 0; }
  e.expireS = (uint32_t)left;
  e.storedMs += ageS * 1000UL;
  cacheLruUnlink(i);
  cacheLruFront(i);
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  memcpy(buf, e.pkt, e.len);
  memcpy(buf + 12, dnsQSave + 12, qend - 12);           // this caller's own 0x20 casing
  buf[0] = cid0; buf[1] = cid1;
  dnsCacheHits++;
  return e.len;
}
// Advertise at most 1232 bytes of UDP payload (DNS flag day 2020). Our receive buffer
// is 1536 bytes and anything above ~1232 risks IP fragmentation, so a client that
// advertises 4096 used to make upstream send a datagram we then dropped outright — the
// client saw a timeout instead of TC=1 and never retried over TCP.
static void dnsClampUdpSize(uint8_t* q, int qlen, int qend) {
  const uint32_t ar = ((uint32_t)q[10] << 8) | q[11];
  int i = qend;
  for (uint32_t r = 0; r < ar; r++) {
    i = dnsSkipName(q, qlen, i);
    if (i < 0 || i + 10 > qlen) return;
    const uint16_t type = ((uint16_t)q[i] << 8) | q[i + 1];
    const uint16_t rdlen = ((uint16_t)q[i + 8] << 8) | q[i + 9];
    if (i + 10 + rdlen > qlen) return;
    if (type == 41) {                        // OPT: the class field is the payload size
      const uint16_t want = 1232;
      if ((((uint16_t)q[i + 2] << 8) | q[i + 3]) > want) {
        q[i + 2] = (uint8_t)(want >> 8); q[i + 3] = (uint8_t)want;
      }
      return;
    }
    i += 10 + rdlen;
  }
}

// Only positive NOERROR answers are cached. NXDOMAIN/NODATA and SERVFAIL are cheap
// to re-ask and caching them makes a transient upstream wobble sticky for minutes.
//
// Returns the length of the packet now in buf: caching rewrites the packet in place
// (drops the caller's OPT record, clamps TTLs), so the caller must send exactly this
// many bytes. It used to return void while shortening the packet, which left ARCOUNT=0
// with the OPT bytes still trailing in the datagram sent to the client.
static int dnsCacheStore(int qend, int n, uint32_t h, int klen) {
  if (!dnsCache || klen <= 0 || n < 13 || n > DNS_CACHE_MAXLEN) return n;
  if ((buf[3] & 0x0F) != 0) return n;                       // rcode != NOERROR
  if ((((uint16_t)buf[6] << 8) | buf[7]) == 0) return n;    // ANCOUNT == 0
  // One pass: drop the caller's EDNS OPT and clamp the TTLs to DNS_CACHE_MAX_TTL.
  int32_t ttl = -1;
  const int prepared = dnsWalkTtls(buf, n, 0, true, DNS_CACHE_MAX_TTL, &ttl);
  if (prepared < 13 || ttl <= 0) return n;                  // not cacheable; buf left usable
  n = prepared;

  const size_t need = (size_t)n + (size_t)klen;             // exact size of this entry
  const uint32_t now = millis();
  int slot = dnsCacheFind(h, klen);
  bool fresh = false;
  if (slot >= 0 && dnsCache[slot].cap < need) { dnsCacheDrop(slot); slot = -1; }  // too small
  if (slot < 0) {
    slot = dnsCacheSlot();
    if (slot < 0) return n;
    // heap_caps_malloc, not ps_malloc(): arduino-esp32's ps_malloc() gates on its own
    // "PSRAM is up" flag, which the precompiled opi libs never set here — the PSRAM
    // region is in the heap (heap_caps sees the full 8MB) but ps_malloc() returns NULL.
    uint8_t* p = (uint8_t*)heap_caps_malloc(need, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) return n;                                       // PSRAM exhausted -> run uncached
    memset(&dnsCache[slot], 0, sizeof(DnsCacheEnt));
    dnsCache[slot].pkt = p;
    dnsCache[slot].cap = (uint16_t)need;
    dnsCacheBytes += need;
    fresh = true;
  }
  DnsCacheEnt& e = dnsCache[slot];
  memcpy(e.pkt, buf, n);
  memcpy(e.pkt + n, dnsKeyBuf, klen);
  e.sig = h; e.keyLen = (uint16_t)klen; e.len = (uint16_t)n;
  e.storedMs = now; e.expireS = (uint32_t)ttl;
  if (fresh) {
    const int b = (int)(h & (CACHE_BUCKETS - 1));
    e.hnext = cacheHead[b]; cacheHead[b] = (int16_t)slot;
    e.lprev = e.lnext = -1;
  } else {
    cacheLruUnlink(slot);
  }
  cacheLruFront(slot);
  return n;
}
// Live (not yet expired) entries and the exact PSRAM they hold, for the dashboard.
// This is the only place that walks all slots; it is not in the query path.
static int dnsCacheUsed() {
  if (!dnsCache) return 0;
  const uint32_t now = millis();
  int n = 0;
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) if (dnsCache[i].pkt && dnsCacheRemain(dnsCache[i], now) > 0) n++;
  return n;
}
// Called whenever the rule set changes: answers cached before the swap may point at
// names the new list blocks (or at addresses it no longer blocks), so drop them all.
static void dnsCacheFlush() {
  if (!dnsCache) return;
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) dnsCacheDrop(i);
}
// Allocate the slot table itself: ~34 KB for 1024 slots, so PSRAM, not internal RAM.
static void dnsCacheInit() {
  dnsCache = (DnsCacheEnt*)heap_caps_malloc(sizeof(DnsCacheEnt) * DNS_CACHE_SLOTS,
                                            MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!dnsCache) dnsCache = (DnsCacheEnt*)malloc(sizeof(DnsCacheEnt) * DNS_CACHE_SLOTS);
  if (!dnsCache) { Serial.println("[cache] WARN no memory for the answer cache -> uncached"); return; }
  memset(dnsCache, 0, sizeof(DnsCacheEnt) * DNS_CACHE_SLOTS);
  for (int i = 0; i < CACHE_BUCKETS; i++) cacheHead[i] = -1;
  for (int i = 0; i < DNS_CACHE_SLOTS; i++)
    dnsCache[i].hnext = (int16_t)(i + 1 < DNS_CACHE_SLOTS ? i + 1 : -1);   // free-slot stack
  cacheFree = 0;
  cacheMru = cacheLru = -1;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 8; budget++) {   // 8 per call; the forward path pumps web while waiting
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    // A ban is absolute: a banned device gets sinkhole answers even for names that
    // have an explicit hosts mapping (the mapping used to win).
    bool blocked = ban || (blockingOn && dl && isBlocked(domain));
    uint32_t mapped = (!blocked && dl) ? hostsLookup(domain) : 0;
    // NB: no `numHashes &&` here. The custom list is checked in RAM and has nothing
    // to do with the flash blob; gating on it made custom domains silently useless
    // whenever /blocklist.bin was missing (fresh flash, failed update, ...).
    int rlen;
    if (mapped)  { rlen = buildAnswer(qend, qtype, mapped);       totalAllowed++; if (c) c->allowed++; }
    else if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else {
      // Unblocked: try the answer cache first, then the upstream. The question section
      // is snapshotted because forwardUpstream() overwrites buf with the reply and the
      // cache key / question patch / anti-spoofing check need the caller's own bytes.
      const bool haveQ = dl && qend >= 12 && qend <= (int)sizeof(dnsQSave);
      if (haveQ) { memcpy(dnsQSave, buf, qend); dnsQDo = dnsQueryDo(buf, qlen, qend); }
      // Keep the answer inside buf[]: tell upstream how much room we actually have.
      dnsClampUdpSize(buf, qlen, qend);
      const bool cacheable = haveQ && qend >= 17;
      // Build the key once and reuse the hash for both the lookup and the store.
      const int klen = cacheable ? dnsKeyBuild(qend) : 0;
      const uint32_t kh = klen > 0 ? qHash(dnsKeyBuf, klen) : 0;
      rlen = klen > 0 ? dnsCacheLookup(qend, kh, klen) : 0;
      if (rlen <= 0) {
        if (dl) dnsCacheMiss++;
        const int r = forwardUpstream(qlen, haveQ ? dnsQSave + 12 : nullptr, haveQ ? qend - 12 : 0);
        rlen = (r > 0 && klen > 0) ? dnsCacheStore(qend, r, kh, klen) : r;   // store() may shorten buf
        if (rlen > 0) { totalAllowed++; if (c) c->allowed++; }      // only count answers we got
      } else {
        totalAllowed++; if (c) c->allowed++;
      }
    }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
// JSON string escaping. Control characters matter: a URL with a stray newline in
// /update.cfg used to make /stats.json invalid JSON, which blanked the whole panel.
static String jesc(const String& s) {
  String o; o.reserve(s.length() + 8);
  for (size_t i = 0; i < s.length(); i++) {
    const char ch = s[i];
    if (ch == '"' || ch == '\\') { o += '\\'; o += ch; }
    else if ((uint8_t)ch < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", (unsigned)(uint8_t)ch); o += b; }
    else o += ch;
  }
  return o;
}
// HTML text/attribute escaping for the setup portal. jesc() covers JSON (stats
// endpoint); the portal builds HTML, and its inputs — a scanned SSID, the
// submitted WiFi name — are attacker-controllable during provisioning (the
// portal AP is open, and a nearby attacker can also broadcast an SSID of their
// choosing). Without escaping both, a crafted SSID/name is reflected script
// into the setup page, the same class as the dashboard XSS fixed earlier.
static String htmlEscape(const String& s) {
  String o; o.reserve(s.length());
  for (char ch : s) {
    switch (ch) {
      case '&':  o += "&amp;";  break;
      case '<':  o += "&lt;";   break;
      case '>':  o += "&gt;";   break;
      case '"':  o += "&quot;"; break;
      case '\'': o += "&#39;";  break;
      default:   o += ch;
    }
  }
  return o;
}

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static String upstreamDesc() {
  if (dohAvail) return String("DoH ") + dohHost;
  return String("UDP ") + IPAddress(UPSTREAM).toString() + ":" + UPSTREAM_PORT;
}
// Whether DoH is actually *carrying* queries right now — "configured" is not the same
// thing. off = DOH_URL empty, ntp = no clock yet (certificates can't be validated, so
// queries still go over plain UDP), ok = TLS session up and serving, down = last
// attempt failed and we are in the 30 s backoff (queries fall back to UDP unless
// DOH_UDP_FALLBACK is 0), idle = configured with a valid clock but no live session yet.
static const char* dohState() {
  if (!dohAvail) return "off";
  if (!clockPlausible()) return "ntp";
  if (dohConnected) return "ok";
  if (dohFailAt && millis() - dohFailAt < DOH_BACKOFF_MS) return "down";
  return "idle";
}

// Everything the panel needs, plus the diagnostics that only make sense from a
// terminal (`curl /stats.json | grep ...`): memory watermarks, PSRAM, flash usage,
// staging files left over from an interrupted swap, the DoH backoff countdown, the
// clock (does SNTP actually answer?) and a per-client last-seen age. The panel ignores
// keys it does not know, so adding one here never touches web/src/app.jsx.
static void handleStats() {
  const uint32_t nowMs = millis();
  const uint32_t up = nowMs / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  char built[32]; snprintf(built, sizeof(built), "%s %s", __DATE__, __TIME__);
  uint8_t mac[6]; WiFi.macAddress(mac);
  // Seconds left in the DoH backoff window (0 = not backing off).
  const uint32_t dohBackoffS = (dohFailAt && nowMs - dohFailAt < DOH_BACKOFF_MS)
                                 ? (DOH_BACKOFF_MS - (nowMs - dohFailAt)) / 1000 : 0;
  String j;
  j.reserve(1536 + (size_t)numClients * 128 + (size_t)numCustom * 28 + (size_t)numHosts * 40);
  j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"mac\":\"" + macStr(mac) +
             "\",\"ssid\":\"" + jesc(WiFi.SSID()) + "\",\"gw\":\"" + WiFi.gatewayIP().toString() +
             "\",\"ch\":" + WiFi.channel() +
             ",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"heapTotal\":" + ESP.getHeapSize() +
             ",\"heapMin\":" + ESP.getMinFreeHeap() +
             ",\"psram\":" + (uint32_t)heap_caps_get_free_size(MALLOC_CAP_SPIRAM) +
             ",\"psramTotal\":" + (uint32_t)heap_caps_get_total_size(MALLOC_CAP_SPIRAM) +
             ",\"psramMin\":" + (uint32_t)heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM) +
             ",\"cpu\":" + getCpuFrequencyMhz() + ",\"build\":\"" + built +
             "\",\"idf\":\"" + jesc(ESP.getSdkVersion()) + "\"" +
             ",\"epoch\":" + (uint32_t)time(nullptr) +
             ",\"uptime\":\"" + ut + "\",\"uptimeS\":" + up +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"uphour\":" + updateHour + ",\"uptz\":" + updateTz +
             ",\"upday\":" + lastUpdateDay + ",\"upstat\":\"" + jesc(updateStatus) + "\",\"upbusy\":" + (updRunning ? "true" : "false") +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"led\":" + (ledOn ? "true" : "false") +
             ",\"ledPin\":" + LED_PIN +
             ",\"up\":\"" + jesc(upstreamDesc()) + "\"" +
             ",\"dohState\":\"" + dohState() + "\"" +
             ",\"dohOk\":" + dohOkCount + ",\"dohFail\":" + dohFailCount + ",\"dohFallback\":" + dohFallbackCount +
             ",\"dohBackoffS\":" + dohBackoffS +
             ",\"fetchInsecure\":" + (fetchSecure ? "false" : "true") +
             ",\"fetchChunked\":" + (chunkedFetch ? "true" : "false") +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt && (int32_t)(resumeAt - nowMs) > 0
                                              ? (resumeAt - nowMs) / 1000 : 0) +
             ",\"dnsHit\":" + dnsCacheHits + ",\"dnsMiss\":" + dnsCacheMiss +
             ",\"dnsCacheN\":" + dnsCacheUsed() + ",\"dnsCacheCap\":" + DNS_CACHE_SLOTS +
             ",\"dnsCacheBytes\":" + (uint32_t)dnsCacheBytes +
             ",\"dnsEvict\":" + dnsCacheEvicted +
             ",\"blBytes\":" + (uint32_t)(blocklist ? blocklist.size() : 0) +
             ",\"blIndex\":" + indexEntries + ",\"blCap\":" + (uint32_t)FLASH_HASH_CAPACITY +
             // Non-zero blIndexErr = the index could not be rebuilt (blocking is off);
             // blStreams counts buckets that needed more than one flash read.
             ",\"blIndexErr\":" + blIndexErrors + ",\"blStreams\":" + blRangeStreams +
             ",\"fsUsed\":" + (uint32_t)LittleFS.usedBytes() + ",\"fsTotal\":" + (uint32_t)LittleFS.totalBytes() +
             ",\"clientN\":" + numClients + ",\"banN\":" + numBanned +
             ",\"customN\":" + numCustom + ",\"customCap\":" + MAX_CUSTOM +
             ",\"hostN\":" + numHosts + ",\"hostCap\":" + MAX_HOSTS +
             // A staging file that survives a reboot means a swap was interrupted; the
             // three of them together say whether the old list is still parked.
             ",\"tmpUp\":" + (LittleFS.exists(BL_TMP_UPLOAD) ? "true" : "false") +
             ",\"tmpRemote\":" + (LittleFS.exists(BL_TMP_REMOTE) ? "true" : "false") +
             ",\"blOld\":" + (LittleFS.exists(BL_OLD) ? "true" : "false") +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + ",\"age\":" + (uint32_t)((nowMs - c.lastSeen) / 1000) + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"hosts\":[";
  for (int i = 0; i < numHosts; i++) { IPAddress ip(hostEnt[i].ip); j += (i ? "," : "");
    j += "{\"h\":\"" + jesc(hostEnt[i].dom) + "\",\"ip\":\"" + ip.toString() + "\"}"; }
  j += "]}";
  web.send(200, "application/json", j);
}
// ---------- dashboard (built by web/build.mjs into data/index.html[.gz]) ----------
// The page is one self-contained gzipped HTML (~18KB) stored in LittleFS: no CDN fetch,
// so the dashboard works even when the device itself has no internet access.
static void handleRoot() {
  // WebServer adds "Content-Encoding: gzip" for *any* file ending in .gz without ever
  // looking at the request, so a client that cannot inflate it (curl without
  // --compressed) got binary garbage with no way to tell why. build.mjs writes the
  // plain copy too (60 KB, the partition has room), and we pick here.
  const bool wantsGz = web.header("Accept-Encoding").indexOf("gzip") >= 0;
  File f = LittleFS.open(wantsGz ? "/index.html.gz" : "/index.html", "r");
  // Fall back to whichever file the filesystem actually has (an older fs image only
  // carries the .gz; a rebuilt one carries both).
  if (!f) f = LittleFS.open(wantsGz ? "/index.html" : "/index.html.gz", "r");
  if (!f) { web.send_P(200, "text/html", PAGE); return; }       // flash FS not written yet
  web.sendHeader("Vary", "Accept-Encoding");
  web.sendHeader("Cache-Control", "no-cache");
  web.streamFile(f, "text/html");
  f.close();
}

// Upstream shipped every state-changing/OTA endpoint with zero authentication —
// anyone on the LAN could reflash firmware or rewrite the blocklist. Gate them.
//
// Basic Auth alone isn't enough here: these are GET endpoints with side effects,
// and browsers auto-attach cached Basic Auth credentials to *any* request to an
// already-authenticated origin — including one triggered by a completely
// unrelated page the victim's browser visits later (e.g. <img src="http://
// s3adblock.local/pause?s=0">). That's CSRF, and it defeats the LAN-attacker
// threat model entirely: the attacker doesn't need network access, just to get
// the victim's browser to fire one request. A custom header can't be attached
// by a plain <img>/<form> CSRF vector (only same-origin fetch() can set it, and
// that's exactly what the dashboard's own JS does), so requiring one blocks the
// drive-by case without needing TLS, cookies, or a token endpoint.
static const char* CSRF_HEADER = "X-Requested-With";
static const char* CSRF_VALUE  = "s3-adblock";
static bool requireAuth() {
  if (web.header(CSRF_HEADER) != CSRF_VALUE) { web.send(403, "text/plain", "missing CSRF header"); return false; }
  if (web.authenticate(WEB_USER, WEB_PASS)) return true;
  web.requestAuthentication();
  return false;
}
static void handleBan() {
  if (!requireAuth()) return;
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}

// ---------- blocklist swap (shared by upload + remote fetch) ----------
// Writers always produce a complete temp file first and the live list is only
// replaced once that file has been validated. The old code deleted /blocklist.bin
// *before* writing the replacement, so any failure (bad download, full flash, power
// cut) left the device with zero rules and blocking silently off.
// (BL_TMP_UPLOAD / BL_TMP_REMOTE / BL_OLD / FLASH_HASH_CAPACITY are declared up
// with the other config, both for /stats.json and to keep them in one place.)

static void reopenBlocklist() {
  if (blocklist) blocklist.close();
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
  dnsCacheFlush();          // rules changed -> cached answers may now be wrong
}

static bool readFully(File& f, uint8_t* dst, size_t n) {
  size_t got = 0;
  while (got < n) { const int r = f.read(dst + got, n - got); if (r <= 0) return false; got += (size_t)r; }
  return true;
}

// A hash blob is usable only if it is non-empty, a whole number of 5-byte entries,
// and sorted: inFlash() binary-searches it, so an unsorted or truncated blob
// silently loses rules. Costs ~1 s per MB and only runs on an update.
static bool blocklistIsValid(File& f, uint32_t* outN, const char** why) {
  const size_t sz = f.size();
  if (sz < HASH_BYTES) { *why = "empty"; return false; }
  if (sz % HASH_BYTES) { *why = "size is not a multiple of 5"; return false; }
  if (sz / HASH_BYTES > FLASH_HASH_CAPACITY) { *why = "larger than the partition"; return false; }
  enum { CHUNK = 500 };                            // 100 entries per read
  uint8_t b[CHUNK]; uint64_t prev = 0; bool havePrev = false;
  f.seek(0);
  size_t left = sz;
  while (left) {
    const size_t want = left < (size_t)CHUNK ? left : (size_t)CHUNK;
    if (!readFully(f, b, want)) { *why = "read error"; return false; }
    for (size_t i = 0; i + HASH_BYTES <= want; i += HASH_BYTES) {
      const uint64_t v = unpackHash(b + i);
      if (havePrev && v < prev) { *why = "not sorted"; return false; }
      prev = v; havePrev = true;
    }
    left -= want;
  }
  *outN = (uint32_t)(sz / HASH_BYTES);
  return true;
}

// Validate a fully written temp file and swap it in.
//
// littlefs' rename() does not reliably replace an existing destination (the VFS also
// refuses to rename over an *open* file), so the live list is parked as /bl.old first
// and renamed back if the second step fails. Nothing is ever deleted before a
// validated replacement exists, and setup() restores /bl.old after a power cut.

static bool applyBlocklist(const char* tmpPath, bool preValidated = false, uint32_t preCount = 0) {
  if (!preValidated) {
    File f = LittleFS.open(tmpPath, "r");
    if (!f) { updateStatus = "temp file missing"; return false; }
    uint32_t n = preCount;
    const char* why = "?";
    const bool ok = blocklistIsValid(f, &n, &why);
    f.close();
    if (!ok) {
      LittleFS.remove(tmpPath);
      updateStatus = String("rejected: ") + why;
      Serial.printf("[bl] rejected %s: %s\n", tmpPath, why);
      return false;
    }
  }
  if (blocklist) blocklist.close();
  LittleFS.remove(BL_OLD);
  const bool haveOld = LittleFS.exists(BLOCKLIST_PATH);
  if (haveOld) LittleFS.rename(BLOCKLIST_PATH, BL_OLD);          // park the working list
  if (!LittleFS.rename(tmpPath, BLOCKLIST_PATH)) {
    if (haveOld) LittleFS.rename(BL_OLD, BLOCKLIST_PATH);        // roll back
    LittleFS.remove(tmpPath);
    reopenBlocklist();
    updateStatus = "rename failed";
    Serial.println("[bl] rename failed");
    return false;
  }
  LittleFS.remove(BL_OLD);
  reopenBlocklist();
  updateStatus = "ok: " + String(numHashes) + " domains";
  Serial.printf("[bl] live: %u domains\n", (unsigned)numHashes);
  return true;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static bool upWriteErr = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain", upOk ? "ok" : updateStatus);
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; upWriteErr = false;
      upFile = LittleFS.open(BL_TMP_UPLOAD, "w");      // live list keeps working meanwhile
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      if (!upFile) Serial.println("[ota] cannot create the temp file");
      break;
    case UPLOAD_FILE_WRITE:
      // A short write leaves a truncated temp file, and a truncated hash blob is still
      // "non-empty, 5-aligned and sorted" — i.e. it passes blocklistIsValid() and would
      // silently shrink the rule set. fetchBin() always checked this; this path did not.
      if (upAuthOk && upFile && !upWriteErr && upFile.write(u.buf, u.currentSize) != u.currentSize) {
        upWriteErr = true;
        Serial.println("[ota] write failed (flash full?) -> upload rejected");
      }
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      if (upWriteErr) {
        LittleFS.remove(BL_TMP_UPLOAD);
        upOk = false;
        updateStatus = "upload failed: write error (flash full?)";
        Serial.println("[ota] rejected: write error");
        break;
      }
      upOk = applyBlocklist(BL_TMP_UPLOAD);
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", (unsigned)numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove(BL_TMP_UPLOAD);                    // the live list was never touched
      Serial.println("[ota] aborted");
      break;
  }
}

// ---------- remote blocklist auto-update ----------
// /update.cfg layout (one value per line): url, updateHour, updateTz, lastUpdateDay.
// A legacy two-line file (url + "hours between fetches") is still accepted: the
// interval is ignored and the compiled-in hour/timezone are used instead.
static void loadUpdateCfg() {
  updateUrl = RULE_URL; updateHour = RULE_HOUR; updateTz = RULE_TZ; lastUpdateDay = 0;
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String hh = f.readStringUntil('\n'); hh.trim();
  String tz = f.readStringUntil('\n'); tz.trim();
  String dy = f.readStringUntil('\n'); dy.trim();
  f.close();
  if (tz.length() && dy.length()) {                    // current format
    int h = hh.toInt(); if (h >= 0 && h < 24) updateHour = (uint8_t)h;
    int t = tz.toInt(); if (t >= -12 && t <= 14) updateTz = (int8_t)t;
    lastUpdateDay = dy.toInt();
  }
  if (!updateUrl.length()) updateUrl = RULE_URL;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateHour); f.println(updateTz); f.println(lastUpdateDay);
  f.close();
}
// TLS for rule fetches. Certificate validation needs a plausible clock, so the
// compiled-in root bundle is used whenever SNTP has answered; otherwise we say so
// loudly (stats: fetchInsecure) instead of silently accepting any certificate —
// which is exactly the MITM hole this closes.
static void tlsForFetch(WiFiClientSecure& cs) {
  if (clockPlausible()) { cs.useBuiltinCACertBundle(); fetchSecure = true; }
  else {
    cs.setInsecure(); fetchSecure = false;
    Serial.println("[remote] WARN clock not set (SNTP) -> TLS certificate NOT verified");
  }
}

// A prebuilt hash blob: streamed into the temp file (legacy path, *.bin URLs).
static bool fetchBin(const String& url) {
  Serial.printf("[remote] GET bin %s\n", url.c_str());
  WiFiClientSecure cs; tlsForFetch(cs);
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  const bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { fetchStatus = "begin failed"; return false; }
  const int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); fetchStatus = "HTTP " + String(code); return false; }
  File f = LittleFS.open(BL_TMP_REMOTE, "w");
  if (!f) { http.end(); fetchStatus = "fs open failed"; return false; }
  WiFiClient* stream = http.getStreamPtr();
  const int len = http.getSize();                          // -1 = chunked / unknown
  uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  bool writeErr = false;
  while (!writeErr && http.connected() && (len < 0 || (int)total < len)) {
    const size_t avail = stream->available();
    if (avail) {
      const int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
      if (n > 0) {
        if (f.write(b, (size_t)n) != (size_t)n) writeErr = true;   // flash full / FS error
        total += (size_t)n; idle = millis();
      }
    } else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  if (writeErr) { LittleFS.remove(BL_TMP_REMOTE); fetchStatus = "write failed (flash full?)"; return false; }
  // A truncated body is indistinguishable from a valid prefix once it is on flash,
  // so a length we cannot verify — and a byte count that doesn't match — reject it.
  if (len < 0) { LittleFS.remove(BL_TMP_REMOTE); fetchStatus = "chunked body, size unverifiable"; return false; }
  if ((int)total != len) {
    LittleFS.remove(BL_TMP_REMOTE);
    fetchStatus = "short download (" + String((unsigned)total) + "/" + String(len) + "B)";
    return false;
  }
  return true;
}

// ---------- text rule lists, parsed on the device ----------
// The ESP32-S3 has room to hash a plain-text list itself, so scheduled updates can
// point straight at a rules file (AWAvenue, hosts files, plain domain lists,
// AdGuard basic rules) instead of a prebuilt .bin that someone has to host.
// Domains are hashed into a PSRAM arena, sorted, deduped and written to
// /blocklist.new, then swapped in through the same validation as an upload.
static uint64_t* ruleHashes  = nullptr;
static size_t    ruleCount = 0, ruleCap = 0;
static uint64_t* allowHashes = nullptr;      // @@ allow rules from the same list
static size_t    allowCount = 0, allowCap = 0;
static uint32_t  ruleSkipped = 0;
static bool      ruleOom = false;            // arena could not grow -> fail the update, never truncate

// What an arena may grow to: a third of the PSRAM we can still use, capped by what the
// LittleFS partition can store as 5-byte entries.
//
// The budget is "free now + what this arena already holds", because a realloc that
// needs to move the block consumes exactly the headroom the limit was computed from.
// Using free alone made the ceiling shrink as the arena grew — the real limit worked out
// to about 1/24 of PSRAM instead of 1/3, so big lists failed with "out of memory".
static size_t arenaLimit(const uint64_t* arr, size_t cap) {
  size_t budget = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
  if (arr && cap) budget += cap * sizeof(uint64_t);
  size_t lim = budget / 3 / sizeof(uint64_t);
  if (lim > FLASH_HASH_CAPACITY) lim = FLASH_HASH_CAPACITY;
  return lim;
}
static void arenaPush(uint64_t** arr, size_t* count, size_t* cap, uint64_t h) {
  if (*count + 1 > *cap) {
    size_t want = *cap ? *cap * 2 : 8192;
    const size_t lim = arenaLimit(*arr, *cap);
    if (want > lim) want = lim;
    if (*count + 1 > want) { ruleOom = true; return; }
    uint64_t* p = (uint64_t*)heap_caps_realloc(*arr, want * sizeof(uint64_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) { ruleOom = true; return; }
    *arr = p; *cap = want;
  }
  (*arr)[(*count)++] = h;
}

// Lowercase/normalise a domain exactly like tools/build_blocklist.py's norm():
// strip leading wildcards + dots, trailing dots, a leading "www.".
static void addRuleDomain(const char* raw, bool allow) {
  char d[260];
  size_t n = strlen(raw);
  if (n == 0 || n >= sizeof(d)) return;
  memcpy(d, raw, n + 1);
  char* s = d; while (*s == '*' || *s == '.') s++;
  size_t m = strlen(s); while (m && s[m - 1] == '.') s[--m] = 0;
  if (m > 4 && strncmp(s, "www.", 4) == 0) { s += 4; m -= 4; }
  if (m < 3 || m > 253 || !strchr(s, '.')) return;
  for (size_t i = 0; i < m; i++) {
    char c = s[i];
    if (c >= 'A' && c <= 'Z') s[i] = c + 32;
    else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return;
  }
  // A single label ("localhost") never reaches here: the "must contain a dot" test
  // above already rejects it, so the old localhost special case was dead code.
  if (strcmp(s, "localhost") == 0) return;
  arenaPush(allow ? &allowHashes : &ruleHashes,
            allow ? &allowCount : &ruleCount,
            allow ? &allowCap : &ruleCap, fnv40(s, m));
}

// AdGuard/ABP: ||domain^ and @@||domain^ (allow). Rules carrying a path, wildcard
// or $modifier cannot be expressed as one domain hash and are skipped — the same
// call tools/build_blocklist.py makes, so the on-device parser and a prebuilt .bin
// agree on what a list means. (@@ allow rules used to be dropped outright, which
// made the device block names the list explicitly unblocks.)
static void parsePipeRule(char* dom, bool allow) {
  char* e = dom;
  while (*e && *e != '^' && *e != '$' && *e != '/' && *e != '|') e++;
  const bool bare = (*e == 0) || (*e == '^' && e[1] == 0);
  if (!bare) { ruleSkipped++; return; }
  *e = 0;
  addRuleDomain(dom, allow);
}

static void parseRuleLine(char* line) {
  char* hash = strchr(line, '#'); if (hash) *hash = 0;   // comments (AdGuard cosmetics too)
  char* s = line; while (*s == ' ' || *s == '\t') s++;
  size_t L = strlen(s); while (L && (s[L - 1] == ' ' || s[L - 1] == '\t' || s[L - 1] == '\r')) s[--L] = 0;
  if (!L) return;
  if (*s == '!' || *s == '[' || *s == '/') return;
  if (s[0] == '@' && s[1] == '@') {                      // @@||domain^ = allow rule
    if (s[2] == '|' && s[3] == '|') { parsePipeRule(s + 4, true); return; }
    ruleSkipped++; return;                                // @@domain / other syntax
  }
  if (s[0] == '|' && s[1] == '|') { parsePipeRule(s + 2, false); return; }
  if (strchr(s, '^') || strchr(s, '$') || strchr(s, '*') || strchr(s, '|')) { ruleSkipped++; return; }
  char* sp = s; while (*sp && *sp != ' ' && *sp != '\t') sp++;
  if (*sp) {                                            // hosts line: "0.0.0.0 a b c"
    *sp = 0;
    const bool isIp = !strcmp(s, "0.0.0.0") || !strcmp(s, "127.0.0.1") || !strcmp(s, "::") || !strcmp(s, "::1");
    if (!isIp) return;                                  // "domain   comment" -> ignore
    char* p = sp + 1;
    while (*p) {
      while (*p == ' ' || *p == '\t') p++;
      if (!*p) break;
      char* e = p; while (*e && *e != ' ' && *e != '\t') e++;
      char save = *e; *e = 0; addRuleDomain(p, false); *e = save;
      if (!*e) break;
      p = e + 1;
    }
    return;
  }
  addRuleDomain(s, false);                              // plain domain list
}

static int cmpU64Asc(const void* a, const void* b) {
  uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
  return (x < y) ? -1 : (x > y) ? 1 : 0;
}

// Write the parsed rules to the temp file, minus anything an @@ allow rule covers.
static bool writeRuleBlob(size_t bytesRead) {
  if (ruleOom) { fetchStatus = "out of memory (list too big for the arena)"; return false; }
  if (ruleCount == 0) { fetchStatus = "no rules parsed (" + String((unsigned)bytesRead) + "B)"; return false; }
  qsort(ruleHashes, ruleCount, sizeof(uint64_t), cmpU64Asc);
  if (allowCount) qsort(allowHashes, allowCount, sizeof(uint64_t), cmpU64Asc);
  File f = LittleFS.open(BL_TMP_REMOTE, "w");
  if (!f) { fetchStatus = "fs open failed"; return false; }
  // Write in 4 KB batches. One f.write() per 5-byte hash meant one VFS call and one
  // littlefs lock acquisition per rule, and that lock is global: while the blob was
  // being written, DNS lookups waiting on inFlash() were stuck behind it too.
  // The flush check is `ol + HASH_BYTES > sizeof(out)`, not `ol == sizeof(out)`: the
  // buffer length is not a multiple of 5, so the equality test never fired and the last
  // hash of every batch was written past the end of the array (stack canary!).
  uint8_t out[4096]; size_t ol = 0;
  size_t uniq = 0;
  bool wErr = false;
  for (size_t i = 0; i < ruleCount && !wErr; i++) {
    if (i && ruleHashes[i] == ruleHashes[i - 1]) continue;
    if (allowCount && bsearch(&ruleHashes[i], allowHashes, allowCount, sizeof(uint64_t), cmpU64Asc)) continue;
    if (ol + HASH_BYTES > sizeof(out)) { if (f.write(out, ol) != ol) { wErr = true; break; } ol = 0; }
    packHash(ruleHashes[i], out + ol);
    ol += HASH_BYTES;
    uniq++;
  }
  if (!wErr && ol && f.write(out, ol) != ol) wErr = true;
  f.close();
  if (wErr) { LittleFS.remove(BL_TMP_REMOTE); fetchStatus = "write failed (flash full?)"; return false; }
  Serial.printf("[remote] parsed %u rules (%u skipped, %u allow) -> %u unique\n",
                (unsigned)ruleCount, (unsigned)ruleSkipped, (unsigned)allowCount, (unsigned)uniq);
  if (uniq == 0) { LittleFS.remove(BL_TMP_REMOTE); fetchStatus = "every rule was filtered out"; return false; }
  fetchStatus = "ok: " + String((unsigned)uniq) + " rules";
  return true;
}

static bool fetchRuleText(const String& url) {
  Serial.printf("[remote] GET rules %s\n", url.c_str());
  WiFiClientSecure cs; tlsForFetch(cs);
  WiFiClient cl;
  HTTPClient http; http.setTimeout(25000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  const bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { fetchStatus = "begin failed"; return false; }
  const int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); fetchStatus = "HTTP " + String(code); return false; }

  ruleCount = 0; allowCount = 0; ruleSkipped = 0; ruleOom = false; chunkedFetch = false;
  WiFiClient* stream = http.getStreamPtr();
  const int len = http.getSize();
  char line[320]; size_t ll = 0; bool ovf = false;
  uint8_t b[512]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    const size_t avail = stream->available();
    if (!avail) { if (millis() - idle > 15000) break; delay(2); continue; }
    const int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
    if (n <= 0) continue;
    idle = millis(); total += (size_t)n;
    for (int i = 0; i < n && !ruleOom; i++) {
      const char c = (char)b[i];
      if (c == '\n') {
        if (ovf) { ovf = false; ll = 0; }                 // over-long line (cosmetic junk) -> drop
        else { line[ll] = 0; parseRuleLine(line); ll = 0; }
      } else if (c != '\r') {
        if (ll < sizeof(line) - 1) line[ll++] = c; else ovf = true;
      }
    }
  }
  http.end();
  if (!ruleOom && ll && !ovf) { line[ll] = 0; parseRuleLine(line); }
  if (ruleOom) { fetchStatus = "out of memory (list too big for the arena)"; return false; }
  // A chunked body has no length to compare against, and an interrupted transfer is
  // undetectable — but jsDelivr serves the built-in rules URL chunked, so rejecting it
  // (the way fetchBin() does for .bin files) would break updates entirely. Accept it and
  // say so instead of pretending the size was verified.
  if (len < 0) {
    chunkedFetch = true;
    Serial.println("[remote] WARN chunked body: length cannot be verified");
  } else if ((int)total != len) {
    fetchStatus = "short download (" + String((unsigned)total) + "/" + String(len) + "B)";
    return false;
  }
  return writeRuleBlob(total);
}

static bool fetchRules(const String& url) {
  if (fetchRuleText(url)) return true;
  const String first = fetchStatus;
  if (url == RULE_URL && String(RULE_URL_FALLBACK) != url) {   // mirror only for the built-in URL
    Serial.printf("[remote] primary failed (%s) -> fallback\n", first.c_str());
    if (fetchRuleText(RULE_URL_FALLBACK)) return true;
  }
  fetchStatus = first;
  return false;
}

// Runs in the update task: only ever writes the temp file, never the live list.
static bool fetchBlocklist(const String& url) {
  String u = url; u.trim();
  if (!u.length()) { fetchStatus = "no url set"; return false; }
  const bool ok = u.endsWith(".bin") ? fetchBin(u) : fetchRules(u);
  free(ruleHashes);  ruleHashes = nullptr;  ruleCap = 0;  ruleCount = 0;    // release the PSRAM arenas
  free(allowHashes); allowHashes = nullptr; allowCap = 0; allowCount = 0;
  Serial.printf("[remote] %s\n", fetchStatus.c_str());
  return ok;
}

// ---------- the rule refresh runs in its own task ----------
// A fetch is seconds (good link) to tens of seconds (bad link, TLS retries) of
// blocking I/O. It used to run inside loop(), which stopped DNS for that long.
// The task only writes /blupdate.new and validates it; swapping it in happens in
// updatePoll() on the main task, so numHashes/blIndex/blocklist are still touched by
// one task only. Validating there (reading the whole file back) used to happen on the
// main task, which stalled DNS for seconds right after every download.
static String updUrlSnapshot;      // copied on the main task, read by the fetch task
static uint32_t updN = 0;          // validated entry count
static const char* updWhy = "?";   // validation failure reason
static void updateTask(void* arg) {
  const String url = *(const String*)arg;
  updOk = fetchBlocklist(url);
  if (updOk) {
    File f = LittleFS.open(BL_TMP_REMOTE, "r");
    if (!f) { updOk = false; fetchStatus = "temp file missing"; }
    else {
      const bool ok = blocklistIsValid(f, &updN, &updWhy);
      f.close();
      if (!ok) { updOk = false; fetchStatus = String("rejected: ") + updWhy; }
    }
  }
  __sync_synchronize();              // publish fetchStatus/updN before updDone is seen
  updDone = true;                    // published before updRunning clears, so the two
  updRunning = false;                // never race on a new task starting mid-collection
  vTaskDelete(nullptr);
}

static bool startUpdateTask() {
  if (updRunning) return false;
  updRunning = true; updDone = false; updOk = false; updN = 0;
  fetchStatus = "";
  // /setupdate may change updateUrl while a fetch is in flight, and a second task must
  // never look at this String, so the URL is copied here, on the main task.
  updUrlSnapshot = updateUrl;
  // 16 KB stack: the TLS handshake plus the 320-byte line buffer live there — the same
  // budget the loop task gets for DoH TLS (see platformio.ini). Pinned to core 0 (WiFi)
  // so the DNS loop on core 1 keeps its cycles.
  if (xTaskCreatePinnedToCore(updateTask, "blupdate", 16384, &updUrlSnapshot, 1, nullptr, 0) != pdPASS) {
    updRunning = false;
    return false;
  }
  return true;
}

// Called from loop(): collect the task's result and swap the new list in.
static void updatePoll() {
  if (!updDone) return;
  updDone = false;
  if (updOk && applyBlocklist(BL_TMP_REMOTE, true, updN)) {
    if (updDay > 0) { lastUpdateDay = updDay; saveUpdateCfg(); }   // remember the day across reboots
  } else {
    if (!updOk) updateStatus = fetchStatus.length() ? fetchStatus : String("failed");
    LittleFS.remove(BL_TMP_REMOTE);
    Serial.printf("[remote] %s\n", updateStatus.c_str());
  }
}

// Nightly rule refresh. Runs once per local day, after updateHour (default 03:00
// UTC+8), so fetches land at night and a reboot at 15:00 doesn't shift the window.
// Failures retry after a 10 minute cooldown.
static void autoUpdateTick() {
  if (!updateUrl.length() || updRunning || updDone) return;
  if (lastAttemptMs && millis() - lastAttemptMs < 600000UL) return;   // 10 min cooldown

  const time_t now = time(nullptr);
  bool due = false;
  int32_t day = 0;
  if (now > 1600000000) {                       // NTP has answered
    const time_t local = now + (time_t)updateTz * 3600;
    day = (int32_t)(local / 86400);
    const int hour = (int)((local % 86400) / 3600);
    if (day < lastUpdateDay) lastUpdateDay = 0;               // clock moved backwards -> re-arm
    // Nothing to block yet? Grab a list right away, else wait for tonight's slot.
    due = (numHashes == 0) || (day > lastUpdateDay && hour >= (int)updateHour);
  } else {
    // No clock yet (NTP unreachable): fall back to "once per 24h since boot".
    const uint32_t up = millis();
    if (numHashes == 0) due = up > 60000UL;
    else due = up >= 86400000UL;
  }
  if (!due) return;

  lastAttemptMs = millis() ? millis() : 1;
  updDay = day;
  updateStatus = "fetching...";
  Serial.printf("[remote] scheduled fetch (local day %ld, hour %u)\n", (long)day, updateHour);
  if (!startUpdateTask()) updateStatus = "cannot start the update task";
}

// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static bool fwAuthOk = false;
static void handleFwUpdateDone() {
  if (!fwAuthOk) { web.requestAuthentication(); return; }
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    fwAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
    if (!fwAuthOk) { Serial.println("[fw-ota] auth/CSRF check failed, rejecting flash"); return; }
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (!fwAuthOk) return;
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (!fwAuthOk) return;
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    if (!fwAuthOk) return;
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool hasCreds() {
  prefs.begin("wifi", true); bool nvs = prefs.getString("ssid", "").length() > 0; prefs.end();
  return nvs || (WIFI_SSID && *WIFI_SSID && strcmp(WIFI_SSID, "YOUR_WIFI_SSID") != 0);
}
// Precise failure reason (ESP-IDF wifi_err_reason_t) instead of a bare WL_CONNECT_FAILED:
// 15/204 = 4-way handshake timeout (wrong password), 202 = auth fail, 2 = auth expire
// (often MAC filtering), 201 = AP not found, 205 = connection failed.
static void onWifiEvent(WiFiEvent_t ev, WiFiEventInfo_t info) {
  if (ev == ARDUINO_EVENT_WIFI_STA_CONNECTED) Serial.println("[wifi] associated, authenticating...");
  else if (ev == ARDUINO_EVENT_WIFI_STA_DISCONNECTED)
    Serial.printf("[wifi] disconnected: reason=%d\n", (int)info.wifi_sta_disconnected.reason);
}

static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.setTxPower(WIFI_POWER_11dBm); WiFi.onEvent(onWifiEvent);
  // A cold reset right after a previous session can be rejected once by the AP
  // (reason=202 AUTH_FAIL) while it still holds the stale association — retry a
  // couple of times instead of dropping straight into the setup portal.
  for (int attempt = 1; attempt <= 3 && WiFi.status() != WL_CONNECTED; attempt++) {
    if (attempt > 1) { Serial.printf(" [retry %d]\n", attempt); WiFi.disconnect(true); delay(1000); }
    WiFi.begin(ssid, pass);
    uint32_t t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 15000) { delay(250); Serial.print("."); }
  }
  Serial.println();
  if (WiFi.status() != WL_CONNECTED) {                 // diagnostics: why did the join fail?
    Serial.printf("[wifi] failed, status=%d (1=no ssid, 4=connect failed, 6=disconnected)\n", (int)WiFi.status());
    WiFi.disconnect(true); delay(200);
    int n = WiFi.scanNetworks();
    Serial.printf("[wifi] scan: %d networks\n", n);
    for (int i = 0; i < n && i < 12; i++)
      Serial.printf("[wifi]   %s  rssi=%d enc=%d\n", WiFi.SSID(i).c_str(), (int)WiFi.RSSI(i), (int)WiFi.encryptionType(i));
  }
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>S3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; S3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + htmlEscape(ss) + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>s3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + htmlEscape(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "S3-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.setTxPower(WIFI_POWER_11dBm); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  // A configured device that merely failed to join (router rebooting, weak signal) must not
  // get stuck here: if nobody is using the portal, reboot and retry WiFi every 3 minutes.
  const bool configured = hasCreds();
  uint32_t t0 = millis();
  while (true) {
    dnsPortal.processNextRequest(); web.handleClient(); delay(2);
    if (WiFi.softAPgetStationNum() > 0) t0 = millis();          // someone is setting it up
    if (configured && millis() - t0 > 180000UL) { Serial.println("[setup] retrying WiFi"); ESP.restart(); }
  }
}

void setup() {
  Serial.begin(115200); delay(300);
  // 80MHz keeps Wi-Fi fully functional while cutting dynamic power (and heat).
  // Modem sleep stays OFF (WiFi.setSleep(false)) — DNS latency wins over idle watts.
  setCpuFrequencyMhz(80);
  Serial.printf("[s3-adblock] cpu %u MHz\n", (unsigned)getCpuFrequencyMhz());
  // N16R8 has 8MB of octal PSRAM. Report it from heap_caps: ESP.getPsramSize() reports 0
  // with the precompiled opi framework libs (see the note at dnsCacheStore).
  Serial.printf("[psram] %u KB free / %u KB total\n",
                (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
                (unsigned)(heap_caps_get_total_size(MALLOC_CAP_SPIRAM) / 1024));
  Serial.println("\n[s3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  // A power cut between the two renames in applyBlocklist() leaves the previous list
  // parked as /bl.old — put it back instead of booting with no rules at all.
  if (!LittleFS.exists(BLOCKLIST_PATH) && LittleFS.exists(BL_OLD)) {
    LittleFS.rename(BL_OLD, BLOCKLIST_PATH);
    Serial.println("[bl] restored the previous list from /bl.old");
  }
  // The answer cache table (~34 KB) lives in PSRAM; see dnsCacheInit().
  dnsCacheInit();
  reopenBlocklist();
  if (numHashes) Serial.printf("blocklist: %u domains (%d index buckets)\n", (unsigned)numHashes, indexEntries);
  loadCustom(); loadBanned(); loadHosts(); loadUpdateCfg(); loadLedCfg();
  Serial.printf("custom: %d, hosts: %d, banned: %d\n", numCustom, numHosts, numBanned);
  applyLed();   // LED off setting survives reboots (default: green status light)

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
  // (Named BOOT_GPIO: core's esp32-hal.h already declares a BOOT_PIN enum, which
  // shadowed this local and produced a -Wshadow warning.)
  const int BOOT_GPIO = 0;                    // ESP32-S3 BOOT button (GPIO0)
  pinMode(BOOT_GPIO, INPUT_PULLUP);
  if (digitalRead(BOOT_GPIO) == LOW) { delay(60);
    if (digitalRead(BOOT_GPIO) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi"); } }

  if (!connectWiFi()) startConfigPortal();   // portal blocks + reboots on save; returns only when connected
  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());
  // NTP drives the nightly rule-refresh window. AliDNS answers SNTP too, which keeps
  // it on the same reachable host as DNS (pool.ntp.org is often blocked in CN).
  configTime((long)updateTz * 3600, 0, "ntp.aliyun.com", "223.5.5.5", "ntp.tencent.com");
  { struct tm tmv; bool synced = getLocalTime(&tmv, 3000);
    Serial.printf("[time] %s%s\n", synced ? asctime(&tmv) : "NTP not synced yet",
                  synced ? "" : " (rule refresh falls back to 24h since boot)"); }
  if (MDNS.begin("s3adblock")) { MDNS.addService("http", "tcp", 80); Serial.println("dashboard: http://s3adblock.local"); }

  if (strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0)
    Serial.println("[WARN] secrets.h still has placeholder WEB_PASS/OTA_PASS — those are public "
                    "(they're in the repo's example file). Set real values before trusting this "
                    "device on a network you don't fully control.");

  dnsServer.begin(DNS_PORT); upstreamCli.begin(0);
  // Upstream: DoH when DOH_URL is set, plain UDP otherwise. Parsed here (after WiFi,
  // before the first query) so the dashboard can report which transport is in use.
  {
    const char* dohUrl = DOH_URL;
    if (dohUrl && *dohUrl) {
      if (dohParseUrl(dohUrl)) {
        dohAvail = true;
        Serial.printf("[doh] upstream https://%s:%u%s (%s)\n", dohHost.c_str(), (unsigned)dohPort,
                      dohPath.c_str(), DOH_UDP_FALLBACK ? "UDP fallback on" : "strict");
      } else {
        Serial.println("[doh] DOH_URL must look like https://host/dns-query ; using UDP");
      }
    } else {
      Serial.printf("[dns] upstream %s:%u (plain UDP)\n", IPAddress(UPSTREAM).toString().c_str(), UPSTREAM_PORT);
    }
  }
  // collectHeaders() is what makes web.header() work at all: only collected headers are
  // parsed. CSRF_HEADER is for requireAuth(); Accept-Encoding decides gzip vs plain HTML.
  { const char* hdrs[] = { CSRF_HEADER, "Accept-Encoding" }; web.collectHeaders(hdrs, 2); }
  web.on("/", handleRoot);
  web.on("/auth", []() { if (!requireAuth()) return; web.send(200, "text/plain", "ok"); });
  web.on("/stats.json", handleStats);
  web.on("/ban", HTTP_POST, handleBan);
  // Custom block list / hosts overrides are edited as a whole (textarea in the UI):
  // POST the full text, the device re-parses and rewrites the file. A missing "d"
  // is an error, not an empty list: that used to wipe the whole table.
  web.on("/setblock", HTTP_POST, []() {
    if (!requireAuth()) return;
    if (!web.hasArg("d")) { web.send(400, "text/plain", "missing d"); return; }
    // One pass: the parser builds the new list in place and restores the flash copy by
    // itself if the text is over the limit, so there is nothing left to re-parse.
    const int n = setCustomFromText(web.arg("d"));
    if (n < 0) {
      web.send(413, "text/plain", "too many domains (max " + String(MAX_CUSTOM) + "), nothing saved");
      return;
    }
    saveCustom();
    web.send(200, "text/plain", String(n));
  });
  web.on("/sethosts", HTTP_POST, []() {
    if (!requireAuth()) return;
    if (!web.hasArg("d")) { web.send(400, "text/plain", "missing d"); return; }
    const int n = setHostsFromText(web.arg("d"));
    if (n < 0) {
      web.send(413, "text/plain", "too many mappings (max " + String(MAX_HOSTS) + "), nothing saved");
      return;
    }
    saveHosts();
    web.send(200, "text/plain", String(n));
  });
  web.on("/pause", []() {                    // /pause?s=300  (0 or absent = indefinite)
    if (!requireAuth()) return;
    long s = web.hasArg("s") ? web.arg("s").toInt() : 0;
    blockingOn = false; resumeAt = (s > 0) ? millis() + (uint32_t)s * 1000UL : 0;
    applyLed();
    web.send(200, "text/plain", "paused");
  });
  web.on("/resume", []() { if (!requireAuth()) return; blockingOn = true; resumeAt = 0; applyLed();
    web.send(200, "text/plain", "resumed"); });
  web.on("/setled", []() {                  // /setled?s=0|1  (absent = toggle)
    if (!requireAuth()) return;
    ledOn = web.hasArg("s") ? web.arg("s").toInt() != 0 : !ledOn;
    saveLedCfg(); applyLed();
    web.send(200, "text/plain", ledOn ? "on" : "off");
  });
  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);      // blocklist OTA (auth inside handleUpload)
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);  // firmware OTA (auth inside handleFwUpload)
  web.on("/fetchnow", HTTP_POST, []() {
    if (!requireAuth()) return;
    if (updRunning || updDone) { web.send(200, "text/plain", "already running"); return; }
    lastAttemptMs = millis() ? millis() : 1;
    updDay = 0;                              // manual fetch: don't mark today as done
    updateStatus = "fetching...";
    if (!startUpdateTask()) { updateStatus = "cannot start the update task"; web.send(500, "text/plain", updateStatus); return; }
    web.send(200, "text/plain", "started");   // result shows up in /stats.json upstat
  });
  web.on("/setupdate", []() {
    if (!requireAuth()) return;
    if (web.hasArg("u")) updateUrl = web.arg("u");
    if (web.hasArg("h")) { int h = web.arg("h").toInt(); if (h >= 0 && h < 24) updateHour = (uint8_t)h; }
    if (web.hasArg("tz")) { int t = web.arg("tz").toInt(); if (t >= -12 && t <= 14) { updateTz = (int8_t)t;
      configTime((long)updateTz * 3600, 0, "ntp.aliyun.com", "223.5.5.5", "ntp.tencent.com"); } }
    saveUpdateCfg(); web.send(200, "text/plain", "ok");
  });
  web.onNotFound([]() {
    if (web.uri() == "/favicon.ico" || web.uri() == "/apple-touch-icon.png") { web.send(204, "text/plain", ""); return; }
    web.send(404, "text/plain", "not found");
  });
  web.begin();
  ArduinoOTA.setHostname("s3adblock");   // pio run -t upload --upload-port s3adblock.local
  ArduinoOTA.setPassword(OTA_PASS);      // network OTA was unauthenticated upstream
  ArduinoOTA.begin();
  Serial.println("DNS :53 + dashboard :80 + OTA up");
}

void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (!blockingOn && resumeAt && (int32_t)(millis() - resumeAt) >= 0) {
    blockingOn = true; resumeAt = 0; applyLed();   // paused timer expired -> back to green
  }
  if (updateUrl.length()) autoUpdateTick();   // nightly at updateHour local time
  updatePoll();                               // swap in a fetched list once its task is done
  { static uint32_t ledNext = 0;              // keep the status colour in sync (Wi-Fi drop, pause expiry)
    if ((int32_t)(millis() - ledNext) >= 0) { ledNext = millis() + 1000; applyLed(); } }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}

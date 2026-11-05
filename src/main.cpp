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
#ifndef RULE_INTERVAL_H
#define RULE_INTERVAL_H 24      // legacy knob, superseded by RULE_HOUR/RULE_TZ below
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
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;
static const int INDEX_ENTRIES = 4096;   // 20 KB first-level flash index
static const int CACHE_SIZE = 256;       // must be power of 2
static const int MAX_RANGE = 256;        // max hashes per index bucket (fine up to ~1M hashes; flash holds far fewer)
// Upstream-answer cache (Pi-hole style): a repeated lookup for the same question
// is answered from PSRAM instead of paying a ~40ms round trip to 223.5.5.5.
//
// Sizing is exact, not worst-case: every entry owns a heap_caps_malloc() of exactly
// (reply + key) bytes — a typical entry is ~110 bytes, not the 512 bytes a fixed
// per-slot layout would burn. Two independent limits apply: the entry table
// (DNS_CACHE_SLOTS) and the byte budget, which is derived from the PSRAM actually
// free at boot (8MB on N16R8). Whichever is hit first, the eviction policy picks the
// victim that is closest to expiry, tie-broken by fewest hits and then
// least-recently-used — what dies soonest and earns least goes first.
static const int DNS_CACHE_SLOTS = 1024;        // entry table size (also the ceiling on count)
static const size_t DNS_CACHE_BUDGET_MAX = 4u << 20;  // ceiling for the PSRAM byte budget
static size_t dnsCacheBudget = 256 * 1024;      // raised in setup() from free PSRAM
static const uint16_t DNS_CACHE_MAXLEN = 512;   // largest reply we are willing to cache
static const uint16_t DNS_CACHE_MAXQ = 288;     // largest key we build (question section)
static const uint32_t DNS_CACHE_MAX_TTL = 3600; // seconds; longer TTLs are clamped down

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t buf[1536];   // fits any non-fragmented UDP reply (EDNS answers can exceed 512)

// first-level flash index (sorted sample hashes) + small direct-mapped cache
static uint8_t blIndex[INDEX_ENTRIES][HASH_BYTES];
static uint8_t cacheKey[CACHE_SIZE][HASH_BYTES];
static uint8_t cacheRes[CACHE_SIZE];
static uint8_t cacheValid[CACHE_SIZE];
static uint8_t rangeBuf[MAX_RANGE * HASH_BYTES];

// Key = the question section lowercased + the client's DO bit. Deliberately NOT the
// whole query: EDNS COOKIE (a fresh random cookie per process — even per `dig` run),
// padding and UDP size differ between clients that are asking the same question, and
// keying on them produced a 0% hit rate. Cached replies are stored without their OPT
// record, so one entry is valid for EDNS and non-EDNS clients alike, and on a hit the
// question bytes are patched with the caller's own casing (0x20 clients stay happy).
struct DnsCacheEnt {
  uint32_t sig;       // hash of the key; 0 = empty slot
  uint32_t storedMs;  // millis() when the packet's TTLs were last correct
  uint32_t expireS;   // seconds of life left in the packet at storedMs
  uint32_t lastUse;   // millis() of the last hit (LRU tie-break)
  uint16_t keyLen;    // key length (key is stored right after the reply)
  uint16_t len;       // reply length
  uint16_t cap;       // bytes actually allocated for this entry
  uint16_t hits;      // hits since it was stored (saturating)
  uint8_t* pkt;       // pkt[0..len) = reply, pkt[len..len+keyLen) = key
};
static DnsCacheEnt dnsCache[DNS_CACHE_SLOTS];
static size_t   dnsCacheBytes = 0;      // sum of cap over all live entries
static uint32_t dnsCacheHits = 0, dnsCacheMiss = 0, dnsCacheEvicted = 0;
static uint8_t  dnsQSave[DNS_CACHE_MAXQ];   // copy of the current query's question section
static uint8_t  dnsKeyBuf[DNS_CACHE_MAXQ];  // key built from dnsQSave
static uint8_t  dnsQDo = 0;                 // DO bit of the current query's OPT record

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
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
String updateUrl = "";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint8_t updateHour = RULE_HOUR;     // local hour (0-23) of the nightly fetch
int8_t  updateTz   = RULE_TZ;       // local time = UTC + updateTz hours
int32_t lastUpdateDay = 0;          // local day number (epoch/86400) of the last successful fetch
uint32_t lastAttemptMs = 0;         // millis() of the last attempt (0 = none yet; drives the cooldown)
String updateStatus = "never";

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

static void buildFlashIndex() {
  if (!blocklist || numHashes == 0) return;
  for (int i = 0; i < INDEX_ENTRIES; i++) {
    uint32_t pos = (uint32_t)((uint64_t)i * (numHashes - 1) / (INDEX_ENTRIES - 1));
    blocklist.seek((uint32_t)pos * HASH_BYTES);
    blocklist.read(blIndex[i], HASH_BYTES);
  }
  for (int i = 0; i < CACHE_SIZE; i++) cacheValid[i] = 0;
}

static bool inFlash(uint64_t h) {
  if (numHashes == 0) return false;
  uint64_t first = unpackHash(blIndex[0]);
  uint64_t last  = unpackHash(blIndex[INDEX_ENTRIES - 1]);
  if (h < first || h > last) return false;

  int lo = 0, hi = INDEX_ENTRIES - 2, seg = 0;
  while (lo <= hi) {
    int mid = (lo + hi) >> 1;
    uint64_t midv = unpackHash(blIndex[mid]);
    if (midv < h) {
      seg = mid;
      lo = mid + 1;
    } else if (midv > h) {
      hi = mid - 1;
    } else {
      return true;
    }
  }

  uint32_t startPos = (uint32_t)((uint64_t)seg * (numHashes - 1) / (INDEX_ENTRIES - 1));
  uint32_t endPos   = (uint32_t)((uint64_t)(seg + 1) * (numHashes - 1) / (INDEX_ENTRIES - 1));
  if (endPos >= numHashes) endPos = numHashes - 1;
  uint32_t rangeCount = endPos - startPos + 1;
  if (rangeCount > (uint32_t)MAX_RANGE) rangeCount = MAX_RANGE;

  blocklist.seek((uint32_t)startPos * HASH_BYTES);
  blocklist.read(rangeBuf, (uint32_t)rangeCount * HASH_BYTES);

  for (uint32_t i = 0; i < rangeCount; i++) {
    uint64_t v = unpackHash(rangeBuf + i * HASH_BYTES);
    if (v == h) return true;
    if (v > h) break;
  }
  return false;
}

static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }

// Only flash results are cached: the flash list only changes via reopenBlocklist(), which
// rebuilds the index and clears the cache. Custom domains change at runtime, so they're
// checked uncached (a short linear scan) to avoid serving stale answers.
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
  int dots = 0; if (!t.length()) return false;
  for (size_t i = 0; i < t.length(); i++) {
    char c = t[i];
    if (c == '.') { dots++; continue; }
    if (c < '0' || c > '9') return false;
  }
  return dots == 3;
}
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); String d;
    if (!normDomain(l, d)) continue;
    bool dup = false; for (int i = 0; i < numCustom; i++) if (customDom[i] == d) { dup = true; break; }
    if (dup) continue;
    customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++;
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
static bool addCustomDomain(const String& raw) {
  String d; if (!normDomain(raw, d)) return false;
  if (numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; return true;
}
// Replace the whole list from the textarea contents. Accepts one domain per line,
// hosts-file lines ("0.0.0.0 a b c"), and # comments — anything that is not a
// domain token is ignored, so pasting a full hosts file just works.
static void setCustomFromText(const String& text) {
  numCustom = 0;
  int i = 0; const int n = text.length();
  while (i <= n && numCustom < MAX_CUSTOM) {
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
      addCustomDomain(tok);
    }
    if (e >= n) break;
  }
  saveCustom();
}

// ---------- hosts overrides ----------
static uint32_t parseIPv4(const String& s) {
  IPAddress ip; if (!ip.fromString(s)) return 0;
  uint32_t v = (uint32_t)ip; return v ? v : 0;   // 0.0.0.0 is not a useful target
}
static void loadHosts() {
  numHosts = 0; File f = LittleFS.open("/hosts.txt", "r"); if (!f) return;
  while (f.available() && numHosts < MAX_HOSTS) {
    String l = f.readStringUntil('\n');
    int hash = l.indexOf('#'); if (hash >= 0) l = l.substring(0, hash);
    l.replace('\t', ' '); l.trim();
    int sp = l.indexOf(' '); if (sp < 0) continue;
    String dom = l.substring(0, sp); String ip = l.substring(sp + 1); ip.trim();
    String d; uint32_t v = parseIPv4(ip);
    if (!v || !normDomain(dom, d)) continue;
    hostEnt[numHosts].dom = d; hostEnt[numHosts].hash = fnv40(d.c_str(), d.length());
    hostEnt[numHosts].ip = v; numHosts++;
  }
  f.close();
}
static void saveHosts() {
  File f = LittleFS.open("/hosts.txt", "w"); if (!f) return;
  for (int i = 0; i < numHosts; i++) { IPAddress ip(hostEnt[i].ip); f.println(hostEnt[i].dom + " " + ip.toString()); }
  f.close();
}
static void setHostsFromText(const String& text) {
  numHosts = 0;
  int i = 0; const int n = text.length();
  while (i <= n && numHosts < MAX_HOSTS) {
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
    bool dup = false; for (int k = 0; k < numHosts; k++) if (hostEnt[k].dom == d) { dup = true; break; }
    if (dup) continue;
    hostEnt[numHosts].dom = d; hostEnt[numHosts].hash = fnv40(d.c_str(), d.length());
    hostEnt[numHosts].ip = v; numHosts++;
    if (e >= n) break;
  }
  saveHosts();
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
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
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
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
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
// Forward to upstream and wait for the reply that actually belongs to THIS query.
// Issue #10: after one timeout the late reply used to sit in the socket and get relayed
// to the next client (every answer shifted by one). Now: drain stale datagrams first,
// send with a fresh random txid, and only accept a reply whose txid, question section,
// and source address/port match. The client's own txid is restored on the way back.
static int forwardUpstream(int qlen, int qend) {
  upstreamCli.flush();                                   // release any half-read buffer
  while (upstreamCli.parsePacket() > 0) upstreamCli.flush();   // drop stale late replies
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  const uint16_t wid = (uint16_t)esp_random();
  uint8_t q[260]; int ql = qend - 12;
  const bool haveQ = ql > 0 && ql <= (int)sizeof(q) && qend <= qlen;
  if (haveQ) memcpy(q, buf + 12, ql);
  buf[0] = wid >> 8; buf[1] = wid & 0xFF;
  upstreamCli.beginPacket(UPSTREAM, UPSTREAM_PORT); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  const uint32_t t0 = millis();
  while (millis() - t0 < 1000) {                         // deadline, not a retry count
    int sz = upstreamCli.parsePacket();
    if (sz <= 0) { delay(1); continue; }
    const bool fromUp = upstreamCli.remoteIP() == UPSTREAM && upstreamCli.remotePort() == UPSTREAM_PORT;
    int n = upstreamCli.read(buf, sizeof(buf));
    upstreamCli.flush();                                 // oversized datagram can't strand rx_buffer
    if (!fromUp || n < 12 || sz > (int)sizeof(buf)) continue;
    if (buf[0] != (wid >> 8) || buf[1] != (wid & 0xFF)) continue;
    if (haveQ && (n < 12 + ql || memcmp(buf + 12, q, ql) != 0)) continue;
    buf[0] = cid0; buf[1] = cid1;
    return n;
  }
  return 0;
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
// Subtract `age` seconds from every record TTL (clamped at 0) and return the
// smallest lifetime left, or -1 if the message cannot be parsed. The OPT pseudo-RR
// is skipped: its "TTL" field is extended-RCODE/flags, not a lifetime.
static int32_t dnsAgeTtls(uint8_t* p, int len, uint32_t age) {
  if (len < 12) return -1;
  const uint32_t qd = ((uint32_t)p[4] << 8) | p[5];
  const uint32_t rrs = (((uint32_t)p[6] << 8) | p[7]) + (((uint32_t)p[8] << 8) | p[9]) +
                       (((uint32_t)p[10] << 8) | p[11]);
  int i = 12;
  for (uint32_t k = 0; k < qd; k++) {
    i = dnsSkipName(p, len, i);
    if (i < 0 || i + 4 > len) return -1;
    i += 4;                                    // qtype + qclass
  }
  int32_t minTtl = -1;
  for (uint32_t k = 0; k < rrs; k++) {
    i = dnsSkipName(p, len, i);
    if (i < 0 || i + 10 > len) return -1;
    const uint16_t type = ((uint16_t)p[i] << 8) | p[i + 1];
    const uint32_t ttl = ((uint32_t)p[i + 4] << 24) | ((uint32_t)p[i + 5] << 16) |
                         ((uint32_t)p[i + 6] << 8) | p[i + 7];
    const uint16_t rdlen = ((uint16_t)p[i + 8] << 8) | p[i + 9];
    if (i + 10 + rdlen > len) return -1;
    if (type != 41) {                          // 41 = OPT
      const uint32_t nt = ttl > age ? ttl - age : 0;
      p[i + 4] = (uint8_t)(nt >> 24); p[i + 5] = (uint8_t)(nt >> 16);
      p[i + 6] = (uint8_t)(nt >> 8);  p[i + 7] = (uint8_t)nt;
      if (minTtl < 0 || (int32_t)nt < minTtl) minTtl = (int32_t)nt;
    }
    i += 10 + rdlen;
  }
  return minTtl;
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
// Full-byte comparison of the key (the hash alone is never trusted).
static int dnsCacheFind(uint32_t h, int klen) {
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) {
    const DnsCacheEnt& e = dnsCache[i];
    if (!e.pkt || e.sig != h || e.keyLen != klen) continue;
    if (memcmp(e.pkt + e.len, dnsKeyBuf, klen) == 0) return i;
  }
  return -1;
}
static int dnsCacheLookup(int qend) {
  const int klen = dnsKeyBuild(qend);
  if (klen <= 0) return 0;
  const uint32_t h = qHash(dnsKeyBuf, klen);
  const int i = dnsCacheFind(h, klen);
  if (i < 0) return 0;
  DnsCacheEnt& e = dnsCache[i];
  const uint32_t now = millis();
  const uint32_t ageS = (now - e.storedMs) / 1000;
  if (ageS >= e.expireS) return 0;                      // expired: a miss, the slot is up for eviction
  const int32_t left = dnsAgeTtls(e.pkt, e.len, ageS);
  if (left <= 0) return 0;
  e.expireS = (uint32_t)left;
  e.storedMs += ageS * 1000UL;
  e.lastUse = now;
  if (e.hits < 0xFFFF) e.hits++;
  const uint8_t cid0 = buf[0], cid1 = buf[1];
  memcpy(buf, e.pkt, e.len);
  memcpy(buf + 12, dnsQSave + 12, qend - 12);           // this caller's own 0x20 casing
  buf[0] = cid0; buf[1] = cid1;
  dnsCacheHits++;
  return e.len;
}
// Drop a trailing OPT pseudo-RR: the cached copy must not echo another client's EDNS
// parameters (cookie, advertised UDP size). Returns the new length, or -1 if the
// message can't be parsed / has a non-trailing OPT (then it is simply not cached).
static int dnsStripOpt(uint8_t* p, int n) {
  if (n < 12) return -1;
  const uint32_t qd = ((uint32_t)p[4] << 8) | p[5];
  const uint32_t an = ((uint32_t)p[6] << 8) | p[7];
  const uint32_t ns = ((uint32_t)p[8] << 8) | p[9];
  const uint32_t ar = ((uint32_t)p[10] << 8) | p[11];
  if (ar == 0) return n;                              // no EDNS at all
  int i = 12;
  for (uint32_t k = 0; k < qd; k++) {                  // question section: name + 4
    i = dnsSkipName(p, n, i);
    if (i < 0 || i + 4 > n) return -1;
    i += 4;
  }
  for (uint32_t k = 0; k < an + ns; k++) {              // answer/authority sections
    i = dnsSkipName(p, n, i);
    if (i < 0 || i + 10 > n) return -1;
    const uint16_t rdlen = ((uint16_t)p[i + 8] << 8) | p[i + 9];
    if (i + 10 + rdlen > n) return -1;
    i += 10 + rdlen;
  }
  int optStart = -1;
  for (uint32_t k = 0; k < ar; k++) {                  // additional section
    const int start = i;
    i = dnsSkipName(p, n, i);
    if (i < 0 || i + 10 > n) return -1;
    const uint16_t type = ((uint16_t)p[i] << 8) | p[i + 1];
    const uint16_t rdlen = ((uint16_t)p[i + 8] << 8) | p[i + 9];
    if (i + 10 + rdlen > n) return -1;
    i += 10 + rdlen;
    if (type == 41) optStart = start;
  }
  if (optStart < 0) return n;
  if (i != n) return -1;                               // OPT is not the last record
  p[10] = (uint8_t)((ar - 1) >> 8); p[11] = (uint8_t)(ar - 1);
  return optStart;
}

// ---- cache table management: exact accounting + eviction policy --------------
static void dnsCacheDrop(int i) {
  DnsCacheEnt& e = dnsCache[i];
  if (e.pkt) { heap_caps_free(e.pkt); dnsCacheBytes -= e.cap; }
  memset(&e, 0, sizeof(e));
}
static int dnsCacheFreeSlot() {
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) if (!dnsCache[i].pkt) return i;
  return -1;
}
static uint32_t dnsCacheRemain(const DnsCacheEnt& e, uint32_t now) {
  const uint32_t ageS = (now - e.storedMs) / 1000;
  return ageS >= e.expireS ? 0 : e.expireS - ageS;      // 0 = already expired
}
// Victim = (closest to expiry, then fewest hits, then least recently used).
// Expired entries have remain 0, so they are always picked before anything live.
static int dnsCacheWorst(uint32_t now) {
  int best = -1; uint32_t bRemain = 0, bHits = 0, bUse = 0;
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) {
    const DnsCacheEnt& e = dnsCache[i];
    if (!e.pkt) continue;
    const uint32_t r = dnsCacheRemain(e, now);
    const bool better = best < 0 || r < bRemain ||
                        (r == bRemain && (e.hits < bHits ||
                         (e.hits == bHits && (int32_t)(e.lastUse - bUse) < 0)));
    if (better) { best = i; bRemain = r; bHits = e.hits; bUse = e.lastUse; }
  }
  return best;
}
// Free victims until `need` more bytes fit AND a slot is free. Returns false when
// even an empty cache cannot hold this answer (it then simply stays uncached).
static bool dnsCacheMakeRoom(size_t need, uint32_t now) {
  if (need > dnsCacheBudget) return false;
  while (dnsCacheBytes + need > dnsCacheBudget || dnsCacheFreeSlot() < 0) {
    const int v = dnsCacheWorst(now);
    if (v < 0) return false;
    dnsCacheDrop(v);
    dnsCacheEvicted++;
  }
  return true;
}
// Only positive NOERROR answers are cached. NXDOMAIN/NODATA and SERVFAIL are cheap
// to re-ask and caching them makes a transient upstream wobble sticky for minutes.
static void dnsCacheStore(int qend, int n) {
  const int klen = dnsKeyBuild(qend);
  if (klen <= 0 || n < 13 || n > DNS_CACHE_MAXLEN) return;
  if ((buf[3] & 0x0F) != 0) return;                       // rcode != NOERROR
  if ((((uint16_t)buf[6] << 8) | buf[7]) == 0) return;    // ANCOUNT == 0
  const int stripped = dnsStripOpt(buf, n);               // drop the caller's EDNS OPT
  if (stripped < 13) return;
  n = stripped;
  int32_t ttl = dnsAgeTtls(buf, n, 0);
  if (ttl <= 0) return;                                   // TTL 0 / nothing cacheable
  if ((uint32_t)ttl > DNS_CACHE_MAX_TTL) {                // clamp, keeping the packet consistent
    dnsAgeTtls(buf, n, (uint32_t)ttl - DNS_CACHE_MAX_TTL);
    ttl = DNS_CACHE_MAX_TTL;
  }

  const size_t need = (size_t)n + (size_t)klen;           // exact size of this entry
  const uint32_t now = millis();
  const uint32_t h = qHash(dnsKeyBuf, klen);
  int slot = dnsCacheFind(h, klen);
  if (slot >= 0 && dnsCache[slot].cap < need) { dnsCacheDrop(slot); slot = -1; }  // too small: reallocate
  if (slot < 0) {
    if (!dnsCacheMakeRoom(need, now)) return;
    slot = dnsCacheFreeSlot();
    if (slot < 0) return;
  }
  DnsCacheEnt& e = dnsCache[slot];
  if (!e.pkt) {
    // heap_caps_malloc, not ps_malloc(): arduino-esp32's ps_malloc() gates on its own
    // "PSRAM is up" flag, which the precompiled opi libs never set here — the PSRAM
    // region is in the heap (heap_caps sees the full 8MB) but ps_malloc() returns NULL.
    uint8_t* p = (uint8_t*)heap_caps_malloc(need, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) return;                                       // PSRAM exhausted -> run uncached
    e.pkt = p; e.cap = (uint16_t)need; dnsCacheBytes += need; e.hits = 0;
  }
  memcpy(e.pkt, buf, n);
  memcpy(e.pkt + n, dnsKeyBuf, klen);
  e.sig = h; e.keyLen = (uint16_t)klen; e.len = (uint16_t)n;
  e.storedMs = now; e.expireS = (uint32_t)ttl; e.lastUse = now;
}
// Live (not yet expired) entries and the exact PSRAM they hold, for the dashboard.
static int dnsCacheUsed() {
  const uint32_t now = millis();
  int n = 0;
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) if (dnsCache[i].pkt && dnsCacheRemain(dnsCache[i], now) > 0) n++;
  return n;
}
// Called whenever the rule set changes: answers cached before the swap may point at
// names the new list blocks (or at addresses it no longer blocks), so drop them all.
static void dnsCacheFlush() {
  for (int i = 0; i < DNS_CACHE_SLOTS; i++) dnsCacheDrop(i);
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    // hosts overrides win over the blocklist: an explicit mapping is an explicit intent.
    uint32_t mapped = dl ? hostsLookup(domain) : 0;
    bool blocked = !mapped && (ban || (blockingOn && dl && numHashes && isBlocked(domain)));
    int rlen;
    if (mapped)  { rlen = buildAnswer(qend, qtype, mapped);       totalAllowed++; if (c) c->allowed++; }
    else if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else {
      // Unblocked: try the answer cache first, then the upstream. The question section
      // is snapshotted because forwardUpstream() overwrites buf with the reply and the
      // cache key / question patch need the caller's own bytes.
      const bool cacheable = dl && qend >= 17 && qend <= DNS_CACHE_MAXQ;
      if (cacheable) { memcpy(dnsQSave, buf, qend); dnsQDo = dnsQueryDo(buf, qlen, qend); }
      rlen = cacheable ? dnsCacheLookup(qend) : 0;
      if (rlen <= 0) {
        if (dl) dnsCacheMiss++;
        const int r = forwardUpstream(qlen, qend);
        rlen = r;
        if (r > 0 && cacheable) dnsCacheStore(qend, r);
      }
      totalAllowed++; if (c) c->allowed++;
    }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }
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

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"uphour\":" + updateHour + ",\"uptz\":" + updateTz +
             ",\"upday\":" + lastUpdateDay + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"blocking\":" + (blockingOn ? "true" : "false") +
             ",\"led\":" + (ledOn ? "true" : "false") +
             ",\"ledPin\":" + LED_PIN +
             ",\"resumeIn\":" + (uint32_t)(!blockingOn && resumeAt ? (resumeAt - millis()) / 1000 : 0) +
             ",\"dnsHit\":" + dnsCacheHits + ",\"dnsMiss\":" + dnsCacheMiss +
             ",\"dnsCacheN\":" + dnsCacheUsed() + ",\"dnsCacheCap\":" + DNS_CACHE_SLOTS +
             ",\"dnsCacheBytes\":" + (uint32_t)dnsCacheBytes + ",\"dnsCacheBudget\":" + (uint32_t)dnsCacheBudget +
             ",\"dnsEvict\":" + dnsCacheEvicted +
             ",\"defcreds\":" + ((strcmp(WEB_PASS, "CHANGE_ME_WEB_PASSWORD") == 0 || strcmp(OTA_PASS, "CHANGE_ME_OTA_PASSWORD") == 0) ? "true" : "false") +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "],\"hosts\":[";
  for (int i = 0; i < numHosts; i++) { IPAddress ip(hostEnt[i].ip); j += (i ? "," : "");
    j += "{\"h\":\"" + jesc(hostEnt[i].dom) + "\",\"ip\":\"" + ip.toString() + "\"}"; }
  j += "]}";
  web.send(200, "application/json", j);
}
// ---------- dashboard (built by web/build.mjs into data/index.html.gz) ----------
// The page is one self-contained gzipped HTML (~18KB) stored in LittleFS: no CDN fetch,
// so the dashboard works even when the device itself has no internet access.
static void handleRoot() {
  File f = LittleFS.open("/index.html.gz", "r");
  if (!f) { web.send_P(200, "text/html", PAGE); return; }   // flash FS not written yet
  // WebServer adds "Content-Encoding: gzip" itself for a .gz file whose content type
  // is text/html — sending it manually would duplicate the header and break clients.
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
// s3adblock.local/forgetwifi">). That's CSRF, and it defeats the LAN-attacker
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
// The partition holds one list, so we free the old one before writing the new.
// While swapping, numHashes=0 -> device fail-opens (forwards, no blocking).
static void reopenBlocklist() {
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  numHashes = blocklist ? blocklist.size() / HASH_BYTES : 0;
  buildFlashIndex();
  dnsCacheFlush();          // rules changed -> cached answers may now be wrong
}
static void beginBlocklistSwap() {
  if (blocklist) blocklist.close();
  numHashes = 0;
  LittleFS.remove(BLOCKLIST_PATH);
  LittleFS.remove("/blocklist.new");
}
static bool commitNewBlocklist() {                  // /blocklist.new -> live (validated)
  File f = LittleFS.open("/blocklist.new", "r");
  size_t sz = f ? f.size() : 0; if (f) f.close();
  bool ok = sz > 0 && (sz % HASH_BYTES) == 0;       // sorted hash blob -> 5-byte multiple
  if (ok) LittleFS.rename("/blocklist.new", BLOCKLIST_PATH);
  else    LittleFS.remove("/blocklist.new");
  reopenBlocklist();
  return ok;
}

// ---------- OTA blocklist update (browser upload) ----------
static bool upOk = false;
static bool upAuthOk = false;
static File upFile;
static void handleUploadDone() {
  if (!upAuthOk) { web.requestAuthentication(); return; }
  web.send(upOk ? 200 : 500, "text/plain",
           upOk ? "ok" : "rejected: empty or size not a multiple of 5 (not a blocklist.bin?)");
}
static void handleUpload() {
  HTTPUpload& u = web.upload();
  switch (u.status) {
    case UPLOAD_FILE_START:
      upAuthOk = web.header(CSRF_HEADER) == CSRF_VALUE && web.authenticate(WEB_USER, WEB_PASS);
      if (!upAuthOk) { Serial.println("[ota] blocklist upload: auth/CSRF check failed"); break; }
      upOk = false; beginBlocklistSwap();
      upFile = LittleFS.open("/blocklist.new", "w");
      Serial.printf("[ota] receiving %s\n", u.filename.c_str());
      break;
    case UPLOAD_FILE_WRITE:
      if (upAuthOk && upFile) upFile.write(u.buf, u.currentSize);
      break;
    case UPLOAD_FILE_END:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      upOk = commitNewBlocklist();
      Serial.printf("[ota] %s -> %u domains\n", upOk ? "OK" : "REJECTED", numHashes);
      break;
    case UPLOAD_FILE_ABORTED:
      if (!upAuthOk) break;
      if (upFile) upFile.close();
      LittleFS.remove("/blocklist.new"); reopenBlocklist();
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
// A prebuilt hash blob: streamed straight into LittleFS (legacy path, *.bin URLs).
static bool fetchBin(const String& url) {
  Serial.printf("[remote] GET bin %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();            // blocklist isn't secret -> skip cert pinning
  WiFiClient cl;
  HTTPClient http; http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);  // GitHub release -> CDN redirect
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { http.end(); updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize(); uint8_t b[1024]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (avail) { int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail); if (n > 0) { f.write(b, n); total += n; idle = millis(); } }
    else { if (millis() - idle > 15000) break; delay(2); }
  }
  f.close(); http.end();
  bool ok = commitNewBlocklist();
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains (bin)") : ("bad data (" + String(total) + "B)");
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// ---------- text rule lists, parsed on the device ----------
// The ESP32-S3 has room to hash a plain-text list itself, so scheduled updates can
// point straight at a rules file (AWAvenue, hosts files, plain domain lists,
// AdGuard basic rules) instead of a prebuilt .bin that someone has to host.
// Domains are hashed into a PSRAM arena, sorted, deduped and written to
// /blocklist.new, then swapped in through the same validation as an upload.
static uint64_t* ruleHashes = nullptr;
static size_t    ruleCount = 0, ruleCap = 0;
static uint32_t  ruleSkipped = 0;

static bool ruleReserve() {
  if (ruleCount + 1 <= ruleCap) return true;
  size_t cap = ruleCap ? ruleCap * 2 : 4096;
  if (cap > 4000000) return false;                        // hard cap: 32MB of hashes
  uint64_t* p = (uint64_t*)heap_caps_realloc(ruleHashes, cap * sizeof(uint64_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!p) p = (uint64_t*)realloc(ruleHashes, cap * sizeof(uint64_t));
  if (!p) return false;
  ruleHashes = p; ruleCap = cap; return true;
}

// Lowercase/normalise a domain exactly like tools/build_blocklist.py's norm():
// strip leading wildcards + dots, trailing dots, a leading "www.".
static void addRuleDomain(const char* raw) {
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
  if (strcmp(s, "localhost") == 0) return;
  if (!ruleReserve()) return;
  ruleHashes[ruleCount++] = fnv40(s, m);
}

static void parseRuleLine(char* line) {
  char* hash = strchr(line, '#'); if (hash) *hash = 0;   // comments (AdGuard cosmetics too)
  char* s = line; while (*s == ' ' || *s == '\t') s++;
  size_t L = strlen(s); while (L && (s[L - 1] == ' ' || s[L - 1] == '\t' || s[L - 1] == '\r')) s[--L] = 0;
  if (!L) return;
  if (*s == '!' || *s == '[' || *s == '/' || *s == '@') { if (*s == '@') ruleSkipped++; return; }
  if (s[0] == '|' && s[1] == '|') {                      // AdGuard / ABP: ||domain^
    char* t = s + 2; char* e = t;
    while (*e && *e != '^' && *e != '$' && *e != '/' && *e != '|') e++;
    if (*e == '$' || *e == '|') { ruleSkipped++; return; }   // $modifiers / regex can't be hashed
    *e = 0; addRuleDomain(t); return;
  }
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
      char save = *e; *e = 0; addRuleDomain(p); *e = save;
      if (!*e) break;
      p = e + 1;
    }
    return;
  }
  addRuleDomain(s);                                     // plain domain list
}

static int cmpU64Asc(const void* a, const void* b) {
  uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
  return (x < y) ? -1 : (x > y) ? 1 : 0;
}

static bool commitRuleHashes(size_t bytesRead) {
  if (ruleCount == 0) { updateStatus = "no rules parsed (" + String(bytesRead) + "B)"; return false; }
  qsort(ruleHashes, ruleCount, sizeof(uint64_t), cmpU64Asc);
  beginBlocklistSwap();
  File f = LittleFS.open("/blocklist.new", "w");
  if (!f) { updateStatus = "fs open failed"; reopenBlocklist(); return false; }
  uint8_t b[HASH_BYTES]; size_t uniq = 0;
  for (size_t i = 0; i < ruleCount; i++) {
    if (i && ruleHashes[i] == ruleHashes[i - 1]) continue;
    packHash(ruleHashes[i], b);
    if (f.write(b, HASH_BYTES) != HASH_BYTES) { f.close(); updateStatus = "write failed"; reopenBlocklist(); return false; }
    uniq++;
  }
  f.close();
  bool ok = commitNewBlocklist();
  Serial.printf("[remote] parsed %u domains (%u skipped) -> %u unique\n",
                (unsigned)ruleCount, (unsigned)ruleSkipped, (unsigned)uniq);
  updateStatus = ok ? ("ok: " + String(numHashes) + " domains") : "bad data";
  return ok;
}

static bool fetchRuleText(const String& url) {
  Serial.printf("[remote] GET rules %s\n", url.c_str());
  WiFiClientSecure cs; cs.setInsecure();
  WiFiClient cl;
  HTTPClient http; http.setTimeout(25000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
  bool https = url.startsWith("https");
  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) { updateStatus = "begin failed"; return false; }
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); updateStatus = "HTTP " + String(code); Serial.printf("[remote] %s\n", updateStatus.c_str()); return false; }

  ruleCount = 0; ruleSkipped = 0;
  WiFiClient* stream = http.getStreamPtr();
  int len = http.getSize();
  char line[320]; size_t ll = 0; bool ovf = false;
  uint8_t b[512]; size_t total = 0; uint32_t idle = millis();
  while (http.connected() && (len < 0 || (int)total < len)) {
    size_t avail = stream->available();
    if (!avail) { if (millis() - idle > 15000) break; delay(2); continue; }
    int n = stream->readBytes(b, avail > sizeof(b) ? sizeof(b) : avail);
    if (n <= 0) continue;
    idle = millis(); total += n;
    for (int i = 0; i < n; i++) {
      char c = (char)b[i];
      if (c == '\n') {
        if (ovf) { ovf = false; ll = 0; }                 // over-long line (cosmetic junk) -> drop
        else { line[ll] = 0; parseRuleLine(line); ll = 0; }
      } else if (c != '\r') {
        if (ll < sizeof(line) - 1) line[ll++] = c; else ovf = true;
      }
    }
  }
  http.end();
  if (ll && !ovf) { line[ll] = 0; parseRuleLine(line); }
  return commitRuleHashes(total);
}

static bool fetchRules(const String& url) {
  if (fetchRuleText(url)) return true;
  const String first = updateStatus;
  if (url == RULE_URL && String(RULE_URL_FALLBACK) != url) {   // mirror only for the built-in URL
    Serial.printf("[remote] primary failed (%s) -> fallback\n", first.c_str());
    if (fetchRuleText(RULE_URL_FALLBACK)) return true;
  }
  updateStatus = first;
  return false;
}

static bool fetchBlocklist(String url) {
  url.trim(); if (!url.length()) { updateStatus = "no url set"; return false; }
  bool ok = url.endsWith(".bin") ? fetchBin(url) : fetchRules(url);
  free(ruleHashes); ruleHashes = nullptr; ruleCap = 0; ruleCount = 0;   // release the PSRAM arena
  Serial.printf("[remote] %s\n", updateStatus.c_str());
  return ok;
}

// Nightly rule refresh. Runs once per local day, after updateHour (default 03:00
// UTC+8), so fetches land at night and a reboot at 15:00 doesn't shift the window.
// The fetch itself is synchronous and pauses DNS for a few seconds — which is the
// whole point of doing it at 3am. Failures retry after a 10 minute cooldown.
static void autoUpdateTick() {
  if (!updateUrl.length()) return;
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
  Serial.printf("[remote] scheduled fetch (local day %ld, hour %u)\n", (long)day, updateHour);
  if (fetchBlocklist(updateUrl) && day > 0) {
    lastUpdateDay = day;
    saveUpdateCfg();                            // remember the day across reboots
  }
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
  Serial.printf("[psram] %u KB free / %u KB total, dns cache budget %u KB\n",
                (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
                (unsigned)(heap_caps_get_total_size(MALLOC_CAP_SPIRAM) / 1024),
                (unsigned)(dnsCacheBudget / 1024));
  Serial.println("\n[s3-adblock] booting");
  if (!LittleFS.begin(true)) Serial.println("LittleFS FAILED");
  // Hand the DNS answer cache a generous slice of PSRAM: it only allocates per stored
  // answer (exact size, ~110B typical), so the budget is a ceiling, not a reservation.
  // Keep 2MB of headroom for the rule parser arena + WiFi/LWIP buffers.
  {
    const size_t freePs = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t cap = freePs > (2u << 20) ? freePs - (2u << 20) : 0;
    if (cap > DNS_CACHE_BUDGET_MAX) cap = DNS_CACHE_BUDGET_MAX;
    if (cap > dnsCacheBudget) dnsCacheBudget = cap;
  }
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");
  if (blocklist) {
    numHashes = blocklist.size() / HASH_BYTES;
    Serial.printf("blocklist: %u domains\n", numHashes);
    buildFlashIndex();
  }
  loadCustom(); loadBanned(); loadHosts(); loadUpdateCfg(); loadLedCfg();
  Serial.printf("custom: %d, hosts: %d, banned: %d\n", numCustom, numHosts, numBanned);
  applyLed();   // LED off setting survives reboots (default: green status light)

  // Hold BOOT at power-on to wipe saved WiFi and force the setup portal.
#if CONFIG_IDF_TARGET_ESP32C3
  const int BOOT_PIN = 9;     // C3 BOOT button
#else
  const int BOOT_PIN = 0;     // ESP32-S3 / classic ESP32 BOOT button
#endif
  pinMode(BOOT_PIN, INPUT_PULLUP);
  if (digitalRead(BOOT_PIN) == LOW) { delay(60);
    if (digitalRead(BOOT_PIN) == LOW) { prefs.begin("wifi", false); prefs.clear(); prefs.end();
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
  { const char* hdrs[] = { CSRF_HEADER }; web.collectHeaders(hdrs, 1); }  // needed for requireAuth()'s CSRF check
  web.on("/", handleRoot);
  web.on("/auth", []() { if (!requireAuth()) return; web.send(200, "text/plain", "ok"); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  // Custom block list / hosts overrides are edited as a whole (textarea in the UI):
  // POST the full text, the device re-parses and rewrites the file.
  web.on("/setblock", []() {
    if (!requireAuth()) return;
    setCustomFromText(web.arg("d"));
    web.send(200, "text/plain", String(numCustom));
  });
  web.on("/sethosts", []() {
    if (!requireAuth()) return;
    setHostsFromText(web.arg("d"));
    web.send(200, "text/plain", String(numHosts));
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
  web.on("/fetchnow", []() { if (!requireAuth()) return; fetchBlocklist(updateUrl); web.send(200, "text/plain", updateStatus); });
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
  { static uint32_t ledNext = 0;              // keep the status colour in sync (Wi-Fi drop, pause expiry)
    if ((int32_t)(millis() - ledNext) >= 0) { ledNext = millis() + 1000; applyLed(); } }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}

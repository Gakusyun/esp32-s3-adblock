#pragma once
// Copy this file to secrets.h and fill in your credentials.
// secrets.h is gitignored so your credentials never get committed.
static const char* WIFI_SSID = "YOUR_WIFI_SSID";
static const char* WIFI_PASS = "YOUR_WIFI_PASSWORD";

// Auth for the dashboard's state-changing endpoints (/ban, /setblock, /sethosts,
// /pause, /resume, /setled, /upload, /update, /setupdate, /fetchnow) and for network
// OTA (ArduinoOTA). These used to be wide open to anyone who could reach the device
// on the LAN — pick real values here, ideally not the same as your WiFi password.
static const char* WEB_USER = "admin";
static const char* WEB_PASS = "CHANGE_ME_WEB_PASSWORD";
static const char* OTA_PASS = "CHANGE_ME_OTA_PASSWORD";

// Nightly rule refresh: always at the same local hour, so a fetch lands at night and
// a reboot in the afternoon doesn't shift the window.
#define RULE_HOUR 3             // 03:00 local time
#define RULE_TZ 8               // local time = UTC + RULE_TZ hours (8 = China)

// Blocklist source. Text rules (hosts / plain domain list / AdGuard basic, including
// @@ allow rules) are parsed and hashed on the device; a URL ending in ".bin" is
// treated as a prebuilt 5-byte hash blob instead.
#define RULE_URL "https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-hosts.txt"
#define RULE_URL_FALLBACK "https://gcore.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-hosts.txt"

// ---- DNS-over-HTTPS upstream (optional, recommended on untrusted networks) ----
// Leave DOH_URL empty to keep plain UDP/53 to UPSTREAM_IP (223.5.5.5). Anything else
// must be an RFC 8484 endpoint over https; the firmware POSTs the raw DNS message,
// validates the server certificate against the built-in root bundle, and keeps one
// TLS session alive for all queries (~45 KB of heap, first lookup after a reconnect
// is 0.3-1 s slower). It needs NTP: certificate dates can't be checked without a
// clock, so DoH stays off until SNTP answers.
//
// #define DOH_URL "https://dns.alidns.com/dns-query"   // Alibaba (mainland CN)
// #define DOH_URL "https://doh.pub/dns-query"          // Tencent
//
// DOH_UDP_FALLBACK 1 = if the endpoint is unreachable, answer over plain UDP so the
// LAN stays online (stats: dohFallback counts the downgrades). 0 = strict: a DoH
// failure is a DNS failure, which is the only mode that really resists an attacker
// who can block the tunnel.
// #define DOH_UDP_FALLBACK 0

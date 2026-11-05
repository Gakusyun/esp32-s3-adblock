# ESP32-S3 广告拦截器（DNS 黑洞 + 网页面板）

一个跑在 **ESP32-S3 (16MB Flash + 8MB PSRAM)** 上的 Pi-hole 式 DNS 广告拦截器：
拦截表以**排序后的 40 位哈希**存在 Flash 里，查询时二分查找，RAM 占用约 10KB，
**不需要把域名列表读进内存**。

> **上游项目**：本项目 fork 自
> [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)（面向 ESP32-C3 / 4MB Flash）。
> 哈希存 Flash + 二分查找的核心设计、DNS 转发逻辑、网页面板均来自上游，遵循 MIT 许可。
>
> **本 fork 的改动**
> - 目标板改为 **ESP32-S3（N16R8：16MB Flash + 8MB Octal PSRAM）**，串口走板载 CH343
>   （`/dev/ttyACM0`，UART0），不启用原生 USB-CDC；
> - 分区表改为 16MB 双 OTA：两个 2MB app 槽 + 11.94MiB LittleFS（固件和规则都能网页 OTA）；
> - 上游 DNS 由 Quad9 换成 **阿里 DNS `223.5.5.5`**（国内延迟低）；
> - 拦截规则换成 **[AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) 完整版**；
> - 新增**设备端解析文本规则**：直接填 AWAvenue 的 rules 文本 URL，设备自己解析 → 哈希 → 写 Flash，
>   支持 hosts / 纯域名 / AdGuard 基础语法（含 `@@` 白名单）三种格式（主 URL 失败自动换备用 CDN）；
> - 规则拉取改到**独立任务**，下载/解析期间 DNS 不再停摆；规则表采用**先写临时文件、校验、再原子 rename**
>   的替换方式，下载失败/断电不会把拦截表清空；
> - 新增 **DNS-over-HTTPS 上游**（可选，证书校验），规则拉取也改用 CA 校验；
> - 删除了原项目的 C3 浏览器安装页（`docs/`）与日文 README。

## 工作原理

```
DNS 查询 ──▶ 取出域名 ──▶ FNV-1a 哈希（连同各级父域名）
                        ──▶ 在 Flash 的哈希表里二分查找
                             ├─ 命中 ──▶ 直接应答 0.0.0.0（黑洞）
                             └─ 未命中 ─▶ 转发上游（UDP 223.5.5.5 或 DoH）
                                          └─▶ 答案存进 DNS 缓存（按 TTL 过期）
```

- 每条规则占 **5 字节（40bit）**，AWAvenue 完整版约 1000 条 ≈ **5KB**；
  就算 50 万条也只占 2.5MB Flash，Flash 有 11.94MiB 可用。
- 40bit 在 50 万条量级下碰撞约 0~1 个（最坏情况是多误杀一个域名）。
- 被拦截域名自动连带拦截其子域名（查询时逐级哈希父域名）。

### DNS 缓存（转发答案缓存）

同一个域名第二次查询不再往上游跑（省掉 ~40ms RTT），直接回 PSRAM 里的答案：

- **键**＝问题段（域名**小写** + qtype + qclass）+ **DO 位**。
  故意**不接受**整条查询：`dig` / 浏览器每次都带一个随机的 EDNS **COOKIE**（还有 padding、
  声明的 UDP 大小），按整包比就永远命中不了（实测命中率 0）。
  不用整包还有一个原因：缓存的应答已经**剪掉了 OPT 记录**（不把上一个客户端的 cookie /
  UDP 大小回给下一个），所以同一条缓存 EDNS / 非 EDNS 客户端都能用；
  命中时再把应答里的问题段换回**当前客户端自己的大小写**（0x20 随机化客户端不会报错）。
- **TTL**：每条记录按存放时长递减（每次命中都会改写 TTL，下次不再重复扣），
  最小 TTL 到期就失效；上游 TTL 超过 1 小时的一律截到 1 小时。
  平时**只在访问时查 TTL 是否需要重新获取**，不靠定时器扫全表。
- **只缓存**肯定性的 NOERROR 应答（带 A/AAAA 等记录）。NXDOMAIN / NODATA / SERVFAIL
  不缓存：上游抖一下就缓存住几分钟，比重新问一次更痛苦。
- **内存按条精确分配**：每条自己 `heap_caps_malloc` 恰好 `应答长度 + 键长度` 字节
  （典型 **~110B**，不是每槽固定预 512B），已用字节实时记账，**不会溢出**。
  唯一的硬上限是**表项数 1024**（`DNS_CACHE_SLOTS`）：
  单条最大 `512 + 288` 字节，所以 1024 条最多占 ~800KB，典型只有 ~110KB。
  槽位表本身（1024 × 28B ≈ 28KB）在**开机时从 PSRAM 分配**，不再占内部 RAM；
  想让缓存更大就调 `DNS_CACHE_SLOTS`，用 `/stats.json` 的 `dnsCacheN` / `dnsCacheBytes` 观察。
- **查找 / 淘汰都是 O(1)**：256 个桶的链式哈希 + 侵入式 LRU 链表。
  > 早先这里是“线性扫 1024 槽找命中”，淘汰还要再扫两遍挑“TTL 最接近过期”的，
  > 表满时每次未命中要遍历约 4000 个槽；现在只剩链上几个槽的比对，淘汰固定丢 LRU 尾部
  > （过期条目本来就会沉到尾部）。
- 过期的条目在**被再次查到时就地释放**（早先它只是返回 miss，却继续占着槽、每次还要重新解析一遍）。
  被拦截/被 Hosts 映射的查询不经过缓存，只有真正转发的才会占位。
- 规则表更新（远程拉取 / 网页上传）时清空一次缓存，避免新规则与旧答案不一致。
- 面板「概览 → 统计」只显示**缓存命中率**（命中 / 未命中次数）；条目数、占用字节、淘汰次数
  不在面板里显示，但都在 `/stats.json`：`dnsCacheN`、`dnsCacheBytes`、`dnsEvict`，
  命令行排查用。

> ⚠️ 如果自己写 PSRAM 分配，别用 Arduino 的 `ps_malloc()`：在这套预编译 opi 库下它
> 会因内部的 `spiramDetected` 标志未置位而**恒返回 NULL**（`ESP.getPsramSize()` 也报 0），
> 但 `heap_caps_get_total_size(MALLOC_CAP_SPIRAM)` 能看到完整 8MB。
> 本固件统一用 `heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)`。

### 上游：UDP 还是 DoH

默认上游是**明文 UDP/53 发到 `223.5.5.5`**。只要能处在链路上（同一个 Wi-Fi、被劫持的路由器、
运营商），任何人就能**改你收到的答案**：他可以直接回一个看起来正常的 A 记录，你的规则表根本
看不到这个域名，拦截也就失效了。改不了拦截规则的，但能绕过它（或者反过来用 DNS 投毒）。

想要防中间人，在 `secrets.h` 里设 `DOH_URL`（**RFC 8484**）：

```cpp
#define DOH_URL "https://dns.alidns.com/dns-query"   // 阿里，国内直连
// #define DOH_URL "https://doh.pub/dns-query"       // 腾讯
#define DOH_UDP_FALLBACK 1      // 端点不可用时回退明文 UDP；0 = 严格模式（宁可不解析）
```

- 查询被封装成一个 `application/dns-message` 的 HTTPS POST，**TLS 证书用内置根证书包校验**
  （不做 `setInsecure`）；报文仍走原来的 txid + 问题段校验。
- **一条 TLS 会话长连接复用**：每次查询都重新握手会多 0.3–1 s（80MHz 的 S3 上），
  所以只断线时重连。代价是常驻 **~45KB 堆**。
- 需要 **NTP**：没时钟就校验证书有效期，所以 SNTP 同步之前 DoH 不会启用（会先走 UDP）。
- 端点挂掉时：`DOH_UDP_FALLBACK=1` 会在 30s 退避后回退到 UDP，`dohFallback` 计数在
  `/stats.json`，面板不隐藏降级；`0` 则直接解析失败（真正“不降级”的选项）。
- **配置了 ≠ 生效中**。`/stats.json` 的 `dohState` 说真话：
  | 值 | 含义 |
  |---|---|
  | `off` | `DOH_URL` 为空，走上游 UDP |
  | `ntp` | 已配，但还没 SNTP 同步（证书无法校验）→ 查询仍走明文 UDP |
  | `idle` | 已配、时钟 OK，但还没有活着的 TLS 会话（刚开机/下次重连） |
  | `ok` | **TLS 会话已建立并在服务**，这才是真在用 DoH |
  | `down` | 最近一次失败，处于 30s 退避中 → 回退明文 UDP（面板会弹黄色警告） |
- 面板「系统 → 设备信息」的 **DNS 上游** 会带上这个状态；`dohOk` / `dohFail` /
  `dohFallback` 是三个计数器。想确认真的在用 DoH：
  ```bash
  curl -s http://<设备IP>/stats.json | grep -o '"up":"[^"]*","dohState":"[^"]*"'
  # -> "up":"DoH dns.alidns.com","dohState":"ok"
  ```
  注意 `dohState` 只描述**转发到上游**的那部分查询；被拦截、Hosts 映射、缓存命中的查询
  本来就不会去上游。
- ⚠️ `DOH_URL` 是编译期宏（不归 `/setupdate` 管），改完要 `pio run -t upload` 重刷固件，
  只 `uploadfs` 不生效。SNTP 本身仍是明文 NTP（`223.5.5.5`/`ntp.aliyun.com`），DoH 覆盖不到它。
- 想先确认端点本身能用（在 PC 上）：
  ```bash
  curl -s -D - -o reply.bin -H 'content-type: application/dns-message' \
       --data-binary @q.bin https://dns.alidns.com/dns-query   # q.bin = 一条裸 DNS 查询
  ```

## 硬件

- ESP32-S3，**16MB Flash + 8MB PSRAM**（开发板丝印常见 N16R8），本仓库分区表按 16MB 写死
- USB 供电要稳（手机充电器 / 路由器 USB 口都行）；USB-UART 桥接芯片为 CH343
- 板载 **WS2812 RGB 灯**默认接 **GPIO48**（绿色=拦截中、琥珀色=已暂停、蓝色=启动中/未联网），可在面板「系统」页关掉；
  若你的板子是 GPIO38 的克隆板，用 `-D LED_PIN=38` 或写在 `secrets.h` 里重编译。
  另有一颗直接接电源的电源指示灯，固件无法控制。
- 串口参数 **115200 8N1**，设备节点 `/dev/ttyACM0`

## 编译与烧录

需要较新版本的 PlatformIO（`pip install -U platformio`；apt 的 4.x 太旧会报 `resultcallback` 错）。

```bash
# 1. 配置（secrets.h 已在 .gitignore 中，不会提交）
cp src/secrets.example.h src/secrets.h
#    编辑 src/secrets.h：WiFi、WEB_PASS / OTA_PASS、规则 URL

# 2. 构建网页面板（Preact + Tailwind，产物 data/index.html.gz，不入库，必须自己生成）
cd web && npm install && npm run build && cd ..

# 3. 预生成一份规则哈希表打进 LittleFS（也可跳过，设备首次联网会自己拉）
python3 tools/build_blocklist.py data/blocklist.bin

# 4. 编译 + 烧录固件 + 烧录文件系统（uploadfs 会把 data/ 打包成 LittleFS）
pio run -t upload
pio run -t uploadfs

# 5. 看启动日志
pio device monitor
```

> `uploadfs` 会用 `data/` **重建整个 LittleFS**：面板上的自定义屏蔽 / Hosts 映射 /
> 封禁列表 / 指示灯设置都会被清掉（规则表变回 `data/blocklist.bin` 里预置的那份）。
> 只刷固件用 `pio run -t upload` 不会动文件系统。

烧完设备会自动连 `secrets.h` 里的 WiFi，面板地址 **http://s3adblock.local**。
WiFi 连不上时（或没填 `secrets.h`）会开一个开放热点 **`S3-AdBlock-XXXX`**，
手机连上去填 SSID/密码即可；想重新配网：**按住 BOOT(GPIO0) 再上电**（会清掉保存的 WiFi 并进配网门户）。

### 分区表（16MB，双 OTA）

| 分区 | 偏移 | 大小 |
|---|---|---|
| nvs | 0x9000 | 20KB |
| otadata | 0xe000 | 8KB |
| app0 (ota_0) | 0x10000 | 2MB |
| app1 (ota_1) | 0x210000 | 2MB |
| littlefs | 0x410000 | 11.94MiB |

想放弃固件 OTA、把空间全给规则表，改 `partitions.csv` 即可。

## 网页面板

面板是独立的 **Preact + Tailwind CSS** 前端（`web/`），构建后是**一个 18KB 的 gzip HTML**（另存一份 60KB 未压缩版 `data/index.html`），
存在 LittleFS 的 `/index.html.gz`，由固件直接吐给浏览器 —— 不依赖 CDN，设备没外网也能打开。
带 `Accept-Encoding: gzip` 的浏览器拿 gzip，其余（如没加 `--compressed` 的 `curl`）拿未压缩版，
不会像原来那样把 gzip 字节当 HTML 发出去。
样式遵循 [Kailoinf/salary-calc](https://github.com/Kailoinf/salary-calc) 的 STYLE.md：
浅色为主 + `dark:` 跟随系统、白卡片 `rounded-xl`、sky 作强调色、不用自定义 CSS。

标签页：

| 标签 | 内容 |
|---|---|
| 概览 | 拦截状态（暂停 30s/5min/30min/手动恢复）、拦截/放行/规则数/**缓存命中率**、温度·内存·信号·时长、规则源 |
| 客户端 | 每个 IP/MAC 的拦截/放行计数，搜索、封禁/解封 |
| 规则 | 改规则 URL 与每天几点更新、立即拉取、上传 `blocklist.bin` |
| 屏蔽 | 自定义屏蔽：一个文本框，一行一个域名（也接受 hosts 格式），整表保存 |
| Hosts | 自定义 hosts 映射：`域名 IP`，设备直接应答该 IP |
| 系统 | 指示灯开关（关掉 WS2812）、固件 OTA 上传、设备信息（含当前 DNS 上游） |

### 自定义屏蔽 vs Hosts 映射

两个功能分开做，各占一个标签页，互不影响：

- **屏蔽**：只写域名，命中就答 `0.0.0.0`（子域名一并拦截）。粘贴一整份 hosts 文件也行，
  只要域名，前面的 `0.0.0.0` / `127.0.0.1` 会被忽略。最多 512 条**去重后**的域名，
  超过就整表拒绝（旧的保存结果不变），不会只存前 512 条。
- **Hosts 映射**：写 `域名 目标IP`，设备按你给的 IPv4 应答，典型用法 `nas.home 192.168.4.100`。
  支持父域继承（`nas.home` 也覆盖 `foo.nas.home`）；AAAA 查询返回空应答，客户端自动走 IPv4。
  最多 128 条。优先级：**封禁 > Hosts 映射 > 屏蔽表**（被封的设备连映射也拿不到）。

两边都是"整表覆盖"语义：文本框里是什么就存什么，删掉一行再保存即取消。

**认证**：`/`、`/stats.json` 只读开放；改状态的接口（`/auth`、`/ban`、`/setblock`、`/sethosts`、
`/pause`、`/resume`、`/setled`、`/upload`、`/update`、`/setupdate`、`/fetchnow`）需要
HTTP Basic Auth（`WEB_USER`/`WEB_PASS`）+ 自定义请求头 `X-Requested-With: s3-adblock`（防 CSRF）。
面板顶部「登录」把凭据存进 `sessionStorage`，之后的请求自动带 `Authorization`。
网络 OTA 用 `OTA_PASS`：

```bash
pio run -t upload --upload-port s3adblock.local --upload-protocol espota
```

> 注意：面板是**纯 HTTP**，Basic Auth 只是 base64，能挡住局域网里"裸访问接口"的情况，
> 挡不住同网段的抓包。密码别和 WiFi 密码共用。

## 规则来源与更新

默认规则：[AWAvenue-Ads-Rule 完整版 hosts 列表](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)
（广告 + 隐私追踪 + 不受欢迎内容，约 1000 个域名）。

默认 URL（`src/secrets.h` 中的 `RULE_URL`）：

```
https://cdn.jsdelivr.net/gh/TG-Twilight/AWAvenue-Ads-Rule@main/Filters/AWAvenue-Ads-Rule-hosts.txt
```

- 主用的 jsDelivr 在国内可直连；`RULE_URL_FALLBACK` 是同一份文件的 gcore 节点，
  主 URL 失败时自动回退。`raw.githubusercontent.com` 在国内常常不通，别用。
- **每天固定的本地时间自动拉一次**（`RULE_HOUR`，默认 **03:00 UTC+8**，时区 `RULE_TZ`），
  不再是"开机后 N 小时"。拉取在**独立 FreeRTOS 任务**里跑（TLS + 解析在堆里做，
  下载再慢 DNS 也照常应答），结果由主循环收集。
  设备开机后 NTP 同步时间（`ntp.aliyun.com` / `223.5.5.5`）；同一个本地日期只拉一次，
  重启也不会重复拉（日期存在 `/update.cfg`）。几个例外：
  - 开机时设备里**没有规则表**（`numHashes == 0`）→ 立刻拉，不等半夜；
  - 拉取失败 → 10 分钟后重试，直到成功；
  - NTP 不可达（时钟没同步）→ 退化成"开机后每 24 小时一次"，
    并且**规则拉取不校验证书**（面板会提示 `fetchInsecure`，能修就先修 NTP）。
- 面板「规则」页可以改 URL、**每天几点更新**、时区，或点「立即拉取」（立即返回，
  进度看「上次」/`upbusy`）。
- **替换是原子的**：新表先写进临时文件（`/blupdate.new` 或 `/blocklist.new`），校验
  （非空、5 字节整数倍、**有序**、`Content-Length` 对得上）之后才 `rename()` 覆盖旧的。
  所以下载被截断、证书失效、写满、断电都不会把正在用的规则表弄没（旧版本是**先删再写**）。
- 下载用 `HTTPClient::writeToStream()` 而不是裸 socket：**chunked 传输会自动解块**，
  分块边界不会混进文本解析器；截断的分块流会返回错误而不是被当成“有序的前缀”收下。
  chunked 没有总长度可比对，所以 `/stats.json` 仍会标 `fetchChunked`。
- 规则表被替换（远程拉取 / 网页上传）时**清空一次 DNS 缓存**：旧答案可能指向新规则要拦的域名。
- 设备端支持的格式（与 `tools/build_blocklist.py` 保持一致）：
  - hosts：`0.0.0.0 ads.example.com`、`127.0.0.1 x`、`:: x`（一行多个域名也支持）
  - 纯域名列表：一行一个
  - AdGuard / ABP 基础规则：`||ads.example.com^`
  - `@@||ads.example.com^` **白名单**：会从同一份表里减掉（不再被忽略而误拦）
  - 不支持的（正则、通配符、带路径、`$` 修饰符、`##` 外观规则）会被跳过并计数
- URL **以 `.bin` 结尾**时按"预编译哈希表"处理（老路径），否则按文本规则解析。
- 设备端解析的规模受 PSRAM 限制（每个域名 8 字节）：约 **30 万个域名**；超过会报
  `out of memory` 并保留旧表。更大的表请用 `.bin`（整块 11.94MiB 分区 ≈ 240 万条）。
- 也想用命令行生成 `.bin`（在 LittleFS 里预置一份当兜底）：

```bash
python3 tools/build_blocklist.py data/blocklist.bin          # 默认 AWAvenue 完整版
python3 tools/build_blocklist.py data/blocklist.bin <文件或URL> ...
```

## 验证

```bash
curl -s http://<设备IP>/stats.json | head -c 400   # 含 up="UDP 223.5.5.5:53" / "DoH dns.alidns.com"
curl -i http://<设备IP>/        # 面板
```

`/stats.json` 比面板全：面板只取其中几个字段，其余专给命令行排查（加字段不需要改前端）。

| 字段 | 含义 |
|---|---|
| `heap` / `heapTotal` / `heapMin` | 内部 SRAM 剩余 / 总量 / 启动以来最低水位（字节） |
| `psram` / `psramTotal` / `psramMin` | PSRAM 剩余 / 总量 / 最低水位 |
| `dnsHit` / `dnsMiss` | DNS 缓存命中 / 未命中 |
| `dnsCacheN` / `dnsCacheBytes` / `dnsCacheCap` / `dnsEvict` | 缓存条目数 / 占用 PSRAM / 槽位上限 / 淘汰次数 |
| `blBytes` / `blIndex` / `blCap` | 规则表字节数 / 一级索引条目数 / 分区能放的条数上限 |
| `blIndexErr` / `blStreams` | 建索引失败（读失败或 PSRAM 不足；非 0 = 本次开机不拦截）/ 需要多读一段的查询次数 |
| `fsUsed` / `fsTotal` | LittleFS 已用 / 总容量 |
| `epoch` | 当前时间戳（仍停在 1970 → NTP 没同步，规则拉取会不校验证书） |
| `build` / `idf` / `cpu` | 固件编译时间 / ESP-IDF 版本 / CPU 频率（用来确认 OTA 真的生效） |
| `mac` / `ssid` / `gw` / `ch` | 本机 MAC / 已连 SSID / 网关 / 信道 |
| `tmpUp` / `tmpRemote` / `blOld` | 残留的临时文件，`true` = 上次规则表替换被打断 |
| `dohState` / `dohBackoffS` / `dohFallback` | DoH 实际状态 / 退避剩余秒数 / 降级到 UDP 的次数 |
| `clientN` / `banN` / `customN` / `hostN` | 客户端 / 封禁 / 自定义屏蔽 / Hosts 条数 |
| `customCap` / `hostCap` | 自定义屏蔽 / Hosts 的条数上限（面板直接用它，不写死） |
| `fetchChunked` | 上次拉取是 chunked 传输（分块边界已校验，但服务器没有给出总长度） |
| `clients[].age` | 该客户端距离上次查询多少秒（判断表项是否过时） |

> 面板「可用内存」显示的是 `heap`（**内部 SRAM**，100～200KB 是正常值）；8MB PSRAM 是独立
> 地址空间，只有当固件显式 `heap_caps_malloc(MALLOC_CAP_SPIRAM)` 时才会用到（DNS 缓存、
> 规则解析 arena），在 `/stats.json` 的 `psram` 字段里。

配合面板「概览」看拦截/放行/缓存命中率，「规则」看 `upstat`（会显示 `fetching...` →
`ok: N domains` / `rejected: ...`）。DNS 侧：

```bash
# 注意：验证要用列表里真有的域名。AWAvenue 里是 ad.doubleclick.net，
# 不带 ad. 的 doubleclick.net 不在列表里，不会被拦。
dig @<设备IP> ad.doubleclick.net   # -> 0.0.0.0（被拦）
dig @<设备IP> github.com           # -> 真实 IP（转发）
dig @<设备IP> github.com           # -> 同样答案，第二次走缓存（TTL 递减）
curl -s http://<设备IP>/stats.json | grep -o '"dnsH[^,]*,"dnsM[^,]*'   # 命中/未命中计数
```

把设备的 IP 设为路由器 DHCP 下发的 DNS（或单机手动指定）即可全屋生效。

## 功耗与温度

- CPU 降到 **80MHz**（Wi-Fi 仍正常），网页面板轮询 5s，Wi-Fi 发射功率降到 **11dBm**
  （近距离完全够用）。实测芯片内部温度从 ~43°C 降到 ~39°C，`dig` 拦截查询 8–16ms、转发 40–48ms。
- Wi-Fi **modem sleep 保持关闭**（`WiFi.setSleep(false)`）：DNS 响应优先，这是有意的取舍。
- 冷启动后第一次关联偶尔会被路由器以 `reason=202` 拒绝（旧关联未过期），固件会**自动重试 3 次**。
- 板载 RGB 灯也能关：面板「系统 → 指示灯」切成关闭，固件就不再驱动 WS2812（`/setled?s=0`），
  设置存 `/led.cfg`，重启仍生效。开着时绿色=拦截中、琥珀色=已暂停、蓝色=启动中/未联网。
  部分板子另有一颗直接接电源的指示灯，那颗固件关不掉。
- 开了 DoH 会多占 **~45KB 堆**（否则无所谓）；80MHz 下 TLS 握手比 240MHz 慢，
  断线后的第一次解析可能多花 0.3–1 s（之后复用长连接，与 UDP 差别不大）。

## 已知限制

- 只支持 Wi-Fi 2.4GHz（芯片限制），不支持 5GHz。
- 面板/OTA 都是明文 HTTP；局域网信任边界内的防护，不是加密方案。
- `/stats.json` 不鉴权（内网只读），里面有每个客户端的 IP/MAC、自定义屏蔽与 Hosts 表。
- 默认上游是**明文 UDP DNS**（可被链路上的中间人改写/投毒），想防就开 DoH（见上）。
  规则拉取用 CA 校验，但**没有 NTP 时会降级不校验**；规则 URL 写成 `http://` 时
  同样没有证书校验，两者都会让 `fetchInsecure` 为 true。
- DNS 应答已按 EDNS 规范重建（只带 question + 1 条 answer，ARCOUNT=0），
  个别客户端若仍异常，优先怀疑上游/DNS 报文被中间设备改写。
- 上游转发在解析器里是阻塞等待（最多 1s），等待期间会穿插 `web.handleClient()`，
  所以面板不会卡，但 DNS 查询本身是串行的（家庭规模够用）。
- Ubuntu/Fedora 上的 ModemManager 会抢 `/dev/ttyACM0` 并反复复位板子：
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```

## 目录结构

```
platformio.ini        目标板 / 烧录参数（唯一 env: s3）
partitions.csv        16MB 双 OTA 分区表
src/main.cpp          固件：DNS、面板、OTA、规则解析
src/page.h            文件系统缺面板时的兜底提示页
web/                  面板前端源码（Preact + Tailwind，npm run build）
data/index.html.gz    面板构建产物（npm run build 生成，不入库，随 uploadfs 烧进 LittleFS）
src/secrets.example.h 配置模板（WiFi / 面板密码 / 规则 URL）
tools/build_blocklist.py  文本规则 -> 5 字节哈希表
data/blocklist.bin    预置规则表（本地生成，未入库；烧进 LittleFS 当兜底）
```

## 许可

MIT，见 [LICENSE](LICENSE)。原始版权归上游
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) 作者所有。

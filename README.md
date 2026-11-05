# ESP32-S3 广告拦截器（DNS 黑洞 + 网页面板）

一个跑在 **ESP32-S3 (16MB Flash + 8MB PSRAM)** 上的 Pi-hole 式 DNS 广告拦截器：
拦截表以**排序后的 40 位哈希**存在 Flash 里，查询时二分查找，RAM 占用约 50KB，
**不需要把域名列表读进内存**。

> **上游项目**：本项目 fork 自
> [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)（面向 ESP32-C3 / 4MB Flash）。
> 哈希存 Flash + 二分查找的核心设计、DNS 转发逻辑、网页面板均来自上游，遵循 MIT 许可。
>
> **本 fork 的改动**
> - 目标板改为 **ESP32-S3（N16R8：16MB Flash + 8MB Octal PSRAM）**，串口走板载 CH343
>   （`/dev/ttyACM0`，UART0），不启用原生 USB-CDC；
> - 分区表改为 16MB 双 OTA：两个 2MB app 槽 + 11.75MB LittleFS（固件和规则都能网页 OTA）；
> - 上游 DNS 由 Quad9 换成 **阿里 DNS `223.5.5.5`**（国内延迟低）；
> - 拦截规则换成 **[AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule) 完整版**；
> - 新增**设备端解析文本规则**：直接填 AWAvenue 的 rules 文本 URL，设备自己解析 → 哈希 → 写 Flash，
>   支持 hosts / 纯域名 / AdGuard 基础语法三种格式（主 URL 失败自动换备用 CDN）；
> - 删除了原项目的 C3 浏览器安装页（`docs/`）与日文 README。

## 工作原理

```
DNS 查询 ──▶ 取出域名 ──▶ FNV-1a 哈希（连同各级父域名）
                        ──▶ 在 Flash 的哈希表里二分查找
                             ├─ 命中 ──▶ 直接应答 0.0.0.0（黑洞）
                             └─ 未命中 ─▶ 转发 223.5.5.5
                                          └─▶ 答案存进 DNS 缓存（按 TTL 过期）
```

- 每条规则占 **5 字节（40bit）**，AWAvenue 完整版约 1000 条 ≈ **5KB**；
  就算 50 万条也只占 2.5MB Flash，Flash 有 11.75MB 可用。
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
  两个上限，先到先算：
  - 表项数 **1024**（`DNS_CACHE_SLOTS`，静态数组约 28KB 内部 RAM）；
  - byte 预算：开机时按 PSRAM 实际空闲算出 `min(4MB, 空闲 - 2MB)`（N16R8 上就是 **4MB**），
     `DNS_CACHE_BUDGET_MAX` 可改。预算只是天花板，按需分配 —— 1024 条典型只占 ~110KB。
  > 之前写的固定 192KB 是按"每槽 512B 最坏情况"拍的，在精确分配下没有意义，已改成上面这套。
- **缺空间时的淘汰策略**（类似页面置换）：
  1. 已过期的先丢；
  2. 否则丢“**TTL 最接近过期**”的；
  3. 一样的再比**命中次数最少**的；
  4. 再一样就丢**最久没被用过**的（LRU）。
  被拦截/被 Hosts 映射的查询不经过缓存，只有真正转发的才会占位。
- 规则表更新（远程拉取 / 网页上传）时清空一次缓存，避免新规则与旧答案不一致。
- 面板「概览 → 统计」只显示**缓存命中率**（命中 / 未命中次数）；条目数、占用字节、预算、淘汰次数
  不在面板里显示，但都在 `/stats.json`：`dnsCacheN`、`dnsCacheBytes`、`dnsCacheBudget`、`dnsEvict`，
  命令行排查用。

> ⚠️ 如果自己写 PSRAM 分配，别用 Arduino 的 `ps_malloc()`：在这套预编译 opi 库下它
> 会因内部的 `spiramDetected` 标志未置位而**恒返回 NULL**（`ESP.getPsramSize()` 也报 0），
> 但 `heap_caps_get_total_size(MALLOC_CAP_SPIRAM)` 能看到完整 8MB。
> 本固件统一用 `heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)`。

## 硬件

- ESP32-S3，**16MB Flash + 8MB PSRAM**（开发板丝印常见 N16R8），本仓库分区表按 16MB 写死
- USB 供电要稳（手机充电器 / 路由器 USB 口都行）；USB-UART 桥接芯片为 CH343
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
| littlefs | 0x410000 | 11.75MB |

想放弃固件 OTA、把空间全给规则表，改 `partitions.csv` 即可。

## 网页面板

面板是独立的 **Preact + Tailwind CSS** 前端（`web/`），构建后是**一个 18KB 的 gzip HTML**，
存在 LittleFS 的 `/index.html.gz`，由固件直接吐给浏览器 —— 不依赖 CDN，设备没外网也能打开。
样式遵循 [Kailoinf/salary-calc](https://github.com/Kailoinf/salary-calc) 的 STYLE.md：
浅色为主 + `dark:` 跟随系统、白卡片 `rounded-xl`、sky 作强调色、不用自定义 CSS。

标签页：

| 标签 | 内容 |
|---|---|
| 概览 | 拦截状态（暂停 30s/5min/30min/手动恢复）、拦截/放行/规则数/**缓存命中率**、温度·内存·信号·时长、规则源 |
| 客户端 | 每个 IP/MAC 的拦截/放行计数，搜索、封禁/解封 |
| 规则 | 改规则 URL 与更新间隔、立即拉取、上传 `blocklist.bin` |
| 屏蔽 | 自定义屏蔽：一个文本框，一行一个域名（也接受 hosts 格式），整表保存 |
| Hosts | 自定义 hosts 映射：`域名 IP`，设备直接应答该 IP |
| 系统 | 固件 OTA 上传、设备信息 |

### 自定义屏蔽 vs Hosts 映射

两个功能分开做，各占一个标签页，互不影响：

- **屏蔽**：只写域名，命中就答 `0.0.0.0`（子域名一并拦截）。粘贴一整份 hosts 文件也行，
  只要域名，前面的 `0.0.0.0` / `127.0.0.1` 会被忽略。最多 512 条。
- **Hosts 映射**：写 `域名 目标IP`，设备按你给的 IPv4 应答，典型用法 `nas.home 192.168.4.100`。
  支持父域继承（`nas.home` 也覆盖 `foo.nas.home`）；AAAA 查询返回空应答，客户端自动走 IPv4。
  最多 128 条。映射优先级高于屏蔽表（显式映射就是显式意图）。

两边都是"整表覆盖"语义：文本框里是什么就存什么，删掉一行再保存即取消。

**认证**：`/`、`/stats.json` 只读开放；改状态的接口（`/auth`、`/ban`、`/setblock`、`/sethosts`、
`/pause`、`/resume`、`/upload`、`/update`、`/setupdate`、`/fetchnow`）需要
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
  不再是"开机后 N 小时"——拉取是同步的，那几秒 DNS 会暂停应答，放在半夜谁也察觉不到。
  设备开机后 NTP 同步时间（`ntp.aliyun.com` / `223.5.5.5`）；同一个本地日期只拉一次，
  重启也不会重复拉（日期存在 `/update.cfg`）。几个例外：
  - 开机时设备里**没有规则表**（`numHashes == 0`）→ 立刻拉，不等半夜；
  - 拉取失败 → 10 分钟后重试，直到成功；
  - NTP 不可达（时钟没同步）→ 退化成"开机后每 24 小时一次"。
- 面板「规则」页可以改 URL、**每天几点更新**、时区，或点「立即拉取」。
- 规则表被替换（远程拉取 / 网页上传）时**清空一次 DNS 缓存**：旧答案可能指向新规则要拦的域名。
- 设备端支持的格式：
  - hosts：`0.0.0.0 ads.example.com`、`127.0.0.1 x`、`:: x`（一行多个域名也支持）
  - 纯域名列表：一行一个
  - AdGuard / ABP 基础规则：`||ads.example.com^`
  - 不支持的（正则、通配符、`$` 修饰符、`##` 外观规则、`@@` 白名单）会被跳过并计数
- URL **以 `.bin` 结尾**时按"预编译哈希表"处理（老路径），否则按文本规则解析。
- 也想用命令行生成 `.bin`（在 LittleFS 里预置一份当兜底）：

```bash
python3 tools/build_blocklist.py data/blocklist.bin          # 默认 AWAvenue 完整版
python3 tools/build_blocklist.py data/blocklist.bin <文件或URL> ...
```

## 验证

```bash
dig @<设备IP> doubleclick.net   # -> 0.0.0.0（被拦）
dig @<设备IP> github.com        # -> 真实 IP（转发，第一次 ~40ms）
dig @<设备IP> github.com        # -> 同样答案，第二次走缓存（<5ms，TTL 递减）
curl -s http://<设备IP>/stats.json | grep -o '"dnsH[^,]*,"dnsM[^,]*'   # 命中/未命中计数
curl -i http://<设备IP>/        # 面板
```

把设备的 IP 设为路由器 DHCP 下发的 DNS（或单机手动指定）即可全屋生效。

## 功耗与温度

- CPU 降到 **80MHz**（Wi-Fi 仍正常），网页面板轮询 5s，Wi-Fi 发射功率降到 **11dBm**
  （近距离完全够用）。实测芯片内部温度从 ~43°C 降到 ~39°C，`dig` 拦截查询 8–16ms、转发 40–48ms。
- Wi-Fi **modem sleep 保持关闭**（`WiFi.setSleep(false)`）：DNS 响应优先，这是有意的取舍。
- 冷启动后第一次关联偶尔会被路由器以 `reason=202` 拒绝（旧关联未过期），固件会**自动重试 3 次**。

## 已知限制

- 只支持 Wi-Fi 2.4GHz（芯片限制），不支持 5GHz。
- 面板/OTA 都是明文 HTTP；局域网信任边界内的防护，不是加密方案。
- DNS 应答已按 EDNS 规范重建（只带 question + 1 条 answer，ARCOUNT=0），
  个别客户端若仍异常，优先怀疑上游/DNS 报文被中间设备改写。
- 规则更新时是同步下载解析，几秒内 DNS 会暂停响应（设备规模小，影响可接受）。
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

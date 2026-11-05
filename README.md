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
                             └─ 未命中 ─▶ 转发 223.5.5.5，原样回传
```

- 每条规则占 **5 字节（40bit）**，AWAvenue 完整版约 1000 条 ≈ **5KB**；
  就算 50 万条也只占 2.5MB Flash，Flash 有 11.75MB 可用。
- 40bit 在 50 万条量级下碰撞约 0~1 个（最坏情况是多误杀一个域名）。
- 被拦截域名自动连带拦截其子域名（查询时逐级哈希父域名）。

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

# 2. 预生成一份规则哈希表打进 LittleFS（也可跳过，设备首次联网会自己拉）
python3 tools/build_blocklist.py data/blocklist.bin

# 3. 编译 + 烧录固件 + 烧录文件系统
pio run -t upload
pio run -t uploadfs

# 4. 看启动日志
pio device monitor
```

烧完设备会自动连 `secrets.h` 里的 WiFi，面板地址 **http://s3adblock.local**。
WiFi 连不上时（或没填 `secrets.h`）会开一个开放热点 **`S3-AdBlock-XXXX`**，
手机连上去填 SSID/密码即可；想重新配网：面板点「Forget WiFi」，或**按住 BOOT(GPIO0) 再上电**。

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

- 统计：总拦截 / 总放行、规则条数、每客户端（IP/MAC）拦截计数、WiFi 信号、芯片温度、可用内存、运行时长
- 操作：封禁/解封某个客户端、添加/删除自定义屏蔽域名、暂停拦截（30 秒 / 5 分钟 / 30 分钟 / 手动恢复）
- 规则：网页上传 `blocklist.bin`，或填文本规则 URL 定时自动拉取
- 固件：网页上传 `.pio/build/s3/firmware.bin` 直接 OTA 重启

**认证**：`/`, `/stats.json` 只读开放；所有会改状态的接口（`/ban`、`/addblock`、`/unblock`、
`/pause`、`/resume`、`/forgetwifi`、`/upload`、`/update`、`/setupdate`、`/fetchnow`）
需要 HTTP Basic Auth（`WEB_USER`/`WEB_PASS`）+ 自定义请求头 `X-Requested-With: s3-adblock`
（防 CSRF）。网络 OTA 用 `OTA_PASS`：

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
- 设备每 `RULE_INTERVAL_H`（默认 24）小时自动拉一次；在面板上可以改 URL / 间隔、点「Fetch now」。
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
dig @<设备IP> github.com        # -> 真实 IP（转发）
curl -i http://<设备IP>/        # 面板
```

把设备的 IP 设为路由器 DHCP 下发的 DNS（或单机手动指定）即可全屋生效。

## 功耗与温度

- CPU 降到 **80MHz**（Wi-Fi 仍正常），网页面板轮询 3s → **10s**，Wi-Fi 发射功率降到 **11dBm**
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
src/page.h            面板 HTML
src/secrets.example.h 配置模板（WiFi / 面板密码 / 规则 URL）
tools/build_blocklist.py  文本规则 -> 5 字节哈希表
data/blocklist.bin    预置规则表（本地生成，未入库；烧进 LittleFS 当兜底）
```

## 许可

MIT，见 [LICENSE](LICENSE)。原始版权归上游
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) 作者所有。

#pragma once
// 文件系统里没有 /index.html.gz 时的兜底页。正常情况下面板由 web/ 构建产物
// (data/index.html.gz) 提供，这个页面只在刷了固件但忘了刷文件系统时出现。

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang="zh-CN"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark"><title>S3 AdBlock</title>
<style>
:root{color-scheme:light dark}
body{font:16px/1.6 system-ui,-apple-system,"Noto Sans SC",sans-serif;max-width:34rem;margin:3rem auto;padding:0 1.25rem;color:#1e293b;background:#fff}
@media(prefers-color-scheme:dark){body{color:#e2e8f0;background:#000}}
h1{font-size:1.25rem;margin:0 0 .25rem}
.card{border:1px solid #e2e8f0;border-radius:.75rem;padding:1rem;margin-top:1rem}
@media(prefers-color-scheme:dark){.card{border-color:#334155}}
code{font-family:ui-monospace,Menlo,monospace;font-size:.85em;background:#f1f5f9;padding:.1em .35em;border-radius:.25rem}
@media(prefers-color-scheme:dark){code{background:#1e293b}}
a{color:#0284c7}
.muted{color:#64748b;font-size:.875rem}
</style></head><body>
<h1>&#128737; S3 AdBlock</h1>
<p class="muted">设备已启动，但文件系统里没有面板文件。</p>
<div class="card">
  <strong>面板未烧录</strong>
  <p class="muted">在仓库根目录执行下面任一命令即可：</p>
  <p><code>pio run -e s3 -t uploadfs</code>&nbsp;（推荐，只刷文件系统）</p>
  <p><code>cd web &amp;&amp; npm run build &amp;&amp; cd .. &amp;&amp; pio run -e s3 -t uploadfs</code>&nbsp;（重新构建面板后再刷）</p>
  <p class="muted">规则接口照常可用：<code>/stats.json</code>。源码：<a href="https://github.com/Gakusyun/esp32-s3-adblock">Gakusyun/esp32-s3-adblock</a></p>
</div>
</body></html>)HTML";

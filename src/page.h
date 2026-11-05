#pragma once
// 网页面板 HTML（S3 AdBlock）。单独放在头文件里，避免 Arduino IDE 预处理内联标记时出错。
// UI 文案为中文；变量名/接口路径保持英文以便与 main.cpp 对应。

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html lang=zh-CN><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>ESP32-S3 广告拦截器</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><h1>🛡️ S3 AdBlock <span id=host></span></h1></header><div class=wrap>
<div id=credwarn style="display:none;background:#3b1d1d;border:1px solid #f85149;color:#ffb3ae;border-radius:8px;padding:10px 14px;margin-bottom:14px;font-size:13px">
⚠️ <b>仍在使用默认密码。</b><code>secrets.h</code> 里的 <code>WEB_PASS</code>/<code>OTA_PASS</code> 还是占位值——公开在仓库示例文件里，谁都能看到。请改成真实密码后重新烧录。
</div>
<div id=blockbar style="display:flex;align-items:center;gap:12px;margin-bottom:14px;padding:12px 14px;background:#161b22;border:1px solid #30363d;border-radius:8px">
<span id=blockdot style=font-size:20px>🛡️</span><b id=blockstate style=flex:1 data-on=1>拦截已开启</b>
<select id=pausedur style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:5px"><option value=30>30 秒</option><option value=300 selected>5 分钟</option><option value=1800>30 分钟</option><option value=0>直到手动恢复</option></select>
<button id=pausebtn onclick=togglePause()>暂停拦截</button></div>
<div class=cards id=sys></div>
<h2>客户端</h2><table id=ct><thead><tr><th>客户端</th><th>MAC</th><th>已拦截</th><th>已放行</th><th>操作</th></tr></thead><tbody></tbody></table>
<h2>自定义屏蔽域名</h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom()>屏蔽此域名</button></div>
<table id=cl><tbody></tbody></table>
<h2>规则表 &mdash; 上传</h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button>上传 blocklist.bin</button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">用 <code>tools/build_blocklist.py</code> 生成 <code>blocklist.bin</code> 后在此上传 &mdash; 不用插 USB</div>
<h2>规则 &mdash; 远程自动更新</h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/rules.txt" size=40> 每 <input id=uiv size=2 value=24> 小时
<button onclick=saveUpd()>保存</button> <button onclick=fetchNow()>立即拉取</button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">设备定时拉取规则文本（hosts / 纯域名 / AdGuard 格式，在设备上计算哈希），也支持预编译的 <code>blocklist.bin</code>；默认使用 AWAvenue 规则。上次：<span id=ustat>&mdash;</span></div>
<h2>固件 &mdash; OTA 升级</h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button>上传固件</button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px">上传 <code>.pio/build/s3/firmware.bin</code> &mdash; 设备校验后重启进入新固件</div>
<h2>Wi-Fi</h2>
<div style=margin-bottom:18px><button onclick="if(confirm('清除已保存的 WiFi 并重启进入配网门户？'))forgetWifi()">忘记 WiFi</button></div>
</div><script>
function fmt(n){return n.toLocaleString()}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
// 普通 <img>/<form> 触发的 CSRF 无法携带自定义请求头，只有同源 fetch() 可以，
// 所以要求这个头就能挡掉"浏览器缓存 Basic Auth 被别的页面借刀"这类攻击。
const CSRF_HDRS={'X-Requested-With':'s3-adblock'}
function togglePause(){fetch(blockstate.dataset.on=='1'?'/pause?s='+pausedur.value:'/resume',{headers:CSRF_HDRS}).then(load);}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
credwarn.style.display=s.defcreds?'block':'none';
let on=s.blocking!==false;blockstate.dataset.on=on?'1':'0';
blockdot.textContent=on?'🛡️':'⏸️';blockbar.style.borderColor=on?'#30363d':'#f0883e';
blockstate.textContent=on?'拦截已开启':(s.resumeIn>0?'已暂停 — '+s.resumeIn+' 秒后自动恢复':'已暂停');
pausebtn.textContent=on?'暂停拦截':'恢复拦截';pausedur.style.display=on?'':'none';
sys.innerHTML=[['已拦截',fmt(s.blocked),'b'],['已放行',fmt(s.allowed),'a'],['规则表',fmt(s.domains)+' 条',''],
['客户端',s.clients.length,''],['WiFi 信号',s.rssi+' dBm',''],['芯片温度',s.temp+' °C',''],['可用内存',Math.round(s.heap/1024)+' KB',''],['运行时长',s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>已封禁</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban data-ip="${c.ip}">${c.banned?'解封':'封禁'}</button></td></tr>`).join('')||'<tr><td colspan=5 style=color:#8b949e>暂无客户端</td></tr>';
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${esc(d)}</td><td style=text-align:right><button class=rmbtn data-d="${esc(d)}">移除</button></td></tr>`).join('')||'<tr><td style=color:#8b949e>暂无</td></tr>';
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||24;
ustat.textContent=s.upstat||'—';}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d),{headers:CSRF_HDRS}).then(()=>{dom.value='';load()})}}
ct.addEventListener('click',e=>{if(e.target.classList.contains('ban'))fetch('/ban?ip='+e.target.dataset.ip,{headers:CSRF_HDRS}).then(load)});
cl.addEventListener('click',e=>{if(e.target.classList.contains('rmbtn'))fetch('/unblock?d='+encodeURIComponent(e.target.dataset.d),{headers:CSRF_HDRS}).then(load)});
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||24),{headers:CSRF_HDRS}).then(load)}
function fetchNow(){ustat.textContent='正在拉取...';fetch('/fetchnow',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
function forgetWifi(){fetch('/forgetwifi',{headers:CSRF_HDRS}).then(r=>r.text()).then(t=>alert(t))}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='正在写入 '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',headers:CSRF_HDRS,body:fd});fwmsg.textContent=r.ok?'✓ 正在重启，约 15 秒后重新连接':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ 正在重启，约 15 秒后重新连接';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='正在上传 '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',headers:CSRF_HDRS,body:fd});upmsg.textContent=r.ok?'✓ 已更新':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ 上传失败';}
blf.value='';setTimeout(load,600);};
load();setInterval(load,3000);
</script></body></html>)HTML";

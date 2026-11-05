import { render } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';

/* ── 统一样式常量（与 salary-calc 的 ui.tsx 约定一致，不写自定义 CSS） ── */
const INPUT =
  'px-2 py-1.5 rounded-md border border-slate-300 dark:border-slate-600 bg-white dark:bg-black text-sm text-slate-800 dark:text-slate-100 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:border-sky-500 dark:focus:border-sky-400 focus:outline-none focus:ring-1 focus:ring-sky-500 dark:focus:ring-sky-400 w-full';
const BTN =
  'px-3 py-1.5 rounded-lg bg-sky-600 text-white text-sm font-medium hover:bg-sky-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors';
const BTN_OUTLINE =
  'px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-600 text-sm text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-900 disabled:opacity-50 disabled:cursor-not-allowed transition-colors';
const SMALL_BTN =
  'text-xs px-2 py-1 rounded-md border border-slate-300 dark:border-slate-600 text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-900 transition-colors';

const CSRF = { 'X-Requested-With': 's3-adblock' };
const POLL_MS = 5000;

const fmt = (n) => (n === undefined || n === null ? '—' : Number(n).toLocaleString('zh-CN'));

// The device owns every limit and default (MAX_CUSTOM / MAX_HOSTS in src/main.cpp) and
// publishes them in /stats.json, so the UI never hardcodes a number that can drift.
// An IPv4 check that accepts 999.1.1.1 is worse than none: the device silently drops
// such a line and the user is told it was saved.
const OCTET = '(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_RE = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);

const TABS = [
  { id: 'overview', label: '概览' },
  { id: 'clients', label: '客户端' },
  { id: 'rules', label: '规则' },
  { id: 'block', label: '屏蔽' },
  { id: 'hosts', label: 'Hosts' },
  { id: 'system', label: '系统' },
];

/* ── 共享组件 ── */
function Card({ title, action, children }) {
  return (
    <section className="bg-white dark:bg-black rounded-xl border border-slate-200 dark:border-slate-700 p-4 shadow-sm dark:shadow-none space-y-3">
      {(title || action) && (
        <div className="flex items-center justify-between gap-2">
          <h2 className="font-semibold text-slate-900 dark:text-slate-100">{title}</h2>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

function Field({ label, hint, children, className }) {
  return (
    <label className={'flex flex-col gap-1 text-sm text-slate-600 dark:text-slate-400' + (className ? ' ' + className : '')}>
      {label}
      {children}
      {hint ? <span className="text-xs text-slate-400 dark:text-slate-500">{hint}</span> : null}
    </label>
  );
}

function SmallBtn({ onClick, children, disabled }) {
  return (
    <button type="button" onClick={onClick} disabled={disabled} className={SMALL_BTN}>
      {children}
    </button>
  );
}

/** 原生 file input 没法好好样式化：隐藏 input + 自定义按钮，顺便显示文件名/大小 */
function FilePicker({ file, onPick, accept, label = '选择文件' }) {
  const ref = useRef(null);
  return (
    <div className="flex min-w-0 items-center gap-2">
      <button type="button" className={BTN_OUTLINE} onClick={() => ref.current && ref.current.click()}>
        {label}
      </button>
      <span className="min-w-0 truncate text-xs text-slate-500 dark:text-slate-400">
        {file ? `${file.name} · ${(file.size / 1024).toFixed(0)} KB` : '未选择文件'}
      </span>
      <input
        ref={ref}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => onPick(e.currentTarget.files[0] || null)}
      />
    </div>
  );
}

function Stat({ label, value, sub, tone }) {
  return (
    <div className="space-y-0.5">
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div className={'text-xl font-semibold tabular-nums ' + (tone || 'text-slate-900 dark:text-slate-100')}>{value}</div>
      {sub ? <div className="text-xs text-slate-400 dark:text-slate-500">{sub}</div> : null}
    </div>
  );
}

function LoginModal({ onDone, onClose }) {
  const [user, setUser] = useState('admin');
  const [pass, setPass] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setErr('');
    // btoa() only takes Latin-1: encode to UTF-8 first so a password with
    // non-ASCII characters doesn't throw InvalidCharacterError.
    const token = btoa(String.fromCharCode(...new TextEncoder().encode(`${user}:${pass}`)));
    try {
      const r = await fetch('/auth', { headers: { ...CSRF, Authorization: `Basic ${token}` } });
      if (!r.ok) throw new Error('用户名或密码不对');
      sessionStorage.setItem('s3auth', token);
      onDone(token);
    } catch (e) {
      setErr(e.message || '登录失败');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/50 p-4">
      <div className="flex min-h-full items-center justify-center">
        <form
          onSubmit={submit}
          className="w-full max-w-sm bg-white dark:bg-black rounded-xl border border-slate-200 dark:border-slate-700 p-4 shadow-xl space-y-3"
        >
          <div>
            <h2 className="font-semibold text-slate-900 dark:text-slate-100">登录</h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">修改配置、上传固件需要认证。</p>
          </div>
          <Field label="用户名">
            <input autoComplete="username" value={user} onInput={(e) => setUser(e.currentTarget.value)} className={INPUT} />
          </Field>
          <Field label="密码">
            <input
              type="password"
              autoComplete="current-password"
              value={pass}
              onInput={(e) => setPass(e.currentTarget.value)}
              className={INPUT}
              autofocus
            />
          </Field>
          {err ? <p className="text-sm text-rose-500 dark:text-rose-400">{err}</p> : null}
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" className={BTN_OUTLINE} onClick={onClose}>
              取消
            </button>
            <button className={BTN} disabled={busy}>
              {busy ? '验证中…' : '登录'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function Toast({ toast }) {
  if (!toast) return null;
  const tone =
    toast.tone === 'error'
      ? 'bg-rose-600 text-white'
      : 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900';
  return (
    <div className={`fixed inset-x-4 bottom-4 z-50 mx-auto max-w-sm rounded-lg px-4 py-2.5 text-sm shadow-xl ${tone}`}>
      {toast.msg}
    </div>
  );
}

/* ── 主应用 ── */
function App() {
  const [stats, setStats] = useState(null);
  // 自定义屏蔽 / Hosts 映射整表单独取（/lists.json），不塞进 5 秒轮询的 /stats.json。
  const [lists, setLists] = useState(null);
  // 支持 ?t=hosts 之类深链，方便直接打开某个标签页
  const [tab, setTab] = useState(() => {
    const t = new URLSearchParams(location.search).get('t');
    return TABS.some((x) => x.id === t) ? t : 'overview';
  });
  const [toast, setToast] = useState(null);
  const [auth, setAuth] = useState(() => sessionStorage.getItem('s3auth') || '');
  const [loginOpen, setLoginOpen] = useState(false);
  const [busy, setBusy] = useState('');

  const toastTimer = useRef(0);
  function say(msg, tone = 'ok') {
    setToast({ msg, tone });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 3500);
  }

  async function api(path, opts = {}) {
    const headers = { ...CSRF, ...(opts.headers || {}) };
    if (auth) headers.Authorization = `Basic ${auth}`;
    const r = await fetch(path, { ...opts, headers });
    if (r.status === 401 || r.status === 403) {
      setLoginOpen(true);
      throw new Error('需要登录');
    }
    if (!r.ok) throw new Error((await r.text()) || `HTTP ${r.status}`);
    return r;
  }

  async function refresh() {
    try {
      const r = await fetch('/stats.json', { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setStats(await r.json());
    } catch {
      /* 设备重启/网络抖动时保留上一次数据 */
    }
  }

  async function refreshLists() {
    try {
      const r = await fetch('/lists.json', { cache: 'no-store' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      setLists(await r.json());
    } catch {
      /* 设备重启/网络抖动时保留旧值，下次打开标签页再取 */
    }
  }

  async function run(name, fn, okMsg) {
    setBusy(name);
    try {
      await fn();
      if (okMsg) say(okMsg);
    } catch (e) {
      if (e.message !== '需要登录') say(e.message || '操作失败', 'error');
    } finally {
      setBusy('');
      refresh();
    }
  }

  useEffect(() => {
    refresh();
    const id = setInterval(() => {
      if (!document.hidden) refresh();
    }, POLL_MS);
    return () => clearInterval(id);
  }, []);

  // 只在打开带列表编辑器的标签页时才取整表；取过一次就不再重复（保存后会刷新）。
  useEffect(() => {
    if ((tab === 'block' || tab === 'hosts') && !lists) refreshLists();
  }, [tab, lists]);

  // 弹窗打开时锁定页面滚动
  useEffect(() => {
    if (!loginOpen) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = prev;
    };
  }, [loginOpen]);

  const total = (stats?.blocked || 0) + (stats?.allowed || 0);
  const ratio = total ? Math.round((stats.blocked / total) * 100) : 0;
  const ctx = { stats, lists, refreshLists, api, run, busy, say };

  return (
    <div className="min-h-screen bg-white dark:bg-black text-slate-800 dark:text-slate-100">
      <div className="mx-auto max-w-4xl px-4 py-6 space-y-5">
        <Header stats={stats} auth={auth} onLogin={() => setLoginOpen(true)} onLogout={() => { sessionStorage.removeItem('s3auth'); setAuth(''); say('已退出登录'); }} />
        <TabBar tab={tab} setTab={setTab} />

        {stats?.defcreds ? (
          <div className="rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-black px-4 py-3 text-sm text-amber-800 dark:text-amber-300">
            <b>仍在使用默认密码</b>：<code>secrets.h</code> 里的 <code>WEB_PASS</code> / <code>OTA_PASS</code> 还是示例值，谁都能改配置或刷固件。
          </div>
        ) : null}

        {tab === 'overview' && <Overview {...ctx} ratio={ratio} total={total} />}
        {tab === 'clients' && <Clients {...ctx} />}
        {tab === 'rules' && <Rules {...ctx} />}
        {tab === 'block' && <BlockList {...ctx} />}
        {tab === 'hosts' && <Hosts {...ctx} />}
        {tab === 'system' && <System {...ctx} />}

        <footer className="pt-4 text-center text-xs text-slate-300 dark:text-slate-600 space-y-1">
          <div>S3 AdBlock · ESP32-S3 DNS 广告拦截</div>
          <a href="https://github.com/Gakusyun/esp32-s3-adblock" target="_blank" rel="noreferrer" className="hover:text-slate-400">
            github.com/Gakusyun/esp32-s3-adblock
          </a>
        </footer>
      </div>
      <Toast toast={toast} />
      {loginOpen && (
        <LoginModal
          onClose={() => setLoginOpen(false)}
          onDone={(t) => {
            setAuth(t);
            setLoginOpen(false);
            say('已登录');
          }}
        />
      )}
    </div>
  );
}

function Header({ stats, auth, onLogin, onLogout }) {
  const online = !!stats;
  return (
    <header className="flex items-center gap-3">
      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-sky-50 dark:bg-slate-900 text-sm font-semibold text-sky-600 dark:text-sky-400">S3</div>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <h1 className="truncate text-lg font-semibold text-slate-900 dark:text-slate-100">S3 AdBlock</h1>
          <span
            className={
              'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ' +
              (online
                ? 'bg-emerald-50 dark:bg-black text-emerald-700 dark:text-emerald-400 border border-emerald-200 dark:border-emerald-900'
                : 'bg-rose-50 dark:bg-black text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-900')
            }
          >
            <span className={'h-1.5 w-1.5 rounded-full ' + (online ? 'bg-emerald-500' : 'bg-rose-500')} />
            {online ? '在线' : '离线'}
          </span>
        </div>
        <div className="truncate font-mono text-xs text-slate-500 dark:text-slate-400">{stats?.ip || '连接中…'}</div>
      </div>
      <button type="button" className={SMALL_BTN} onClick={auth ? onLogout : onLogin}>
        {auth ? '退出' : '登录'}
      </button>
    </header>
  );
}

function TabBar({ tab, setTab }) {
  return (
    <nav className="flex flex-wrap gap-1.5">
      {TABS.map((t) => (
        <button
          key={t.id}
          type="button"
          onClick={() => setTab(t.id)}
          className={
            'shrink-0 px-2.5 py-1.5 rounded-lg text-[13px] sm:px-3 sm:text-sm transition-colors ' +            (tab === t.id
              ? 'bg-sky-600 text-white'
              : 'text-slate-500 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-900')
          }
        >
          {t.label}
        </button>
      ))}
    </nav>
  );
}

function Overview({ stats, api, run, busy, ratio, total }) {
  const [dur, setDur] = useState(300);
  if (!stats) return <Card title="状态">正在读取设备状态…</Card>;
  const on = stats.blocking !== false;
  const lookups = (stats.dnsHit || 0) + (stats.dnsMiss || 0);
  const cacheRate = lookups ? Math.round((stats.dnsHit / lookups) * 100) : null;
  return (
    <>
      <Card
        title="拦截状态"
        action={<SmallBtn onClick={() => run('refresh', async () => {}, '已刷新')}>刷新</SmallBtn>}
      >
        <div className="flex flex-wrap items-center gap-3">
          <span className={'h-2.5 w-2.5 shrink-0 rounded-full ' + (on ? 'bg-emerald-500' : 'bg-amber-500')} />
          <div className="min-w-0 flex-1">
            <div className={'font-medium ' + (on ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400')}>
              {on ? '拦截已开启' : stats.resumeIn > 0 ? `已暂停 · ${stats.resumeIn} 秒后恢复` : '已暂停'}
            </div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {on ? '全部查询经拦截表' : '查询直接转发上游'}
            </div>
          </div>
          {on ? (
            <div className="flex items-center gap-2">
              <select value={dur} onChange={(e) => setDur(+e.currentTarget.value)} className={INPUT + ' !w-auto'}>
                <option value={30}>30 秒</option>
                <option value={300}>5 分钟</option>
                <option value={1800}>30 分钟</option>
                <option value={0}>手动恢复</option>
              </select>
              <button
                type="button"
                className={BTN_OUTLINE}
                disabled={busy === 'pause'}
                onClick={() => run('pause', () => api(`/pause?s=${dur}`, { method: 'POST' }), '已暂停拦截')}
              >
                暂停
              </button>
            </div>
          ) : (
            <button
              type="button"
              className={BTN}
              disabled={busy === 'resume'}
              onClick={() => run('resume', () => api('/resume', { method: 'POST' }), '已恢复拦截')}
            >
              恢复拦截
            </button>
          )}
        </div>
        <div>
          <div className="h-1.5 w-full rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden">
            <div className="h-full rounded-full bg-rose-500 transition-all" style={{ width: `${ratio}%` }} />
          </div>
          <div className="mt-1.5 flex justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>拦截 {fmt(stats.blocked)}（{ratio}%）</span>
            <span>放行 {fmt(stats.allowed)}</span>
          </div>
        </div>
      </Card>

      <Card title="统计">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="已拦截" value={fmt(stats.blocked)} sub={total ? `共 ${fmt(total)} 次查询` : '暂无查询'} tone="text-rose-500 dark:text-rose-400" />
          <Stat label="已放行" value={fmt(stats.allowed)} sub="转发上游成功" tone="text-emerald-600 dark:text-emerald-400" />
          <Stat label="规则条数" value={fmt(stats.domains)} sub={`自定义 ${fmt(stats.customN ?? 0)} · Hosts ${fmt(stats.hostN ?? 0)}`} />
          <Stat label="缓存命中率" value={cacheRate !== null ? `${cacheRate}%` : '—'}
                sub={`${fmt(stats.dnsHit)} 命中 · ${fmt(stats.dnsMiss)} 未命中`} tone="text-sky-600 dark:text-sky-400" />
        </div>
      </Card>

      <Card title="设备">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="芯片温度" value={`${stats.temp} °C`} />
          <Stat label="可用内存" value={`${Math.round(stats.heap / 1024)} KB`} />
          <Stat label="WiFi 信号" value={`${stats.rssi} dBm`} />
          <Stat label="运行时长" value={stats.uptime} />
        </div>
      </Card>

      <Card
        title="规则源"
        action={<SmallBtn onClick={() => run('fetch', () => api('/fetchnow', { method: 'POST' }), '已开始拉取')} disabled={busy === 'fetch'}>立即更新</SmallBtn>}
      >
        <p className="break-all font-mono text-xs text-slate-500 dark:text-slate-400">{stats.upurl || '未设置'}</p>
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
          <span>每天 {String(stats.uphour).padStart(2, '0')}:00 自动更新（UTC+{stats.uptz}）</span>
          <span>上次：{stats.upstat || '从未'}</span>
        </div>
      </Card>
    </>
  );
}

function Clients({ stats, api, run, busy }) {
  const [q, setQ] = useState('');
  const rows = useMemo(() => {
    const list = [...(stats?.clients || [])];
    list.sort((a, b) => b.blocked + b.allowed - (a.blocked + a.allowed));
    const k = q.trim().toLowerCase();
    return k ? list.filter((c) => c.ip.includes(k) || c.mac.includes(k)) : list;
  }, [stats, q]);

  return (
    <Card
      title={`客户端 · ${rows.length}`}
      action={<input placeholder="搜索 IP / MAC" value={q} onInput={(e) => setQ(e.currentTarget.value)} className={INPUT + ' !w-40 !py-1 !text-xs'} />}
    >
      <div className="overflow-x-auto -mx-4 px-4">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-slate-500 dark:text-slate-400">
              <th className="py-1.5 text-left font-medium">IP</th>
              <th className="py-1.5 text-left font-medium hidden sm:table-cell">MAC</th>
              <th className="py-1.5 text-right font-medium">拦截</th>
              <th className="py-1.5 text-right font-medium">放行</th>
              <th className="py-1.5 text-right font-medium">操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={5} className="py-3 text-center text-slate-400 dark:text-slate-500">
                  暂无客户端
                </td>
              </tr>
            )}
            {rows.map((c) => (
              <tr key={c.ip} className="border-t border-slate-200 dark:border-slate-800">
                <td className="py-1.5 font-mono text-slate-700 dark:text-slate-300">
                  {c.ip}
                  {c.banned ? (
                    <span className="ml-1.5 rounded px-1 py-0.5 text-[10px] text-rose-600 dark:text-rose-400 border border-rose-200 dark:border-rose-900">封禁</span>
                  ) : null}
                </td>
                <td className="py-1.5 font-mono text-xs text-slate-500 dark:text-slate-400 hidden sm:table-cell">{c.mac}</td>
                <td className="py-1.5 text-right tabular-nums text-rose-500 dark:text-rose-400">{fmt(c.blocked)}</td>
                <td className="py-1.5 text-right tabular-nums text-emerald-600 dark:text-emerald-400">{fmt(c.allowed)}</td>
                <td className="py-1.5 text-right">
                  <button
                    type="button"
                    className={SMALL_BTN}
                    disabled={busy === 'ban' + c.ip}
                    onClick={() =>
                      run(
                        'ban' + c.ip,
                        () => api(`/ban?ip=${encodeURIComponent(c.ip)}`, { method: 'POST' }),
                        c.banned ? '已解封' : '已封禁',
                      )
                    }
                  >
                    {c.banned ? '解封' : '封禁'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Rules({ stats, api, run, busy }) {
  const [url, setUrl] = useState('');
  const [hour, setHour] = useState(3);
  const [tz, setTz] = useState(8);
  const [file, setFile] = useState(null);
  const [msg, setMsg] = useState('');
  const seeded = useRef(false);

  useEffect(() => {
    if (!seeded.current && stats) {
      seeded.current = true;
      setUrl(stats.upurl || '');
      setHour(stats.uphour ?? 3);
      setTz(stats.uptz ?? 8);
    }
  }, [stats]);

  async function upload(e) {
    e.preventDefault();
    if (!file) return;
    setMsg(`上传 ${(file.size / 1024).toFixed(0)} KB…`);
    const fd = new FormData();
    fd.append('f', file);
    await run('upload', async () => {
      await api('/upload', { method: 'POST', body: fd });
      setMsg('已更新');
    });
  }

  return (
    <>
      <Card title="远程规则源">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          填规则文本地址（hosts / 纯域名 / AdGuard 基础语法都行，设备自己解析并算哈希），也可以填预编译的 <code>.bin</code>。
        </p>
        <Field label="URL">
          <input
            className={INPUT + ' font-mono text-xs'}
            value={url}
            onInput={(e) => setUrl(e.currentTarget.value)}
            placeholder="https://cdn.jsdelivr.net/gh/.../AWAvenue-Ads-Rule-hosts.txt"
          />
        </Field>
        <div className="flex flex-wrap items-end gap-2">
          <Field label="每天何时更新（0-23 时）" className="w-40">
            <input type="number" min="0" max="23" className={INPUT} value={hour} onInput={(e) => setHour(Math.max(0, Math.min(23, +e.currentTarget.value || 0)))} />
          </Field>
          <Field label="时区（UTC+）" className="w-32">
            <input type="number" min="-12" max="14" className={INPUT} value={tz} onInput={(e) => setTz(Math.max(-12, Math.min(14, +e.currentTarget.value || 0)))} />
          </Field>
          <button
            type="button"
            className={BTN}
            disabled={busy === 'save'}
            onClick={() => run('save', () => api(`/setupdate?u=${encodeURIComponent(url.trim())}&h=${hour}&tz=${tz}`, { method: 'POST' }), '已保存')}
          >
            保存
          </button>
          <button
            type="button"
            className={BTN_OUTLINE}
            disabled={busy === 'fetch'}
            onClick={() => run('fetch', () => api('/fetchnow', { method: 'POST' }), '已开始拉取')}
          >
            立即拉取
          </button>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">上次：{stats?.upstat || '从未'}</p>
        {stats?.upbusy ? (
          <p className="text-xs text-sky-600 dark:text-sky-400">正在后台拉取，DNS 不受影响；结果会显示在「上次」。</p>
        ) : null}
        {stats?.fetchInsecure ? (
          <p className="text-xs text-amber-600 dark:text-amber-400">
            警告：拉取时系统时间还没同步，TLS 证书未校验（中间人可篡改规则表）。检查 NTP / 时间设置。
          </p>
        ) : null}
      </Card>

      <Card title="上传规则表">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          用 <code>tools/build_blocklist.py</code> 生成的 <code>blocklist.bin</code>，直接上传替换，不用插 USB。
        </p>
        <form className="flex flex-wrap items-center gap-2" onSubmit={upload}>
          <FilePicker file={file} onPick={setFile} accept=".bin" />
          <button className={BTN} disabled={!file || busy === 'upload'}>
            上传
          </button>
          {msg ? <span className="text-xs text-slate-500 dark:text-slate-400">{msg}</span> : null}
        </form>
      </Card>

      <Card title="当前生效">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Stat label="规则条数" value={fmt(stats?.domains)} />
          <Stat label="自定义屏蔽" value={fmt(stats?.customN ?? 0)} />
          <Stat label="Hosts 映射" value={fmt(stats?.hostN ?? 0)} />
          <Stat label="更新状态" value={<span className="text-sm font-normal">{stats?.upstat || '—'}</span>} />
        </div>
      </Card>
    </>
  );
}

function ListEditor({ title, hint, placeholder, value, onChange, onSave, busy, count, footer }) {
  return (
    <Card title={title} action={<span className="text-xs text-slate-500 dark:text-slate-400">{count} 条</span>}>
      <p className="text-xs text-slate-500 dark:text-slate-400">{hint}</p>
      <textarea
        className={INPUT + ' min-h-[240px] font-mono text-xs leading-relaxed'}
        spellCheck={false}
        placeholder={placeholder}
        value={value}
        onInput={(e) => onChange(e.currentTarget.value)}
      />
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" className={BTN} disabled={busy} onClick={onSave}>
          保存
        </button>
        {footer}
      </div>
    </Card>
  );
}

const parseLines = (text) =>
  text
    .split('\n')
    .map((l) => l.split('#')[0].trim())
    .filter(Boolean);

// Mirror of normDomain() / setCustomFromText() in src/main.cpp. The device counts
// distinct normalized domains across every whitespace-separated token, so a pasted
// hosts line must not count its "0.0.0.0", and repeats must not count twice.
const normDomain = (token) => {
  let s = token.trim().toLowerCase();
  if (s.startsWith('http://')) s = s.slice(7);
  if (s.startsWith('https://')) s = s.slice(8);
  const slash = s.indexOf('/');
  if (slash >= 0) s = s.slice(0, slash);
  s = s.replace(/^[*.]+/, '').replace(/\.+$/, '');
  if (s.startsWith('www.') && s.length > 4) s = s.slice(4);
  return s.length >= 3 && s.length <= 253 && s.includes('.') && /^[a-z0-9._-]+$/.test(s) ? s : '';
};

const countCustomDomains = (text) => {
  const found = new Set();
  for (const line of text.split('\n')) {
    // 与固件一致：先按 # 截断，再把 tab 当空格，只按空格切 token（不按 \r 等）。
    for (const token of line.split('#')[0].replace(/\t/g, ' ').split(' ')) {
      if (!token || IPV4_RE.test(token) || token === '::' || token === '::1') continue;
      const d = normDomain(token);
      if (d) found.add(d);
    }
  }
  return found.size;
};

function BlockList({ stats, lists, refreshLists, api, run, busy }) {
  const [text, setText] = useState('');
  const seeded = useRef(false);
  useEffect(() => {
    if (!seeded.current && lists?.custom) {
      seeded.current = true;
      setText(lists.custom.join('\n'));
    }
  }, [lists]);

  const count = countCustomDomains(text);

  return (
    <ListEditor
      title="自定义屏蔽"
      hint="一行一个域名（也可以直接粘 hosts 格式，只取域名）。保存后立即生效，子域名一并拦截。删掉某行再保存就是取消屏蔽。"
      placeholder={'ads.example.com\ntracker.example.net\n0.0.0.0 stats.example.org'}
      value={text}
      onChange={setText}
      count={count}
      busy={busy === 'setblock'}
      onSave={() =>
        // 保存后重新取整表：切走再切回来会按设备里真正存下的内容重新初始化。
        run('setblock', () => api('/setblock', { method: 'POST', body: new URLSearchParams({ d: text }) }), '自定义屏蔽已保存').then(refreshLists)
      }
      footer={<span className="text-xs text-slate-500 dark:text-slate-400">最多 {fmt(stats?.customCap ?? 512)} 条，超出会拒绝保存</span>}
    />
  );
}

function Hosts({ stats, lists, refreshLists, api, run, busy }) {
  const [text, setText] = useState('');
  const seeded = useRef(false);
  useEffect(() => {
    if (!seeded.current && lists?.hosts) {
      seeded.current = true;
      setText(lists.hosts.map((h) => `${h.h} ${h.ip}`).join('\n'));
    }
  }, [lists]);

  const lines = parseLines(text);
  const bad = lines.filter((l) => {
    const p = l.split(/\s+/);
    return p.length < 2 || !IPV4_RE.test(p[1]);
  });

  return (
    <>
      <ListEditor
        title="Hosts 映射"
        hint={`一行一条「域名 空格 目标IP」，设备直接按你写的 IP 应答（相当于内置 /etc/hosts）。只做 IPv4；AAAA 查询返回空，客户端会走 IPv4。最多 ${fmt(stats?.hostCap ?? 128)} 条。`}
        placeholder={'nas.home 192.168.4.100\nrouter.lan 192.168.4.250\nprinter.lan 192.168.4.120'}
        value={text}
        onChange={setText}
        count={lines.length - bad.length}
        busy={busy === 'sethosts'}
        onSave={() =>
          run('sethosts', () => api('/sethosts', { method: 'POST', body: new URLSearchParams({ d: text }) }), 'Hosts 映射已保存').then(refreshLists)
        }
        footer={<span className="text-xs text-slate-500 dark:text-slate-400"># 之后为注释</span>}
      />
      {bad.length ? (
        <div className="rounded-lg border border-rose-300 dark:border-rose-800 bg-rose-50 dark:bg-black px-4 py-3 text-sm text-rose-700 dark:text-rose-300">
          {bad.length} 行格式不对（需要「域名 + IPv4」）：<span className="font-mono text-xs">{bad.slice(0, 3).join(' / ')}</span>
        </div>
      ) : null}
    </>
  );
}

function Toggle({ on, onChange, disabled, onLabel = '已开启', offLabel = '已关闭' }) {  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={() => onChange(!on)}
      className={
        'inline-flex items-center gap-2 rounded-full border px-2 py-1 text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed ' +
        (on
          ? 'border-emerald-300 dark:border-emerald-800 bg-emerald-50 dark:bg-black text-emerald-700 dark:text-emerald-400'
          : 'border-slate-300 dark:border-slate-600 text-slate-500 dark:text-slate-400')
      }
    >
      <span className={'h-2 w-2 rounded-full ' + (on ? 'bg-emerald-500' : 'bg-slate-400 dark:bg-slate-600')} />
      {on ? onLabel : offLabel}
    </button>
  );
}

/* DoH 是“配上”了还是“真在用”：off=未启用，ntp=等时钟，ok=TLS 会话在服务，
   down=端点失败正在回退明文 UDP，idle=已配置但还没建立会话 */
const DOH_STATE = {
  off: '',
  ntp: '等待 NTP',
  ok: '已连接',
  down: '端点异常 · 回退 UDP',
  idle: '未建立会话',
};

function System({ stats, api, run, busy }) {
  const [file, setFile] = useState(null);
  const [msg, setMsg] = useState('');
  const led = stats?.led !== false;   // undefined (旧固件) 当作开着
  return (
    <>
      <Card
        title="指示灯"
        action={
          <Toggle
            on={led}
            disabled={busy === 'led'}
            onChange={(next) =>
              run('led', () => api(`/setled?s=${next ? 1 : 0}`, { method: 'POST' }), next ? '指示灯已开启' : '指示灯已关闭')
            }
          />
        }
      >
        <div className="space-y-0.5 text-xs text-slate-500 dark:text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />绿色：正在拦截
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-full bg-amber-500" />琥珀色：已暂停
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 shrink-0 rounded-full bg-sky-500" />蓝色：启动中 / 未连上 Wi-Fi
          </div>
        </div>
      </Card>

      <Card title="固件 OTA">
        <p className="text-xs text-slate-500 dark:text-slate-400">
          上传 <code>.pio/build/s3/firmware.bin</code>，校验后写入备用分区并重启。
        </p>
        <form
          className="flex flex-wrap items-center gap-2"
          onSubmit={async (e) => {
            e.preventDefault();
            if (!file) return;
            setMsg(`写入中 ${(file.size / 1048576).toFixed(2)} MB…`);
            const fd = new FormData();
            fd.append('f', file);
            try {
              await api('/update', { method: 'POST', body: fd });
              setMsg('已写入，设备正在重启');
            } catch (err) {
              setMsg(err.message === '需要登录' ? '需要登录' : `失败：${err.message || '未知错误'}`);
            }
          }}
        >
          <FilePicker file={file} onPick={setFile} accept=".bin" label="选择固件" />
          <button className={BTN} disabled={!file}>
            上传并重启
          </button>
          {msg ? <span className="text-xs text-slate-500 dark:text-slate-400">{msg}</span> : null}
        </form>
      </Card>

      <Card title="设备信息">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 text-sm">
          {[
            ['IP', stats?.ip],
            ['DNS 上游', stats?.up ? `${stats.up}${DOH_STATE[stats?.dohState] ? ` · ${DOH_STATE[stats.dohState]}` : ''}` : undefined],
            // 0 是合法读数（信号 0 dBm、0 °C、堆耗尽），不能用真值判断把它变成「—」。
            ['WiFi 信号', stats?.rssi != null ? `${stats.rssi} dBm` : undefined],
            ['温度', stats?.temp != null ? `${stats.temp} °C` : undefined],
            ['可用内存', stats?.heap != null ? `${Math.round(stats.heap / 1024)} KB` : undefined],
            ['运行时长', stats?.uptime],
            ['规则条数', fmt(stats?.domains)],
          ].map(([k, v]) => (
            <div key={k}>
              <div className="text-xs text-slate-500 dark:text-slate-400">{k}</div>
              <div className="font-mono text-slate-700 dark:text-slate-300">{v ?? '—'}</div>
            </div>
          ))}
        </div>
      </Card>

      {stats?.dohState === 'down' ? (
        <div className="rounded-lg border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-black px-4 py-3 text-sm text-amber-800 dark:text-amber-300">
          DoH 端点连不上，现在实际走的是<b>明文 UDP</b>（已回退 {fmt(stats.dohFallback)} 次）。
          检查网络/系统时间；想让它宁可失败也不降级，把 <code>DOH_UDP_FALLBACK</code> 设为 0。
        </div>
      ) : null}
      {stats?.dohState === 'ntp' ? (
        <div className="rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-black px-4 py-3 text-sm text-slate-600 dark:text-slate-400">
          DoH 已配置，但系统时间还没同步（证书有效期无法校验），暂时仍走明文 UDP。
        </div>
      ) : null}
    </>
  );
}

render(<App />, document.getElementById('app'));

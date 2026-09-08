'use strict';
/*
 * ClamSentinel · 哨兵杀毒
 * 原创后端服务（零第三方依赖，仅使用 Node 标准库）。
 * 通过 ClamAV 官方 clamd 的 TCP 明文协议（PING / VERSION / CONTSCAN）驱动扫描。
 * 与任何第三方 ClamAV Web 项目均无代码关联。
 *
 * v3.1.2 修复：clamd 协议没有 RECURSIVESCAN 命令（旧版错把 clamscan 命令行参数当 clamd 指令），
 *           且 CONTSCAN 对目录路径只扫描直接子项、不递归子目录。改为服务端递归遍历 FS
 *           拿到所有文件路径，再逐文件对 clamd 发 CONTSCAN（性能足够家庭 NAS）。
 */

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { promisify } = require('util');

const scryptAsync = promisify(crypto.scrypt);
const randomBytes = promisify(crypto.randomBytes);

/* ---------------- 环境与常量 ---------------- */

const PORT = Number(process.env.PORT || 8080);
const APP_ROOT = process.env.APP_ROOT || '/vol1/@appcenter/clamsentinel';
/* ---- 关闭服务的允许列表（仅 root 且必须是 admin 才能 POST） ---- */
let serviceStopped = false; // 关闭后立刻标记，让 /api/state 下次返回 { stopped: true }
const DATA_DIR = process.env.DATA_DIR || '/data';
const QUAR_DIR = process.env.QUAR_DIR || '/quarantine';
const CLAMD_HOST = process.env.CLAMD_HOST || '127.0.0.1';
const CLAMD_PORT = Number(process.env.CLAMD_PORT || 3310);
const PUBLIC_DIR = path.join(__dirname, 'public');
const DB_MOUNT = process.env.DB_MOUNT || '/db';

/* 读取 manifest 里的 version 字段（一次缓存，/api/state 返回真实版本） */
let _cachedVersion = null;
function readVersion() {
  if (_cachedVersion) return _cachedVersion;
  try {
    /* manifest 路径：fnOS 解压到 /vol1/@appcenter/clamsentinel/，server.js 在 app/web/ 下
       web/ 上一级就到 clamsentinel/，所以只需要一个 ../ */
    const mPath = path.join(__dirname, '..', 'manifest');
    const mTxt = fs.readFileSync(mPath, 'utf8');
    const m = mTxt.match(/^\s*version\s*=\s*(\S+)/m);
    if (m) { _cachedVersion = m[1]; return _cachedVersion; }
  } catch (e) { /* fallthrough */ }
  _cachedVersion = 'unknown';
  return _cachedVersion;
}
/* ---- 方案 B：web 永远驻留；clamd 在 idle 后停掉，由 server.js 按需 lazy 启动 ---- */
const CLAMD_BIN = process.env.CLAMD_BIN || '/usr/sbin/clamd';
const CMD_MAIN = process.env.CMD_MAIN || '/var/apps/clamsentinel/cmd/main';
const CLAMD_PID_FILE = process.env.CLAMD_PID_FILE || '/vol1/@appdata/clamsentinel/run/clamd.pid';
const CLAMD_SOCK_FILE = process.env.CLAMD_SOCK_FILE || '/vol1/@appdata/clamsentinel/run/clamd.sock';

const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const JOBS_DIR = path.join(DATA_DIR, 'jobs');
const QUAR_META_FILE = path.join(DATA_DIR, 'quarantine-meta.json');

const SESSION_MAX_AGE = 24 * 3600 * 1000;
const LOGIN_WINDOW = 10 * 60 * 1000;
const LOGIN_MAX_FAILS = 5;
const SCRYPT_N = 16384;
const MAX_BODY = 2 * 1024 * 1024;
const STORE_THREAT_CAP = 5000;

/* ---------------- 统一日志（app.log）：hook 全部 console.*，落盘 + 容量滚动 ---------------- */
const LOG_DIR = process.env.LOG_DIR || path.join(DATA_DIR, '..', 'log');
const LOG_FILE = path.join(LOG_DIR, 'app.log');
const LOG_MAX_BYTES = 4 * 1024 * 1024;
function initAppLog() {
  try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch (_) {}
  const real = { log: console.log, warn: console.warn, error: console.error };
  const fmt = (a) => a.map((x) =>
    typeof x === 'string' ? x
    : (x instanceof Error ? (x.stack || (x.name + ': ' + x.message)) : JSON.stringify(x)));
  const write = (line) => {
    try {
      fs.appendFileSync(LOG_FILE, line);
      try {
        if (fs.statSync(LOG_FILE).size > LOG_MAX_BYTES) {
          try { fs.renameSync(LOG_FILE, LOG_FILE + '.1'); } catch (_) {}
          fs.appendFileSync(LOG_FILE, '==== 滚动：旧日志已存 app.log.1 ' + new Date().toISOString() + ' ====\n');
        }
      } catch (_) {}
    } catch (_) {}
  };
  const emit = (sink, tag, a) => { try { sink.apply(console, a); } catch (_) {} write('[' + tag + ' ' + new Date().toISOString() + '] ' + fmt(a).join(' ') + '\n'); };
  console.log = (...a) => emit(real.log, 'log', a);
  console.warn = (...a) => emit(real.warn, 'warn', a);
  console.error = (...a) => emit(real.error, 'error', a);
  write('==== ClamSentinel 启动 ' + new Date().toISOString() + ' ====\n');
}
initAppLog();
function readLogFile(file, capBytes) {
  try {
    let b = fs.readFileSync(file);
    if (capBytes && b.length > capBytes) b = b.slice(-capBytes);
    return b;
  } catch (_) { return null; }
}
/* ---------------- 最小 ZIP（stored，免依赖） ---------------- */
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xFFFFFFFF; for (let i = 0; i < buf.length; i++) c = (c >>> 8) ^ CRC_TABLE[(c ^ buf[i]) & 0xFF]; return (c ^ 0xFFFFFFFF) >>> 0; }
function makeZip(files) {
  const chunks = [], cd = []; let offset = 0;
  const now = new Date();
  const dostime = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1);
  const dosdate = (((now.getFullYear() - 1980) & 0x7f) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
  for (const f of files) {
    const nb = Buffer.from(f.name, 'utf8');
    const data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const crc = crc32(data);
    const ldh = Buffer.alloc(30);
    ldh.writeUInt32LE(0x04034b50, 0); ldh.writeUInt16LE(20, 4); ldh.writeUInt16LE(0x0800, 6); ldh.writeUInt16LE(0, 8);
    ldh.writeUInt16LE(dostime, 10); ldh.writeUInt16LE(dosdate, 12);
    ldh.writeUInt32LE(crc, 14); ldh.writeUInt32LE(data.length, 18); ldh.writeUInt32LE(data.length, 22);
    ldh.writeUInt16LE(nb.length, 26); ldh.writeUInt16LE(0, 28);
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0); cdh.writeUInt16LE(20, 4); cdh.writeUInt16LE(20, 6);
    cdh.writeUInt16LE(0x0800, 8); cdh.writeUInt16LE(0, 10); cdh.writeUInt16LE(dostime, 12); cdh.writeUInt16LE(dosdate, 14);
    cdh.writeUInt32LE(crc, 16); cdh.writeUInt32LE(data.length, 20); cdh.writeUInt32LE(data.length, 24);
    cdh.writeUInt16LE(nb.length, 28); cdh.writeUInt16LE(0, 30); cdh.writeUInt16LE(0, 32);
    cdh.writeUInt16LE(0, 34); cdh.writeUInt16LE(0, 36); cdh.writeUInt32LE(0, 38);
    cdh.writeUInt32LE(offset, 42);
    chunks.push(ldh, nb, data); cd.push(Buffer.concat([cdh, nb]));
    offset += ldh.length + nb.length + data.length;
  }
  const cdbody = Buffer.concat(cd);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(0, 4); eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(files.length, 8); eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdbody.length, 12); eocd.writeUInt32LE(offset, 16); eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...chunks, cdbody, eocd]);
}

/* ---------------- 性能档位（性能调节器） ----------------
 * 并发由 server 端同时打开的 CONTSCAN 连接数（内存压力阀）决定。
 * clamd 的 MaxThreads 已在 cmd/main 固定为兜底值（线程惰性创建，空闲零额外开销），
 * 因此切换档位只需改 settings.perfMode，下一次扫描立即生效，无需重启 clamd。 */
const PERF_MODES = {
  eco:      { label: '节能模式', cores: 1, concurrent: 1 },
  balanced: { label: '均衡模式', cores: 2, concurrent: 2 },
};
const PERF_DEFAULT = 'balanced';
function currentPerf() {
  const m = settings && PERF_MODES[settings.perfMode] ? settings.perfMode : PERF_DEFAULT;
  return { mode: m, ...PERF_MODES[m] };
}

/* ---------------- 存储 ---------------- */

let settings = null;
let usersCache = null;

async function ensureDirs() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  await fsp.mkdir(JOBS_DIR, { recursive: true });
  await fsp.mkdir(QUAR_DIR, { recursive: true });
}

async function readJson(file, fallback) {
  try { return JSON.parse(await fsp.readFile(file, 'utf8')); } catch (e) { return fallback; }
}

async function writeJsonAtomic(file, obj) {
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(obj), 'utf8');
  await fsp.rename(tmp, file);
}

async function loadSettings() {
  settings = await readJson(SETTINGS_FILE, null);
  if (!settings) {
    settings = {
      secret: (await randomBytes(32)).toString('hex'),
      createdAt: new Date().toISOString(),
    };
    await writeJsonAtomic(SETTINGS_FILE, settings);
  }
  if (typeof settings.dbAutoUpdate !== 'boolean') settings.dbAutoUpdate = true;
  if (!Number.isInteger(settings.dbAutoHour)) settings.dbAutoHour = DB_DEFAULT_AUTO_HOUR;
  if (!PERF_MODES[settings.perfMode]) settings.perfMode = PERF_DEFAULT;
}

/* 自动更新调度：每 30 秒检查一次，到点（精确到分钟）就触发 */
function startDbScheduler() {
  if (dbScheduler) return;
  dbScheduler = setInterval(() => {
    const now = new Date();
    if (settings.dbAutoUpdate && now.getHours() === settings.dbAutoHour && now.getMinutes() === 0) {
      runDbUpdate().then((r) => {
        settings.dbLastUpdate = new Date().toISOString();
        settings.dbLastResult = r.error ? { ok: false, msg: r.error } : { ok: true };
        writeJsonAtomic(SETTINGS_FILE, settings).catch(() => {});
      }).catch(() => {});
    }
  }, 30 * 1000);
}
function stopDbScheduler() {
  if (dbScheduler) { clearInterval(dbScheduler); dbScheduler = null; }
}

/* ===== 方案 B 残存辅助：仅保留 ensureClamd 用于扫描前保险 ===== */
let lastActivityAt = Date.now();  // 最近一次用户活动（任何 HTTP 请求）
let clamdOnline = false;          // 缓存的 clamd 实时状态（每次 ping 更新）
function touchActivity() { lastActivityAt = Date.now(); }

/* 检测 clamd 是否在跑（PID 文件 + 端口）。返回 bool */
function isClamdRunning() {
  try {
    const pid = Number(fs.readFileSync(CLAMD_PID_FILE, 'utf8') || 0);
    if (!pid) return false;
    try { process.kill(pid, 0); return true; } catch (_) { return false; }
  } catch (_) { return false; }
}

/* 启动 clamd（spawn cmd/main clamd-on，poll 端口直到就绪，最多 8 秒） */
async function ensureClamd() {
  if (isClamdRunning()) {
    clamdOnline = true;
    return true;
  }
  console.log('[clamsentinel] clamd 离线，正在拉起…');
  clamdOnline = false;
  try {
    const { spawn } = require('child_process');
    spawn('bash', ['-c', `nohup ${CMD_MAIN} clamd-on >/tmp/cs_clamd_on.log 2>&1 &`], { detached: true, stdio: 'ignore' }).unref();
  } catch (e) { /* 容忍 */ }
  // 等待 clamd listen TCP，最多 10 秒
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 400));
    if (isClamdRunning()) { clamdOnline = true; return true; }
  }
  console.error('[clamsentinel] clamd 启动超时（10s），可能病毒库缺失或 LD_LIBRARY_PATH 错');
  return false;
}

/* 方案 B：sentinel 接管所有 idle/睡眠调度。web 自己不再做任何 clamd 关停逻辑。
 * 仅保留 /api/service/shutdown（紧急立即停用）作为用户级强制入口。
 *
 * ensureClamd() 仍然保留作为最后一道防线：sentinel 一定先启动 clamd 再转发，
 * 但万一 sentinel 与 web 之间出现竞态/状态不一致，web 自己能再拉一次。 */

/* 用户的交互活动：所有"重型"操作都先 ensureClamd（场景：扫描、更新病毒库、查看 dashboard）*/

async function loadUsers() {
  if (!usersCache) usersCache = (await readJson(USERS_FILE, { users: {} })).users || {};
  return usersCache;
}
async function saveUsers(users) {
  usersCache = users;
  await writeJsonAtomic(USERS_FILE, { users });
}

async function scryptHash(value) {
  const salt = (await randomBytes(12)).toString('hex');
  const hash = await scryptAsync(String(value), salt, 32, { N: SCRYPT_N });
  return `s1:${salt}:${hash.toString('hex')}`;
}

async function scryptVerify(value, record) {
  const parts = String(record || '').split(':');
  if (parts.length !== 3 || parts[0] !== 's1') return false;
  const hash = await scryptAsync(String(value), parts[1], 32, { N: SCRYPT_N });
  const a = Buffer.from(hash.toString('hex'), 'hex');
  const b = Buffer.from(parts[2], 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const hashPassword = scryptHash;
const verifyPassword = scryptVerify;

/* ---------------- 会话 ---------------- */

function signSession(uid, exp) {
  const payload = `${uid}.${exp}`;
  const mac = crypto.createHmac('sha256', settings.secret).update(payload).digest('base64url');
  return `${payload}.${mac}`;
}

function verifySession(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const [uid, exp, mac] = parts;
    const expected = crypto.createHmac('sha256', settings.secret).update(`${uid}.${exp}`).digest('base64url');
    const a = Buffer.from(mac, 'base64url');
    const b = Buffer.from(expected, 'base64url');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    if (Number(exp) < Date.now()) return null;
    return uid;
  } catch (e) { return null; }
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie || '';
  for (const pair of raw.split(';')) {
    const idx = pair.indexOf('=');
    if (idx > 0) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  }
  return out;
}
const sessionCookie = (t) => `csi=${encodeURIComponent(t)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(SESSION_MAX_AGE / 1000)}`;
const clearCookie = () => 'csi=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0';

const loginFails = new Map();
function loginBlocked(ip) {
  const rec = loginFails.get(ip);
  if (!rec) return false;
  if (Date.now() - rec.at > LOGIN_WINDOW) { loginFails.delete(ip); return false; }
  return rec.count >= LOGIN_MAX_FAILS;
}
function loginFail(ip) {
  const rec = loginFails.get(ip) || { count: 0, at: Date.now() };
  if (Date.now() - rec.at > LOGIN_WINDOW) { rec.count = 0; rec.at = Date.now(); }
  rec.count += 1;
  loginFails.set(ip, rec);
}

/* ---------------- 扫描根（多路径） ---------------- */

/* 扫描根目录是数据共享（@appshare）下的 scan 子目录。
   运行时由 cmd/main 从 fnOS 的 data-share 创建在 /var/apps/clamsentinel/shares/clamsentinel/scan，
   实际可能软链到 /vol1/@appshare/clamsentinel/scan。 */
const SCAN_SHARE_DEFAULT = path.resolve(process.env.SCAN_SHARE || '/var/apps/clamsentinel/shares/clamsentinel/scan');

/* 预定义的根集合（实际暴露给 UI 的会动态探测） */
const ROOT_PRESETS = [
  { id: 'scan', label: '扫描目录（推荐）',         path: () => SCAN_SHARE_DEFAULT },
  { id: 'vol1', label: '整个 /vol1',               path: () => '/vol1' },
  { id: 'vol2', label: '整个 /vol2',               path: () => '/vol2' },
  { id: 'user', label: '我的文件（所有用户家目录）', path: () => '/vol1/1000' },
  { id: 'team', label: '团队空间',                 path: () => '/vol1/@team' },
  { id: 'mnt',  label: '外接存储（/mnt 根）',        path: () => '/mnt' },
];

const ROOT_CACHE = { roots: null, at: 0 };
async function listRoots() {
  if (ROOT_CACHE.roots && Date.now() - ROOT_CACHE.at < 10000) return ROOT_CACHE.roots;
  const out = [];
  for (const r of ROOT_PRESETS) {
    const p = r.path();
    if (await pathAccessible(p)) {
      out.push({ id: r.id, label: r.label, path: p, realPath: await realPathSafe(p) });
    }
  }
  // 自动发现额外卷：/volN
  for (const v of ['/vol2', '/vol3']) {
    if (await pathAccessible(v) && !out.find(x => x.path === v)) {
      out.push({ id: 'vol' + v.slice(-1), label: '整个 ' + v, path: v, realPath: await realPathSafe(v) });
    }
  }
  // /mnt 子目录（外接存储）
  try {
    for (const name of await fsp.readdir('/mnt')) {
      const p = '/mnt/' + name;
      if (!out.find(x => x.path === p) && await pathAccessible(p)) {
        const st = await fsp.stat(p).catch(() => null);
        if (st && st.isDirectory()) {
          out.push({ id: 'mnt-' + name, label: '外接存储 · ' + name, path: p, realPath: await realPathSafe(p) });
        }
      }
    }
  } catch (e) {}
  ROOT_CACHE.roots = out;
  ROOT_CACHE.at = Date.now();
  return out;
}

async function pathAccessible(p) {
  try { await fsp.access(p, fs.constants.R_OK | fs.constants.X_OK); return true; } catch (e) { return false; }
}

async function realPathSafe(p) {
  try { return await fsp.realpath(p); } catch (e) { return p; }
}

async function resolveRoot(rootId) {
  const roots = await listRoots();
  if (!rootId || rootId === 'scan') {
    const scan = roots.find(r => r.id === 'scan') || { id: 'scan', label: '扫描目录', path: SCAN_SHARE_DEFAULT, realPath: await realPathSafe(SCAN_SHARE_DEFAULT) };
    return scan;
  }
  const r = roots.find(x => x.id === rootId);
  if (!r) return null;
  return r;
}

/* 将 API 输入的相对路径拼接成根下的绝对路径，并做越界检查（不能逃出根目录） */
async function relToAbs(rootReal, rel) {
  if (rel && rel.startsWith('/')) return null; // 不允许绝对路径
  const abs = path.resolve(rootReal, String(rel || '').replace(/^\/+/, ''));
  if (abs !== rootReal && !abs.startsWith(rootReal + path.sep)) return null;
  return abs;
}

function isUnderRoot(abs, rootReal) {
  if (abs === rootReal) return true;
  return abs.startsWith(rootReal + path.sep);
}

/* ---------------- 系统监控（CPU / 内存） ----------------
 * /proc/stat 与 /proc/meminfo 两次采样相减即得瞬时 CPU%；
 * CPU 核心数与内存总量缓存不变。 */
let sysPrev = null; // { total, idle }
let sysCoresCached = 0;

async function readProcStat() {
  try {
    const txt = await fsp.readFile('/proc/stat', 'utf8');
    const m = txt.match(/^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/m);
    if (!m) return null;
    const u = (i) => Number(m[i]);
    return {
      total: u(1) + u(2) + u(3) + u(4) + u(5) + u(6) + u(7),
      idle: u(4) + u(5),
    };
  } catch (e) { return null; }
}

async function readProcMem() {
  try {
    const txt = await fsp.readFile('/proc/meminfo', 'utf8');
    const get = (k) => {
      const m = txt.match(new RegExp('^' + k + ':\\s+(\\d+)', 'm'));
      return m ? Number(m[1]) : 0;
    };
    const total = get('MemTotal');
    const available = get('MemAvailable') || (get('MemFree') + get('Buffers') + get('Cached'));
    return { total, available, used: total - available, free: get('MemFree'), buffers: get('Buffers'), cached: get('Cached') };
  } catch (e) { return { total: 0, available: 0, used: 0 }; }
}

async function readCpuCores() {
  if (sysCoresCached > 0) return sysCoresCached;
  try {
    const txt = await fsp.readFile('/proc/cpuinfo', 'utf8');
    const n = (txt.match(/^processor\s+:/gm) || []).length;
    sysCoresCached = n > 0 ? n : 1;
  } catch (e) { sysCoresCached = 1; }
  return sysCoresCached;
}

async function readLoadAvg() {
  try {
    const txt = await fsp.readFile('/proc/loadavg', 'utf8');
    const parts = txt.trim().split(/\s+/);
    return parts.slice(0, 3).map(Number);
  } catch (e) { return [0, 0, 0]; }
}

async function readUptime() {
  try {
    const txt = await fsp.readFile('/proc/uptime', 'utf8');
    return Math.floor(Number(txt.trim().split(/\s+/)[0]) || 0);
  } catch (e) { return 0; }
}

/* 病毒库更新（命令：freshclam --config-file=$FRESHCONF）
 * 全程在子进程里跑（前台等），完成后由 caller 决定 SIGHUP clamd 让其重新加载病毒库。
 * 优先使用 cmd/main 注入的 FRESHCLAM_BIN（指向 bundled runtime）；找不到时再回退到 PATH。 */
const FRESHCLAM_BIN = process.env.FRESHCLAM_BIN
  || (() => {
    const PATH = (process.env.PATH || '').split(':');
    for (const d of PATH) {
      try { if (require('fs').statSync(d + '/freshclam').isFile()) return d + '/freshclam'; }
      catch (_) { /* 继续下一个 */ }
    }
    return '/usr/bin/freshclam';
  })();
const FRESHCLAM_CONF = process.env.FRESHCLAM_CONF || '/etc/clamav/freshclam.conf';
async function runDbUpdate() {
  if (updateLock) return { error: '已有更新在进行中' };
  updateLock = { startedAt: Date.now() };
  const { spawn } = require('child_process');
  // 把宿主已有的 LD_LIBRARY_PATH 显式传给子进程（runtime .so 路径）
  const env = Object.assign({}, process.env, { LD_LIBRARY_PATH: process.env.LD_LIBRARY_PATH || '' });
  try {
    const result = await new Promise((resolve) => {
      const cp = spawn(FRESHCLAM_BIN, ['--config-file=' + FRESHCLAM_CONF], { env });
      let stdout = '', stderr = '';
      cp.stdout.on('data', (d) => stdout += d.toString());
      cp.stderr.on('data', (d) => stderr += d.toString());
      const timer = setTimeout(() => { try { cp.kill('SIGTERM'); } catch (_) {} }, 5 * 60 * 1000);
      cp.on('close', (code) => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
    });
    if (result.code !== 0) {
      const errObj = { error: 'freshclam 返回非 0 (' + result.code + ')', output: (result.stdout + result.stderr).slice(-800) };
      settings.dbLastUpdate = new Date().toISOString();
      settings.dbLastResult = { ok: false, msg: errObj.error };
      writeJsonAtomic(SETTINGS_FILE, settings).catch(() => {});
      return errObj;
    }
    // 通知 clamd 重载病毒库（clamd 1.4 接受此命令，但失败也容忍：clamd 会按 SelfCheck 周期自动重载）
    try { await clamdRequest('RELOAD', { timeoutMs: 4000 }).catch(() => {}); }
    catch (e) { /* 容忍 */ }
    const okObj = { ok: true, output: (result.stdout + result.stderr).slice(-400) };
    settings.dbLastUpdate = new Date().toISOString();
    settings.dbLastResult = { ok: true };
    writeJsonAtomic(SETTINGS_FILE, settings).catch(() => {});
    return okObj;
  } finally {
    updateLock = null;
  }
}

async function getSystemSnapshot() {
  const cur = await readProcStat();
  let cpu = 0;
  if (cur && sysPrev) {
    const dt = cur.total - sysPrev.total;
    const di = cur.idle - sysPrev.idle;
    cpu = dt > 0 ? Math.max(0, Math.min(100, (1 - di / dt) * 100)) : 0;
  }
  sysPrev = cur || sysPrev;
  const [mem, cores, load, uptime] = await Promise.all([readProcMem(), readCpuCores(), readLoadAvg(), readUptime()]);
  return {
    cpu: Math.round(cpu * 10) / 10,
    cores,
    ram: mem,
    load,
    uptime,
  };
}

/* ---------------- HTTP 基础设施 ---------------- */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; form-action 'self'");
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cache-Control', 'no-store');
  // V1.0 版权标识（HTTP header 强制 ASCII，作者中文名用 latin1 编码避免 ERR_INVALID_CHAR）
  res.setHeader('X-Powered-By', 'ClamSentinel-V1.0-PrivateBuild');
  res.setHeader('X-Author', Buffer.from('很多问题的小明同学', 'utf8').toString('latin1'));
  res.setHeader('X-License', 'Proprietary-Personal-Use-Only');
}

function sendJson(res, code, obj) {
  const body = JSON.stringify(obj);
  securityHeaders(res);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

async function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath);
  if (rel === '/') rel = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR)) return sendJson(res, 403, { error: 'forbidden' });
  let data;
  try { data = await fsp.readFile(file); } catch (e) { return sendJson(res, 404, { error: 'not found' }); }
  const ext = path.extname(file).toLowerCase();
  securityHeaders(res);
  res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
  // 前端静态资源一律不缓存：应用升级后无需手动清浏览器缓存即可加载最新版本（避免旧 app.js 残留）
  res.setHeader('Cache-Control', 'no-store');
  res.writeHead(200);
  res.end(data);
}

function bodyParser(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); reject(new Error('请求体过大')); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(new Error('无效 JSON')); }
    });
    req.on('error', reject);
  });
}

function sameOriginOk(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try { return new URL(origin).host === req.headers.host; } catch (e) { return false; }
}

function getClientIp(req) {
  const fwd = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket.remoteAddress || '?';
}

/* ---------------- clamd 客户端 ---------------- */

function clamdRequest(command, opts) {
  return new Promise((resolve, reject) => {
    const timeoutMs = (opts && opts.timeoutMs) || 20000;
    const sock = net.connect(CLAMD_PORT, CLAMD_HOST);
    let buf = '';
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; try { sock.destroy(); } catch (_) {} reject(e); } };
    const timer = setTimeout(() => fail(new Error('clamd 响应超时')), timeoutMs);

    sock.on('connect', () => sock.write(command + '\n'));
    sock.on('data', (c) => {
      buf += c.toString('utf8');
      if (settled) return;
      if (command === 'PING') {
        if (buf.includes('PONG')) { settled = true; clearTimeout(timer); sock.end(); resolve('PONG'); }
      } else if (command === 'VERSION') {
        const i = buf.indexOf('\n');
        if (i >= 0) { settled = true; clearTimeout(timer); sock.end(); resolve(buf.slice(0, i)); }
      } else if (command.startsWith('STATUS')) {
        if (buf.includes('\n\n')) { settled = true; clearTimeout(timer); sock.end(); resolve(buf.replace(/\n+$/g, '')); }
      } else if (buf.includes('\nDONE')) {
        settled = true; clearTimeout(timer); sock.end(); resolve(buf);
      }
    });
    sock.on('error', fail);
    sock.on('close', () => {
      if (!settled) {
        settled = true; clearTimeout(timer);
        if (command === 'VERSION') resolve(buf.split('\n')[0]);
        else if (command.startsWith('STATUS')) resolve(buf.replace(/\n+$/g, ''));
        else if (/DONE/.test(buf)) resolve(buf);
        else reject(new Error('clamd 连接提前关闭'));
      }
    });
  });
}

/* ---------------- 扫描任务 ---------------- */

let running = false;
let currentJob = null;    // 当前正在跑的任务对象；暂停 API 直接修改它的 paused 字段
let paused = false;        // 用户主动暂停
let updateLock = null;       // 病毒库更新互斥锁（对象存在即占用中）
let idleSleepTimer = null;   // 20 分钟空闲睡眠定时器句柄

/* 病毒库自动更新调度（持久化到 settings.json） */
let dbScheduler = null;      // setInterval 句柄
const DB_DEFAULT_AUTO_HOUR = 9;  // 默认每天 09:00

async function persistJob(job) {
  await writeJsonAtomic(path.join(JOBS_DIR, `${job.id}.json`), job);
}

/* ★ v3.3.1 启动时清理"僵尸 running" jobs：web 被 SIGKILL 干掉时 finally 没机会跑，
   jobs 文件状态停留在 running。启动时把所有 running 标记为 abandoned。 */
async function cleanupZombieJobs() {
  try {
    const names = await fsp.readdir(JOBS_DIR);
    let cleaned = 0;
    for (const f of names.filter((x) => x.endsWith('.json'))) {
      const j = await readJson(path.join(JOBS_DIR, f), null);
      if (j && j.status === 'running') {
        j.status = 'abandoned';
        j.endedAt = j.endedAt || new Date().toISOString();
        j.error = 'web 重启前扫描被中断（可能因 app 重启 / 进程被 kill / 断电）';
        await persistJob(j);
        cleaned++;
      }
    }
    if (cleaned > 0) console.log('[clamsentinel] 清理僵尸 running jobs: ' + cleaned + ' 个 → abandoned');
  } catch (e) {
    console.error('[clamsentinel] cleanupZombieJobs 失败:', e.message);
  }
}

async function listJobs() {
  const out = [];
  try {
    const names = await fsp.readdir(JOBS_DIR);
    for (const f of names.filter((x) => x.endsWith('.json'))) {
      const j = await readJson(path.join(JOBS_DIR, f), null);
      if (j) out.push(j);
    }
    out.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
  } catch (e) {}
  return out;
}

function jobPublic(job) {
  return {
    id: job.id,
    display: job.display,
    rootId: job.rootId,
    rootLabel: job.rootLabel,
    status: job.status,
    createdAt: job.createdAt,
    startedAt: job.startedAt || null,
    endedAt: job.endedAt || null,
    scannedFiles: job.scannedFiles || 0,
    sampleFiles: (job.sampleFiles || []).slice(),
    threats: (job.threats || []).slice(),
    threatCount: job.threatCount || 0,
    errorCount: (job.errors || []).length,
    errors: (job.errors || []).slice(0, 200),
    truncated: !!job.truncated,
    paused: !!job.paused,
    error: job.error || null,
    kind: job.kind || 'file',
  };
}

async function startScan(rootId, relPath) {
  if (running) return { error: '已有扫描任务进行中，请等待其完成' };
  const root = await resolveRoot(rootId);
  if (!root) return { error: '未知扫描位置' };
  const abs = await relToAbs(root.realPath, relPath);
  if (!abs) return { error: '路径不合法' };
  let st;
  try { st = await fsp.stat(abs); } catch (e) { return { error: '目标路径不存在或不可读' }; }

  // 方案 B：扫描前确保 clamd 在线（idle 后可能停掉了），最多等 10 秒
  const ok = await ensureClamd();
  if (!ok) return { error: 'clamd 离线且启动失败（10 秒超时），请稍后再试或到应用中心检查状态' };
  touchActivity();  // 扫描正式开始，刷新活动时间

  const job = {
    id: Date.now().toString(36) + '-' + (await randomBytes(3)).toString('hex'),
    rootId: root.id,
    rootLabel: root.label,
    rootPath: root.path,
    rootReal: root.realPath,
    target: String(relPath || '').replace(/^\/+/, ''),
    display: relPath ? ('/' + String(relPath).replace(/^\/+/, '')) : ('/' + (root.label.split('（')[0] || root.label).trim()),
    kind: st.isDirectory() ? 'directory' : 'file',
    status: 'running',
    createdAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
    endedAt: null,
    scannedFiles: 0,
    sampleFiles: [],   // 抽样保留最多 200 个已扫描文件绝对路径，前端「扫描详情」显示
    threats: [],
    threatCount: 0,
    errors: [],
    truncated: false,
    paused: false,      // 本任务是否被用户暂停过
    error: null,
  };
  running = true;
  currentJob = job;       // 修复 v3.3.0 历史 bug：原代码忘记赋值 currentJob，导致 pause/resume 找不到 job
  paused = false;
  await persistJob(job);

  (async () => {
    try {
      await runClamdScan(abs, job);
      job.status = 'done';
    } catch (e) {
      job.status = 'failed';
      job.error = String((e && e.message) || e);
    } finally {
      job.endedAt = new Date().toISOString();
      if (job.threats.length > STORE_THREAT_CAP) { job.truncated = true; }
      await persistJob(job);
      running = false;
      currentJob = null;
      scheduleIdleSleep();
    }
  })();

  return { job: jobPublic(job) };
}

/* 扫描任务结束后空闲自动停服务 —— v3.3.0 起交由 sentinel 接管（24 分钟）。
 * 此函数保留为 stub 避免调用方引用 undefined，且会重置已有定时器。 */
function scheduleIdleSleep() {
  if (idleSleepTimer) { clearTimeout(idleSleepTimer); idleSleepTimer = null; }
  // sentinel 在 24 分钟无活动后会自动停 web+clamd，无需 web 端再调 cmd/main stop
}


/* 递归遍历 FS 收集所有常规文件路径（跳过符号链接，避免循环和 /proc 陷阱）。
 * 上限：单任务最多处理 MAX_SCAN_FILES 个文件，防止个别胖目录把内存打爆。 */
const MAX_SCAN_FILES = 200000;
const SKIP_DIR_NAMES = new Set(['proc', 'sys', 'run', 'dev', 'lost+found']);

async function collectFiles(abs, job) {
  const stack = [abs];
  let count = 0;
  while (stack.length > 0 && count < MAX_SCAN_FILES) {
    const dir = stack.pop();
    let entries;
    try { entries = await fsp.readdir(dir, { withFileTypes: true }); }
    catch (e) { continue; }
    for (const ent of entries) {
      if (count >= MAX_SCAN_FILES) break;
      const p = path.join(dir, ent.name);
      if (ent.isSymbolicLink()) continue;
      if (ent.isDirectory()) {
        if (SKIP_DIR_NAMES.has(ent.name)) continue;
        stack.push(p);
      } else if (ent.isFile()) {
        job.fileList.push(p);
        count += 1;
      }
    }
  }
  if (count >= MAX_SCAN_FILES) job.truncated = true;
  return job.fileList;
}

/* clamd CONTSCAN 协议：
 *   CONTSCAN <file-or-dir>\0
 *   单文件：返回 `<path>: OK | FOUND | ERROR` 一行后关闭连接
 *   单层目录：只扫描直接子项，不会递归到子目录
 *   关键：clamd 没有 RECURSIVESCAN 命令（那是 clamscan 命令行参数）。
 *   要扫整个目录树必须服务端自己递归 FS 后逐文件发 CONTSCAN。 */
const SAMPLE_FILE_CAP = 200;
/* RK3566 + 2GB RAM 设备推荐并发数：clamd.conf MaxThreads=2 + server 端 2 路并发
 * （再大会因 fork 子进程 + 缓冲 IO 把内存推到 1GB+，2GB 设备就吃紧了） */
/* 并发数由当前性能档位决定（PERF_MODES → settings.perfMode），无需重启，下次扫描生效。
 * 历史参考：RK3566+2GB 推荐并发 2 路 + clamd MaxThreads 兜底 8（再大会把内存推到 1GB+）。 */
const SCAN_CONCURRENCY = () => currentPerf().concurrent;

function runClamdScan(scanPath, job) {
  return new Promise(async (resolve, reject) => {
    job.fileList = job.fileList || [];
    job.scannedFiles = 0;
    try { await collectFiles(scanPath, job); }
    catch (e) { return reject(e); }

    const files = job.fileList;
    if (files.length === 0) { return resolve(); }

    // 并发池：SCAN_CONCURRENCY 个 worker 异步跑 CONTSCAN；每个文件间检查 paused。
    // 单文件扫描在文件级粒度中断（不破坏 clamd 协议），不丢已完成进度。
    const idx = { i: 0, done: 0 };
    const waitWhilePaused = () => new Promise((r) => {
      if (!paused) return r();
      const tick = () => { if (!paused) return r(); setTimeout(tick, 500); };
      tick();
    });
    const finish = () => {
      if (idx.done >= files.length) {
        persistJob(job).then(() => resolve()).catch(() => resolve());
      }
    };
    const worker = async () => {
      while (true) {
        while (paused) { await waitWhilePaused(); if (idx.i >= files.length) return finish(); }
        const myIdx = idx.i; idx.i += 1;
        if (myIdx >= files.length) return finish();
        const fp = files[myIdx];
        try { await scanOneFile(fp); }
        catch (e) { /* 单文件失败不中断整体 */ }
        idx.done += 1;
        if (idx.done % 50 === 0) persistJob(job).catch(() => {});
      }
    };
    await Promise.all(Array.from({ length: SCAN_CONCURRENCY() }, () => worker()));
  });

  function scanOneFile(filePath) {
    return new Promise((resolveOne) => {
      const sock = net.connect(CLAMD_PORT, CLAMD_HOST);
      let buf = '';
      const timer = setTimeout(() => {
        try { sock.destroy(); } catch (_) {}
        job.errors.push(filePath + ' → 扫描超时');
        if (job.errors.length > 500) job.errors.shift();
        resolveOne();
      }, 30000);

      sock.on('error', () => { clearTimeout(timer); resolveOne(); });
      sock.on('connect', () => sock.write('CONTSCAN ' + filePath + '\0'));
      sock.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const raw = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          const line = raw.replace(/\r$/, '');
          const t = line.trim();
          if (!t) continue;
          if (/(OK|FOUND|ERROR)\s*$/i.test(t)) {
            job.scannedFiles += 1;
            if (job.sampleFiles.length < SAMPLE_FILE_CAP) {
              job.sampleFiles.push(raw.slice(0, raw.indexOf(':')).trim());
            }
            parseScanLine(line, job);
          }
        }
      });
      sock.on('close', () => { clearTimeout(timer); resolveOne(); });
    });
  }
}

function relUnderRoot(filePath, rootReal, rootPath) {
  // 优先用 rootReal（解绑软链后的真实路径），其次用 rootPath
  if (rootReal && String(filePath).startsWith(rootReal + path.sep)) {
    return String(filePath).slice(rootReal.length).replace(/^[/\\]+/, '');
  }
  if (rootPath && String(filePath).startsWith(rootPath + path.sep)) {
    return String(filePath).slice(rootPath.length).replace(/^[/\\]+/, '');
  }
  return String(filePath);
}

function parseScanLine(line, job) {
  const colon = line.indexOf(':');
  if (colon < 0) { pushError(job, line); return; }
  const filePath = line.slice(0, colon).trim();
  const rest = line.slice(colon + 1).trim();
  if (/FOUND$/i.test(rest)) {
    const name = rest.replace(/\s*FOUND\s*$/i, '').trim();
    job.threatCount += 1;
    if (job.threats.length < STORE_THREAT_CAP) {
      job.threats.push({
        rel: relUnderRoot(filePath, job.rootReal, job.rootPath) || filePath,
        abs: filePath,
        name: name || '未命名威胁',
      });
    }
  } else if (/ERROR/i.test(rest)) {
    pushError(job, filePath + ' → ' + rest);
  } else if (!/OK/i.test(rest)) {
    pushError(job, line);
  }
  function pushError(job, msg) {
    if (job.errors.length < 500) job.errors.push(msg.slice(0, 300));
  }
}

/* ---------------- 隔离区 ---------------- */

async function loadQuarMeta() { return readJson(QUAR_META_FILE, []); }

async function listQuarantine() {
  const meta = await loadQuarMeta();
  const out = [];
  for (const item of meta) {
    try { await fsp.access(item.location); out.push(item); } catch (e) {}
  }
  return out;
}

function isUnderAnyRoot(abs, job) {
  if (isUnderRoot(abs, job.rootReal)) return true;
  return isUnderRoot(abs, job.rootPath);
}

async function moveAcross(src, dst) {
  await fsp.mkdir(path.dirname(dst), { recursive: true });
  await fsp.copyFile(src, dst);
  try { await fsp.unlink(src); } catch (e) {}
}

async function ensureNoOverwrite(target) {
  try { await fsp.access(target); return false; } catch (e) { return true; }
}

/* ---------------- API 路由 ---------------- */

async function handleApi(req, res, url) {
  const method = req.method;
  const p = url.pathname;

  /* 匿名：state / setup / login / logout */
  if (p === '/api/state' && method === 'GET') {
    const users = await loadUsers();
    const names = Object.keys(users);
    const uid = names.length ? verifySession(parseCookies(req).csi) : null;
    const me = uid && users[uid] ? { name: uid, role: users[uid].role } : null;
    const roots = await listRoots();
    return sendJson(res, 200, {
      setup: names.length === 0,
      authed: !!me,
      user: me,
      product: 'ClamSentinel',
      version: readVersion(),
      roots: roots.map(r => ({ id: r.id, label: r.label, path: r.path })),
      serviceStopped: !!serviceStopped,
      idleSleepMin: 24,             // v3.3.0 起 sentinel 接管；固定为 24
      managedBy: 'sentinel',
      webInternalPort: PORT,
    });
  }

  /* 系统监控（CPU/Cores/RAM/Load/Uptime）—— 匿名可访问，3 秒刷新用于右上角小工具 */
  if (p === '/api/system' && method === 'GET') {
    const snap = await getSystemSnapshot();
    return sendJson(res, 200, snap);
  }

  if (p === '/api/setup' && method === 'POST') {
    const users = await loadUsers();
    if (Object.keys(users).length > 0) return sendJson(res, 409, { error: '系统已完成初始化' });
    const body = await bodyParser(req);
    const name = String(body.username || '').trim();
    const pw = String(body.password || '');
    if (name.length < 2 || name.length > 32 || !/^[A-Za-z0-9_\u4e00-\u9fa5-]+$/.test(name))
      return sendJson(res, 400, { error: '用户名需为 2-32 位字母数字或中文' });
    if (pw.length < 8) return sendJson(res, 400, { error: '密码至少 8 位' });
    users[name] = { role: 'admin', hash: await hashPassword(pw), createdAt: new Date().toISOString() };
    await saveUsers(users);
    res.setHeader('Set-Cookie', sessionCookie(signSession(name, Date.now() + SESSION_MAX_AGE)));
    return sendJson(res, 200, { ok: true });
  }

  if (p === '/api/login' && method === 'POST') {
    const ip = getClientIp(req);
    if (loginBlocked(ip)) return sendJson(res, 429, { error: '尝试次数过多，请稍后再试' });
    const users = await loadUsers();
    const body = await bodyParser(req);
    const name = String(body.username || '').trim();
    const user = users[name];
    const ok = user ? await verifyPassword(String(body.password || ''), user.hash) : false;
    if (!ok) { loginFail(ip); return sendJson(res, 401, { error: '用户名或密码错误' }); }
    loginFails.delete(ip);
    res.setHeader('Set-Cookie', sessionCookie(signSession(name, Date.now() + SESSION_MAX_AGE)));
    return sendJson(res, 200, { ok: true, name });
  }

  if (p === '/api/logout' && method === 'POST') {
    res.setHeader('Set-Cookie', clearCookie());
    return sendJson(res, 200, { ok: true });
  }

  /* ---- 以下需登录 ---- */
  const users = await loadUsers();
  const uid = verifySession(parseCookies(req).csi);
  if (!uid || !users[uid]) return sendJson(res, 401, { error: 'authentication required' });
  const actor = { name: uid, role: users[uid].role };
  if (!sameOriginOk(req)) return sendJson(res, 403, { error: '跨域请求被拒绝' });

  /* 病毒库：手动立即更新 */
  if (p === '/api/db/update' && method === 'POST') {
    if (!actor.role) return sendJson(res, 403, { error: '需要管理员' });
    // 方案 B：freshclam 之前确保 clamd 在线，避免 zombie 状态
    const ok = await ensureClamd();
    if (!ok) return sendJson(res, 503, { error: 'clamd 启动超时，请重试' });
    const r = await runDbUpdate();
    return sendJson(res, r.error ? 500 : 200, r);
  }

  /* 病毒库：自动更新调度配置 */
  if (p === '/api/db/settings' && method === 'GET') {
    return sendJson(res, 200, {
      auto: !!settings.dbAutoUpdate,
      hour: Number.isInteger(settings.dbAutoHour) ? settings.dbAutoHour : DB_DEFAULT_AUTO_HOUR,
      lastUpdate: settings.dbLastUpdate || null,
      lastResult: settings.dbLastResult || null,
    });
  }
  if (p === '/api/db/settings' && method === 'POST') {
    if (!actor.role) return sendJson(res, 403, { error: '需要管理员' });
    const body = await bodyParser(req);
    if (typeof body.auto === 'boolean') settings.dbAutoUpdate = !!body.auto;
    if (Number.isInteger(body.hour) && body.hour >= 0 && body.hour <= 23) settings.dbAutoHour = body.hour;
    await writeJsonAtomic(SETTINGS_FILE, settings);
    if (settings.dbAutoUpdate) startDbScheduler(); else stopDbScheduler();
    return sendJson(res, 200, { ok: true, auto: !!settings.dbAutoUpdate, hour: settings.dbAutoHour });
  }

  /* 性能调节器：档位（eco/balanced）。GET 返回当前档位参数；POST 保存——下次扫描立即生效，无需重启 */
  if (p === '/api/perf' && method === 'GET') {
    return sendJson(res, 200, currentPerf());
  }
  if (p === '/api/perf' && method === 'POST') {
    if (!actor.role) return sendJson(res, 403, { error: '需要管理员' });
    const body = await bodyParser(req);
    if (!PERF_MODES[body.mode]) return sendJson(res, 400, { error: '无效档位' });
    settings.perfMode = body.mode;
    await writeJsonAtomic(SETTINGS_FILE, settings);
    touchActivity();  // 设置档位也算用户活动，避免被当作 idle 停机
    return sendJson(res, 200, { ok: true, ...currentPerf() });
  }

  /* 诊断日志导出：打包 app.log + sentinel.log + clamd.log + 环境信息 + 近期任务，供用户下载返给开发者 */
  if (p === '/api/logs' && method === 'GET') {
    if (!actor.role) return sendJson(res, 403, { error: '需要管理员' });
    touchActivity();
    const down = (name, data) => ({ name: name, data: data });
    const files = [];
    const push = (name, data) => { if (data && data.length) files.push(down(name, data)); };
    push('app.log', readLogFile(LOG_FILE, 2 * 1024 * 1024));
    push('app.log.1', readLogFile(LOG_FILE + '.1', 2 * 1024 * 1024));
    push('sentinel.log', readLogFile(path.join(LOG_DIR, 'sentinel.log'), 2 * 1024 * 1024));
    push('clamd.log', readLogFile(path.join(LOG_DIR, 'clamd.log'), 3 * 1024 * 1024));
    push('clamd.log.1', readLogFile(path.join(LOG_DIR, 'clamd.log.1'), 3 * 1024 * 1024));
    const info = [];
    info.push('ClamSentinel 诊断导出  ' + new Date().toISOString());
    info.push('软件版本: V' + readVersion());
    info.push('webInternalPort: ' + PORT);
    info.push('性能档位: ' + currentPerf().label + ' (mode=' + settings.perfMode + ')');
    info.push('病毒库自动更新: ' + (settings.dbAutoUpdate ? ('每天 ' + settings.dbAutoHour + ':00') : '关闭'));
    info.push('空闲停止: 由 sentinel 接管（24 分钟无活动自动停 web+clamd）');
    info.push('---- CPU ----');
    try { info.push(fs.readFileSync('/proc/cpuinfo', 'utf8').split('\n').filter((l) => /^(Hardware|model name|Processor)/.test(l)).slice(0, 4).join('\n')); } catch (_) {}
    info.push('---- 内存 ----');
    try { info.push(fs.readFileSync('/proc/meminfo', 'utf8').split('\n').filter((l) => /^MemTotal|^MemAvailable|^SwapTotal|^SwapFree/.test(l)).join('\n')); } catch (_) {}
    push('info.txt', Buffer.from(info.join('\n') + '\n', 'utf8'));
    try {
      const names = fs.readdirSync(JOBS_DIR).filter((n) => n.endsWith('.json')).sort().slice(-15);
      for (const n of names) push('jobs/' + n, readLogFile(path.join(JOBS_DIR, n), 512 * 1024));
    } catch (_) {}
    const zip = makeZip(files);
    res.writeHead(200, {
      'Content-Type': 'application/zip',
      'Content-Disposition': 'attachment; filename="clamsentinel-diagnostics-V' + readVersion() + '.zip"',
      'Content-Length': zip.length,
      'Cache-Control': 'no-store',
    });
    return res.end(zip);
  }

  /* 扫描任务：暂停 / 继续 —— 立即持久化以让前端 /api/jobs 立刻看到 paused 字段变化 */
  if (p === '/api/scan/pause' && method === 'POST') {
    if (!running) return sendJson(res, 400, { error: '当前没有扫描任务' });
    paused = true;
    if (currentJob) {
      currentJob.paused = true;
      currentJob.pausedAt = new Date().toISOString();
      // 立刻写盘 —— 否则 UI 端 /api/jobs 读到的是磁盘上过期状态
      persistJob(currentJob).catch((e) => console.error('[clamsentinel] pause persist failed:', e.message));
    }
    return sendJson(res, 200, { ok: true, paused: true, pausedAt: new Date().toISOString() });
  }
  if (p === '/api/scan/resume' && method === 'POST') {
    if (!running) return sendJson(res, 400, { error: '当前没有扫描任务' });
    paused = false;
    if (currentJob) {
      currentJob.paused = false;
      delete currentJob.pausedAt;
      persistJob(currentJob).catch((e) => console.error('[clamsentinel] resume persist failed:', e.message));
    }
    return sendJson(res, 200, { ok: true, paused: false });
  }

  /* 服务控制：web 进程本身是 root，能直接调 cmd/main stop；停掉后应用中心会显示已停止，重新启动去应用中心点开始 */
  if (p === '/api/service/shutdown' && method === 'POST') {
    if (process.getuid && process.getuid() !== 0) {
      return sendJson(res, 403, { error: '当前进程不是 root，无法关闭服务' });
    }
    if (serviceStopped) return sendJson(res, 200, { ok: true, already: true });
    serviceStopped = true;
    const { spawn } = require('child_process');
    try {
      // 异步给 fnOS appcenter 发 stop，等几秒 appcenter 会帮我们杀进程。
      // 我们自己进程延迟退出，因为 cmd/main stop 是 do_stop + pkill，1 秒内就死。
      spawn('bash', ['-c', "nohup /var/apps/clamsentinel/cmd/main stop >>/tmp/csshutdown.log 2>&1 &"], { detached: true, stdio: 'ignore' }).unref();
    } catch (e) { /* 容忍 */ }
    return sendJson(res, 200, { ok: true });
  }

  /* 服务控制：空闲自动停止 —— v3.3.0 起 sentinel 强制接管（24 分钟）。
   * 此接口仍保留向后兼容，固定返回 sentinel 默认值；POST 持久化但实际由 sentinel 调度。 */
  if (p === '/api/service/idle-sleep' && method === 'GET') {
    return sendJson(res, 200, { idleSleepMin: 24, managedBy: 'sentinel' });
  }
  if (p === '/api/service/idle-sleep' && method === 'POST') {
    return sendJson(res, 200, { ok: true, idleSleepMin: 24, managedBy: 'sentinel', note: 'v3.3.0 起空闲策略由 sentinel 进程统一管理（24 分钟无活动自动释放 ~1GB RAM）' });
  }

  /* Sentinel 状态查询：前端轮询以显示"即将睡眠"倒计时 */
  if (p === '/api/sentinel/state' && method === 'GET') {
    let sentinelInfo = { mode: 'unknown', untilSleepSec: 0, idleSec: 0, managedBy: 'sentinel' };
    try {
      // sentinel 自己 /api/sentinel 端口是同一进程（8080）；直接内部再发个 HTTP 看自己
      const r = await new Promise((resolve) => {
        const req = http.get({ host: '127.0.0.1', port: PORT, path: '/api/sentinel', timeout: 1500 }, (resp) => {
          let body = ''; resp.on('data', (d) => body += d); resp.on('end', () => resolve({ code: resp.statusCode, body }));
        });
        req.on('error', () => resolve({ code: 0, body: '' }));
        req.on('timeout', () => { req.destroy(); resolve({ code: 0, body: '' }); });
      });
      if (r.code === 200 && r.body) {
        try {
          const inner = JSON.parse(r.body);
          const sinceMs = Number(inner.sinceLastActivity) || 0;
          const idleSec = Math.round(sinceMs / 1000);
          const untilSleepSec = Math.max(0, Math.round((Number(inner.idleMs) || 1440000) / 1000) - idleSec);
          sentinelInfo = Object.assign(sentinelInfo, inner, {
            idleSec, untilSleepSec, idleMs: Number(inner.idleMs) || 1440000,
            serverPort: PORT,
          });
        } catch (_) {}
      }
    } catch (_) {}
    return sendJson(res, 200, sentinelInfo);
  }


  /* 列出扫描根（也是登录可见的） */
  if (p === '/api/roots' && method === 'GET') {
    const roots = await listRoots();
    return sendJson(res, 200, { roots });
  }

  /* 仪表盘 */
  if (p === '/api/dashboard' && method === 'GET') {
    let engine = null, ping = false, engineText = '';
    try {
      engineText = (await clamdRequest('VERSION', { timeoutMs: 6000 })) || '';
      engine = engineText;
    } catch (e) { engine = null; }
    try {
      ping = (await clamdRequest('PING', { timeoutMs: 4000 })) === 'PONG';
    } catch (e) { ping = false; }
    const dbBuild = (engineText.match(/\/(\d+)\//) || [])[1] || null;
    let dbInfo = { present: false, updated: null, build: null, files: [], downloading: false, missing: [] };
    try {
      // 日常增量库可能是 daily.cvd 或 daily.cld 任一形态（新版 freshclam 常直接下载为 daily.cld，属正常），
      // 因此按"逻辑库名"检测，任一扩展存在即视为该库已就绪。
      // main + daily 必须齐全才算就绪（bytecode 可选，仅影响解包能力），
      // 避免只下 partial 就判定就绪，导致重启后不再触发首补、长期缺 main.cvd。
      const dbNames = ['main', 'daily', 'bytecode'];
      const required = ['main', 'daily'];
      let bestMtime = null;
      const presentFiles = [];
      const missing = [];
      for (const nm of dbNames) {
        let found = null, st = null;
        for (const ext of ['cvd', 'cld']) {
          try { st = await fsp.stat(path.join(DB_MOUNT, nm + '.' + ext)); found = nm + '.' + ext; break; } catch (e) {}
        }
        if (found && st) {
          presentFiles.push(found);
          if (!bestMtime || st.mtime > bestMtime) bestMtime = st.mtime;
        } else if (required.indexOf(nm) >= 0) {
          missing.push(nm);
        }
      }
      // freshclam 下载期间会在库目录建 tmp.xxxx 临时目录，据此判断"正在下载"
      let downloading = false;
      try {
        const ents = await fsp.readdir(DB_MOUNT);
        downloading = ents.some((n) => n.indexOf('tmp.') === 0);
      } catch (e) { downloading = false; }
      if (missing.length === 0 && presentFiles.length) {
        let dbSize = 0;
        try {
          const ents = await fsp.readdir(DB_MOUNT);
          await Promise.all(ents.map((n) => fsp.stat(path.join(DB_MOUNT, n)).then((x) => { dbSize += x.size; }).catch(() => 0)));
        } catch (e) { dbSize = 0; }
        dbInfo = {
          present: true,
          updated: bestMtime.toISOString(),
          build: dbBuild,
          files: presentFiles,
          size: dbSize,
          downloading: false,
          missing: [],
        };
      } else {
        dbInfo = {
          present: false,
          updated: null,
          build: null,
          files: presentFiles,
          downloading,
          missing,
        };
      }
    } catch (e) {}

    const jobs = await listJobs();
    const done = jobs.filter((j) => j.status === 'done');
    const recent = done.slice(0, 10).map((j) => jobPublic(j));
    const totalFiles = done.reduce((s, j) => s + (j.scannedFiles || 0), 0);
    const totalThreats = done.reduce((s, j) => s + (j.threatCount || 0), 0);
    return sendJson(res, 200, {
      engine: { online: ping || (typeof engine === 'string' && engine.length > 0), version: engine },
      db: dbInfo,
      totals: { files: totalFiles, threats: totalThreats, scans: done.length },
      recent,
      quarantineCount: (await listQuarantine()).length,
      scanning: running,
      scanPaused: running && currentJob ? !!currentJob.paused : false,  // v3.3.0：暂停状态暴露给 dashboard
      roots: (await listRoots()).map(r => ({ id: r.id, label: r.label, path: r.path })),
      idleSleepMin: 24,             // v3.3.0 起 sentinel 接管；固定为 24 分钟
      managedBy: 'sentinel',
      clamdOnline: isClamdRunning(),
    });
  }

  /* 浏览某根下的子路径 */
  if (p === '/api/browse' && method === 'GET') {
    const root = await resolveRoot(url.searchParams.get('root') || 'scan');
    if (!root) return sendJson(res, 400, { error: '未知扫描位置' });
    const rel = String(url.searchParams.get('path') || '');
    const abs = await relToAbs(root.realPath, rel);
    if (!abs) return sendJson(res, 400, { error: '路径不合法' });
    const entries = [];
    try {
      for (const name of await fsp.readdir(abs)) {
        const full = path.join(abs, name);
        try {
          const st = await fsp.stat(full);
          entries.push({
            name,
            rel: path.relative(root.realPath, full).split(path.sep).join('/'),
            dir: st.isDirectory(),
            size: st.isDirectory() ? null : st.size,
            mtime: st.mtime.toISOString(),
          });
        } catch (e) {}
      }
      entries.sort((a, b) => (b.dir - a.dir) || a.name.localeCompare(b.name, 'zh-CN'));
    } catch (e) {
      return sendJson(res, 400, { error: '无法读取目录：' + ((e && e.message) || e) });
    }
    const parent = rel === '' ? null : rel.split('/').slice(0, -1).join('/');
    return sendJson(res, 200, {
      root: root.id, rootLabel: root.label, rootPath: root.path,
      rel, parent, entries, readOnly: false,
    });
  }

  /* 发起扫描 */
  if (p === '/api/scan' && method === 'POST') {
    const body = await bodyParser(req);
    const r = await startScan(String(body.root || 'scan'), String(body.path || ''));
    if (r.error) return sendJson(res, 400, { error: r.error });
    return sendJson(res, 200, r.job);
  }

  /* 任务/历史 */
  if (p === '/api/jobs' && method === 'GET') {
    const jobs = (await listJobs()).map(jobPublic);
    return sendJson(res, 200, { jobs, running });
  }

  const detailMatch = p.match(/^\/api\/jobs\/([a-z0-9-]+)$/);
  if (detailMatch && method === 'GET') {
    const j = await readJson(path.join(JOBS_DIR, detailMatch[1] + '.json'), null);
    if (!j) return sendJson(res, 404, { error: '任务不存在' });
    return sendJson(res, 200, {
      ...jobPublic(j),
      threats: (j.threats || []).slice(0, STORE_THREAT_CAP),
      errors: (j.errors || []).slice(0, 200),
    });
  }

  /* 威胁处置（隔离 / 删除） */
  if (p === '/api/dispose' && method === 'POST') {
    const body = await bodyParser(req);
    const job = await readJson(path.join(JOBS_DIR, String(body.job || '') + '.json'), null);
    if (!job) return sendJson(res, 404, { error: '任务不存在' });
    const action = String(body.action || '');
    const all = !!body.all;
    const indices = Array.isArray(body.indices) ? body.indices.map(Number) : [];
    const targets = all ? job.threats : job.threats.filter((_, i) => indices.includes(i));
    if (!targets.length) return sendJson(res, 400, { error: '没有可处置的条目' });

    const results = [];
    for (const t of targets) {
      // threat abs 应在任务的根目录下
      const absCheck = (job.rootReal && t.abs.startsWith(job.rootReal + path.sep)) || t.abs.startsWith(job.rootPath + path.sep);
      if (!absCheck) { results.push({ rel: t.rel, error: '路径越界' }); continue; }
      try {
        if (action === 'quarantine') {
          const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, '');
          const qdir = path.join(QUAR_DIR, stamp);
          await fsp.mkdir(qdir, { recursive: true });
          const dest = path.join(qdir, path.basename(t.abs) + '.' + job.id + '.quar');
          await moveAcross(t.abs, dest);
          const meta = await loadQuarMeta();
          meta.push({ location: dest, orig: t.rel, root: job.rootId, name: t.name, at: new Date().toISOString(), size: 0 });
          await writeJsonAtomic(QUAR_META_FILE, meta);
          results.push({ rel: t.rel, ok: true, action: 'quarantined' });
        } else if (action === 'delete') {
          await fsp.unlink(t.abs);
          results.push({ rel: t.rel, ok: true, action: 'deleted' });
        } else {
          return sendJson(res, 400, { error: '未知处置动作' });
        }
      } catch (e) {
        results.push({ rel: t.rel, error: String((e && e.message) || e) });
      }
    }
    return sendJson(res, 200, { results });
  }

  /* 隔离区 */
  if (p === '/api/quarantine' && method === 'GET') {
    const list = await listQuarantine();
    return sendJson(res, 200, { list: list.sort((a, b) => String(b.at).localeCompare(String(a.at))) });
  }
  if (p === '/api/quarantine/restore' && method === 'POST') {
    const body = await bodyParser(req);
    const loc = String(body.id || '');
    const item = (await loadQuarMeta()).find((m) => m.location === loc);
    if (!item) return sendJson(res, 404, { error: '隔离条目不存在' });
    const root = await resolveRoot(item.root || 'scan');
    if (!root) return sendJson(res, 400, { error: '原扫描根不可访问' });
    const targetAbs = await relToAbs(root.realPath, item.orig);
    if (!targetAbs) return sendJson(res, 400, { error: '原路径越界' });
    try {
      if (!(await ensureNoOverwrite(targetAbs))) return sendJson(res, 409, { error: '原位置已存在同名文件，恢复被拒绝' });
      await moveAcross(item.location, targetAbs);
      await writeJsonAtomic(QUAR_META_FILE, (await loadQuarMeta()).filter((m) => m.location !== loc));
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 409, { error: '恢复失败：' + ((e && e.message) || e) });
    }
  }
  if (p === '/api/quarantine/delete' && method === 'POST') {
    const body = await bodyParser(req);
    const loc = String(body.id || '');
    try {
      await fsp.unlink(loc);
      await writeJsonAtomic(QUAR_META_FILE, (await loadQuarMeta()).filter((m) => m.location !== loc));
      return sendJson(res, 200, { ok: true });
    } catch (e) {
      return sendJson(res, 409, { error: '删除失败：' + ((e && e.message) || e) });
    }
  }

  /* 修改密码 */
  if (p === '/api/settings/password' && method === 'POST') {
    const body = await bodyParser(req);
    const user = users[actor.name];
    if (!(await verifyPassword(String(body.oldPassword || ''), user.hash))) return sendJson(res, 403, { error: '原密码不正确' });
    const np = String(body.newPassword || '');
    if (np.length < 8) return sendJson(res, 400, { error: '新密码至少 8 位' });
    user.hash = await hashPassword(np);
    await saveUsers(users);
    return sendJson(res, 200, { ok: true });
  }

  return sendJson(res, 404, { error: 'not found' });
}

/* ---------------- 启动 ---------------- */

async function main() {
  await ensureDirs();
  await loadSettings();
  // V1.0 启动横幅版权声明
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  ClamSentinel V1.0');
  console.log('  © 2026  很多问题的小明同学 · 保留所有权利');
  console.log('  授权：单机私用 · 禁止二次分发或商用');
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('');
  console.log('[clamsentinel] 启动信息：');
  console.log('[clamsentinel]   数据目录 = ' + DATA_DIR);
  console.log('[clamsentinel]   隔离区 = ' + QUAR_DIR);
  console.log('[clamsentinel]   clamd 地址 = ' + CLAMD_HOST + ':' + CLAMD_PORT);
  const roots = await listRoots();
  console.log('[clamsentinel]   扫描根 = ' + roots.map(r => r.label + '(' + r.path + ')').join(', '));
  console.log('[clamsentinel]   病毒库自动更新 = ' + (settings.dbAutoUpdate ? ('每天 ' + settings.dbAutoHour + ':00') : '已关闭'));

  if (settings.dbAutoUpdate) startDbScheduler();
  console.log('[clamsentinel]   空闲停止调度 = 由 sentinel 接管（方案 B：24 分钟无活动自动停 web+clamd）');

  const server = http.createServer(async (req, res) => {
    touchActivity();  // 任何 HTTP 请求都算"用户活动"，重置 idle 计时
    try {
      const url = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));
      if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
      else await serveStatic(req, res, url.pathname);
    } catch (e) {
      console.error('[clamsentinel] 请求处理异常:', e);
      if (!res.headersSent) sendJson(res, 500, { error: '服务器内部错误' });
      else res.end();
    }
  });
  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });
  server.listen(PORT, '0.0.0.0', async () => {
    console.log('[clamsentinel] Web 服务已就绪，监听 :' + PORT);
    // ★ v3.3.1 启动时清理僵尸 running jobs（被 SIGKILL 中断留下的）
    await cleanupZombieJobs();
  });
}

main().catch((e) => {
  console.error('[clamsentinel] 启动失败:', e);
  process.exit(1);
});

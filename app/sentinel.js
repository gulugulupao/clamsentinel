#!/usr/bin/env node
/* ClamSentinel · 哨兵（sentinel）
 *
 * 方案 B - 24 分钟空闲自动停 web+clamd，节省 ~1GB RAM
 *
 * 永远监听 :8080 (fnOS service_port)，确保 fnOS 始终认为应用健康。
 * 收到请求时若 web (端口 8081) 未起，则 lazy 启动 clamd + web.js，
 * 启动完成后转发请求。空闲 IDLE_MS 毫秒后再请求过 0 次 → 停 web+clamd。
 *
 * fnOS appcenter 看到的 8080 一直有响应 → 健康检查永远通过。
 */

'use strict';

const http   = require('http');
const net    = require('net');
const fs     = require('fs');
const path   = require('path');
const { spawn } = require('child_process');

/* -------- 从 env 读取配置（cmd/main 注入） -------- */
const SENTINEL_PORT = parseInt(process.env.SENTINEL_PORT || '8080', 10);
const WEB_PORT      = parseInt(process.env.WEB_PORT      || '8081', 10);
const IDLE_MS       = parseInt(process.env.IDLE_MS       || (10 * 60 * 1000), 10);   // 10 min (V1.0 私有版：比 24min 更积极省电)
const POLL_MS       = parseInt(process.env.POLL_MS       || '20000', 10);            // 20s
const WAKE_TIMEOUT  = parseInt(process.env.WAKE_TIMEOUT_MS || '60000', 10);          // 60s
const WAKE_GRACE_MS = parseInt(process.env.WAKE_GRACE_MS || '120000', 10);         // 唤醒宽限 120s：clamd 加载病毒库需 20-30s，期间不算失联
const CLAMD_BIN     = process.env.CLAMD_BIN     || '/usr/sbin/clamd';
const CLAMD_CONF    = process.env.CLAMD_CONF    || '/etc/clamav/clamd.conf';
const CLAMD_PIDF    = process.env.CLAMD_PIDF    || '';
const CLAMD_SOCK    = process.env.CLAMD_SOCK    || '';
const NODE_BIN      = process.env.NODE_BIN      || 'node';
const WEB_SCRIPT    = process.env.WEB_SCRIPT    || '';
const WEB_PIDF      = process.env.WEB_PIDF      || '';
const JOBS_DIR      = process.env.JOBS_DIR      || '';
const LOG_FILE      = process.env.LOG_FILE      || '/tmp/sentinel.log';

/* -------- 状态 -------- */
let mode           = 'sleep';  // sleep / waking / active / sleeping
let lastActivity   = Date.now();
let wakeStartAt    = 0;

function ts() { return new Date().toISOString(); }
function log() {
  const a = Array.prototype.map.call(arguments, (x) => typeof x === 'string' ? x : JSON.stringify(x));
  const line = '[sentinel ' + ts() + '] ' + a.join(' ') + '\n';
  try { fs.appendFileSync(LOG_FILE, line); } catch (_) {}
  try { process.stderr.write(line); } catch (_) {}
}

/* -------- 工具函数 -------- */
function fileExists(p) { try { return p && fs.existsSync(p); } catch (_) { return false; } }
function readPid(p)    { try { return parseInt(fs.readFileSync(p, 'utf8').trim(), 10) || 0; } catch (_) { return 0; } }
function writePid(p, pid) { try { fs.writeFileSync(p, String(pid)); } catch (_) {} }
function rmPid(p)      { try { fs.unlinkSync(p); } catch (_) {} }
function procAlive(pid) { if (!pid || pid <= 0) return false; try { process.kill(pid, 0); return true; } catch (_) { return false; } }
function killTree(pid) {
  if (!procAlive(pid)) return;
  try { process.kill(pid, 'SIGTERM'); } catch (_) {}
  setTimeout(() => {
    if (procAlive(pid)) { try { process.kill(pid, 'SIGKILL'); } catch (_) {} }
  }, 2500);
}
function portReady(port, timeout) {
  return new Promise((resolve) => {
    const s = net.createConnection({ host: '127.0.0.1', port });
    const t = setTimeout(() => { try { s.destroy(); } catch (_) {} resolve(false); }, timeout || 700);
    s.once('connect', () => { clearTimeout(t); try { s.destroy(); } catch (_) {} resolve(true); });
    s.once('error',   () => { clearTimeout(t); resolve(false); });
  });
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

/* -------- clamd 控制 -------- */
function startClamd() {
  if (procAlive(readPid(CLAMD_PIDF))) return log('clamd 已在运行');
  if (CLAMD_SOCK && fileExists(CLAMD_SOCK)) { try { fs.unlinkSync(CLAMD_SOCK); } catch (_) {} }
  const env = Object.assign({}, process.env);
  const fs = require('fs');
  const out = fs.openSync(LOG_FILE + '.clamd.log', 'a');
  const err = fs.openSync(LOG_FILE + '.clamd.log', 'a');
  const p = spawn(CLAMD_BIN, ['--config-file=' + CLAMD_CONF], {
    env, stdio: ['ignore', out, err], detached: false,
  });
  writePid(CLAMD_PIDF, p.pid);
  log('clamd 启动 PID=' + p.pid);
  return true;
}
function stopClamd() {
  const pid = readPid(CLAMD_PIDF);
  if (pid > 0) { killTree(pid); log('clamd 停止'); }
  rmPid(CLAMD_PIDF);
  if (CLAMD_SOCK && fileExists(CLAMD_SOCK)) { try { fs.unlinkSync(CLAMD_SOCK); } catch (_) {} }
}

/* -------- web 控制 -------- */
function startWeb() {
  if (procAlive(readPid(WEB_PIDF))) return log('web 已在运行');
  const env = Object.assign({}, process.env, { PORT: String(WEB_PORT) });
  // V1.0d：把 stdout/stderr 重定向到 LOG_FILE + '.web.log' 而不是 'ignore'，
  // 避免某些 Node 版本在 stdin=ignore 时丢失 SIGTERM/SIGINT 信号导致进程异常退出
  const fs = require('fs');
  const out = fs.openSync(LOG_FILE + '.web.log', 'a');
  const err = fs.openSync(LOG_FILE + '.web.log', 'a');
  const p = spawn(NODE_BIN, [WEB_SCRIPT], {
    env,
    stdio: ['ignore', out, err],
    detached: false,
  });
  writePid(WEB_PIDF, p.pid);
  log('web 启动 PID=' + p.pid);
}
function stopWeb() {
  const pid = readPid(WEB_PIDF);
  if (pid > 0) { killTree(pid); log('web 停止'); }
  rmPid(WEB_PIDF);
}

/* -------- 任务运行检测（防止扫描中被停） -------- */
function hasRunningJob() {
  if (!JOBS_DIR || !fileExists(JOBS_DIR)) return false;
  try {
    const files = fs.readdirSync(JOBS_DIR).filter(f => f.endsWith('.json'));
    for (const f of files) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(JOBS_DIR, f), 'utf8'));
        if (j.status === 'running' || j.status === 'paused') return true;
      } catch (_) {}
    }
  } catch (_) {}
  return false;
}

/* -------- 醒 / 睡 -------- */
async function wakeUp() {
  if (mode === 'waking' || mode === 'active') return;
  mode = 'waking';
  wakeStartAt = Date.now();
  log('wake begin');
  startClamd();
  await sleep(2000);     // 给 clamd listen 3310 + web 后续连上
  startWeb();
}

async function sleepNow() {
  if (mode === 'sleep' || mode === 'sleeping') return;
  log('sleep begin (release ~1.05GB RAM)');
  mode = 'sleeping';
  stopWeb();
  await sleep(800);
  stopClamd();
  await sleep(500);
  mode = 'sleep';
  log('sleep done');
}

/* -------- HTTP 代理 -------- */
function forwardTo(req, res, port) {
  const opts = {
    host: '127.0.0.1', port, method: req.method, path: req.url, headers: req.headers,
  };
  const pr = http.request(opts, (upstream) => {
    res.writeHead(upstream.statusCode || 502, upstream.headers || {});
    upstream.pipe(res);
  });
  pr.on('error', (e) => {
    log('forward err', e.message);
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('sentinel: backend error');
  });
  req.pipe(pr);
}

/* -------- 主 HTTP 服务器（8080 永远在） -------- */
// ★ v3.3.1 启动前端口检测：端口被占时优雅退出而不是崩溃
function tryBind(port, host) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', (e) => { resolve({ ok: false, code: e.code }); });
    s.once('listening', () => { s.close(() => resolve({ ok: true })); });
    s.listen(port, host || '0.0.0.0');
  });
}
const server = http.createServer(async (req, res) => {
  lastActivity = Date.now();

  // /api/sentinel - 给前端看状态
  if (req.url === '/api/sentinel' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      mode, idleMs: IDLE_MS, sinceLastActivity: Date.now() - lastActivity,
      untilSleepMs: Math.max(0, IDLE_MS - (Date.now() - lastActivity)),
      untilSleepSec: Math.max(0, Math.floor((IDLE_MS - (Date.now() - lastActivity)) / 1000)),
      waitingFor: mode === 'waking' ? (Date.now() - wakeStartAt) : 0,
    }));
    return;
  }

  // 已经活动？直接转发
  if (mode === 'active' && await portReady(WEB_PORT, 400)) {
    return forwardTo(req, res, WEB_PORT);
  }

  // 否则唤醒
  if (mode !== 'waking') {
    wakeUp().catch((e) => log('wake err', e.message));
  }

  // 等待 web 上线
  const start = Date.now();
  while (Date.now() - start < WAKE_TIMEOUT) {
    if (await portReady(WEB_PORT, 600)) {
      mode = 'active';
      return forwardTo(req, res, WEB_PORT);
    }
    await sleep(700);
  }

  // 超时：返回「正在唤醒」提示
  res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(
    '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="3"><title>ClamSentinel 唤醒中</title>' +
    '<style>body{margin:0;background:#0b1220;color:#9fb1cc;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}' +
    '.b{text-align:center;padding:42px;background:#11192b;border:1px solid #1c2942;border-radius:14px;max-width:420px}' +
    'h1{color:#5cd2a3;margin:0 0 14px}p{color:#7e8aa5;line-height:1.7;margin:6px 0}</style></head>' +
    '<body><div class="b"><div style="font-size:52px">💤</div>' +
    '<h1>哨兵正在唤醒…</h1><p>空闲 24 分钟后哨兵已自动休眠以释放 1GB RAM。<br>首次访问需 10-15 秒加载病毒引擎，请稍候。</p>' +
    '<p style="margin-top:18px"><a style="color:#5cd2a3" href="' + req.url + '">↻ 点此重试</a></p></div></body></html>'
  );
});

(async () => {
  const bind = await tryBind(SENTINEL_PORT);
  if (!bind.ok) {
    log('启动失败：端口 ' + SENTINEL_PORT + ' 被占用 (code=' + bind.code + ')，可能是本应用已运行或端口冲突');
    log('检测已有 sentinel 进程...');
    try {
      const existing = readPid(SENTINEL_PIDF);
      if (existing > 0 && procAlive(existing)) {
        log('已有 sentinel 运行 PID=' + existing + '，本进程退出');
        process.exit(0);
      }
    } catch (_) {}
    log('没有发现已运行的 sentinel，但端口被占，等待 2 秒后退出（让 fnOS 重启时不冲突）');
    setTimeout(() => process.exit(2), 2000);
    return;
  }
  server.listen(SENTINEL_PORT, () => {
    console.log('');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('  ClamSentinel V1.0 (sentinel 守护进程)');
    console.log('  © 2026  很多问题的小明同学 · 保留所有权利');
    console.log('  授权：单机私用 · 禁止二次分发或商用');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log('');
    log('listening :' + SENTINEL_PORT + ' (web 内部 :' + WEB_PORT + ')，空闲阈值 ' + (IDLE_MS/60000) + ' 分钟');
  });
})();

/* -------- 周期调度：决定醒/睡 -------- */
setInterval(async () => {
  if (mode === 'waking' && Date.now() - wakeStartAt > WAKE_TIMEOUT) {
    log('waking 超时重置');
    mode = 'sleep';
  }
  const webUp  = await portReady(WEB_PORT, 800).catch(() => false);
  const clamUp = await portReady(3310,    600).catch(() => false);
  if (webUp && clamUp) {
    if (mode !== 'active') log('active');
    mode = 'active';
    const idleFor = Date.now() - lastActivity;
    if (idleFor > IDLE_MS && !hasRunningJob()) {
      log(`空闲 ${Math.round(idleFor/60000)} 分钟，无扫描任务 → sleep`);
      sleepNow().catch((e) => log('sleep err', e.message));
    }
  } else {
    // V1.0y5 修复：唤醒后 120s 宽限期内（clamd 仍在加载病毒库、3310 未就绪）不算失联。
    // 原逻辑：web 先起(8082)→mode=active，而 clamd 后起(3310) 需 20-30s，
    // 期间轮询误判 'web/clamd 失联 → sleep'，导致状态错乱（sentinel 以为睡了、进程却没停）。
    if (mode === 'active' && Date.now() - wakeStartAt > WAKE_GRACE_MS) { log('web/clamd 失联 → sleep'); mode = 'sleep'; }
  }
}, POLL_MS);

/* -------- 信号处理：SIGTERM 时级联停止 web+clamd 再退出 -------- */
async function handleSignal(sig) {
  log('收到 ' + sig + ' → 级联停止 web+clamd 然后退出');
  try { await sleepNow(); } catch (_) {}
  try { server.close(() => process.exit(0)); } catch (_) { process.exit(0); }
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', () => handleSignal('SIGTERM'));
process.on('SIGINT',  () => handleSignal('SIGINT'));
process.on('SIGHUP',  () => {});  // 忽略 shell hangup

process.on('uncaughtException',    (e) => log('uncaughtException',  e && (e.stack || e.message)));
process.on('unhandledRejection',   (e) => log('unhandledRejection', e && (e.stack || e.message)));

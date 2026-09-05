/* ClamSentinel · 哨兵杀毒 —— 原创前端（无框架） */
'use strict';

/* 全局错误兜底：任何未捕获异常都展示在 #app-error，便于排查，避免 JS 报错导致整个界面空白 */
window.addEventListener('error', (e) => {
  try {
    const box = document.getElementById('app-error');
    if (box) {
      box.classList.remove('hidden');
      box.textContent = '[前端异常] ' + (e.message || String(e.error || e)) +
        (e.filename ? '  at ' + e.filename + ':' + e.lineno : '');
    }
  } catch (_) { /* 静默 */ }
});

/* ============ 基础工具 ============ */
const $ = (s, r) => (r || document).querySelector(s);
const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function fmtSize(n) {
  if (n == null) return '—';
  if (n < 1024) return n + ' B';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  for (let i = 0; i < u.length; i++) {
    v /= 1024;
    if (v < 1024 || i === u.length - 1) return v.toFixed(v >= 100 ? 0 : 1) + ' ' + u[i];
  }
  return '';
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  const p = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts || {}));
  let data = null;
  try { data = await res.json(); } catch (e) { /* 空响应 */ }
  if (!res.ok) throw new Error((data && data.error) || ('HTTP ' + res.status));
  return data;
}

function toast(msg, kind) {
  const root = $('#toast-root');
  const el = document.createElement('div');
  el.className = 'toast ' + (kind || '');
  el.textContent = msg;
  root.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 2600);
  setTimeout(() => el.remove(), 3000);
}

function confirmBox(message, onOk, opts) {
  const root = $('#confirm-root');
  root.innerHTML = `
    <div class="mask">
      <div class="box">
        <p style="margin:0 0 4px;font-size:15px;font-weight:600">${esc(opts && opts.title || '请确认操作')}</p>
        <p style="color:var(--muted);line-height:1.7;margin:8px 0 0;white-space:pre-wrap">${esc(message)}</p>
        <div class="btns">
          <button class="btn" data-act="no">取消</button>
          <button class="btn ${(opts && opts.danger) ? 'btn-danger' : 'btn-primary'}" data-act="yes">${esc(opts && opts.yes || '确定')}</button>
        </div>
      </div>
    </div>`;
  $('#confirm-root .mask').addEventListener('click', (e) => { if (e.target.classList.contains('mask')) close(); });
  function close() { root.innerHTML = ''; }
  $$('#confirm-root button').forEach((b) => b.addEventListener('click', () => {
    const act = b.dataset.act;
    close();
    if (act === 'yes') onOk();
  }));
}

const ICONS = {
  folder: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="#f5b75c" stroke-width="1.8"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>',
  file: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="#8ea0bd" stroke-width="1.8"><path d="M6 2h8l4 4v16H6z"/><path d="M14 2v4h4"/></svg>',
  back: '<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 5l-7 7 7 7"/></svg>',
};

/* ============ 全局状态 ============ */
let S = { setup: true, authed: false, user: null, roots: [] };
let scanPollTimer = null;
let currentRoot = 'scan'; // 用户当前选中的扫描根 id

/* ============ 视图渲染 ============ */
function viewShell(html) { $('#view').innerHTML = html; }

async function renderDashboard() {
  let d, dbCfg, sentinelInfo;
  try { d = await api('/api/dashboard'); } catch (e) { return showError(e.message); }
  try { dbCfg = await api('/api/db/settings'); } catch (e) { dbCfg = { auto: true, hour: 9 }; }
  try { sentinelInfo = await api('/api/sentinel'); } catch (e) { sentinelInfo = { mode: 'unknown' }; }
  const engineLoading = !d.engine.online && !d.db.present;
  const engCls = d.engine.online ? 'on' : (engineLoading ? 'loading' : 'off');
  const engTxt = d.engine.online ? '扫描引擎在线' : (engineLoading ? '病毒库加载中' : '扫描引擎离线');
  // 方案 B：sentinel 模式 — 'sleep' (web+clamd 都停) / 'active' (都在) / 'waking' / 'sleeping'
  const sensorLine = (function () {
    const m = sentinelInfo.mode;
    if (m === 'sleep') {
      const mins = Math.max(0, Math.round((sentinelInfo.untilSleepSec || 0) / 60));
      return `<span class="chip" style="background:#0e7490;color:#fff;font-weight:600">💤 哨兵待命中</span> <span class="muted small">（web+clamd 已休眠 · 释放 ~1.05GB RAM）</span>`;
    }
    if (m === 'active') {
      const mins = Math.max(0, Math.round((sentinelInfo.untilSleepSec || 0) / 60));
      const minsTxt = mins >= 1 ? `${mins} 分钟后自动休眠` : `不到 1 分钟即将休眠`;
      return `<span class="chip chip-running">▶ 在线</span> <span class="muted small">${minsTxt}</span>`;
    }
    if (m === 'waking') {
      return `<span class="chip chip-running">⏳ 唤醒中</span> <span class="muted small">首次访问需 10-15 秒加载病毒引擎…</span>`;
    }
    return `<span class="muted small">${esc(m)}</span>`;
  })();
  const dbFiles = (d.db.files || []).map(f => f.replace(/\.(cvd|cld)$/i, '')).join('、') || 'main、daily、bytecode';
  const dbTxt = d.db.present
    ? '病毒库已就绪'
    : '病毒库尚未生成（首次启动请耐心等待）';
  const recent = d.recent.length
    ? d.recent.map((r) => `
      <div class="row">
        <div class="k">${fmtTime(r.createdAt)}</div>
        <div style="max-width:45%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.display || '')}">${esc(r.display || '—')}</div>
        <div><span class="chip done">${r.threatCount} 威胁 / ${r.scannedFiles} 文件</span></div>
      </div>`).join('')
    : '<div class="muted small" style="text-align:center;padding:14px">暂无扫描记录</div>';

  viewShell(`
    <div class="grid cols-4">
      <div class="card stat"><div class="num ok-text">${d.engine.online ? '在线' : (engineLoading ? '加载中' : '离线')}</div><div class="lbl">扫描引擎</div></div>
      <div class="card stat"><div class="num">${d.totals.scans}</div><div class="lbl">累计扫描次数</div></div>
      <div class="card stat"><div class="num">${d.totals.files}</div><div class="lbl">累计扫描文件</div></div>
      <div class="card stat"><div class="num ${d.totals.threats ? 'danger-text' : 'ok-text'}">${d.totals.threats}</div><div class="lbl">累计检出威胁</div></div>
    </div>

    <div class="grid cols-2 mt18">
      <div class="card">
        <h3>引擎与病毒库</h3>
        <div class="row"><span class="k engine">定时引擎</span><span class="v mono small">${sensorLine}</span></div>
        <div class="row"><span class="k">病毒库</span><span class="v small">${dbTxt}</span></div>
        <div class="row"><span class="k">隔离区</span><span class="v ${d.quarantineCount ? 'warn-text' : ''}">${d.quarantineCount} 项</span></div>
        <div class="row"><span class="k">扫描进行中</span><span class="v">${d.scanning ? (d.scanPaused ? '<span class="chip chip-paused">⏸ 已暂停</span>' : '<span class="chip running">运行中</span>') : '空闲'}</span></div>
        <div class="row toolbar" style="align-items:flex-start">
          <button class="btn btn-sm btn-primary" id="db-update-now">立即更新病毒库</button>
          <label class="muted small" style="display:flex;align-items:center;gap:6px;margin-left:8px">
            <input type="checkbox" id="db-auto" ${dbCfg.auto ? 'checked' : ''}> 每天自动更新
          </label>
          <span class="muted small" style="margin-left:8px">· 固定每天 09:00 自动更新</span>
          <span id="db-update-status" class="muted small" style="margin-right:8px"></span>
        </div>
        <div class="muted small mt6">上次更新：${dbCfg.lastUpdate ? fmtTime(dbCfg.lastUpdate) : '—'}${dbCfg.lastResult && dbCfg.lastResult.ok === false ? ' <span class="danger-text">(上次失败：' + esc(dbCfg.lastResult.msg || 'unknown') + ')</span>' : ''}</div>
        <div class="mt18" style="border-top:1px dashed var(--border);padding-top:14px">
          <div class="row toolbar" style="align-items:center">
            <button class="btn btn-sm btn-danger" id="svc-shutdown">立即停用 ClamSentinel</button>
          </div>
          <div class="muted small mt6" style="margin-left:2px">点此彻底停用（全部进程退出，唤醒需到 fnOS 应用中心点开始）。</div>
          <div class="row toolbar mt10" style="align-items:flex-start;flex-direction:column;gap:6px">
            <div>
              <span class="muted small"><b>智能睡眠</b>：由 sentinel 守护进程统一调度。</span>
            </div>
            <div class="muted small" style="line-height:1.7">
              当未在进行扫描或当10 分钟没有任何操作（无人访问 web、无扫描任务）时，sentinel 会自动停止 web+clamd 释放约 <b>1.05 GB</b> 内存（仅剩 sentinel ~30 MB）。<br>
              <b>下次恢复方式</b>：浏览器重新打开 <code>http://NAS-IP:8080</code>，sentinel 检测到访问会自动唤醒 web+clamd（约 10-15 秒）；也可到 fnOS 应用中心手动「停止/开始」一次。
            </div>
          </div>
        </div>
      </div>
      <div class="card">
        <h3>最近扫描</h3>
        ${recent}
        <div class="mt10"><a class="btn btn-sm" href="#/scan">前往扫描 →</a></div>
      </div>
    </div>
    <div class="card mt18">
      <h3>使用说明</h3>
      <ul class="small muted" style="line-height:2;padding-left:18px;margin:0">
        <li>顶部「扫描位置」可切换多个扫描根：扫描目录、整个 /vol1、我的文件、团队空间、外接存储。</li>
        <li>选中根目录后可浏览子目录，对单文件或整目录点「扫描」；「扫描整个当前位置」会递归扫描当前根。</li>
        <li>扫描进行中可点「暂停扫描」随时中止，再点同一按钮恢复（不会丢失已完成进度）。</li>
        <li>检出结果支持「隔离 / 删除」；隔离区可恢复或彻底删除。</li>
        <li>隔离与删除会直接改动文件，建议先用小文件验证流程。</li>
      </ul>
    </div>
    <div class="card mt18 about-author" style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
      <img src="images/qrcode-wechat-only.png" alt="微信公众号二维码" style="width:120px;height:120px;border-radius:8px;background:#fff;padding:6px;flex-shrink:0" onerror="this.style.display='none'">
      <div style="flex:1;min-width:240px">
        <div style="font-size:15px;font-weight:600;margin-bottom:6px;color:var(--primary,#3b82f6)">关于作者</div>
        <div class="muted small" style="line-height:1.8">
          微信公众号：<b>很多问题的小明同学</b>（扫码关注）<br>
          GitHub：<a href="https://github.com/gulugulupao" target="_blank" rel="noopener" style="color:var(--primary,#3b82f6)">@gulugulupao</a><br>
          项目仓库：<a href="https://github.com/gulugulupao/clamsentinel" target="_blank" rel="noopener" style="color:var(--primary,#3b82f6)">gulugulupao/clamsentinel</a>
        </div>
        <div class="muted small" style="margin-top:8px;opacity:0.7">有 Bug / 改进建议欢迎公众号留言或 GitHub 提 Issue · 持续更新中</div>
      </div>
    </div>
    <div class="card mt18 legal-note">
      <div class="muted small" style="line-height:1.9;opacity:0.85">
        <b style="color:var(--muted);">关于本应用与免责声明</b><br>
        ClamSentinel 应用属于社区提供的额外辅助安全方案，与飞牛官方无关，不属于官方安全体系。<br>
        本应用不提供任何形式的明示或默示担保；其病毒扫描能力完全取决于 ClamAV（思科 Talos 团队维护）的病毒库与签名规则、以及用户自行配置的可疑文件处理方式。<br>
        在 fnOS 应用市场安装并使用本应用时，出现的任何性能、表现、兼容性及其他问题，均应由用户自行承担；如本应用与您的硬件/系统环境存在不兼容或冲突，请及时卸载以恢复原状。
      </div>
    </div>
    <div class="muted small mt18" style="text-align:center;padding-top:10px;border-top:1px dashed var(--border);opacity:0.7">
      © 很多问题的小明同学 · ClamSentinel V1.0 · 开源免费 · 禁止商用
    </div>
  `);
  bindDbControls();
}

async function bindDbControls() {
  const $now = $('#db-update-now'), $auto = $('#db-auto'), $stat = $('#db-update-status');
  const $svcShut = $('#svc-shutdown');
  if ($now) $now.addEventListener('click', async () => {
    $now.disabled = true; $stat.textContent = '正在更新...';
    try {
      const r = await api('/api/db/update', { method: 'POST' });
      if (r.ok) {
        $stat.textContent = '✓ 更新成功';
        $stat.className = 'ok-text small';
        setTimeout(() => api('/api/db/settings').then(()=>{}).catch(()=>{}), 1500);
      } else {
        $stat.textContent = '✗ ' + (r.error || '失败');
        $stat.className = 'danger-text small';
        toast(r.error || '病毒库更新失败', 'err');
      }
    } catch (e) {
      $stat.textContent = '✗ ' + e.message;
      $stat.className = 'danger-text small';
      toast(e.message, 'err');
    }
    $now.disabled = false;
  });
  if ($auto) $auto.addEventListener('change', async () => {
    try {
      await api('/api/db/settings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ auto: $auto.checked, hour: 9 }) });
      toast('已保存（每天 09:00 自动更新）', 'ok');
    } catch (e) { toast(e.message, 'err'); }
  });
  // v3.3.0: 「立即停用」—— 仅 sentinel + web+clamd 立即全停。重启需去 fnOS 应用中心。
  if ($svcShut) $svcShut.addEventListener('click', async () => {
    if (!confirm('立即停用 ClamSentinel 将：\n\n· 关闭 sentinel（端口 8080 立即无响应）\n· 关闭 web+clamd（释放约 1 GB 内存）\n· 关闭 freshclam 后台循环\n\n从应用中心「开始」可重新启动。\n\n确认停用？')) return;
    $svcShut.disabled = true;
    $svcShut.textContent = '停用中...';
    try {
      const r = await api('/api/service/shutdown', { method: 'POST' });
      if (r.ok) {
        $svcShut.textContent = '已停用';
        $svcShut.classList.add('btn-success');
        toast('已通知 cmd/main stop，约 2 秒后所有进程会下线', 'ok', 4000);
        setTimeout(() => { try { location.reload(); } catch (_) {} }, 2200);
      } else {
        $svcShut.disabled = false;
        $svcShut.textContent = '立即停用 ClamSentinel';
        toast(r.error || '停用失败', 'err');
      }
    } catch (e) {
      $svcShut.disabled = false;
      $svcShut.textContent = '立即停用 ClamSentinel';
      toast(e.message, 'err');
    }
  });
  // 周期拉取 sentinel 状态，更新「即将休眠」倒计时 + 引擎徽标
  if (!window._sentinelPolling) {
    window._sentinelPolling = setInterval(async () => {
      try {
        const s = await api('/api/sentinel');
        const rows = $$('.row.toolbar .muted.small').forEach(() => {}); // no-op
        // 简单：找到顶部的"在线 / 待命"chip 的父行并就地刷新文字
        const sensorRow = $$('.row.engine, .row .chip').find((c) => /在线|哨兵|唤醒/.test(c.textContent || ''));
        if (sensorRow && sensorRow.parentElement) {
          const m = s.mode, mins = Math.max(0, Math.round((s.untilSleepSec || 0) / 60));
          let html = '';
          if (m === 'sleep') {
            html = `<span class="chip" style="background:#0e7490;color:#fff;font-weight:600">💤 哨兵待命中</span> <span class="muted small">（web+clamd 已休眠 · 释放 ~1.05GB RAM）</span>`;
          } else if (m === 'active') {
            const txt = mins >= 1 ? `${mins} 分钟后自动休眠` : '不到 1 分钟即将休眠';
            html = `<span class="chip chip-running">▶ 在线</span> <span class="muted small">${txt}</span>`;
          } else if (m === 'waking') {
            html = `<span class="chip chip-running">⏳ 唤醒中</span> <span class="muted small">首次访问需 10-15 秒加载病毒引擎…</span>`;
          } else {
            html = `<span class="muted small">${esc(m)}</span>`;
          }
          sensorRow.parentElement.innerHTML = html + '<span class="v mono small">' + esc('—') + '</span>';
        }
      } catch (_) {}
    }, 15 * 1000);
  }
}

function scanRootLabel() { return '/scan（宿主机 /vol1/@appshare/clamsentinel/scan）'; }

/* ------- 病毒扫描（多根目录浏览） ------- */
let browseRel = '';
let browsePage = 1;

function rootChips() {
  const roots = S.roots && S.roots.length ? S.roots : [{ id: 'scan', label: '扫描目录' }];
  return roots.map((r) => `
    <button class="root-chip ${r.id === currentRoot ? 'active' : ''}" data-root="${esc(r.id)}" title="${esc(r.path)}">
      <i class="root-dot"></i><span>${esc(r.label)}</span><em class="mono">${esc(r.path)}</em>
    </button>
  `).join('');
}

async function renderScan(dir) {
  browseRel = dir || '';
  let d;
  try { d = await api('/api/browse?root=' + encodeURIComponent(currentRoot) + '&path=' + encodeURIComponent(browseRel)); }
  catch (e) { return showError(e.message); }
  const crumbParts = buildCrumb(browseRel, d.rootPath);
  // 文件列表分页：每页 5 行（避免长列表把底部"扫描进度"顶到看不见的地方）
  const PAGE_SIZE = 5;
  const allEntries = d.entries || [];
  browsePage = (parseInt((location.hash.match(/page=(\d+)/) || [])[1], 10) || 1);
  if (browsePage > Math.max(1, Math.ceil(allEntries.length / PAGE_SIZE))) browsePage = 1;
  const totalPages = Math.max(1, Math.ceil(allEntries.length / PAGE_SIZE));
  const startIdx = (browsePage - 1) * PAGE_SIZE;
  const pageEntries = allEntries.slice(startIdx, startIdx + PAGE_SIZE);
  const rows = pageEntries.map((it) => `
    <tr>
      <td class="name-cell">${it.dir ? ICONS.folder : ICONS.file}
        <span>${esc(it.name)}</span></td>
      <td class="muted small">${it.dir ? '目录' : '文件'}</td>
      <td class="muted small">${it.dir ? '—' : fmtSize(it.size)}</td>
      <td class="muted small">${fmtTime(it.mtime)}</td>
      <td>
        <div class="toolbar">
          ${it.dir ? `<button class="btn btn-sm" data-act="open" data-rel="${esc(it.rel)}">进入</button>` : ''}
          <button class="btn btn-sm btn-primary" data-act="scan" data-rel="${esc(it.rel)}" data-name="${esc(it.name)}">扫描</button>
        </div>
      </td>
    </tr>`).join('');
  const pager = totalPages > 1 ? `
    <div class="toolbar mt6" style="justify-content:flex-end">
      <span class="muted small">第 ${browsePage} / ${totalPages} 页（${allEntries.length} 项）</span>
      <button class="btn btn-sm" data-act="page-prev" ${browsePage <= 1 ? 'disabled' : ''}>上一页</button>
      <button class="btn btn-sm" data-act="page-next" ${browsePage >= totalPages ? 'disabled' : ''}>下一页</button>
    </div>` : '';

  viewShell(`
    <div class="card">
      <div class="toolbar mb10 root-toolbar">
        <span class="muted small">扫描位置：</span>
        ${rootChips()}
      </div>
      <div class="toolbar mb10">
        <span class="muted small mono">${esc(d.rootPath || '')}</span>
      </div>
      <div class="toolbar mb10">${crumbParts.join('')}</div>
      <div class="toolbar mb10">
        <button class="btn" id="scan-refresh">刷新</button>
        <button class="btn btn-danger" data-act="scan-root">扫描整个当前位置</button>
        <span id="scan-hint" class="muted small"></span>
      </div>
      <table class="list">
        <thead><tr><th>名称</th><th>类型</th><th>大小</th><th>修改时间</th><th style="width:170px">操作</th></tr></thead>
        <tbody>
          ${d.parent != null ? `<tr><td class="name-cell" colspan="5"><button class="btn btn-ghost btn-sm" data-act="up">${ICONS.back} 返回上级目录</button></td></tr>` : ''}
          ${rows || ''}
        </tbody>
      </table>
      ${pager}
      ${(!rows && d.parent == null) ? '<div class="empty">此位置为空。<br><span class="small">可把待扫描文件直接放入对应位置</span></div>' : ''}
    </div>
    <div id="scan-status"></div>
  `);
  bindScanEvents(d);
}

function buildCrumb(rel, rootPath) {
  const parts = rel ? rel.split('/').filter(Boolean) : [];
  let acc = '';
  const out = [`<button class="btn btn-sm btn-ghost" data-act="goto" data-rel="">${esc(rootPath || '根')}</button>`];
  parts.forEach((p, i) => {
    acc = acc ? acc + '/' + p : p;
    out.push(`<span class="muted">/</span><button class="btn btn-sm btn-ghost" data-act="goto" data-rel="${esc(acc)}">${esc(p)}</button>`);
  });
  return out;
}

function bindScanEvents(d) {
  $$('#view [data-act]').forEach((el) => el.addEventListener('click', async () => {
    const act = el.dataset.act;
    if (act === 'open') renderScan(el.dataset.rel);
    else if (act === 'up') renderScan(d.parent);
    else if (act === 'goto') renderScan(el.dataset.rel);
    else if (act === 'refresh') renderScan(browseRel);
    else if (act === 'page-prev') { browsePage = Math.max(1, browsePage - 1); renderScan(browseRel); }
    else if (act === 'page-next') { browsePage = browsePage + 1; renderScan(browseRel); }
    else if (act === 'scan-root') { const r = await doScan('', currentRoot); if (r) pollScanStatus(); }
    else if (act === 'scan') { const r = await doScan(el.dataset.rel, currentRoot); if (r) pollScanStatus(); }
  }));
  $$('#view [data-root]').forEach((el) => el.addEventListener('click', () => {
    currentRoot = el.dataset.root;
    renderScan('');
  }));
  $('#scan-refresh').addEventListener('click', () => renderScan(browseRel));
}

async function doScan(rel, rootId) {
  try {
    await api('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ root: rootId, path: rel }) });
    toast('已开始扫描', 'ok');
    return true;
  } catch (e) {
    toast(e.message, 'err');
    return false;
  }
}

/* 扫描状态轮询 */
let scanPaused = false;  // 与 server 端 paused 同步
async function pollScanStatus() {
  if (scanPollTimer) return;
  scanPollTimer = setInterval(async () => {
    try {
      const d = await api('/api/jobs');
      const running = d.jobs.find((j) => j.status === 'running');   // abandoned 不算
      const box = $('#scan-status');
      if (running) {
        scanPaused = !!running.paused;
        if (scanPaused) {
          // ╔═══ 已暂停视觉反馈（黄底 + ⏸ + 绿底"继续扫描"按钮） ═══╗
          if (box) box.innerHTML = `<div class="card mt10 scan-paused-card">
            <div class="toolbar mb10" style="align-items:center">
              <span class="pulse-icon pulse-paused" style="font-size:22px;margin-right:4px">⏸</span>
              <b style="color:#f5a623;font-size:15px">已暂停扫描</b>
              <span class="muted small">· 目标：${esc(running.display || '—')}</span>
              <span class="chip chip-paused">暂停中</span>
              <button class="btn btn-sm scan-resume-btn" data-act="scan-resume" style="margin-left:auto">▶ 继续扫描</button>
            </div>
            <div class="small muted">已处理 <b>${running.scannedFiles}</b> 个对象 · 检出 <b>${running.threatCount || 0}</b> 项威胁</div>
          </div>`;
        } else {
          // ╔═══ 正在扫描视觉反馈（蓝底 + ▶ + 黄底"暂停扫描"按钮） ═══╗
          if (box) box.innerHTML = `<div class="card mt10 scan-running-card">
            <div class="toolbar mb10" style="align-items:center">
              <span class="pulse-icon pulse-running" style="font-size:22px;margin-right:4px">▶</span>
              <b style="color:#3b82f6;font-size:15px">正在扫描</b>
              <span class="muted small">· 目标：${esc(running.display || '—')}</span>
              <span class="chip chip-running">扫描中</span>
              <button class="btn btn-sm btn-warn scan-pause-btn" data-act="scan-pause" style="margin-left:auto">⏸ 暂停扫描</button>
            </div>
            <div class="small muted">已处理 <b>${running.scannedFiles}</b> 个对象 · 检出 <b>${running.threatCount || 0}</b> 项威胁</div>
            <div class="progress"><i class="progress-running" style="width:40%"></i></div>
          </div>`;
        }
        bindScanActions();
        $('#top-status').innerHTML = scanPaused
          ? `<span class="chip chip-paused">⏸ 已暂停</span>`
          : `<span class="chip chip-running">扫描中…</span>`;
      } else {
        if (box) box.innerHTML = '';
        $('#top-status').innerHTML = '';
        scanPaused = false;
      }
    } catch (e) { /* 忽略 */ }
  }, 1500);
}

/* 给 scan-status 内的暂停/继续按钮挂事件 */
function bindScanActions() {
  $$('#scan-status [data-act="scan-pause"]').forEach((el) => el.addEventListener('click', async () => {
    try { await api('/api/scan/pause', { method: 'POST' }); scanPaused = true; }
    catch (e) { toast(e.message, 'err'); }
  }));
  $$('#scan-status [data-act="scan-resume"]').forEach((el) => el.addEventListener('click', async () => {
    try { await api('/api/scan/resume', { method: 'POST' }); scanPaused = false; }
    catch (e) { toast(e.message, 'err'); }
  }));
}

/* ============ 顶部系统监控（CPU/Cores/RAM） 3 秒刷新 ============ */
let sysPollTimer = null;
function fmtKB(n) { // Meminfo 是 kB
  if (!n || n < 0) return '—';
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i += 1; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i];
}
async function pollSystem() {
  if (sysPollTimer) return;
  const cpuVal = $('#sys-cpu-val'), cpuBar = $('#sys-cpu-bar'), coresVal = $('#sys-cores-val');
  const ramVal = $('#sys-ram-val'), ramBar = $('#sys-ram-bar'), ramSub = $('#sys-ram-sub');
  const cpuRow = $('#sys-cpu-row'), ramRow = $('#sys-ram-row');
  const setClass = (el, cls) => { el.classList.remove('warn', 'danger'); if (cls) el.classList.add(cls); };
  const render = () => {
    api('/api/system').then((d) => {
      const cpu = Number(d.cpu || 0);
      cpuVal.textContent = cpu.toFixed(1) + '%';
      cpuBar.style.width = cpu + '%';
      coresVal.textContent = (d.cores || 1) + ' cores';
      setClass(cpuRow, cpu > 85 ? 'danger' : (cpu > 65 ? 'warn' : null));
      const ramPct = d.ram && d.ram.total ? Math.round((d.ram.used / d.ram.total) * 100) : 0;
      ramVal.textContent = ramPct + '%';
      ramBar.style.width = ramPct + '%';
      ramSub.textContent = fmtKB(d.ram.used) + ' / ' + fmtKB(d.ram.total);
      setClass(ramRow, ramPct > 90 ? 'danger' : (ramPct > 75 ? 'warn' : null));
    }).catch(() => { /* 后端未就绪时静默 */ });
  };
  render();
  sysPollTimer = setInterval(render, 3000); // 3 秒采样一次
}
function stopSystemPoll() {
  if (sysPollTimer) { clearInterval(sysPollTimer); sysPollTimer = null; }
}

/* ------- 扫描记录 ------- */
async function renderRecords() {
  let d;
  try { d = await api('/api/jobs'); } catch (e) { return showError(e.message); }
  const fmtTarget = (j) => {
    const t = (j.display || '').trim();
    return t || ('/' + (j.rootLabel || '').replace(/^整个 /, ''));
  };
  const rows = d.jobs.map((j) => `
    <tr data-id="${esc(j.id)}">
      <td class="small muted">${fmtTime(j.createdAt)}</td>
      <td class="name-cell"><span class="mono small" style="max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block" title="${esc(fmtTarget(j))}">${esc(fmtTarget(j))}</span></td>
      <td>${statusChip(j.status)}</td>
      <td class="muted">${j.scannedFiles || 0}</td>
      <td class="${j.threatCount ? 'warn-text' : ''}">${j.threatCount || 0}</td>
      <td><button class="btn btn-sm" data-detail="${esc(j.id)}">详情</button></td>
    </tr>`).join('');
  viewShell(`
    <div class="card">
      <h3>扫描记录（近 100 条）</h3>
      <table class="list">
        <thead><tr><th>时间</th><th>目标</th><th>状态</th><th>文件数</th><th>威胁</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="empty">暂无记录</td></tr>'}</tbody>
      </table>
    </div>`);
  $$('#view [data-detail]').forEach((b) => b.addEventListener('click', () => renderRecordDetail(b.dataset.detail)));
}

function statusChip(st) {
  const map = {
    running: ['running', '进行中'],
    done: ['done', '完成'],
    failed: ['failed', '失败'],
    abandoned: ['warn', '已中断'],   // v3.3.1：web 重启前留下的僵尸任务
  };
  const c = map[st] || ['done', st];
  return `<span class="chip ${c[0]}">${c[1]}</span>`;
}

async function renderRecordDetail(id) {
  let j;
  try { j = await api('/api/jobs/' + id); } catch (e) { return showError(e.message); }
  const threats = j.threats || [];
  const errs = j.errors || [];
  const samples = j.sampleFiles || [];
  const trRows = threats.length
    ? threats.map((t, i) => `
      <tr>
        <td><input type="checkbox" data-idx="${i}" class="tcheck"></td>
        <td class="small mono" style="word-break:break-all">${esc(t.rel)}</td>
        <td><span class="chip threat">${esc(t.name)}</span></td>
      </tr>`).join('')
    : '<tr><td colspan="3" class="muted">本次扫描未检出威胁</td></tr>';

  const sampleRows = samples.length
    ? samples.map((p) => `<div class="sample-line"><svg class="ico-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><path d="M14 3v6h6"/></svg><span class="mono">${esc(p)}</span></div>`).join('')
    : '<div class="muted small">本次任务未保留样本（任务刚启动、或扫描中暂未持久化）</div>';

  viewShell(`
    <button class="btn btn-ghost btn-sm mb10" data-act="back-records" onclick="location.hash='#/records'">← 返回记录</button>
    <div class="card">
      <h3>任务详情</h3>
      <div class="row"><span class="k">目标</span><span class="v mono small">${esc(j.display)}</span></div>
      <div class="row"><span class="k">状态</span><span class="v">${statusChip(j.status)}${j.error ? ' <span class="small danger-text">' + esc(j.error) + '</span>' : ''}</span></div>
      <div class="row"><span class="k">时间</span><span class="v small">${fmtTime(j.startedAt)} → ${fmtTime(j.endedAt)}</span></div>
      <div class="row"><span class="k">已扫描对象</span><span class="v">${j.scannedFiles || 0}</span></div>
      <div class="row"><span class="k">抽样文件路径</span><span class="v small muted">${samples.length} 个${j.scannedFiles > samples.length ? '（最多保留前 200 个）' : ''}</span></div>
      <div class="row"><span class="k">检出威胁</span><span class="v ${j.threatCount ? 'danger-text' : ''}">${j.threatCount || 0}${j.truncated ? '（明细已截断）' : ''}</span></div>
      <div class="row"><span class="k">错误</span><span class="v small muted">${errs.length} 条${errs.length ? '（多为不可读文件/目录）' : ''}</span></div>
    </div>

    <div class="card mt18">
      <h3>已扫描文件清单（前 ${samples.length} 个）</h3>
      <div class="muted small mb10">提示：仅展示 clamd 实际扫描过的文件路径（前 200 个）。如需查看完整扫描对象数，请看上方数字。</div>
      <div class="sample-list">${sampleRows}</div>
    </div>

    ${threats.length ? `
    <div class="card mt18">
      <h3>检出清单与处置</h3>
      <div class="toolbar mb10">
        <button class="btn btn-sm" id="sel-all">全选</button>
        <button class="btn btn-sm btn-danger" id="dis-del">删除选中</button>
        <button class="btn btn-sm btn-warn" id="dis-qua">隔离选中</button>
        <button class="btn btn-sm btn-warn" id="dis-all-qua">全部隔离</button>
        <span class="muted small">已选 <b id="sel-cnt">0</b> 项</span>
      </div>
      <table class="list"><thead><tr><th style="width:32px"></th><th>文件</th><th>威胁名</th></tr></thead>
      <tbody>${trRows}</tbody></table>
    </div>` : ''}

    ${errs.length ? `<div class="card mt18"><h3>错误/告警（前 200 条）</h3><div class="small muted mono" style="line-height:1.9;max-height:220px;overflow:auto">${errs.map(esc).join('<br>')}</div></div>` : ''}
  `);

  // 详情返回记录：用 addEventListener 而非 inline onclick，避开某些浏览器的安全策略差异
  $$('#view [data-act="back-records"]').forEach((el) => el.addEventListener('click', () => { location.hash = '#/records'; }));

  if (threats.length) {
    bindDispose(id, threats.length);
  }
}

function selectedIndices() {
  return $$('#view .tcheck:checked').map((c) => Number(c.dataset.idx));
}
function updateSelCnt() { const c = $('#sel-cnt'); if (c) c.textContent = selectedIndices().length; }

function bindDispose(jobId, total) {
  $$('#view .tcheck').forEach((c) => c.addEventListener('change', updateSelCnt));
  $('#sel-all').addEventListener('click', () => {
    const checks = $$('#view .tcheck');
    const allOn = checks.every((c) => c.checked);
    checks.forEach((c) => { c.checked = !allOn; });
    updateSelCnt();
  });
  const dispose = (action, indices, msg) => {
    const run = async () => {
      try {
        await api('/api/dispose', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ job: jobId, action, indices }) });
        toast(action === 'delete' ? '已删除' : '已隔离', 'ok');
        renderRecordDetail(jobId);
      } catch (e) { toast(e.message, 'err'); }
    };
    if (action === 'delete') confirmBox(msg + '\n\n该操作不可恢复！', run, { danger: true, title: '确认删除' });
    else confirmBox(msg, run, { title: '确认隔离' });
  };
  $('#dis-del').addEventListener('click', () => {
    const idx = selectedIndices();
    if (!idx.length) return toast('请先勾选条目', 'err');
    dispose('delete', idx, `确定删除选中的 ${idx.length} 个威胁文件吗？`);
  });
  $('#dis-qua').addEventListener('click', () => {
    const idx = selectedIndices();
    if (!idx.length) return toast('请先勾选条目', 'err');
    dispose('quarantine', idx, `确定将选中的 ${idx.length} 个威胁文件移入隔离区吗？`);
  });
  $('#dis-all-qua').addEventListener('click', () => dispose('quarantine', [], `确定将本任务检出的全部 ${total} 个威胁文件移入隔离区吗？`));
}

/* ------- 隔离区 ------- */
async function renderQuarantine() {
  let d;
  try { d = await api('/api/quarantine'); } catch (e) { return showError(e.message); }
  const rows = d.list.map((it) => `
    <tr>
      <td class="small muted">${fmtTime(it.at)}</td>
      <td class="small mono" style="word-break:break-all">${esc(it.orig)}</td>
      <td><span class="chip threat">${esc(it.name)}</span></td>
      <td><span class="small muted">${esc(it.location.split('/').pop())}</span></td>
      <td><div class="toolbar">
        <button class="btn btn-sm btn-primary" data-act="restore" data-id="${esc(it.location)}">恢复</button>
        <button class="btn btn-sm btn-danger" data-act="purge" data-id="${esc(it.location)}">删除</button>
      </div></td>
    </tr>`).join('');
  viewShell(`
    <div class="card">
      <h3>隔离区（${d.list.length} 项）</h3>
      <p class="small muted" style="margin-top:0">恢复会把文件放回原路径；「删除」为彻底删除隔离文件。</p>
      <table class="list">
        <thead><tr><th>时间</th><th>原路径</th><th>威胁名</th><th>隔离文件名</th><th style="width:150px">操作</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="empty">隔离区为空</td></tr>'}</tbody>
      </table>
    </div>`);
  $$('#view [data-act]').forEach((b) => b.addEventListener('click', () => {
    const act = b.dataset.act;
    const id = b.dataset.id;
    const doIt = async () => {
      try {
        await api(act === 'restore' ? '/api/quarantine/restore' : '/api/quarantine/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
        toast(act === 'restore' ? '已恢复' : '已删除', 'ok');
        renderQuarantine();
      } catch (e) { toast(e.message, 'err'); }
    };
    if (act === 'purge') confirmBox('将彻底删除该隔离文件，不可恢复。确定继续？', doIt, { danger: true });
    else confirmBox('将文件恢复到原路径。若原位置已有同名文件则恢复失败。确定继续？', doIt);
  }));
}

/* ------- 设置 ------- */
async function renderSettings() {
  viewShell(`
    <div style="display:flex;flex-direction:column;gap:18px;min-height:100%;">
      <div class="card">
        <h3>修改登录密码</h3>
        <div class="field"><label>原密码</label><input id="pw-old" type="password"></div>
        <div class="field"><label>新密码（至少 8 位）</label><input id="pw-new" type="password"></div>
        <div class="field"><label>确认新密码</label><input id="pw-new2" type="password"></div>
        <button class="btn btn-primary" id="pw-save">保存密码</button>
      </div>
      <div style="flex:1 0 auto;"></div>
      <div class="card">
        <h3>关于</h3>
        <div class="row"><span class="k">扫描引擎</span><span class="v">ClamAV（官方开源引擎）</span></div>
        <div class="row"><span class="k">作者</span><span class="v">很多问题的小明同学</span></div>
        <div class="row"><span class="k">GitHub</span><span class="v">@gulugulupao</span></div>
      </div>
    </div>`);
  $('#pw-save').addEventListener('click', async () => {
    if ($('#pw-new').value !== $('#pw-new2').value) return toast('两次输入的新密码不一致', 'err');
    try {
      await api('/api/settings/password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oldPassword: $('#pw-old').value, newPassword: $('#pw-new').value }) });
      toast('密码已更新', 'ok');
      $$('#view input').forEach((i) => i.value = '');
    } catch (e) { toast(e.message, 'err'); }
  });
}

function showError(msg) {
  // 用 toast 浮窗，不替换 #view 内容（避免破坏当前页面）
  toast(msg || '未知错误', 'err');
}

/* ============ 路由 ============ */
async function route() {
  const hash = location.hash || '#/dashboard';
  const m = hash.match(/^#\/jobs\/([\w-]+)/);
  const views = {
    '#/dashboard': renderDashboard,
    '#/scan': () => renderScan(''),
    '#/records': renderRecords,
    '#/quarantine': renderQuarantine,
    '#/settings': renderSettings,
  };
  const titles = {
    '#/dashboard': '状态面板',
    '#/scan': '病毒扫描',
    '#/records': '扫描记录',
    '#/quarantine': '隔离区',
    '#/settings': '系统设置',
  };
  $$('.nav-item').forEach((n) => n.classList.toggle('active', n.getAttribute('href') === hash));
  $('#crumb').innerHTML = m ? '<small style="font-weight:400">扫描记录 / 详情</small>' : (titles[hash] || '');
  if (m) { await renderRecordDetail(m[1]); return; }
  const fn = views[hash];
  if (fn) { await fn(); return; }
  if (!views[hash]) { location.hash = '#/dashboard'; }
}

/* ============ 认证视图 ============ */
function showAuthView(mode) {
  $('#app').classList.add('hidden');
  $('#auth-view').classList.remove('hidden');
  const isSetup = mode === 'setup';
  // 用 form data-mode 标记当前模式（避免靠 hidden class 反向推断）
  $('#auth-form').dataset.mode = isSetup ? 'setup' : 'login';
  $('#auth-title').textContent = isSetup ? '首次初始化' : '登录';
  $('#auth-sub').textContent = isSetup ? '创建系统首个管理员账号' : '欢迎回来，请输入管理员账号';
  // 确认密码字段：setup 和 login 都显示（用户希望"输两遍防错"）
  const pass2 = $('#auth-pass2-field') || $('#auth-pass2').parentElement;
  if (pass2) pass2.classList.remove('hidden');
  $('#auth-btn').textContent = isSetup ? '创建并进入' : '登录';
  $('#auth-err').classList.add('hidden');
  $('#auth-user').value = 'admin';
  // 密码字段不预填（用户要求只在脚注说明默认值，不在输入框填入）
  $('#auth-pass').value = '';
  $('#auth-pass2').value = '';
  // 确认密码字段：只在 setup 模式显示（登录模式不需要）
  const pass2Field = $('#auth-pass2-field') || $('#auth-pass2').parentElement;
  if (pass2Field) {
      if (isSetup) pass2Field.classList.remove('hidden');
      else pass2Field.classList.add('hidden');
  }
  $('#auth-foot').innerHTML = isSetup
    ? '① 用户名默认 <b>admin</b>，可改为其他（3-20 字符）<br>② 密码 8-16 位任意字符，建议用你能记住的强密码（<b>下方有确认密码框</b>，请再输一次确认一致）<br>③ 完成初始化后请记下用户名+密码，<b>妥善保存</b>'
    : '① 用户名默认 <b>admin</b>（如有多个管理员请填对应的）<br>② 默认密码为：<b>test1234</b>（首次初始化时设的，<b>建议登录后立刻修改</b>）<br>③ 如需修改<b>密码</b>，可在「系统设置」页修改';
  pollSystem(); // 登录前也能在右上看 CPU/RAM
}

function bindAuthForm() {
  $('#auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#auth-err');
    err.classList.add('hidden');
    const isSetup = $('#auth-form').dataset.mode === 'setup';
    const btn = $('#auth-btn');
    btn.disabled = true;
    try {
      if (isSetup) {
        if ($('#auth-pass').value !== $('#auth-pass2').value) throw new Error('两次输入的密码不一致');
        await api('/api/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: $('#auth-user').value, password: $('#auth-pass').value }) });
        toast('初始化完成，欢迎使用', 'ok');
      } else {
        // 登录模式：可选校验"确认密码"（如果用户填了就必须一致，防输错）
        const pw1 = $('#auth-pass').value, pw2 = $('#auth-pass2').value;
        if (pw2 && pw2 !== pw1) throw new Error('两次输入的密码不一致');
        await api('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: $('#auth-user').value, password: pw1 }) });
        toast('登录成功', 'ok');
      }
      enterApp();
    } catch (ex) {
      err.textContent = ex.message;
      err.classList.remove('hidden');
    } finally {
      btn.disabled = false;
    }
  });
}

function enterApp() {
  $('#auth-view').classList.add('hidden');
  $('#app').classList.remove('hidden');
  loadAppState();
}

async function loadAppState() {
  try {
    const st = await api('/api/state');
    S = st;
    if (st.roots && st.roots.length) S.roots = st.roots;
    if (st.setup) { showAuthView('setup'); return; }
    if (!st.authed) { showAuthView('login'); return; }
    $('#who-name').textContent = st.user ? st.user.name : '';
    if (!$('#top-status')) addTopStatus();
    route();
    pollScanStatus();
    pollSystem();
  } catch (e) {
    showAuthView('login');
  }
}

function addTopStatus() {
  const el = document.createElement('span');
  el.id = 'top-status';
  $('#top-actions').appendChild(el);
  return el;
}

/* ============ 启动 ============ */
window.addEventListener('hashchange', () => {
  if (!S.authed) return;
  route();
});

$('#logout-btn').addEventListener('click', async () => {
  try { await api('/api/logout', { method: 'POST' }); } catch (e) { /* 忽略 */ }
  if (scanPollTimer) { clearInterval(scanPollTimer); scanPollTimer = null; }
  stopSystemPoll();
  loadAppState();
});

window.addEventListener('load', () => {
  bindAuthForm();
  setTimeout(() => { $('#boot').classList.add('hidden'); loadAppState(); }, 250);
});

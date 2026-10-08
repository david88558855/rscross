/* rscross 控制台前端
 * 无构建步骤的 SPA：hash 路由 + fetch。所有插值都经 esc() 转义，防 XSS。
 * 交互与信息架构参考 gostc-open 的后台风格（仅风格参考，未复用其代码）。
 *
 * 两种部署形态共用这一套 UI：
 *   独立控制台（rscross-console） → 管理多个「服务端节点」
 *   内嵌控制台（rscross-server）   → 节点列表里只有本机一行，其余用法不变
 */
(function () {
  'use strict';

  const TOKEN_KEY = 'rscross.token';
  const state = {
    token: localStorage.getItem(TOKEN_KEY) || '',
    user: null,
    nodes: [],
    clients: [],
    tunnels: [],
    version: '',
    embedded: false,
    logsTimer: null,
    logsAuto: true,
    logLevel: '',
    logKeyword: '',
  };

  // ------------------------------------------------------------ 基础工具

  const $ = (id) => document.getElementById(id);

  function esc(value) {
    if (value === null || value === undefined) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function toast(message, kind) {
    let wrap = document.querySelector('.toast-wrap');
    if (!wrap) {
      wrap = document.createElement('div');
      wrap.className = 'toast-wrap';
      document.body.appendChild(wrap);
    }
    const el = document.createElement('div');
    el.className = 'toast' + (kind ? ' ' + kind : '');
    el.textContent = message;
    wrap.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  async function api(path, options) {
    const opts = Object.assign({ method: 'GET' }, options || {});
    opts.headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    if (state.token) opts.headers.Authorization = 'Bearer ' + state.token;
    if (opts.body && typeof opts.body !== 'string') opts.body = JSON.stringify(opts.body);

    const res = await fetch(path, opts);
    if (res.status === 401) {
      logoutLocal();
      throw new Error('会话已过期，请重新登录');
    }
    const text = await res.text();
    let payload = null;
    if (text) {
      try { payload = JSON.parse(text); } catch (_) { payload = { message: text }; }
    }
    if (!res.ok) {
      throw new Error((payload && payload.message) || ('请求失败 HTTP ' + res.status));
    }
    return payload;
  }

  function logoutLocal() {
    state.token = '';
    state.user = null;
    localStorage.removeItem(TOKEN_KEY);
    if (state.logsTimer) { clearInterval(state.logsTimer); state.logsTimer = null; }
    location.hash = '#/login';
    render();
  }

  function fmtBytes(n) {
    n = Number(n || 0);
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return i === 0 ? n + ' B' : n.toFixed(2) + ' ' + units[i];
  }

  function fmtTime(raw) {
    if (!raw) return '—';
    const d = new Date(raw);
    if (isNaN(d.getTime())) return esc(raw);
    const pad = (x) => String(x).padStart(2, '0');
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
      ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function relTime(raw) {
    if (!raw) return '从未';
    const diff = (Date.now() - new Date(raw).getTime()) / 1000;
    if (isNaN(diff)) return '—';
    if (diff < 60) return Math.max(0, Math.round(diff)) + ' 秒前';
    if (diff < 3600) return Math.round(diff / 60) + ' 分钟前';
    if (diff < 86400) return Math.round(diff / 3600) + ' 小时前';
    return Math.round(diff / 86400) + ' 天前';
  }

  function statusTag(status) {
    const map = {
      online: ['ok', '在线'],
      pending: ['warn', '待接入'],
      offline: ['bad', '离线'],
      disabled: ['bad', '已禁用'],
    };
    const hit = map[status] || ['info', status || '未知'];
    return '<span class="tag ' + hit[0] + '"><i class="dot"></i>' + esc(hit[1]) + '</span>';
  }

  function protoTag(proto) {
    const map = { tcp: 'info', http: 'ok', https: 'ok', udp: 'warn' };
    return '<span class="tag ' + (map[proto] || 'info') + '">' + esc(String(proto).toUpperCase()) + '</span>';
  }

  function nodeName(id) {
    if (!id) return '<span class="muted">未分配</span>';
    const n = state.nodes.find((x) => x.id === id);
    return n ? esc(n.name) : '<span class="muted">(已删除)</span>';
  }

  function clientName(id) {
    const c = state.clients.find((x) => x.id === id);
    return c ? c.name : '(已删除)';
  }

  // ------------------------------------------------------------ 页面骨架

  const NAV = [
    { group: '总览' },
    { key: 'dashboard', label: '仪表盘', ico: '▤' },
    { group: '资源' },
    { key: 'nodes', label: '服务端节点', ico: '⛁' },
    { key: 'tunnels', label: '隧道列表', ico: '⇄' },
    { key: 'clients', label: '客户端管理', ico: '▣' },
    { key: 'logs', label: '日志', ico: '≡' },
    { group: '系统' },
    { key: 'settings', label: '配置', ico: '⚙' },
  ];

  function shell(active, title, bodyHtml) {
    const items = NAV.map((item) => {
      if (item.group) return '<div class="nav-group">' + esc(item.group) + '</div>';
      let badge = '';
      if (item.key === 'nodes') badge = state.nodes.length;
      if (item.key === 'clients') badge = state.clients.length;
      return '<div class="nav-item' + (item.key === active ? ' active' : '') +
        '" data-nav="' + item.key + '"><span class="ico">' + item.ico + '</span>' +
        esc(item.label) +
        (badge !== '' ? '<span class="badge">' + esc(badge) + '</span>' : '') +
        '</div>';
    }).join('');

    const mode = state.embedded ? '内嵌控制台' : '独立控制台';
    return '' +
      '<div class="layout">' +
        '<aside class="sidebar">' +
          '<div class="brand"><span class="logo">RS</span> rscross</div>' +
          '<nav class="nav">' + items + '</nav>' +
          '<div class="sidebar-foot">v' + esc(state.version || '—') + ' · ' + esc(mode) + '</div>' +
        '</aside>' +
        '<div class="main">' +
          '<header class="topbar">' +
            '<h1>' + esc(title) + '</h1>' +
            '<div class="spacer"></div>' +
            '<span class="who">' + esc(state.user ? state.user.username : '') + '</span>' +
            '<button class="sm" id="btn-refresh">刷新</button>' +
            '<button class="sm" id="btn-logout">退出</button>' +
          '</header>' +
          '<main class="content"><div class="page">' + bodyHtml + '</div></main>' +
        '</div>' +
      '</div>';
  }

  function bindShell() {
    document.querySelectorAll('[data-nav]').forEach((el) => {
      el.onclick = () => { location.hash = '#/' + el.getAttribute('data-nav'); };
    });
    const refresh = $('btn-refresh');
    if (refresh) refresh.onclick = () => render();
    const logout = $('btn-logout');
    if (logout) logout.onclick = doLogout;
  }

  function copyButton(targetId, label) {
    return '<button class="sm" data-copy="' + targetId + '">' + esc(label || '复制') + '</button>';
  }

  function bindCopyButtons() {
    document.querySelectorAll('[data-copy]').forEach((el) => {
      el.onclick = () => {
        const src = $(el.getAttribute('data-copy'));
        if (!src) return;
        navigator.clipboard.writeText(src.textContent)
          .then(() => toast('已复制', 'ok'))
          .catch(() => toast('复制失败，请手动选择', 'err'));
      };
    });
  }

  // ------------------------------------------------------------ 登录页

  function renderLogin() {
    document.body.innerHTML = '' +
      '<div class="login-wrap"><div class="login-box">' +
        '<div class="brand-row"><span class="logo">RS</span>' +
          '<div><h1>rscross 控制台</h1><p class="sub">直连优先 · 中继兜底 · 多节点汇聚</p></div>' +
        '</div>' +
        '<label class="field"><span>用户名</span>' +
          '<input id="login-user" autocomplete="username" value="admin" /></label>' +
        '<label class="field"><span>密码</span>' +
          '<input id="login-pass" type="password" autocomplete="current-password" /></label>' +
        '<button class="primary" id="login-go" style="width:100%">登录</button>' +
        '<p class="muted" style="font-size:12px;margin:14px 0 0">' +
          '首次启动的管理员密码打印在服务端/控制台进程的标准错误输出中。</p>' +
      '</div></div>';

    const go = async () => {
      const username = $('login-user').value.trim();
      const password = $('login-pass').value;
      if (!username || !password) { toast('请输入用户名与密码', 'err'); return; }
      const btn = $('login-go');
      btn.disabled = true;
      try {
        const res = await api('/api/v1/auth/login', {
          method: 'POST',
          body: { username, password },
        });
        state.token = res.token;
        state.user = res.user;
        localStorage.setItem(TOKEN_KEY, res.token);
        toast('登录成功', 'ok');
        location.hash = '#/dashboard';
      } catch (err) {
        toast(err.message, 'err');
        btn.disabled = false;
      }
    };

    $('login-go').onclick = go;
    $('login-pass').onkeydown = (e) => { if (e.key === 'Enter') go(); };
    $('login-pass').focus();
  }

  async function doLogout() {
    try { await api('/api/v1/auth/logout', { method: 'POST' }); } catch (_) {}
    logoutLocal();
  }

  // ------------------------------------------------------------ 仪表盘

  function sparkline(series) {
    if (!series || !series.length) {
      return '<div class="empty">暂无流量数据（客户端建立连接后开始采样）</div>';
    }
    const w = 900, h = 180, pad = 24;
    const max = Math.max(1, ...series.map((p) => Number(p.bytes_in || 0) + Number(p.bytes_out || 0)));
    const stepX = series.length > 1 ? (w - pad * 2) / (series.length - 1) : 0;
    const toY = (v) => h - pad - (Number(v) / max) * (h - pad * 2);

    const line = (key) => series.map((p, i) =>
      (i === 0 ? 'M' : 'L') + (pad + i * stepX).toFixed(1) + ' ' + toY(p[key]).toFixed(1)
    ).join(' ');

    const area = line('bytes_in') +
      ' L' + (pad + (series.length - 1) * stepX).toFixed(1) + ' ' + (h - pad) +
      ' L' + pad + ' ' + (h - pad) + ' Z';

    return '<svg class="spark" viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
      '<defs><linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">' +
        '<stop offset="0%" stop-color="#2f6df6" stop-opacity=".22"/>' +
        '<stop offset="100%" stop-color="#2f6df6" stop-opacity="0"/></linearGradient></defs>' +
      '<path d="' + area + '" fill="url(#g1)"/>' +
      '<path d="' + line('bytes_in') + '" fill="none" stroke="#2f6df6" stroke-width="2"/>' +
      '<path d="' + line('bytes_out') + '" fill="none" stroke="#12a150" stroke-width="2" stroke-dasharray="4 3"/>' +
      '</svg>' +
      '<div class="toolbar" style="margin-top:8px;font-size:12px;color:#7c8698">' +
        '<span>入向（实线）</span><span>出向（虚线）</span>' +
        '<span style="margin-left:auto">峰值 ' + esc(fmtBytes(max)) + ' / 小时</span>' +
      '</div>';
  }

  function statCard(label, value, sub) {
    return '<div class="card stat"><div class="label">' + esc(label) + '</div>' +
      '<div class="value">' + esc(value) + '</div>' +
      '<div class="sub">' + esc(sub) + '</div></div>';
  }

  async function renderDashboard() {
    const data = await api('/api/v1/overview');
    const direct = Number(data.bytes_direct_24h || 0);
    const relayed = Number(data.bytes_relayed_24h || 0);
    const total = direct + relayed;
    const directPct = total > 0 ? Math.round((direct / total) * 100) : 0;

    const body = '' +
      '<div class="grid cols-4">' +
        statCard('服务端节点', data.nodes_online + ' / ' + data.nodes_total, '在线 / 总数') +
        statCard('客户端', data.clients_online + ' / ' + data.clients_total, '在线 / 总数') +
        statCard('隧道', data.tunnels_enabled + ' / ' + data.tunnels_total, '启用 / 总数') +
        statCard('24h 流量',
          fmtBytes(Number(data.bytes_in_24h) + Number(data.bytes_out_24h)),
          '入 ' + fmtBytes(data.bytes_in_24h) + ' · 出 ' + fmtBytes(data.bytes_out_24h)) +
      '</div>' +

      '<div class="card"><div class="card-head"><h2>流量趋势（最近 24 小时）</h2></div>' +
        '<div class="card-body">' + sparkline(data.series) + '</div></div>' +

      '<div class="grid cols-2">' +
        '<div class="card"><div class="card-head"><h2>数据面概况</h2></div><div class="card-body">' +
          '<dl class="kv">' +
            '<dt>24h 连接数</dt><dd>' + esc(data.conns_24h) + '</dd>' +
            '<dt>24h 直连流量</dt><dd>' + esc(fmtBytes(direct)) + '（' + directPct + '%）</dd>' +
            '<dt>24h 中继流量</dt><dd>' + esc(fmtBytes(relayed)) + '</dd>' +
            '<dt>控制台形态</dt><dd>' + (state.embedded
              ? '<span class="tag info">内嵌（单机自用）</span>'
              : '<span class="tag ok">独立（多节点汇聚）</span>') + '</dd>' +
          '</dl>' +
          '<p class="muted" style="font-size:12px;margin:14px 0 0">' +
            '直连由 Iroh 打洞承担；打洞失败时自动回落 FerroTunnel 中继。' +
            '所有流量都在服务端节点与客户端之间，控制台不参与转发。</p>' +
        '</div></div>' +

        '<div class="card"><div class="card-head"><h2>快速上手</h2></div><div class="card-body">' +
          '<ol class="steps">' +
            '<li>' + (state.embedded ? '本进程已内嵌控制台' : '在「服务端节点」页创建一个节点') +
              '，拿到节点接入命令并在公网机器上执行。</li>' +
            '<li>在「客户端管理」页签发接入令牌，把生成的命令贴到内网机器上执行。</li>' +
            '<li>在「隧道列表」新建隧道（HTTP 按 Host，TCP/UDP 按端口），客户端下一次心跳自动生效。</li>' +
          '</ol>' +
        '</div></div>' +
      '</div>';

    document.body.innerHTML = shell('dashboard', '仪表盘', body);
    bindShell();
  }

  // ------------------------------------------------------------ 服务端节点

  async function renderNodes() {
    const nodes = await api('/api/v1/nodes');
    state.nodes = nodes;

    const rows = nodes.length
      ? nodes.map((n) => '' +
          '<tr>' +
            '<td><strong>' + esc(n.name) + '</strong></td>' +
            '<td>' + statusTag(n.status) + '</td>' +
            '<td class="mono">' + esc(n.public_host || n.public_ip || '—') + '</td>' +
            '<td class="mono">' + esc(n.tunnel_port != null ? ':' + n.tunnel_port : '—') + '</td>' +
            '<td class="mono">' + esc((n.os || '') + ' ' + (n.arch || '')) + '</td>' +
            '<td class="mono">' + esc(n.version || '—') + '</td>' +
            '<td class="mono" title="' + esc(n.endpoint_id || '') + '">' +
              esc(n.endpoint_id ? String(n.endpoint_id).slice(0, 10) + '…' : '—') + '</td>' +
            '<td class="nowrap">' + esc(relTime(n.last_seen_at)) + '</td>' +
            '<td class="right row-actions">' +
              '<button class="sm" data-node-rotate="' + esc(n.id) + '" data-name="' + esc(n.name) + '">轮换令牌</button>' +
              '<button class="sm" data-node-disable="' + esc(n.id) + '" data-disabled="' + (n.disabled ? '1' : '0') + '">' +
                (n.disabled ? '启用' : '禁用') + '</button>' +
              '<button class="sm danger" data-node-del="' + esc(n.id) + '" data-name="' + esc(n.name) + '">删除</button>' +
            '</td>' +
          '</tr>').join('')
      : '<tr><td colspan="9"><div class="empty">还没有服务端节点。' +
        (state.embedded ? '内嵌控制台会在服务端启动时自动注册本机节点。'
                        : '点击「添加节点」签发令牌。') + '</div></td></tr>';

    const body = '' +
      '<div class="card"><div class="card-head">' +
        '<h2>服务端节点（' + nodes.length + '）</h2><div class="spacer"></div>' +
        '<button class="primary sm" id="btn-new-node"' +
          (state.embedded ? ' disabled title="内嵌形态下节点由服务端进程自身注册"' : '') +
          '>添加节点</button>' +
      '</div><div class="card-body tight"><table>' +
        '<thead><tr><th>名称</th><th>状态</th><th>对外主机</th><th>隧道端口</th><th>平台</th>' +
        '<th>版本</th><th>EndpointId</th><th>最近心跳</th><th></th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div></div>' +
      (state.embedded
        ? '<div class="card"><div class="card-body"><p class="muted mb0">' +
          '当前是<b>内嵌控制台</b>（单机自用）：服务端节点就是本进程，客户端直接把 <code>--console</code> 指向本控制台地址即可，' +
          '在「客户端管理」与「隧道列表」里创建的配置会通过心跳下发到客户端。</p></div></div>'
        : '<div class="card"><div class="card-body"><p class="muted mb0">' +
          '当前是<b>独立控制台</b>（多节点汇聚）：在这里创建的节点会拿到一条接入命令，' +
          '在公网机器上执行后即成为数据面节点；客户端则由令牌绑定到某个节点。</p></div></div>');

    document.body.innerHTML = shell('nodes', '服务端节点', body);
    bindShell();

    const add = $('btn-new-node');
    if (add && !state.embedded) add.onclick = openNodeModal;
    bindCopyButtons();

    document.querySelectorAll('[data-node-del]').forEach((el) => {
      el.onclick = async () => {
        const name = el.getAttribute('data-name');
        if (!confirm('确认删除节点「' + name + '」？其下客户端会解除归属但保留。')) return;
        try {
          await api('/api/v1/nodes/' + el.getAttribute('data-node-del'), { method: 'DELETE' });
          toast('节点已删除', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    });

    document.querySelectorAll('[data-node-disable]').forEach((el) => {
      el.onclick = async () => {
        const disabled = el.getAttribute('data-disabled') === '1';
        try {
          await api('/api/v1/nodes/' + el.getAttribute('data-node-disable'), {
            method: 'PATCH',
            body: { disabled: !disabled },
          });
          toast(disabled ? '节点已启用' : '节点已禁用', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    });

    document.querySelectorAll('[data-node-rotate]').forEach((el) => {
      el.onclick = async () => {
        const name = el.getAttribute('data-name');
        if (!confirm('轮换节点「' + name + '」的令牌？旧令牌立即失效，需要用新命令重启节点。')) return;
        try {
          const res = await api('/api/v1/nodes/' + el.getAttribute('data-node-rotate') + '/token',
            { method: 'POST' });
          showCommandModal('节点令牌已轮换', res.command,
            '旧令牌已失效。请在节点机器上用下面这条命令重启服务端。');
        } catch (err) { toast(err.message, 'err'); }
      };
    });
  }

  function showCommandModal(title, command, hint) {
    const html = '' +
      '<div class="modal-mask" id="modal"><div class="modal">' +
        '<h3>' + esc(title) + '</h3><div class="modal-body">' +
          '<pre class="code" id="cmd-text">' + esc(command) + '</pre>' +
          (hint ? '<p class="muted" style="font-size:12px">' + esc(hint) + '</p>' : '') +
          '<div style="margin-top:8px">' + copyButton('cmd-text', '复制命令') + '</div>' +
        '</div>' +
        '<div class="modal-foot"><button id="m-cancel">关闭</button></div>' +
      '</div></div>';
    document.body.insertAdjacentHTML('beforeend', html);
    $('m-cancel').onclick = () => { const m = $('modal'); if (m) m.remove(); };
    $('modal').onclick = (e) => { if (e.target.id === 'modal') $('modal').remove(); };
    bindCopyButtons();
  }

  function openNodeModal() {
    const html = '' +
      '<div class="modal-mask" id="modal"><div class="modal">' +
        '<h3>添加服务端节点</h3><div class="modal-body">' +
          '<label class="field"><span>节点名</span><input id="n-name" placeholder="node-hk-1" />' +
            '<div class="hint">仅字母、数字、-、_、.。</div></label>' +
          '<label class="field"><span>对外主机 / IP</span>' +
            '<input id="n-host" placeholder="203.0.113.9 或 node1.example.com" />' +
            '<div class="hint">客户端会用它连接该节点的反向隧道；留空则用控制台观测到的出口 IP。</div></label>' +
          '<div id="n-result"></div>' +
        '</div>' +
        '<div class="modal-foot">' +
          '<button id="m-cancel">关闭</button>' +
          '<button class="primary" id="m-ok">创建并签发令牌</button>' +
        '</div>' +
      '</div></div>';

    document.body.insertAdjacentHTML('beforeend', html);
    const close = () => { const m = $('modal'); if (m) m.remove(); };
    $('m-cancel').onclick = close;
    $('modal').onclick = (e) => { if (e.target.id === 'modal') close(); };

    $('m-ok').onclick = async () => {
      const name = $('n-name').value.trim();
      if (!name) { toast('请填写节点名', 'err'); return; }
      try {
        const res = await api('/api/v1/nodes', {
          method: 'POST',
          body: { name, public_host: $('n-host').value.trim() || null },
        });
        $('n-result').innerHTML =
          '<label class="field"><span>在公网机器上执行</span></label>' +
          '<pre class="code" id="n-cmd">' + esc(res.command) + '</pre>' +
          '<p class="muted" style="font-size:12px">节点令牌只显示这一次。</p>' +
          '<div style="margin-top:8px">' + copyButton('n-cmd', '复制命令') + '</div>';
        bindCopyButtons();
        state.nodes = null;
        render.bind(null);
      } catch (err) { toast(err.message, 'err'); }
    };
  }

  // ------------------------------------------------------------ 客户端管理

  async function renderClients() {
    const [clients, nodes, tunnels] = await Promise.all([
      api('/api/v1/clients'),
      api('/api/v1/nodes'),
      api('/api/v1/tunnels'),
    ]);
    state.clients = clients;
    state.nodes = nodes;
    state.tunnels = tunnels;

    const countOf = (id) => tunnels.filter((t) => t.client_id === id).length;

    const rows = clients.length
      ? clients.map((c) => '' +
          '<tr>' +
            '<td><strong>' + esc(c.name) + '</strong></td>' +
            '<td>' + statusTag(c.status) + '</td>' +
            '<td>' + nodeName(c.node_id) + '</td>' +
            '<td class="mono">' + esc(c.public_ip || '—') + '</td>' +
            '<td class="mono">' + esc((c.os || '') + ' ' + (c.arch || '')) + '</td>' +
            '<td class="mono">' + esc(c.version || '—') + '</td>' +
            '<td class="nowrap">' + esc(relTime(c.last_seen_at)) + '</td>' +
            '<td>' + countOf(c.id) + '</td>' +
            '<td class="right row-actions">' +
              '<button class="sm" data-client-disable="' + esc(c.id) + '" data-disabled="' + (c.disabled ? '1' : '0') + '">' +
                (c.disabled ? '启用' : '禁用') + '</button>' +
              '<button class="sm danger" data-client-del="' + esc(c.id) + '" data-name="' + esc(c.name) + '">删除</button>' +
            '</td>' +
          '</tr>').join('')
      : '<tr><td colspan="9"><div class="empty">还没有客户端。点击「签发接入令牌」，把命令贴到内网机器上执行。</div></td></tr>';

    const body = '' +
      '<div class="card"><div class="card-head">' +
        '<h2>客户端（' + clients.length + '）</h2><div class="spacer"></div>' +
        '<button class="primary sm" id="btn-new-client">签发接入令牌</button>' +
      '</div><div class="card-body tight"><table>' +
        '<thead><tr><th>名称</th><th>状态</th><th>归属节点</th><th>出口 IP</th><th>平台</th>' +
        '<th>版本</th><th>最近心跳</th><th>隧道</th><th></th></tr></thead>' +
        '<tbody>' + rows + '</tbody></table></div></div>';

    document.body.innerHTML = shell('clients', '客户端管理', body);
    bindShell();
    $('btn-new-client').onclick = () => openClientModal(nodes);

    document.querySelectorAll('[data-client-del]').forEach((el) => {
      el.onclick = async () => {
        const name = el.getAttribute('data-name');
        if (!confirm('确认删除客户端「' + name + '」？其名下隧道会一并删除。')) return;
        try {
          await api('/api/v1/clients/' + el.getAttribute('data-client-del'), { method: 'DELETE' });
          toast('客户端已删除', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    });

    document.querySelectorAll('[data-client-disable]').forEach((el) => {
      el.onclick = async () => {
        const disabled = el.getAttribute('data-disabled') === '1';
        try {
          await api('/api/v1/clients/' + el.getAttribute('data-client-disable'), {
            method: 'PATCH',
            body: { disabled: !disabled },
          });
          toast(disabled ? '客户端已启用' : '客户端已禁用', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    });
  }

  function openClientModal(nodes) {
    const enabled = nodes.filter((n) => !n.disabled);
    if (!enabled.length) {
      toast('请先添加并启用一个服务端节点', 'err');
      return;
    }
    const options = enabled.map((n) =>
      '<option value="' + esc(n.id) + '">' + esc(n.name) + '</option>').join('');

    const html = '' +
      '<div class="modal-mask" id="modal"><div class="modal">' +
        '<h3>签发客户端接入令牌</h3><div class="modal-body">' +
          (enabled.length > 1
            ? '<label class="field"><span>归属服务端节点</span><select id="c-node">' + options + '</select>' +
              '<div class="hint">该客户端的反向隧道会连到这台节点。之后可在客户端列表里改派。</div></label>'
            : '<input type="hidden" id="c-node" value="' + esc(enabled[0].id) + '" />' +
              '<p class="muted" style="font-size:12.5px">归属节点：<b>' + esc(enabled[0].name) + '</b></p>') +
          '<label class="field"><span>客户端名</span><input id="c-name" placeholder="office-nas" />' +
            '<div class="hint">留空则注册时自动命名。</div></label>' +
          '<label class="field"><span>令牌有效期（分钟）</span><input id="c-ttl" value="30" /></label>' +
          '<div id="c-result"></div>' +
        '</div>' +
        '<div class="modal-foot">' +
          '<button id="m-cancel">关闭</button>' +
          '<button class="primary" id="m-ok">签发</button>' +
        '</div>' +
      '</div></div>';

    document.body.insertAdjacentHTML('beforeend', html);
    const close = () => { const m = $('modal'); if (m) m.remove(); };
    $('m-cancel').onclick = close;
    $('modal').onclick = (e) => { if (e.target.id === 'modal') close(); };

    $('m-ok').onclick = async () => {
      const ttl = parseInt($('c-ttl').value || '30', 10);
      try {
        const res = await api('/api/v1/clients', {
          method: 'POST',
          body: {
            name: $('c-name').value.trim() || null,
            node_id: $('c-node').value,
            ttl_minutes: ttl,
          },
        });
        $('c-result').innerHTML =
          '<label class="field"><span>在目标机器上执行</span></label>' +
          '<pre class="code" id="c-cmd">' + esc(res.command) + '</pre>' +
          '<p class="muted" style="font-size:12px">令牌仅显示这一次，有效期至 ' +
            esc(fmtTime(res.expires_at)) + '。</p>' +
          '<div style="margin-top:8px">' + copyButton('c-cmd', '复制命令') + '</div>';
        bindCopyButtons();
      } catch (err) { toast(err.message, 'err'); }
    };
  }

  // ------------------------------------------------------------ 隧道列表

  async function renderTunnels() {
    const [tunnels, clients, nodes] = await Promise.all([
      api('/api/v1/tunnels'),
      api('/api/v1/clients'),
      api('/api/v1/nodes'),
    ]);
    state.tunnels = tunnels;
    state.clients = clients;
    state.nodes = nodes;

    const rows = tunnels.length
      ? tunnels.map((t) => {
          const client = clients.find((x) => x.id === t.client_id);
          return '' +
            '<tr>' +
              '<td>' + esc(t.name) + '</td>' +
              '<td>' + protoTag(t.proto) + '</td>' +
              '<td class="mono">' + esc(t.local_addr) + '</td>' +
              '<td class="mono">' + esc(t.remote_port || t.host || '—') + '</td>' +
              '<td>' + esc(client ? client.name : '(已删除)') + '</td>' +
              '<td>' + nodeName(client ? client.node_id : null) + '</td>' +
              '<td>' + (t.enabled
                ? '<span class="tag ok"><i class="dot"></i>启用</span>'
                : '<span class="tag bad"><i class="dot"></i>停用</span>') + '</td>' +
              '<td class="nowrap">' + esc(t.rate_limit_kbps ? t.rate_limit_kbps + ' Kbps' : '不限') + '</td>' +
              '<td class="right row-actions">' +
                '<button class="sm" data-toggle="' + esc(t.id) + '" data-enabled="' + (t.enabled ? '1' : '0') + '">' +
                  (t.enabled ? '停用' : '启用') + '</button>' +
                '<button class="sm danger" data-del-tunnel="' + esc(t.id) + '" data-name="' + esc(t.name) + '">删除</button>' +
              '</td>' +
            '</tr>';
        }).join('')
      : '<tr><td colspan="9"><div class="empty">还没有隧道。先在「客户端管理」接入一个客户端，再为它创建隧道。</div></td></tr>';

    const body = '' +
      '<div class="card"><div class="card-head">' +
        '<h2>隧道（' + tunnels.length + '）</h2><div class="spacer"></div>' +
        '<button class="primary sm" id="btn-new-tunnel">新建隧道</button>' +
      '</div><div class="card-body tight"><table>' +
        '<thead><tr><th>名称</th><th>协议</th><th>本地地址</th><th>公网入口</th>' +
        '<th>客户端</th><th>服务端节点</th><th>状态</th><th>限速</th><th></th></tr></thead>' +
        '<tbody>' + rows + '</tbody>' +
      '</table></div></div>';

    document.body.innerHTML = shell('tunnels', '隧道列表', body);
    bindShell();

    $('btn-new-tunnel').onclick = () => openTunnelModal(clients);
    document.querySelectorAll('[data-del-tunnel]').forEach((el) => {
      el.onclick = async () => {
        const name = el.getAttribute('data-name');
        if (!confirm('确认删除隧道「' + name + '」？该隧道会从客户端下线。')) return;
        try {
          await api('/api/v1/tunnels/' + el.getAttribute('data-del-tunnel'), { method: 'DELETE' });
          toast('隧道已删除', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    });
    document.querySelectorAll('[data-toggle]').forEach((el) => {
      el.onclick = async () => {
        const enabled = el.getAttribute('data-enabled') === '1';
        try {
          await api('/api/v1/tunnels/' + el.getAttribute('data-toggle'), {
            method: 'PATCH',
            body: { enabled: !enabled },
          });
          toast(enabled ? '隧道已停用' : '隧道已启用', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    });
  }

  function openTunnelModal(clients) {
    if (!clients.length) { toast('请先接入一个客户端', 'err'); return; }

    const options = clients.map((c) =>
      '<option value="' + esc(c.id) + '">' + esc(c.name) +
      (c.node_id ? '' : '（未分配节点）') + '</option>').join('');

    const html = '' +
      '<div class="modal-mask" id="modal"><div class="modal">' +
        '<h3>新建隧道</h3><div class="modal-body">' +
          '<label class="field"><span>所属客户端</span><select id="t-client">' + options + '</select></label>' +
          '<label class="field"><span>隧道名称</span><input id="t-name" placeholder="web" />' +
            '<div class="hint">仅字母、数字、-、_、.，同一客户端内唯一。</div></label>' +
          '<label class="field"><span>协议</span><select id="t-proto">' +
            '<option value="http">HTTP（按 Host 路由）</option>' +
            '<option value="https">HTTPS</option>' +
            '<option value="tcp">TCP（端口映射）</option>' +
            '<option value="udp">UDP（端口映射）</option>' +
          '</select></label>' +
          '<label class="field"><span>本地地址</span><input id="t-local" placeholder="127.0.0.1:8080" />' +
            '<div class="hint">客户端所在机器上可访问的地址。</div></label>' +
          '<label class="field" id="f-host"><span>Host 域名</span><input id="t-host" placeholder="app.example.com" /></label>' +
          '<label class="field" id="f-port" style="display:none"><span>公网端口</span>' +
            '<input id="t-port" placeholder="留空则自动分配" /></label>' +
          '<label class="field"><span>限速（Kbps，0 = 不限）</span><input id="t-rate" value="0" /></label>' +
        '</div>' +
        '<div class="modal-foot">' +
          '<button id="m-cancel">取消</button>' +
          '<button class="primary" id="m-ok">创建</button>' +
        '</div>' +
      '</div></div>';

    document.body.insertAdjacentHTML('beforeend', html);

    const close = () => { const m = $('modal'); if (m) m.remove(); };
    const syncFields = () => {
      const proto = $('t-proto').value;
      $('f-port').style.display = proto === 'tcp' || proto === 'udp' ? '' : 'none';
      $('f-host').style.display = proto === 'http' || proto === 'https' ? '' : 'none';
    };
    $('t-proto').onchange = syncFields;
    syncFields();
    $('m-cancel').onclick = close;
    $('modal').onclick = (e) => { if (e.target.id === 'modal') close(); };

    $('m-ok').onclick = async () => {
      const proto = $('t-proto').value;
      const portRaw = $('t-port').value.trim();
      const body = {
        name: $('t-name').value.trim(),
        proto,
        local_addr: $('t-local').value.trim(),
        rate_limit_kbps: parseInt($('t-rate').value || '0', 10) || 0,
      };
      if (proto === 'http' || proto === 'https') body.host = $('t-host').value.trim();
      if (portRaw) body.remote_port = parseInt(portRaw, 10);

      try {
        await api('/api/v1/clients/' + $('t-client').value + '/tunnels', {
          method: 'POST',
          body,
        });
        toast('隧道已创建，客户端下次心跳（≤15 秒）生效', 'ok');
        close();
        render();
      } catch (err) { toast(err.message, 'err'); }
    };
  }

  // ------------------------------------------------------------ 日志

  async function renderLogs() {
    const body = '' +
      '<div class="card">' +
        '<div class="card-head">' +
          '<h2>实时日志</h2><div class="spacer"></div>' +
          '<div class="toolbar">' +
            '<select id="log-level">' +
              '<option value="">全部级别</option>' +
              '<option value="ERROR">ERROR</option>' +
              '<option value="WARN">WARN</option>' +
              '<option value="INFO">INFO</option>' +
              '<option value="DEBUG">DEBUG</option>' +
            '</select>' +
            '<input id="log-q" placeholder="关键字，如 隧道 / 客户端名" style="min-width:220px" />' +
            '<button class="sm" id="log-auto">暂停</button>' +
          '</div>' +
        '</div>' +
        '<div class="card-body tight"><div id="log-body"><div class="empty">加载中…</div></div></div>' +
      '</div>';

    document.body.innerHTML = shell('logs', '日志', body);
    bindShell();

    $('log-level').value = state.logLevel;
    $('log-q').value = state.logKeyword;
    $('log-level').onchange = () => { state.logLevel = $('log-level').value; refreshLogs(); };
    $('log-q').oninput = () => {
      state.logKeyword = $('log-q').value.trim();
      clearTimeout(state.logDebounce);
      state.logDebounce = setTimeout(refreshLogs, 250);
    };
    $('log-auto').onclick = () => {
      state.logsAuto = !state.logsAuto;
      $('log-auto').textContent = state.logsAuto ? '暂停' : '继续';
    };

    if (state.logsTimer) { clearInterval(state.logsTimer); state.logsTimer = null; }
    await refreshLogs();
    state.logsTimer = setInterval(() => { if (state.logsAuto) refreshLogs(); }, 3000);
  }

  async function refreshLogs() {
    const box = $('log-body');
    if (!box) return;
    const params = new URLSearchParams({ limit: '300' });
    if (state.logLevel) params.set('level', state.logLevel);
    if (state.logKeyword) params.set('q', state.logKeyword);

    try {
      const data = await api('/api/v1/logs?' + params.toString());
      if (!data.entries.length) {
        box.innerHTML = '<div class="empty">没有匹配的日志</div>';
        return;
      }
      const levelColor = (lv) => {
        const up = String(lv).toUpperCase();
        if (up === 'ERROR') return 'bad';
        if (up === 'WARN') return 'warn';
        if (up === 'INFO') return 'ok';
        return 'info';
      };
      box.innerHTML = '<table><thead><tr><th style="width:170px">时间</th>' +
        '<th style="width:80px">级别</th><th style="width:220px">来源</th><th>内容</th></tr></thead><tbody>' +
        data.entries.map((e) => '<tr>' +
          '<td class="mono nowrap">' + esc(fmtTime(e.ts)) + '</td>' +
          '<td><span class="tag ' + levelColor(e.level) + '">' + esc(String(e.level).toUpperCase()) + '</span></td>' +
          '<td class="mono">' + esc(e.target || '—') + '</td>' +
          '<td class="mono">' + esc(e.message) + '</td>' +
        '</tr>').join('') + '</tbody></table>';
    } catch (err) {
      box.innerHTML = '<div class="empty">' + esc(err.message) + '</div>';
    }
  }

  // ------------------------------------------------------------ 配置

  async function renderSettings() {
    const [cfg, audit] = await Promise.all([
      api('/api/v1/config'),
      api('/api/v1/audit?limit=50'),
    ]);
    const c = cfg.config;

    const auditRows = audit.length
      ? audit.map((a) => '<tr>' +
          '<td class="mono nowrap">' + esc(fmtTime(a.ts)) + '</td>' +
          '<td>' + esc(a.action) + '</td>' +
          '<td class="mono">' + esc(a.target || '—') + '</td>' +
          '<td class="mono">' + esc(a.ip || '—') + '</td>' +
        '</tr>').join('')
      : '<tr><td colspan="4"><div class="empty">暂无审计记录</div></td></tr>';

    const body = '' +
      '<div class="card"><div class="card-head"><h2>控制台配置</h2><div class="spacer"></div>' +
        '<span class="muted" style="font-size:12px">' + esc(cfg.config_path) + '</span>' +
      '</div><div class="card-body">' +
        (cfg.readonly ? '<p class="muted">配置已被锁定（admin.allow_config_edit = false）。</p>' : '') +
        '<div class="grid cols-3">' +
          field('s-name', '控制台名', c.console.name, cfg.readonly) +
          field('s-bind', '监听地址', c.console.bind, cfg.readonly) +
          field('s-public', '对外地址', c.console.public_url || '', cfg.readonly, 'https://panel.example.com') +
          field('s-hb', '心跳间隔（秒）', c.console.heartbeat_secs, cfg.readonly) +
          field('s-offline', '离线判定（秒）', c.console.offline_after_secs, cfg.readonly) +
          field('s-range', '端口池', c.ingress.port_range, cfg.readonly) +
          field('s-domain', '默认域名', c.ingress.default_domain || '', cfg.readonly, 't.example.com') +
          field('s-nodes', '最大节点数（0=不限）', c.limits.max_nodes, cfg.readonly) +
          field('s-clients', '最大客户端数（0=不限）', c.limits.max_clients, cfg.readonly) +
        '</div>' +
        '<div class="toolbar" style="margin-top:6px">' +
          '<button class="primary" id="s-save"' + (cfg.readonly ? ' disabled' : '') + '>保存配置</button>' +
          '<span class="muted" style="font-size:12px">监听地址类变更需要重启进程生效。</span>' +
        '</div>' +
      '</div></div>' +

      '<div class="card"><div class="card-head"><h2>审计记录</h2></div>' +
        '<div class="card-body tight"><table>' +
          '<thead><tr><th style="width:170px">时间</th><th>动作</th><th>对象</th><th>来源 IP</th></tr></thead>' +
          '<tbody>' + auditRows + '</tbody></table></div></div>';

    document.body.innerHTML = shell('settings', '配置', body);
    bindShell();

    const save = $('s-save');
    if (save) {
      save.onclick = async () => {
        const next = JSON.parse(JSON.stringify(c));
        next.console.name = $('s-name').value.trim();
        next.console.bind = $('s-bind').value.trim();
        next.console.public_url = $('s-public').value.trim() || null;
        next.console.heartbeat_secs = parseInt($('s-hb').value, 10) || 15;
        next.console.offline_after_secs = parseInt($('s-offline').value, 10) || 45;
        next.ingress.port_range = $('s-range').value.trim();
        next.ingress.default_domain = $('s-domain').value.trim() || null;
        next.limits.max_nodes = parseInt($('s-nodes').value, 10) || 0;
        next.limits.max_clients = parseInt($('s-clients').value, 10) || 0;

        try {
          await api('/api/v1/config', { method: 'PUT', body: next });
          toast('配置已保存', 'ok');
          render();
        } catch (err) { toast(err.message, 'err'); }
      };
    }
  }

  function field(id, label, value, readonly, placeholder) {
    return '<label class="field"><span>' + esc(label) + '</span>' +
      '<input id="' + id + '" value="' + esc(value) + '"' +
      (placeholder ? ' placeholder="' + esc(placeholder) + '"' : '') +
      (readonly ? ' disabled' : '') + ' /></label>';
  }

  // ------------------------------------------------------------ 路由

  const ROUTES = {
    dashboard: renderDashboard,
    nodes: renderNodes,
    tunnels: renderTunnels,
    clients: renderClients,
    logs: renderLogs,
    settings: renderSettings,
  };

  async function render() {
    const hash = location.hash.replace(/^#\/?/, '') || 'dashboard';
    if (state.logsTimer && hash !== 'logs') { clearInterval(state.logsTimer); state.logsTimer = null; }

    if (!state.token) { renderLogin(); return; }

    if (!state.user) {
      try {
        state.user = await api('/api/v1/auth/me');
      } catch (_) {
        logoutLocal();
        return;
      }
    }

    const view = ROUTES[hash] || renderDashboard;
    try {
      await view();
    } catch (err) {
      document.body.innerHTML = shell(hash, '出错了',
        '<div class="card"><div class="card-body"><div class="empty">' +
        esc(err.message) + '</div></div></div>');
      bindShell();
    }
  }

  window.addEventListener('hashchange', render);

  // 版本与形态用于页脚/仪表盘展示；失败不影响使用。
  fetch('/api/v1/health')
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (d) {
        state.version = d.version || '';
        state.embedded = !!d.embedded;
      }
    })
    .catch(() => {})
    .finally(render);
})();

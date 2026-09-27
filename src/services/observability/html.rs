pub const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>trimrouter Dashboard</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0284c7;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --terminal-bg: #090d16;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background-color: var(--bg); color: var(--text-main); line-height: 1.5; padding: 1.5rem; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--card-border); flex-wrap: wrap; gap: 0.75rem; }
    .brand { display: flex; align-items: center; gap: 0.75rem; }
    .logo { font-size: 1.5rem; font-weight: 700; color: var(--accent); letter-spacing: -0.025em; }
    .badge { font-size: 0.75rem; font-weight: 600; padding: 0.2rem 0.6rem; border-radius: 9999px; background: rgba(56, 189, 248, 0.15); color: var(--accent); border: 1px solid rgba(56, 189, 248, 0.3); }
    .status-pill { display: inline-flex; align-items: center; gap: 0.4rem; font-size: 0.8rem; font-weight: 600; padding: 0.25rem 0.75rem; border-radius: 9999px; }
    .status-pill.online { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
    .status-pill.warn { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; margin-bottom: 1.5rem; }
    .card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 0.75rem; padding: 1.25rem; }
    .card-title { font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 0.75rem; display: flex; justify-content: space-between; align-items: center; }
    .stat-val { font-size: 1.5rem; font-weight: 700; color: var(--text-main); margin-bottom: 0.25rem; }
    .stat-sub { font-size: 0.8rem; color: var(--text-muted); }
    .key-value { display: flex; flex-direction: column; gap: 0.5rem; }
    .kv-row { display: flex; justify-content: space-between; font-size: 0.85rem; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 0.35rem; }
    .kv-key { color: var(--text-muted); }
    .kv-val { font-weight: 600; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    table { width: 100%; border-collapse: collapse; font-size: 0.875rem; }
    th { text-align: left; padding: 0.6rem 0.75rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--card-border); }
    td { padding: 0.6rem 0.75rem; border-bottom: 1px solid rgba(255,255,255,0.05); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.85rem; }
    .terminal-card { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 0.75rem; padding: 1.25rem; margin-top: 1.5rem; }
    .terminal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }
    .terminal-controls { display: flex; gap: 0.5rem; align-items: center; font-size: 0.8rem; }
    .terminal-controls button, .terminal-controls select { background: var(--bg); color: var(--text-main); border: 1px solid var(--card-border); padding: 0.3rem 0.6rem; border-radius: 0.375rem; font-size: 0.8rem; cursor: pointer; }
    .terminal-controls button:hover { background: var(--card-border); }
    .terminal { background: var(--terminal-bg); border: 1px solid var(--card-border); border-radius: 0.5rem; padding: 1rem; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.8rem; height: 320px; overflow-y: auto; display: flex; flex-direction: column; gap: 0.25rem; }
    .log-line { white-space: pre-wrap; word-break: break-all; }
    .log-INFO { color: #38bdf8; }
    .log-WARN { color: #fbbf24; }
    .log-ERROR { color: #f87171; font-weight: 600; }
    .log-DEBUG { color: #94a3b8; }
    .log-ts { color: #64748b; margin-right: 0.5rem; }
    .log-svc { color: #a78bfa; margin-right: 0.5rem; }
    .log-msg { color: var(--text-main); }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="logo">trimrouter</div>
      <span class="badge" id="version-badge">v0.3.0</span>
      <span class="badge" id="sha-badge">git: ...</span>
    </div>
    <div style="display: flex; gap: 0.75rem; align-items: center;">
      <div class="status-pill online" id="status-pill"><span class="dot"></span> Online</div>
      <div class="status-pill warn" id="watchdog-pill"><span class="dot"></span> Watchdog Active</div>
    </div>
  </header>

  <div class="grid">
    <!-- System Resources -->
    <div class="card">
      <div class="card-title">System Resources</div>
      <div class="key-value">
        <div class="kv-row"><span class="kv-key">Uptime</span><span class="kv-val" id="sys-uptime">--</span></div>
        <div class="kv-row"><span class="kv-key">Load Average</span><span class="kv-val" id="sys-load">--</span></div>
        <div class="kv-row"><span class="kv-key">Memory Used</span><span class="kv-val" id="sys-mem">--</span></div>
        <div class="kv-row"><span class="kv-key">Memory Total</span><span class="kv-val" id="sys-mem-total">--</span></div>
      </div>
    </div>

    <!-- WAN Interface -->
    <div class="card">
      <div class="card-title">WAN Interface (<span id="wan-iface">wan</span>)</div>
      <div class="key-value">
        <div class="kv-row"><span class="kv-key">IP Address</span><span class="kv-val" id="wan-ip">--</span></div>
        <div class="kv-row"><span class="kv-key">Gateway</span><span class="kv-val" id="wan-gw">--</span></div>
        <div class="kv-row"><span class="kv-key">DNS Servers</span><span class="kv-val" id="wan-dns">--</span></div>
        <div class="kv-row"><span class="kv-key">RX / TX Traffic</span><span class="kv-val" id="wan-traffic">--</span></div>
      </div>
    </div>

    <!-- LAN Interface -->
    <div class="card">
      <div class="card-title">LAN Interface (<span id="lan-iface">lan</span>)</div>
      <div class="key-value">
        <div class="kv-row"><span class="kv-key">Gateway IP</span><span class="kv-val" id="lan-ip">--</span></div>
        <div class="kv-row"><span class="kv-key">Subnet Mode</span><span class="kv-val" id="lan-mode">primary</span></div>
        <div class="kv-row"><span class="kv-key">MAC Address</span><span class="kv-val" id="lan-mac">--</span></div>
        <div class="kv-row"><span class="kv-key">RX / TX Traffic</span><span class="kv-val" id="lan-traffic">--</span></div>
      </div>
    </div>

    <!-- Services Health -->
    <div class="card">
      <div class="card-title">Core Services</div>
      <div class="key-value">
        <div class="kv-row"><span class="kv-key">DNS Forwarder Queries</span><span class="kv-val" id="dns-queries">0</span></div>
        <div class="kv-row"><span class="kv-key">DNS Cache Hit Ratio</span><span class="kv-val" id="dns-cache">0% (0 items)</span></div>
        <div class="kv-row"><span class="kv-key">Active DHCP Leases</span><span class="kv-val" id="dhcp-count">0</span></div>
        <div class="kv-row"><span class="kv-key">SNTP Clock Sync</span><span class="kv-val" id="sntp-sync">--</span></div>
      </div>
    </div>
  </div>

  <!-- DHCP Leases Table -->
  <div class="card" style="margin-bottom: 1.5rem;">
    <div class="card-title">Active DHCP Leases</div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>IP Address</th>
            <th>MAC Address</th>
            <th>Hostname</th>
            <th>Expires In</th>
            <th>Type</th>
          </tr>
        </thead>
        <tbody id="leases-body">
          <tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active leases</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Live Log Terminal -->
  <div class="terminal-card">
    <div class="terminal-header">
      <div class="card-title" style="margin: 0;">Live System Logs</div>
      <div class="terminal-controls">
        <label><input type="checkbox" id="autoscroll-chk" checked> Auto-scroll</label>
        <select id="level-filter">
          <option value="ALL">All Levels</option>
          <option value="INFO">Info & Higher</option>
          <option value="WARN">Warnings & Errors</option>
          <option value="ERROR">Errors Only</option>
        </select>
        <button id="pause-btn">Pause</button>
        <button id="clear-btn">Clear</button>
      </div>
    </div>
    <div class="terminal" id="log-terminal"></div>
  </div>

  <script>
    function formatBytes(bytes) {
      if (bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return (bytes / Math.pow(k, i)).toFixed(1) + ' ' + sizes[i];
    }

    function formatUptime(seconds) {
      const d = Math.floor(seconds / (3600*24));
      const h = Math.floor(seconds % (3600*24) / 3600);
      const m = Math.floor(seconds % 3600 / 60);
      const s = Math.floor(seconds % 60);
      let res = '';
      if (d > 0) res += d + 'd ';
      if (h > 0 || d > 0) res += h + 'h ';
      res += m + 'm ' + s + 's';
      return res;
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();

        document.getElementById('version-badge').textContent = 'v' + data.system.version;
        document.getElementById('sha-badge').textContent = 'git:' + data.system.git_sha.substring(0, 7);
        document.getElementById('sys-uptime').textContent = formatUptime(data.system.uptime_seconds);
        document.getElementById('sys-load').textContent = data.system.load_average.map(n => n.toFixed(2)).join(', ');
        document.getElementById('sys-mem').textContent = formatBytes(data.system.memory.used_bytes);
        document.getElementById('sys-mem-total').textContent = formatBytes(data.system.memory.total_bytes);

        document.getElementById('wan-iface').textContent = data.network.wan.interface;
        document.getElementById('wan-ip').textContent = (data.network.wan.ip || 'No Lease') + (data.network.wan.prefix_len ? '/' + data.network.wan.prefix_len : '');
        document.getElementById('wan-gw').textContent = data.network.wan.gateway || '--';
        document.getElementById('wan-dns').textContent = data.network.wan.dns_servers.join(', ') || '--';
        document.getElementById('wan-traffic').textContent = formatBytes(data.network.wan.rx_bytes) + ' / ' + formatBytes(data.network.wan.tx_bytes);

        document.getElementById('lan-iface').textContent = data.network.lan.interface;
        document.getElementById('lan-ip').textContent = data.network.lan.ip + '/' + data.network.lan.prefix_len;
        document.getElementById('lan-mode').textContent = data.network.lan.mode;
        document.getElementById('lan-mac').textContent = data.network.lan.mac;
        document.getElementById('lan-traffic').textContent = formatBytes(data.network.lan.rx_bytes) + ' / ' + formatBytes(data.network.lan.tx_bytes);

        document.getElementById('dns-queries').textContent = data.dns_forwarder.queries_total.toLocaleString();
        document.getElementById('dns-cache').textContent = (data.dns_forwarder.cache_hit_ratio * 100).toFixed(1) + '% (' + data.dns_forwarder.cached_entries_count + ' items)';
        document.getElementById('dhcp-count').textContent = data.dhcp_server.active_leases_count;

        const sntpText = data.sntp.synchronized ? ('Synced (' + (data.sntp.server || 'NTP') + ')') : 'Not Synchronized';
        document.getElementById('sntp-sync').textContent = sntpText;

        const tbody = document.getElementById('leases-body');
        if (data.dhcp_server.leases && data.dhcp_server.leases.length > 0) {
          tbody.innerHTML = data.dhcp_server.leases.map(l => `
            <tr>
              <td>${l.ip}</td>
              <td>${l.mac}</td>
              <td>${l.hostname || '<span style="color:var(--text-muted);">unknown</span>'}</td>
              <td>${formatUptime(l.expires_in_seconds)}</td>
              <td><span class="badge" style="font-size:0.7rem;">${l.is_static ? 'STATIC' : 'DYNAMIC'}</span></td>
            </tr>
          `).join('');
        } else {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No active leases</td></tr>';
        }
      } catch (err) {
        console.error('Failed to fetch status:', err);
      }
    }

    // Terminal Logging Logic
    let isPaused = false;
    const terminal = document.getElementById('log-terminal');
    const pauseBtn = document.getElementById('pause-btn');
    const clearBtn = document.getElementById('clear-btn');
    const autoscrollChk = document.getElementById('autoscroll-chk');
    const levelFilter = document.getElementById('level-filter');

    pauseBtn.addEventListener('click', () => {
      isPaused = !isPaused;
      pauseBtn.textContent = isPaused ? 'Resume' : 'Pause';
    });

    clearBtn.addEventListener('click', () => {
      terminal.innerHTML = '';
    });

    function parseLogLine(raw) {
      const match = raw.match(/^\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]\s+(.*)$/);
      if (match) {
        return { ts: match[1], level: match[2].toUpperCase(), svc: match[3], msg: match[4] };
      }
      return { ts: '', level: 'INFO', svc: '', msg: raw };
    }

    function appendLog(raw) {
      if (isPaused) return;
      const parsed = parseLogLine(raw.trim());
      const selectedLevel = levelFilter.value;
      if (selectedLevel === 'ERROR' && parsed.level !== 'ERROR') return;
      if (selectedLevel === 'WARN' && parsed.level !== 'WARN' && parsed.level !== 'ERROR') return;
      if (selectedLevel === 'INFO' && parsed.level === 'DEBUG') return;

      const div = document.createElement('div');
      div.className = 'log-line';
      div.innerHTML = `<span class="log-ts">[${parsed.ts}]</span><span class="log-line log-${parsed.level}">[${parsed.level}]</span> <span class="log-svc">[${parsed.svc}]</span> <span class="log-msg">${escapeHtml(parsed.msg)}</span>`;
      terminal.appendChild(div);

      if (autoscrollChk.checked) {
        terminal.scrollTop = terminal.scrollHeight;
      }
      if (terminal.childNodes.length > 500) {
        terminal.removeChild(terminal.firstChild);
      }
    }

    function escapeHtml(text) {
      const d = document.createElement('div');
      d.textContent = text;
      return d.innerHTML;
    }

    // Connect SSE stream
    function initLogs() {
      fetch('/api/logs?lines=100').then(r => r.json()).then(data => {
        if (data.lines) {
          data.lines.forEach(appendLog);
        }
      }).catch(console.error);

      if (window.EventSource) {
        const source = new EventSource('/api/logs/stream');
        source.onmessage = (e) => appendLog(e.data);
        source.onerror = () => {
          source.close();
          setTimeout(initLogs, 5000);
        };
      }
    }

    fetchStatus();
    setInterval(fetchStatus, 3000);
    initLogs();
  </script>
</body>
</html>
"#;

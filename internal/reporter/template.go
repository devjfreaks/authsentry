package reporter

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuthSentry — Login Risk Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=Inter:wght@300;400;500;600;700&display=swap');

  :root {
    --bg: #0a0a0f;
    --surface: #111118;
    --surface2: #16161f;
    --border: rgba(255,255,255,0.07);
    --text: #e8e8f0;
    --text-muted: #6b6b80;
    --text-dim: #3a3a4a;
    --critical: #ff2d55;
    --high: #ff9500;
    --medium: #ffcc00;
    --low: #34c759;
    --info: #636366;
    --accent: #6e6eff;
    --font-mono: 'JetBrains Mono', monospace;
    --font: 'Inter', sans-serif;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* Noise overlay */
  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 0; pointer-events: none;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E");
    opacity: 0.4;
  }

  .container { max-width: 1400px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }

  /* ── Header ── */
  header {
    border-bottom: 1px solid var(--border);
    padding: 28px 0 24px;
    margin-bottom: 32px;
  }
  .header-inner { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; }
  .logo {
    display: flex; align-items: center; gap: 12px;
  }
  .logo-icon {
    width: 40px; height: 40px;
    background: linear-gradient(135deg, var(--accent) 0%, #ff2d55 100%);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
  }
  .logo-text { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
  .logo-sub { font-size: 12px; color: var(--text-muted); font-family: var(--font-mono); margin-top: 2px; }
  .meta { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); text-align: right; }
  .meta span { display: block; }

  /* ── Stat Cards ── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 32px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.2s;
  }
  .stat-card:hover { border-color: rgba(255,255,255,0.14); }
  .stat-card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--card-accent, var(--accent));
  }
  .stat-value { font-size: 32px; font-weight: 700; font-family: var(--font-mono); line-height: 1; margin-bottom: 6px; }
  .stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.8px; }

  /* ── Section ── */
  .section { margin-bottom: 32px; }
  .section-header {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 16px;
  }
  .section-title { font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }
  .section-line { flex: 1; height: 1px; background: var(--border); }
  .section-count { font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); }

  /* ── Top IPs ── */
  .top-ips { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
  .ip-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 16px;
    display: flex; align-items: center; gap: 12px;
  }
  .ip-badge {
    width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
    box-shadow: 0 0 8px currentColor;
  }
  .ip-addr { font-family: var(--font-mono); font-size: 13px; flex: 1; }
  .ip-count { font-family: var(--font-mono); font-size: 12px; color: var(--text-muted); }
  .ip-level { font-size: 10px; font-weight: 600; padding: 2px 7px; border-radius: 4px; border: 1px solid currentColor; }

  /* ── Events Table ── */
  .table-wrapper {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }
  table { width: 100%; border-collapse: collapse; }
  thead tr {
    background: var(--surface2);
    border-bottom: 1px solid var(--border);
  }
  th {
    padding: 12px 16px;
    text-align: left;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    white-space: nowrap;
  }
  tr.event-row {
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
  }
  tr.event-row:last-child { border-bottom: none; }
  tr.event-row:hover { background: rgba(255,255,255,0.025); }
  td {
    padding: 12px 16px;
    vertical-align: top;
    font-size: 13px;
  }
  td.ts { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); white-space: nowrap; }
  td.ip-cell { font-family: var(--font-mono); font-weight: 500; }
  td.username { font-family: var(--font-mono); font-size: 12px; color: var(--text-muted); }

  /* Risk badge */
  .risk-badge {
    display: inline-flex; align-items: center; gap: 5px;
    padding: 3px 10px; border-radius: 5px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.5px;
    border: 1px solid currentColor;
    white-space: nowrap;
  }
  .risk-dot { width: 6px; height: 6px; border-radius: 50%; background: currentColor; }

  /* Status badge */
  .status-badge {
    font-size: 11px; font-weight: 600; font-family: var(--font-mono);
    padding: 2px 8px; border-radius: 4px;
  }
  .status-badge.success { background: rgba(52,199,89,0.12); color: #34c759; }
  .status-badge.failure { background: rgba(255,45,85,0.10); color: #ff2d55; }

  /* Reason list */
  .reasons { list-style: none; }
  .reasons li {
    font-size: 12px; color: var(--text-muted);
    padding: 1px 0;
    display: flex; gap: 6px; align-items: flex-start;
  }
  .reasons li::before { content: '›'; color: var(--text-dim); flex-shrink: 0; }

  /* Action */
  .action-text { font-size: 12px; color: var(--text-muted); font-style: italic; max-width: 280px; }

  /* Location */
  .location-text { font-size: 12px; font-family: var(--font-mono); color: var(--text-muted); }

  /* Expandable raw line */
  .raw-toggle { 
    cursor: pointer; font-size: 10px; color: var(--text-dim); 
    font-family: var(--font-mono); text-decoration: underline; 
    background: none; border: none; color: var(--text-dim); cursor: pointer;
  }
  .raw-line {
    display: none; margin-top: 6px;
    font-family: var(--font-mono); font-size: 10px; color: var(--text-muted);
    background: var(--surface2); border-radius: 4px;
    padding: 8px; word-break: break-all;
    white-space: pre-wrap; max-width: 500px;
  }

  /* Footer */
  footer {
    border-top: 1px solid var(--border);
    padding: 20px 0;
    margin-top: 40px;
    text-align: center;
    font-size: 12px;
    color: var(--text-dim);
    font-family: var(--font-mono);
  }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--text-dim); border-radius: 3px; }

  /* Filter bar */
  .filter-bar {
    display: flex; gap: 8px; flex-wrap: wrap;
    margin-bottom: 16px; align-items: center;
  }
  .filter-btn {
    padding: 5px 14px; border-radius: 6px;
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text-muted); font-size: 12px; cursor: pointer;
    transition: all 0.15s; font-family: var(--font);
  }
  .filter-btn:hover, .filter-btn.active { border-color: rgba(255,255,255,0.2); color: var(--text); }
  .filter-btn.active { background: var(--surface2); }
  .filter-search {
    flex: 1; min-width: 200px; max-width: 300px;
    padding: 5px 12px; border-radius: 6px;
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text); font-size: 12px; font-family: var(--font-mono);
    outline: none;
  }
  .filter-search::placeholder { color: var(--text-dim); }
  .filter-search:focus { border-color: rgba(255,255,255,0.2); }

  @media (max-width: 768px) {
    th:nth-child(n+5), td:nth-child(n+5) { display: none; }
    .stats-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
</head>
<body>
<div class="container">

  <header>
    <div class="header-inner">
      <div class="logo">
        <div class="logo-icon">🔍</div>
        <div>
          <div class="logo-text">AuthSentry</div>
          <div class="logo-sub">Suspicious Login Detector</div>
        </div>
      </div>
      <div class="meta">
        <span>Generated: {{.GeneratedAt}}</span>
        <span>{{.Total}} events analyzed</span>
      </div>
    </div>
  </header>

  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card" style="--card-accent: var(--critical)">
      <div class="stat-value" style="color:var(--critical)">{{countByLevel "CRITICAL"}}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card" style="--card-accent: var(--high)">
      <div class="stat-value" style="color:var(--high)">{{countByLevel "HIGH"}}</div>
      <div class="stat-label">High Risk</div>
    </div>
    <div class="stat-card" style="--card-accent: var(--medium)">
      <div class="stat-value" style="color:var(--medium)">{{countByLevel "MEDIUM"}}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card" style="--card-accent: var(--low)">
      <div class="stat-value" style="color:var(--low)">{{countByLevel "LOW"}}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card">
      <div class="stat-value">{{.Summary.UniqueIPs}}</div>
      <div class="stat-label">Unique IPs</div>
    </div>
    <div class="stat-card" style="--card-accent: var(--critical)">
      <div class="stat-value" style="color:var(--critical)">{{.Summary.FailedLogins}}</div>
      <div class="stat-label">Failed Logins</div>
    </div>
  </div>

  <!-- Top IPs -->
  {{if .Summary.TopIPs}}
  <div class="section">
    <div class="section-header">
      <span class="section-title">Top IPs by Event Count</span>
      <div class="section-line"></div>
    </div>
    <div class="top-ips">
      {{range .Summary.TopIPs}}
      <div class="ip-card">
        <div class="ip-badge" style="color:{{riskColor .Level}}; background:{{riskColor .Level}}"></div>
        <div class="ip-addr">{{.IP}}</div>
        <div class="ip-count">{{.Count}}×</div>
        <div class="ip-level" style="color:{{riskColor .Level}}">{{.Level}}</div>
      </div>
      {{end}}
    </div>
  </div>
  {{end}}

  <!-- Events Table -->
  <div class="section">
    <div class="section-header">
      <span class="section-title">Login Events</span>
      <div class="section-line"></div>
      <span class="section-count">{{.Total}} total</span>
    </div>

    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterTable('ALL')">All</button>
      <button class="filter-btn" onclick="filterTable('CRITICAL')" style="color:var(--critical)">Critical</button>
      <button class="filter-btn" onclick="filterTable('HIGH')" style="color:var(--high)">High</button>
      <button class="filter-btn" onclick="filterTable('MEDIUM')" style="color:var(--medium)">Medium</button>
      <button class="filter-btn" onclick="filterTable('LOW')" style="color:var(--low)">Low</button>
      <input class="filter-search" type="text" placeholder="Filter by IP or username..." oninput="searchTable(this.value)">
    </div>

    <div class="table-wrapper">
      <table id="events-table">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>IP Address</th>
            <th>Risk</th>
            <th>Status</th>
            <th>Username</th>
            <th>Location</th>
            <th>Reasons</th>
            <th>Recommended Action</th>
          </tr>
        </thead>
        <tbody>
          {{range .Results}}
          <tr class="event-row" data-level="{{.Risk.Level}}" data-ip="{{.IP}}" data-user="{{.Username}}">
            <td class="ts">{{fmtTime .Timestamp}}</td>
            <td class="ip-cell">
              {{.IP}}
              {{if .RawLine}}
              <br><button class="raw-toggle" onclick="toggleRaw(this)">show raw</button>
              <div class="raw-line">{{.RawLine}}</div>
              {{end}}
            </td>
            <td>
              <div class="risk-badge" style="color:{{riskColor .Risk.Level}}; border-color:{{riskColor .Risk.Level}}; background:{{riskBg .Risk.Level}}">
                <div class="risk-dot"></div>
                {{.Risk.Level}} ({{.Risk.Score}})
              </div>
            </td>
            <td>
              <span class="status-badge {{successClass .Success}}">{{successLabel .Success}}</span>
            </td>
            <td class="username">{{if .Username}}{{.Username}}{{else}}<span style="color:var(--text-dim)">—</span>{{end}}</td>
            <td>
              {{if .IPData}}
              <div class="location-text">
                {{if .IPData.Location.CountryEmoji}}{{.IPData.Location.CountryEmoji}} {{end}}{{if .IPData.Location.CountryCode2}}{{.IPData.Location.CountryCode2}}{{end}}{{if .IPData.Location.City}} &middot; {{.IPData.Location.City}}{{end}}
                {{if .IPData.ASN.Organization}}<br><span style="color:var(--text-dim)">{{.IPData.ASN.Organization}}</span>{{end}}
                {{if .IPData.ASN.Type}}<br><span style="color:var(--text-dim)">{{.IPData.ASN.ASNumber}} &middot; {{.IPData.ASN.Type}}</span>{{end}}
                {{if .IPData.Security.IsCloudProvider}}<br><span style="color:var(--high)">&#9729; {{.IPData.Security.CloudProviderName}}</span>{{end}}
              </div>
              {{else}}<span style="color:var(--text-dim)">—</span>{{end}}
            </td>
            <td>
              {{if .Risk.Reasons}}
              <ul class="reasons">
                {{range .Risk.Reasons}}<li>{{.}}</li>{{end}}
              </ul>
              {{else}}<span style="color:var(--text-dim)">—</span>{{end}}
            </td>
            <td>
              <div class="action-text">{{.Risk.RecommendedAction}}</div>
            </td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
  </div>

</div>

<footer>
  <div class="container">
    AuthSentry · Powered by ipgeolocation.io · Report generated {{.GeneratedAt}}
  </div>
</footer>

<script>
function filterTable(level) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.event-row').forEach(row => {
    row.style.display = (level === 'ALL' || row.dataset.level === level) ? '' : 'none';
  });
}

function searchTable(q) {
  q = q.toLowerCase();
  document.querySelectorAll('.event-row').forEach(row => {
    const match = row.dataset.ip.includes(q) || row.dataset.user.toLowerCase().includes(q);
    row.style.display = match ? '' : 'none';
  });
}

function toggleRaw(btn) {
  const rawDiv = btn.nextElementSibling;
  if (rawDiv.style.display === 'block') {
    rawDiv.style.display = 'none';
    btn.textContent = 'show raw';
  } else {
    rawDiv.style.display = 'block';
    btn.textContent = 'hide raw';
  }
}
</script>
</body>
</html>`

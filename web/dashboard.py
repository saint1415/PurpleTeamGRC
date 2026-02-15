#!/usr/bin/env python3
"""
Purple Team GRC - Self-Contained HTML Dashboard
Multi-page SPA using inline CSS and JavaScript.
No external CDN dependencies (air-gapped operation).
Calls the REST API via fetch() for live data.

Tabs: Overview | Scan Center | Schedules | Notifications | AI Assistant
"""


def generate_dashboard_html() -> str:
    """Return the complete HTML dashboard as a string."""
    return _DASHBOARD_HTML


# =========================================================================
# Complete inline dashboard HTML / CSS / JS
# =========================================================================

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Purple Team GRC - Dashboard</title>
<style>
/* ===================================================================
   CSS Reset & Variables
   =================================================================== */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
    --bg-primary:   #1a1a2e;
    --bg-secondary: #16213e;
    --bg-card:      #1f2b47;
    --bg-card-alt:  #253456;
    --border:       #2a3a5c;
    --text:         #e0e0e0;
    --text-muted:   #8892a4;
    --text-bright:  #ffffff;
    --accent:       #6c63ff;
    --accent-dim:   #4a44b3;
    --critical:     #ff4757;
    --high:         #ff7f50;
    --medium:       #ffa502;
    --low:          #2ed573;
    --info:         #45aaf2;
    --resolved:     #26de81;
    --overdue:      #fc5c65;
    --font-data:    'Consolas', 'Courier New', 'Liberation Mono', monospace;
    --font-ui:      -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    --radius:       8px;
    --shadow:       0 2px 12px rgba(0,0,0,0.3);
}
html { font-size: 14px; }
body {
    font-family: var(--font-ui);
    background: var(--bg-primary);
    color: var(--text);
    line-height: 1.5;
    min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ===================================================================
   Layout
   =================================================================== */
.dashboard {
    max-width: 1440px;
    margin: 0 auto;
    padding: 20px;
}

/* Header */
.header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(135deg, var(--bg-secondary), #0f3460);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px 28px;
    margin-bottom: 0;
}
.header-left { display: flex; align-items: center; gap: 16px; }
.header-logo {
    width: 42px; height: 42px;
    background: var(--accent);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 22px; font-weight: 700; color: #fff;
}
.header h1 { font-size: 1.5rem; color: var(--text-bright); font-weight: 600; }
.header-sub { font-size: 0.85rem; color: var(--text-muted); }
.header-right { text-align: right; font-size: 0.8rem; color: var(--text-muted); }
.header-right .status-dot {
    display: inline-block; width: 8px; height: 8px;
    background: var(--resolved); border-radius: 50%;
    margin-right: 4px; vertical-align: middle;
}

/* Tab Navigation */
.tab-nav {
    display: flex;
    gap: 0;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    border-top: none;
    border-radius: 0 0 var(--radius) var(--radius);
    margin-bottom: 20px;
    overflow-x: auto;
    padding: 0 8px;
}
.tab-btn {
    background: none; border: none;
    color: var(--text-muted);
    font-family: var(--font-ui);
    font-size: 0.85rem; font-weight: 600;
    padding: 12px 20px;
    cursor: pointer;
    border-bottom: 2px solid transparent;
    transition: color 0.2s, border-color 0.2s;
    white-space: nowrap;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active {
    color: var(--accent);
    border-bottom-color: var(--accent);
}

/* Tab pages */
.tab-page { display: none; }
.tab-page.active { display: block; }

/* Grid */
.grid { display: grid; gap: 16px; margin-bottom: 20px; }
.grid-4 { grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); }
.grid-2 { grid-template-columns: repeat(auto-fill, minmax(440px, 1fr)); }
.grid-3 { grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); }

/* Cards */
.card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px;
    box-shadow: var(--shadow);
}
.card-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 12px;
}
.card-title {
    font-size: 0.9rem; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase;
    letter-spacing: 0.5px;
}
.card-badge {
    font-size: 0.7rem; padding: 2px 8px;
    border-radius: 10px; font-weight: 600;
}

/* Stat cards */
.stat-card { text-align: center; padding: 22px 16px; }
.stat-value {
    font-size: 2.2rem; font-weight: 700;
    font-family: var(--font-data);
    line-height: 1.2; margin-bottom: 4px;
}
.stat-label {
    font-size: 0.8rem; color: var(--text-muted);
    text-transform: uppercase; letter-spacing: 0.5px;
}
.stat-trend { font-size: 0.75rem; margin-top: 6px; }

/* Tables */
.table-wrap { overflow-x: auto; }
table {
    width: 100%; border-collapse: collapse;
    font-size: 0.85rem;
}
th {
    text-align: left; padding: 10px 12px;
    background: var(--bg-card-alt);
    color: var(--text-muted); font-weight: 600;
    font-size: 0.75rem; text-transform: uppercase;
    letter-spacing: 0.3px;
    border-bottom: 1px solid var(--border);
}
td {
    padding: 9px 12px;
    border-bottom: 1px solid var(--border);
}
tr:hover td { background: rgba(108,99,255,0.06); }
.sev-badge {
    display: inline-block; padding: 2px 8px;
    border-radius: 3px; color: #fff;
    font-size: 0.72rem; font-weight: 600;
    text-transform: uppercase;
}
.sev-critical { background: var(--critical); }
.sev-high     { background: var(--high); }
.sev-medium   { background: var(--medium); color: #1a1a2e; }
.sev-low      { background: var(--low); color: #1a1a2e; }
.sev-info     { background: var(--info); }

/* Progress bars */
.progress-bar {
    height: 8px; background: var(--bg-primary);
    border-radius: 4px; overflow: hidden;
    margin-top: 6px;
}
.progress-fill {
    height: 100%; border-radius: 4px;
    transition: width 0.6s ease;
}

/* Risk matrix */
.risk-matrix {
    display: grid;
    grid-template-columns: 40px repeat(5, 1fr);
    grid-template-rows: repeat(5, 48px) 30px;
    gap: 3px;
    max-width: 400px;
    margin: 0 auto;
}
.risk-cell {
    display: flex; align-items: center; justify-content: center;
    border-radius: 4px; font-weight: 700;
    font-family: var(--font-data); font-size: 0.9rem;
    cursor: default; transition: transform 0.15s;
    color: #fff;
}
.risk-cell:hover { transform: scale(1.08); z-index: 1; }
.risk-cell.empty { color: rgba(255,255,255,0.3); font-size: 0.7rem; }
.risk-label {
    display: flex; align-items: center; justify-content: center;
    font-size: 0.65rem; color: var(--text-muted);
    text-transform: uppercase; writing-mode: vertical-lr;
    transform: rotate(180deg);
}
.risk-label-x {
    font-size: 0.65rem; color: var(--text-muted);
    text-transform: uppercase; text-align: center;
}

/* Agent list */
.agent-row {
    display: flex; align-items: center; gap: 10px;
    padding: 8px 0; border-bottom: 1px solid var(--border);
}
.agent-dot {
    width: 10px; height: 10px; border-radius: 50%;
}
.agent-dot.online  { background: var(--resolved); }
.agent-dot.offline { background: var(--overdue); }
.agent-name { font-weight: 600; font-family: var(--font-data); }
.agent-time { color: var(--text-muted); font-size: 0.8rem; margin-left: auto; }

/* Finding expand */
.finding-item {
    border-bottom: 1px solid var(--border);
    padding: 10px 0;
}
.finding-header {
    display: flex; align-items: center; gap: 10px;
    cursor: pointer; user-select: none;
}
.finding-header:hover { color: var(--accent); }
.finding-arrow { transition: transform 0.2s; font-size: 0.8rem; }
.finding-arrow.open { transform: rotate(90deg); }
.finding-body {
    display: none; padding: 10px 0 6px 22px;
    font-size: 0.85rem; color: var(--text-muted);
}
.finding-body.open { display: block; }

/* Loading / Error */
.loading {
    text-align: center; padding: 40px;
    color: var(--text-muted); font-size: 0.9rem;
}
.error-msg {
    background: rgba(255,71,87,0.1); border: 1px solid var(--critical);
    border-radius: var(--radius); padding: 12px 16px;
    color: var(--critical); font-size: 0.85rem;
}

/* ===================================================================
   Form Controls (new)
   =================================================================== */
.form-group { margin-bottom: 14px; }
.form-group label {
    display: block; font-size: 0.8rem; font-weight: 600;
    color: var(--text-muted); text-transform: uppercase;
    letter-spacing: 0.3px; margin-bottom: 4px;
}
.form-group input, .form-group select, .form-group textarea {
    width: 100%;
    padding: 8px 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 0.85rem;
    outline: none;
    transition: border-color 0.2s;
}
.form-group input:focus, .form-group select:focus, .form-group textarea:focus {
    border-color: var(--accent);
}
.form-group textarea { min-height: 70px; resize: vertical; font-family: var(--font-data); }
.form-group select { cursor: pointer; }
.form-group .help-text {
    font-size: 0.72rem; color: var(--text-muted); margin-top: 3px;
}

/* Buttons */
.btn {
    display: inline-flex; align-items: center; gap: 6px;
    padding: 8px 18px;
    border: 1px solid transparent;
    border-radius: var(--radius);
    font-family: var(--font-ui);
    font-size: 0.82rem; font-weight: 600;
    cursor: pointer;
    transition: background 0.2s, border-color 0.2s, opacity 0.2s;
}
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover:not(:disabled) { background: var(--accent-dim); }
.btn-danger { background: var(--critical); color: #fff; }
.btn-danger:hover:not(:disabled) { background: #e0323f; }
.btn-outline {
    background: transparent; color: var(--text);
    border-color: var(--border);
}
.btn-outline:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
.btn-sm { padding: 4px 10px; font-size: 0.75rem; }

/* Toggle switch */
.toggle {
    position: relative; display: inline-block;
    width: 40px; height: 22px;
}
.toggle input { opacity: 0; width: 0; height: 0; }
.toggle-slider {
    position: absolute; cursor: pointer;
    top: 0; left: 0; right: 0; bottom: 0;
    background: var(--border);
    border-radius: 22px;
    transition: background 0.3s;
}
.toggle-slider::before {
    content: '';
    position: absolute; height: 16px; width: 16px;
    left: 3px; bottom: 3px;
    background: white; border-radius: 50%;
    transition: transform 0.3s;
}
.toggle input:checked + .toggle-slider { background: var(--accent); }
.toggle input:checked + .toggle-slider::before { transform: translateX(18px); }

/* Toast notifications */
.toast-container {
    position: fixed; top: 20px; right: 20px;
    z-index: 9999; display: flex; flex-direction: column; gap: 8px;
}
.toast {
    padding: 12px 20px;
    border-radius: var(--radius);
    font-size: 0.85rem; font-weight: 500;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    animation: toastIn 0.3s ease;
    max-width: 400px;
}
.toast-success { background: #1b5e20; color: #c8e6c9; border: 1px solid var(--resolved); }
.toast-error { background: #4a1c1c; color: #ffcdd2; border: 1px solid var(--critical); }
.toast-info { background: #1a2744; color: #bbdefb; border: 1px solid var(--info); }
@keyframes toastIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }

/* Chat (AI) */
.chat-container {
    display: flex; flex-direction: column;
    height: 500px; border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
}
.chat-messages {
    flex: 1; overflow-y: auto; padding: 16px;
    background: var(--bg-primary);
}
.chat-msg {
    margin-bottom: 12px; padding: 10px 14px;
    border-radius: var(--radius); max-width: 85%;
    font-size: 0.85rem; line-height: 1.5;
    white-space: pre-wrap;
}
.chat-msg.user {
    background: var(--accent-dim); color: #fff;
    margin-left: auto;
}
.chat-msg.ai {
    background: var(--bg-card); color: var(--text);
}
.chat-input-row {
    display: flex; gap: 8px; padding: 12px;
    background: var(--bg-card);
    border-top: 1px solid var(--border);
}
.chat-input-row input {
    flex: 1; padding: 8px 12px;
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    color: var(--text);
    font-family: var(--font-ui);
    font-size: 0.85rem;
    outline: none;
}
.chat-input-row input:focus { border-color: var(--accent); }

/* Status pill */
.status-pill {
    display: inline-block; padding: 2px 8px;
    border-radius: 10px; font-size: 0.72rem; font-weight: 600;
}
.status-sent { background: rgba(38,222,129,0.15); color: var(--resolved); }
.status-failed { background: rgba(255,71,87,0.15); color: var(--critical); }
.status-pending { background: rgba(255,165,2,0.15); color: var(--medium); }

/* Footer */
.footer {
    text-align: center; padding: 20px;
    color: var(--text-muted); font-size: 0.75rem;
    border-top: 1px solid var(--border);
    margin-top: 20px;
}

/* Responsive */
@media (max-width: 768px) {
    .grid-4 { grid-template-columns: repeat(2, 1fr); }
    .grid-2, .grid-3 { grid-template-columns: 1fr; }
    .header { flex-direction: column; gap: 10px; text-align: center; }
    .tab-btn { padding: 10px 14px; font-size: 0.78rem; }
}
</style>
</head>
<body>

<div class="dashboard" id="app">

    <!-- Header -->
    <div class="header">
        <div class="header-left">
            <div class="header-logo">P</div>
            <div>
                <h1>Purple Team GRC</h1>
                <div class="header-sub">Governance, Risk &amp; Compliance Platform</div>
            </div>
        </div>
        <div class="header-right">
            <div><span class="status-dot" id="health-dot"></span> <span id="health-status">Connecting...</span></div>
            <div id="last-updated">--</div>
        </div>
    </div>

    <!-- Tab Navigation -->
    <nav class="tab-nav">
        <button class="tab-btn active" data-tab="overview" onclick="switchTab('overview')">Overview</button>
        <button class="tab-btn" data-tab="scan-center" onclick="switchTab('scan-center')">Scan Center</button>
        <button class="tab-btn" data-tab="schedules" onclick="switchTab('schedules')">Schedules</button>
        <button class="tab-btn" data-tab="notifications" onclick="switchTab('notifications')">Notifications</button>
        <button class="tab-btn" data-tab="ai-assistant" onclick="switchTab('ai-assistant')">AI Assistant</button>
    </nav>

    <!-- ============================================================
         TAB 1: Overview (original dashboard)
         ============================================================ -->
    <div class="tab-page active" id="page-overview">

        <!-- Overview Stat Cards -->
        <div class="grid grid-4" id="overview-cards">
            <div class="card stat-card">
                <div class="stat-value" id="stat-assets" style="color:var(--info)">--</div>
                <div class="stat-label">Total Assets</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value" id="stat-findings" style="color:var(--critical)">--</div>
                <div class="stat-label">Open Findings</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value" id="stat-sla" style="color:var(--resolved)">--%</div>
                <div class="stat-label">SLA Compliance</div>
            </div>
            <div class="card stat-card">
                <div class="stat-value" id="stat-risk" style="color:var(--medium)">--</div>
                <div class="stat-label">Avg Risk Score</div>
            </div>
        </div>

        <!-- Row: Findings Chart + Remediation Donut -->
        <div class="grid grid-2">
            <div class="card">
                <div class="card-header"><span class="card-title">Findings by Severity</span></div>
                <div id="findings-chart"><div class="loading">Loading chart...</div></div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Remediation Status</span></div>
                <div id="remediation-chart"><div class="loading">Loading chart...</div></div>
            </div>
        </div>

        <!-- Row: Risk Matrix + Asset Coverage -->
        <div class="grid grid-2">
            <div class="card">
                <div class="card-header"><span class="card-title">Risk Matrix</span></div>
                <div id="risk-matrix-container"><div class="loading">Loading matrix...</div></div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Asset Scan Coverage</span></div>
                <div id="asset-coverage"><div class="loading">Loading coverage...</div></div>
            </div>
        </div>

        <!-- Recent Scans Table -->
        <div class="card" style="margin-bottom:20px">
            <div class="card-header"><span class="card-title">Recent Scans</span></div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Session ID</th><th>Type</th><th>Date</th><th>Status</th><th>Targets</th></tr></thead>
                    <tbody id="scans-table-body"><tr><td colspan="5" class="loading">Loading...</td></tr></tbody>
                </table>
            </div>
        </div>

        <!-- Row: Top Critical Findings + Compliance -->
        <div class="grid grid-2">
            <div class="card">
                <div class="card-header"><span class="card-title">Top Critical Findings</span></div>
                <div id="top-findings"><div class="loading">Loading...</div></div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Compliance Scores</span></div>
                <div id="compliance-scores"><div class="loading">Loading...</div></div>
            </div>
        </div>

        <div class="grid grid-2">
            <div class="card">
                <div class="card-header"><span class="card-title">Exception Status</span></div>
                <div id="exception-status"><div class="loading">Loading...</div></div>
            </div>
            <div class="card">
                <div class="card-header"><span class="card-title">Connected Agents</span></div>
                <div id="agent-status"><div class="loading">Loading...</div></div>
            </div>
        </div>

    </div><!-- /page-overview -->

    <!-- ============================================================
         TAB 2: Scan Center
         ============================================================ -->
    <div class="tab-page" id="page-scan-center">
        <div class="grid grid-2">
            <!-- Launch Scan -->
            <div class="card">
                <div class="card-header"><span class="card-title">Launch Scan</span></div>
                <div class="form-group">
                    <label>Scanner Type</label>
                    <select id="sc-scanner-type"><option value="">Loading scanners...</option></select>
                </div>
                <div class="form-group">
                    <label>Targets</label>
                    <textarea id="sc-targets" placeholder="Enter IPs, CIDRs, or hostnames (one per line)"></textarea>
                    <div class="help-text">Examples: 192.168.1.0/24, 10.0.0.1, example.com</div>
                </div>
                <div class="form-group">
                    <label>Scan Depth</label>
                    <select id="sc-depth">
                        <option value="quick">Quick</option>
                        <option value="standard" selected>Standard</option>
                        <option value="deep">Deep</option>
                    </select>
                </div>
                <button class="btn btn-primary" onclick="launchScan()">Launch Scan</button>
            </div>

            <!-- Recent Scans -->
            <div class="card">
                <div class="card-header"><span class="card-title">Recent Scans</span></div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Session</th><th>Type</th><th>Status</th><th>Date</th><th>Action</th></tr></thead>
                        <tbody id="sc-scans-body"><tr><td colspan="5" class="loading">Loading...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Findings Panel -->
        <div class="card" id="sc-findings-panel" style="display:none;margin-top:16px">
            <div class="card-header">
                <span class="card-title">Findings for: <span id="sc-findings-session"></span></span>
            </div>
            <div id="sc-findings-list"><div class="loading">Loading findings...</div></div>
        </div>
    </div><!-- /page-scan-center -->

    <!-- ============================================================
         TAB 3: Schedules
         ============================================================ -->
    <div class="tab-page" id="page-schedules">
        <div class="grid grid-2">
            <!-- Create Schedule -->
            <div class="card">
                <div class="card-header"><span class="card-title">Create Schedule</span></div>
                <div class="form-group">
                    <label>Schedule Name</label>
                    <input type="text" id="sched-name" placeholder="e.g. Weekly Network Scan"/>
                </div>
                <div class="form-group">
                    <label>Scanner Type</label>
                    <select id="sched-scanner">
                        <option value="network">Network</option>
                        <option value="vulnerability">Vulnerability</option>
                        <option value="web">Web Application</option>
                        <option value="ssl">SSL/TLS</option>
                        <option value="windows">Windows</option>
                        <option value="linux">Linux</option>
                        <option value="ad">Active Directory</option>
                        <option value="cloud">Cloud</option>
                        <option value="container">Container</option>
                        <option value="sbom">SBOM</option>
                        <option value="full">Full Suite</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Targets</label>
                    <textarea id="sched-targets" placeholder="IPs, CIDRs, or hostnames (one per line)"></textarea>
                </div>
                <div class="form-group">
                    <label>Cron Expression</label>
                    <input type="text" id="sched-cron" placeholder="0 2 * * 1"/>
                    <div class="help-text">Format: minute hour day month weekday (e.g. "0 2 * * 1" = Mon 2:00 AM)</div>
                </div>
                <div class="form-group">
                    <label>Scan Depth</label>
                    <select id="sched-depth">
                        <option value="quick">Quick</option>
                        <option value="standard" selected>Standard</option>
                        <option value="deep">Deep</option>
                    </select>
                </div>
                <button class="btn btn-primary" onclick="createSchedule()">Create Schedule</button>
            </div>

            <!-- Schedule List -->
            <div class="card">
                <div class="card-header"><span class="card-title">All Schedules</span></div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Name</th><th>Scanner</th><th>Cron</th><th>Next Run</th><th>Enabled</th><th>Actions</th></tr></thead>
                        <tbody id="sched-list-body"><tr><td colspan="6" class="loading">Loading...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Run History -->
        <div class="card" id="sched-history-panel" style="display:none;margin-top:16px">
            <div class="card-header">
                <span class="card-title">Run History: <span id="sched-history-name"></span></span>
            </div>
            <div class="table-wrap">
                <table>
                    <thead><tr><th>Run ID</th><th>Started</th><th>Completed</th><th>Status</th><th>Session</th></tr></thead>
                    <tbody id="sched-history-body"><tr><td colspan="5" class="loading">Loading...</td></tr></tbody>
                </table>
            </div>
        </div>
    </div><!-- /page-schedules -->

    <!-- ============================================================
         TAB 4: Notifications
         ============================================================ -->
    <div class="tab-page" id="page-notifications">
        <div class="grid grid-2">
            <!-- Add Channel -->
            <div class="card">
                <div class="card-header"><span class="card-title">Add Notification Channel</span></div>
                <div class="form-group">
                    <label>Channel Name</label>
                    <input type="text" id="notif-name" placeholder="e.g. Security Team Email"/>
                </div>
                <div class="form-group">
                    <label>Channel Type</label>
                    <select id="notif-type" onchange="notifTypeChanged()">
                        <option value="email">Email (SMTP)</option>
                        <option value="slack">Slack</option>
                        <option value="teams">Microsoft Teams</option>
                        <option value="webhook">Webhook</option>
                        <option value="syslog">Syslog</option>
                        <option value="sms_twilio">SMS (Twilio)</option>
                        <option value="sms_sns">SMS (AWS SNS)</option>
                        <option value="sms_gateway">SMS (HTTP Gateway)</option>
                        <option value="sms_email">SMS (Carrier Email)</option>
                    </select>
                </div>
                <div id="notif-config-fields">
                    <!-- Dynamic fields populated by JS -->
                </div>
                <button class="btn btn-primary" onclick="addChannel()">Add Channel</button>
            </div>

            <!-- Channels List -->
            <div class="card">
                <div class="card-header"><span class="card-title">Notification Channels</span></div>
                <div id="notif-channels-list"><div class="loading">Loading channels...</div></div>
            </div>
        </div>

        <div class="grid grid-2" style="margin-top:0">
            <!-- Statistics -->
            <div class="card">
                <div class="card-header"><span class="card-title">Notification Statistics</span></div>
                <div id="notif-stats"><div class="loading">Loading stats...</div></div>
            </div>

            <!-- Recent Notifications -->
            <div class="card">
                <div class="card-header"><span class="card-title">Recent Notifications</span></div>
                <div class="table-wrap">
                    <table>
                        <thead><tr><th>Time</th><th>Event</th><th>Channel</th><th>Status</th></tr></thead>
                        <tbody id="notif-history-body"><tr><td colspan="4" class="loading">Loading...</td></tr></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div><!-- /page-notifications -->

    <!-- ============================================================
         TAB 5: AI Assistant
         ============================================================ -->
    <div class="tab-page" id="page-ai-assistant">
        <div class="grid grid-2">
            <!-- Chat -->
            <div class="card" style="padding:0">
                <div class="card-header" style="padding:14px 18px;margin-bottom:0">
                    <span class="card-title">AI Assistant</span>
                    <span id="ai-status-badge" class="status-pill status-pending">checking...</span>
                </div>
                <div class="chat-container">
                    <div class="chat-messages" id="ai-chat-messages">
                        <div class="chat-msg ai">Welcome! I can help you analyze findings, triage vulnerabilities, generate remediation steps, and answer security questions. What would you like to know?</div>
                    </div>
                    <div class="chat-input-row">
                        <input type="text" id="ai-chat-input" placeholder="Ask about your scan results, findings, or security topics..."
                               onkeydown="if(event.key==='Enter')aiSendMessage()"/>
                        <button class="btn btn-primary btn-sm" onclick="aiSendMessage()">Send</button>
                    </div>
                </div>
            </div>

            <!-- Quick Actions + Status -->
            <div>
                <div class="card" style="margin-bottom:16px">
                    <div class="card-header"><span class="card-title">AI Status</span></div>
                    <div id="ai-status-detail"><div class="loading">Checking AI availability...</div></div>
                </div>
                <div class="card">
                    <div class="card-header"><span class="card-title">Quick Actions</span></div>
                    <div style="display:flex;flex-direction:column;gap:8px">
                        <button class="btn btn-outline" onclick="aiQuickAction('Summarize the most recent scan results')">Summarize Latest Scan</button>
                        <button class="btn btn-outline" onclick="aiQuickAction('What are the top 5 most critical findings that need immediate attention?')">Top Critical Findings</button>
                        <button class="btn btn-outline" onclick="aiQuickAction('Generate a remediation priority list based on risk and exploitability')">Remediation Priorities</button>
                        <button class="btn btn-outline" onclick="aiQuickAction('What is my overall security posture and what should I focus on?')">Security Posture Review</button>
                    </div>
                </div>
            </div>
        </div>
    </div><!-- /page-ai-assistant -->

    <!-- Footer -->
    <div class="footer">
        Purple Team GRC v7.0 &mdash; Dashboard auto-refreshes every 60 seconds
    </div>

</div>

<!-- Toast container -->
<div class="toast-container" id="toast-container"></div>

<!-- ================================================================
     JavaScript  -  All inline, no external dependencies
     ================================================================ -->
<script>
(function() {
    'use strict';

    // ---- Config --------------------------------------------------------
    var API_BASE = window.location.origin + '/api/v1';
    var REFRESH_INTERVAL = 60000;
    var API_KEY = '';
    var activeTab = 'overview';
    var tabLoaded = { overview: false };

    // ---- Helpers -------------------------------------------------------
    function fetchAPI(endpoint, opts) {
        opts = opts || {};
        var headers = { 'Accept': 'application/json' };
        if (API_KEY) headers['X-API-Key'] = API_KEY;
        if (opts.body && typeof opts.body === 'object') {
            headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(opts.body);
        }
        return fetch(API_BASE + endpoint, {
            method: opts.method || 'GET',
            headers: headers,
            body: opts.body || undefined,
        })
        .then(function(r) { return r.json(); })
        .catch(function(e) { console.error('API error:', endpoint, e); return null; });
    }

    function $(id) { return document.getElementById(id); }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;')
            .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    }

    function sevClass(sev) {
        if (!sev) return 'sev-info';
        var s = sev.toUpperCase();
        if (s === 'CRITICAL') return 'sev-critical';
        if (s === 'HIGH')     return 'sev-high';
        if (s === 'MEDIUM')   return 'sev-medium';
        if (s === 'LOW')      return 'sev-low';
        return 'sev-info';
    }

    function sevColor(sev) {
        if (!sev) return 'var(--info)';
        var s = sev.toUpperCase();
        if (s === 'CRITICAL') return 'var(--critical)';
        if (s === 'HIGH')     return 'var(--high)';
        if (s === 'MEDIUM')   return 'var(--medium)';
        if (s === 'LOW')      return 'var(--low)';
        return 'var(--info)';
    }

    // ---- Toast Notifications -------------------------------------------
    window.showToast = function(msg, type) {
        type = type || 'info';
        var container = $('toast-container');
        var toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.textContent = msg;
        container.appendChild(toast);
        setTimeout(function() {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(function() { container.removeChild(toast); }, 300);
        }, 4000);
    };

    // ---- Tab Switching -------------------------------------------------
    window.switchTab = function(tabId) {
        activeTab = tabId;
        document.querySelectorAll('.tab-btn').forEach(function(btn) {
            btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
        });
        document.querySelectorAll('.tab-page').forEach(function(page) {
            page.classList.toggle('active', page.id === 'page-' + tabId);
        });
        // Lazy load tab data
        if (!tabLoaded[tabId]) {
            tabLoaded[tabId] = true;
            loadTabData(tabId);
        }
    };

    function loadTabData(tabId) {
        if (tabId === 'overview') { loadOverview(); }
        else if (tabId === 'scan-center') { loadScanCenter(); }
        else if (tabId === 'schedules') { loadSchedules(); }
        else if (tabId === 'notifications') { loadNotifications(); }
        else if (tabId === 'ai-assistant') { loadAIStatus(); }
    }

    // ---- SVG Chart Generators ------------------------------------------

    function svgBarChart(data, width, height) {
        if (!data || !data.length) return '<div class="loading">No data</div>';
        var maxVal = Math.max.apply(null, data.map(function(d){return d.value;})) || 1;
        var marginLeft = 80, marginRight = 50, marginTop = 10, marginBottom = 10;
        var chartW = width - marginLeft - marginRight;
        var barH = Math.min(28, Math.max(14, (height - marginTop - marginBottom) / data.length - 6));
        var spacing = 6;
        var actualH = marginTop + data.length * (barH + spacing) + marginBottom;
        var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+ width +' '+ actualH +'" width="100%" height="'+ actualH +'">';
        data.forEach(function(d, i) {
            var y = marginTop + i * (barH + spacing);
            var bw = (d.value / maxVal) * chartW;
            var color = d.color || 'var(--accent)';
            svg += '<text x="'+ (marginLeft - 6) +'" y="'+ (y + barH * 0.72) +'" text-anchor="end" font-size="11" fill="var(--text-muted)" font-family="var(--font-ui)">'+ escapeHtml(d.label) +'</text>';
            svg += '<rect x="'+ marginLeft +'" y="'+ y +'" width="'+ bw.toFixed(1) +'" height="'+ barH +'" rx="3" fill="'+ color +'" opacity="0.85"/>';
            svg += '<text x="'+ (marginLeft + bw + 6).toFixed(1) +'" y="'+ (y + barH * 0.72) +'" font-size="11" fill="var(--text)" font-family="var(--font-data)">'+ d.value +'</text>';
        });
        svg += '</svg>';
        return svg;
    }

    function svgDonut(data, size) {
        if (!data || !data.length) return '<div class="loading">No data</div>';
        var total = 0;
        data.forEach(function(d){ total += d.value; });
        if (total === 0) return '<div class="loading">No data</div>';
        var cx = size/2, cy = size/2;
        var outerR = size/2 - 10;
        var innerR = outerR * 0.55;
        var legendH = data.length * 22 + 10;
        var fullH = size + legendH;
        var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 '+ size +' '+ fullH +'" width="100%" height="'+ fullH +'">';
        var angle = -90;
        data.forEach(function(d) {
            if (d.value === 0) return;
            var sweep = (d.value / total) * 360;
            var startRad = angle * Math.PI / 180;
            var endRad = (angle + sweep) * Math.PI / 180;
            var x1o = cx + outerR * Math.cos(startRad);
            var y1o = cy + outerR * Math.sin(startRad);
            var x2o = cx + outerR * Math.cos(endRad);
            var y2o = cy + outerR * Math.sin(endRad);
            var x1i = cx + innerR * Math.cos(endRad);
            var y1i = cy + innerR * Math.sin(endRad);
            var x2i = cx + innerR * Math.cos(startRad);
            var y2i = cy + innerR * Math.sin(startRad);
            var largeArc = sweep > 180 ? 1 : 0;
            var path = 'M '+ x1o.toFixed(2) +' '+ y1o.toFixed(2) +
                ' A '+ outerR +' '+ outerR +' 0 '+ largeArc +' 1 '+ x2o.toFixed(2) +' '+ y2o.toFixed(2) +
                ' L '+ x1i.toFixed(2) +' '+ y1i.toFixed(2) +
                ' A '+ innerR +' '+ innerR +' 0 '+ largeArc +' 0 '+ x2i.toFixed(2) +' '+ y2i.toFixed(2) +' Z';
            svg += '<path d="'+ path +'" fill="'+ d.color +'" opacity="0.85"/>';
            angle += sweep;
        });
        svg += '<text x="'+ cx +'" y="'+ (cy+6) +'" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text-bright)" font-family="var(--font-data)">'+ total +'</text>';
        var ly = size + 5;
        data.forEach(function(d) {
            var pct = total > 0 ? ((d.value / total) * 100).toFixed(0) : 0;
            svg += '<rect x="10" y="'+ ly +'" width="12" height="12" rx="2" fill="'+ d.color +'"/>';
            svg += '<text x="28" y="'+ (ly+11) +'" font-size="11" fill="var(--text)">'+ escapeHtml(d.label) +': '+ d.value +' ('+ pct +'%)</text>';
            ly += 22;
        });
        svg += '</svg>';
        return svg;
    }

    // ---- Risk Matrix ---------------------------------------------------

    function riskCellColor(li, im) {
        var score = li * im;
        if (score >= 20) return 'var(--critical)';
        if (score >= 12) return 'var(--high)';
        if (score >= 6)  return 'var(--medium)';
        if (score >= 3)  return '#6b8f4e';
        return 'var(--low)';
    }

    function renderRiskMatrix(matrix) {
        var html = '<div class="risk-matrix">';
        var liLabels = ['5','4','3','2','1'];
        var imLabels = ['1','2','3','4','5'];
        for (var row = 0; row < 5; row++) {
            html += '<div class="risk-label">'+ liLabels[row] +'</div>';
            for (var col = 0; col < 5; col++) {
                var li = 5 - row;
                var im = col + 1;
                var count = (matrix && matrix[row]) ? (matrix[row][col] || 0) : 0;
                var bg = riskCellColor(li, im);
                var cls = count === 0 ? 'risk-cell empty' : 'risk-cell';
                var label = count > 0 ? count : '';
                html += '<div class="'+ cls +'" style="background:'+ bg +'" title="L'+ li +' x I'+ im +': '+ count +' risks">'+ label +'</div>';
            }
        }
        html += '<div></div>';
        imLabels.forEach(function(l) { html += '<div class="risk-label-x">'+ l +'</div>'; });
        html += '</div>';
        html += '<div style="text-align:center;font-size:0.7rem;color:var(--text-muted);margin-top:8px">Likelihood (Y) vs Impact (X)</div>';
        return html;
    }

    // =====================================================================
    // OVERVIEW TAB
    // =====================================================================

    function loadHealth() {
        fetchAPI('/health').then(function(data) {
            if (!data) {
                $('health-status').textContent = 'Unreachable';
                $('health-dot').style.background = 'var(--critical)';
                return;
            }
            $('health-status').textContent = data.status === 'healthy' ? 'Connected' : data.status;
            $('health-dot').style.background = data.status === 'healthy' ? 'var(--resolved)' : 'var(--critical)';
            $('last-updated').textContent = 'Updated: ' + new Date().toLocaleTimeString();
        });
    }

    function loadStats() {
        fetchAPI('/stats').then(function(data) {
            if (!data) return;
            if (data.assets) {
                $('stat-assets').textContent = data.assets.active || data.assets.total_assets || 0;
            }
            $('stat-findings').textContent = data.open_findings || 0;
            if (data.remediation && data.remediation.sla_status) {
                var sla = data.remediation.sla_status;
                var pct = sla.overall ? sla.overall.pct_within_sla : 100;
                $('stat-sla').textContent = pct + '%';
                $('stat-sla').style.color = pct >= 80 ? 'var(--resolved)' : pct >= 50 ? 'var(--medium)' : 'var(--critical)';
            }
            if (data.risks && data.risks.avg_risk_score !== undefined) {
                $('stat-risk').textContent = data.risks.avg_risk_score;
            }
            if (data.findings_by_severity) {
                var sevData = [];
                ['CRITICAL','HIGH','MEDIUM','LOW','INFO'].forEach(function(s) {
                    var v = data.findings_by_severity[s] || 0;
                    if (v > 0 || s !== 'INFO') sevData.push({ label: s, value: v, color: sevColor(s) });
                });
                $('findings-chart').innerHTML = svgBarChart(sevData, 500, 200);
            } else {
                $('findings-chart').innerHTML = '<div class="loading">No findings data</div>';
            }
            if (data.remediation && data.remediation.metrics && data.remediation.metrics.counts) {
                var counts = data.remediation.metrics.counts;
                var remData = [
                    { label: 'Open',        value: counts.open || 0,        color: 'var(--critical)' },
                    { label: 'In Progress', value: counts.in_progress || 0, color: 'var(--medium)' },
                    { label: 'Resolved',    value: counts.resolved || 0,    color: 'var(--resolved)' },
                    { label: 'Verified',    value: counts.verified || 0,    color: 'var(--low)' },
                    { label: 'Closed',      value: counts.closed || 0,      color: 'var(--info)' },
                    { label: 'Deferred',    value: counts.deferred || 0,    color: 'var(--text-muted)' },
                ].filter(function(d) { return d.value > 0; });
                $('remediation-chart').innerHTML = svgDonut(remData, 220);
            } else {
                var remFallback = [
                    { label: 'Open', value: data.remediation ? (data.remediation.open || 0) : 0, color: 'var(--critical)' },
                    { label: 'Resolved', value: data.remediation ? (data.remediation.resolved || 0) : 0, color: 'var(--resolved)' },
                    { label: 'Overdue', value: data.remediation ? (data.remediation.overdue || 0) : 0, color: 'var(--overdue)' },
                ];
                $('remediation-chart').innerHTML = svgDonut(remFallback, 220);
            }
            if (data.risks && data.risks.matrix) {
                $('risk-matrix-container').innerHTML = renderRiskMatrix(data.risks.matrix);
            } else {
                $('risk-matrix-container').innerHTML = renderRiskMatrix(null);
            }
            if (data.assets && data.assets.scan_coverage) {
                var cov = data.assets.scan_coverage;
                var covHtml = '';
                [{ key: 'last_7_days', label: 'Last 7 Days' }, { key: 'last_30_days', label: 'Last 30 Days' }, { key: 'last_90_days', label: 'Last 90 Days' }].forEach(function(p) {
                    var pv = cov[p.key] || 0;
                    var color = pv >= 80 ? 'var(--resolved)' : pv >= 50 ? 'var(--medium)' : 'var(--critical)';
                    covHtml += '<div style="margin-bottom:14px"><div style="display:flex;justify-content:space-between;font-size:0.85rem"><span>'+ p.label +'</span><span style="font-family:var(--font-data);color:'+ color +'">'+ pv +'%</span></div><div class="progress-bar"><div class="progress-fill" style="width:'+ pv +'%;background:'+ color +'"></div></div></div>';
                });
                if (cov.total_active !== undefined) covHtml += '<div style="font-size:0.8rem;color:var(--text-muted);text-align:center;margin-top:8px">Total active assets: '+ cov.total_active +'</div>';
                $('asset-coverage').innerHTML = covHtml;
            } else {
                $('asset-coverage').innerHTML = '<div class="loading">No coverage data</div>';
            }
            if (data.exceptions) {
                var exc = data.exceptions;
                var excHtml = '<div class="grid grid-3" style="gap:10px">';
                [{ label: 'Active', value: (exc.by_status && exc.by_status.approved) || 0, color: 'var(--info)' },
                 { label: 'Pending', value: (exc.by_status && exc.by_status.pending) || 0, color: 'var(--medium)' },
                 { label: 'Expiring Soon', value: exc.expiring_within_30_days || 0, color: 'var(--overdue)' }].forEach(function(c) {
                    excHtml += '<div style="text-align:center;padding:10px"><div style="font-size:1.6rem;font-weight:700;color:'+ c.color +';font-family:var(--font-data)">'+ c.value +'</div><div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase">'+ c.label +'</div></div>';
                });
                excHtml += '</div>';
                if (exc.expiring_within_30_days > 0) excHtml += '<div style="background:rgba(252,92,101,0.1);border:1px solid var(--overdue);border-radius:var(--radius);padding:8px 12px;margin-top:10px;font-size:0.8rem;color:var(--overdue)">'+ exc.expiring_within_30_days +' exception(s) expiring within 30 days - review required</div>';
                $('exception-status').innerHTML = excHtml;
            } else {
                $('exception-status').innerHTML = '<div class="loading">No exception data</div>';
            }
            if (data.agents) {
                if (data.agents.connected === 0) {
                    $('agent-status').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No agents connected</div>';
                } else {
                    var agHtml = '<div style="font-size:0.9rem;margin-bottom:10px"><span style="font-family:var(--font-data);font-weight:700;color:var(--resolved)">'+ data.agents.connected +'</span> agent(s) connected</div>';
                    if (data.agents.agent_ids) data.agents.agent_ids.forEach(function(aid) { agHtml += '<div class="agent-row"><div class="agent-dot online"></div><span class="agent-name">'+ escapeHtml(aid) +'</span></div>'; });
                    $('agent-status').innerHTML = agHtml;
                }
            } else {
                $('agent-status').innerHTML = '<div class="loading">No agent data</div>';
            }
        });
    }

    function loadScans() {
        fetchAPI('/scans?limit=10').then(function(data) {
            if (!data || !data.sessions || data.sessions.length === 0) {
                $('scans-table-body').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No scan sessions</td></tr>';
                return;
            }
            var html = '';
            data.sessions.forEach(function(s) {
                var targets = '';
                try { var t = JSON.parse(s.target_networks || '[]'); targets = Array.isArray(t) ? t.join(', ') : String(t); } catch(e) { targets = s.target_networks || ''; }
                var statusColor = s.status === 'completed' ? 'var(--resolved)' : s.status === 'running' ? 'var(--medium)' : 'var(--text-muted)';
                html += '<tr><td style="font-family:var(--font-data);font-size:0.8rem">'+ escapeHtml(s.session_id) +'</td><td>'+ escapeHtml(s.scan_type || '--') +'</td><td>'+ escapeHtml((s.start_time || '').substring(0,19)) +'</td><td style="color:'+ statusColor +'">'+ escapeHtml(s.status || '--') +'</td><td style="font-size:0.8rem">'+ escapeHtml(targets) +'</td></tr>';
            });
            $('scans-table-body').innerHTML = html;
        });
    }

    function loadTopFindings() {
        fetchAPI('/findings?severity=CRITICAL&limit=10').then(function(data) {
            if (!data || !data.findings || data.findings.length === 0) {
                fetchAPI('/findings?severity=HIGH&limit=10').then(function(d2) {
                    if (!d2 || !d2.findings || d2.findings.length === 0) { $('top-findings').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No critical or high findings</div>'; return; }
                    renderFindings(d2.findings, 'top-findings');
                });
                return;
            }
            renderFindings(data.findings, 'top-findings');
        });
    }

    function renderFindings(findings, targetId) {
        var html = '';
        findings.slice(0, 10).forEach(function(f) {
            html += '<div class="finding-item">';
            html += '<div class="finding-header" onclick="this.querySelector(\'.finding-arrow\').classList.toggle(\'open\');this.nextElementSibling.classList.toggle(\'open\')">';
            html += '<span class="finding-arrow">&#9654;</span>';
            html += '<span class="sev-badge '+ sevClass(f.severity) +'">'+ escapeHtml(f.severity) +'</span>';
            html += '<span style="flex:1">'+ escapeHtml(f.title) +'</span>';
            if (f.cvss_score) html += '<span style="font-family:var(--font-data);font-size:0.8rem;color:var(--text-muted)">CVSS '+ f.cvss_score +'</span>';
            html += '</div><div class="finding-body">';
            if (f.description) html += '<div style="margin-bottom:6px">'+ escapeHtml(f.description) +'</div>';
            if (f.affected_asset) html += '<div><strong>Asset:</strong> '+ escapeHtml(f.affected_asset) +'</div>';
            if (f.remediation) html += '<div><strong>Remediation:</strong> '+ escapeHtml(f.remediation) +'</div>';
            html += '</div></div>';
        });
        $(targetId).innerHTML = html;
    }

    function loadCompliance() {
        fetchAPI('/stats').then(function(data) {
            if (!data) { $('compliance-scores').innerHTML = '<div class="loading">Unable to load</div>'; return; }
            var frameworks = ['NIST-800-53', 'HIPAA', 'PCI-DSS-v4', 'SOC2-Type2', 'ISO27001-2022'];
            var html = '';
            frameworks.forEach(function(fw) {
                html += '<div style="margin-bottom:12px"><div style="display:flex;justify-content:space-between;font-size:0.85rem"><span>'+ escapeHtml(fw) +'</span><a href="/api/v1/reports/compliance/'+ encodeURIComponent(fw) +'" target="_blank" style="font-size:0.75rem">View Report</a></div><div class="progress-bar"><div class="progress-fill" style="width:0%;background:var(--accent)"></div></div></div>';
            });
            html += '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:8px">Click "View Report" for detailed compliance assessment</div>';
            $('compliance-scores').innerHTML = html;
        });
    }

    function loadOverview() {
        loadHealth(); loadStats(); loadScans(); loadTopFindings(); loadCompliance();
    }

    // =====================================================================
    // SCAN CENTER TAB
    // =====================================================================

    function loadScanCenter() {
        loadScannerTypes();
        loadScanCenterTable();
    }

    function loadScannerTypes() {
        fetchAPI('/scanners').then(function(data) {
            if (!data || !data.scanners) return;
            var sel = $('sc-scanner-type');
            sel.innerHTML = '';
            data.scanners.forEach(function(s) {
                var opt = document.createElement('option');
                opt.value = s.id;
                opt.textContent = s.name;
                opt.title = s.description;
                sel.appendChild(opt);
            });
        });
    }

    window.launchScan = function() {
        var scannerType = $('sc-scanner-type').value;
        var targetsRaw = $('sc-targets').value.trim();
        var depth = $('sc-depth').value;
        if (!targetsRaw) { showToast('Please enter at least one target', 'error'); return; }
        var targets = targetsRaw.split('\n').map(function(t) { return t.trim(); }).filter(Boolean);
        fetchAPI('/scans', {
            method: 'POST',
            body: { scan_type: scannerType, targets: targets, metadata: { depth: depth } }
        }).then(function(data) {
            if (!data) { showToast('Failed to launch scan', 'error'); return; }
            if (data.error) { showToast(data.message || 'Error', 'error'); return; }
            showToast('Scan launched: ' + (data.session_id || ''), 'success');
            $('sc-targets').value = '';
            loadScanCenterTable();
        });
    };

    function loadScanCenterTable() {
        fetchAPI('/scans?limit=20').then(function(data) {
            if (!data || !data.sessions || data.sessions.length === 0) {
                $('sc-scans-body').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No scans yet. Launch your first scan!</td></tr>';
                return;
            }
            var html = '';
            data.sessions.forEach(function(s) {
                var statusColor = s.status === 'completed' ? 'var(--resolved)' : s.status === 'running' ? 'var(--medium)' : 'var(--text-muted)';
                var shortId = (s.session_id || '').substring(0, 12) + '...';
                html += '<tr>';
                html += '<td style="font-family:var(--font-data);font-size:0.78rem" title="'+ escapeHtml(s.session_id) +'">'+ escapeHtml(shortId) +'</td>';
                html += '<td>'+ escapeHtml(s.scan_type || '--') +'</td>';
                html += '<td style="color:'+ statusColor +'">'+ escapeHtml(s.status || '--') +'</td>';
                html += '<td>'+ escapeHtml((s.start_time || '').substring(0,16)) +'</td>';
                html += '<td><button class="btn btn-outline btn-sm" onclick="viewFindings(\''+ escapeHtml(s.session_id) +'\')">Findings</button></td>';
                html += '</tr>';
            });
            $('sc-scans-body').innerHTML = html;
        });
    }

    window.viewFindings = function(sessionId) {
        $('sc-findings-panel').style.display = 'block';
        $('sc-findings-session').textContent = sessionId;
        $('sc-findings-list').innerHTML = '<div class="loading">Loading findings...</div>';
        fetchAPI('/scans/' + encodeURIComponent(sessionId) + '/findings').then(function(data) {
            if (!data || !data.findings || data.findings.length === 0) {
                $('sc-findings-list').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No findings for this session</div>';
                return;
            }
            renderFindings(data.findings, 'sc-findings-list');
        });
    };

    // =====================================================================
    // SCHEDULES TAB
    // =====================================================================

    function loadSchedules() {
        fetchAPI('/schedules').then(function(data) {
            if (!data || !data.schedules || data.schedules.length === 0) {
                $('sched-list-body').innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted)">No schedules configured</td></tr>';
                return;
            }
            var html = '';
            data.schedules.forEach(function(s) {
                var nextRun = s.next_run ? s.next_run.substring(0, 16) : '--';
                html += '<tr>';
                html += '<td>'+ escapeHtml(s.name) +'</td>';
                html += '<td>'+ escapeHtml(s.scanner_type) +'</td>';
                html += '<td style="font-family:var(--font-data);font-size:0.8rem">'+ escapeHtml(s.cron_expression) +'</td>';
                html += '<td>'+ escapeHtml(nextRun) +'</td>';
                html += '<td><label class="toggle"><input type="checkbox" '+ (s.enabled ? 'checked' : '') +' onchange="toggleSchedule(\''+ escapeHtml(s.schedule_id) +'\', this.checked)"/><span class="toggle-slider"></span></label></td>';
                html += '<td>';
                html += '<button class="btn btn-outline btn-sm" onclick="viewRunHistory(\''+ escapeHtml(s.schedule_id) +'\', \''+ escapeHtml(s.name) +'\')">History</button> ';
                html += '<button class="btn btn-danger btn-sm" onclick="deleteSchedule(\''+ escapeHtml(s.schedule_id) +'\')">Delete</button>';
                html += '</td></tr>';
            });
            $('sched-list-body').innerHTML = html;
        });
    }

    window.createSchedule = function() {
        var name = $('sched-name').value.trim();
        var scanner = $('sched-scanner').value;
        var targetsRaw = $('sched-targets').value.trim();
        var cron = $('sched-cron').value.trim();
        var depth = $('sched-depth').value;
        if (!name || !cron) { showToast('Name and cron expression are required', 'error'); return; }
        var targets = targetsRaw ? targetsRaw.split('\n').map(function(t) { return t.trim(); }).filter(Boolean) : [];
        fetchAPI('/schedules', {
            method: 'POST',
            body: { name: name, scanner_type: scanner, targets: targets, cron_expression: cron, scan_type: depth }
        }).then(function(data) {
            if (!data) { showToast('Failed to create schedule', 'error'); return; }
            if (data.error) { showToast(data.message || 'Error', 'error'); return; }
            showToast('Schedule created: ' + name, 'success');
            $('sched-name').value = '';
            $('sched-targets').value = '';
            $('sched-cron').value = '';
            loadSchedules();
        });
    };

    window.toggleSchedule = function(id, enabled) {
        fetchAPI('/schedules/' + encodeURIComponent(id), {
            method: 'PUT',
            body: { enabled: enabled }
        }).then(function(data) {
            if (data && !data.error) showToast('Schedule ' + (enabled ? 'enabled' : 'disabled'), 'success');
            else showToast('Failed to update schedule', 'error');
        });
    };

    window.deleteSchedule = function(id) {
        if (!confirm('Delete this schedule?')) return;
        fetchAPI('/schedules/' + encodeURIComponent(id), { method: 'DELETE' }).then(function(data) {
            if (data && !data.error) { showToast('Schedule deleted', 'success'); loadSchedules(); }
            else showToast('Failed to delete schedule', 'error');
        });
    };

    window.viewRunHistory = function(id, name) {
        $('sched-history-panel').style.display = 'block';
        $('sched-history-name').textContent = name;
        $('sched-history-body').innerHTML = '<tr><td colspan="5" class="loading">Loading...</td></tr>';
        fetchAPI('/schedules/' + encodeURIComponent(id) + '/history').then(function(data) {
            if (!data || !data.runs || data.runs.length === 0) {
                $('sched-history-body').innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No runs yet</td></tr>';
                return;
            }
            var html = '';
            data.runs.forEach(function(r) {
                var statusColor = r.status === 'completed' ? 'var(--resolved)' : r.status === 'failed' ? 'var(--critical)' : 'var(--medium)';
                html += '<tr>';
                html += '<td style="font-family:var(--font-data);font-size:0.78rem">'+ escapeHtml((r.run_id || '').substring(0,12)) +'</td>';
                html += '<td>'+ escapeHtml((r.started_at || '').substring(0,19)) +'</td>';
                html += '<td>'+ escapeHtml((r.completed_at || '--').substring(0,19)) +'</td>';
                html += '<td style="color:'+ statusColor +'">'+ escapeHtml(r.status) +'</td>';
                html += '<td style="font-family:var(--font-data);font-size:0.78rem">'+ escapeHtml(r.session_id || '--') +'</td>';
                html += '</tr>';
            });
            $('sched-history-body').innerHTML = html;
        });
    };

    // =====================================================================
    // NOTIFICATIONS TAB
    // =====================================================================

    var NOTIF_CONFIG_FIELDS = {
        email: [
            { key: 'smtp_host', label: 'SMTP Host', placeholder: 'smtp.example.com' },
            { key: 'smtp_port', label: 'SMTP Port', placeholder: '587', type: 'number' },
            { key: 'smtp_user', label: 'Username', placeholder: 'user@example.com' },
            { key: 'smtp_pass', label: 'Password', placeholder: '', type: 'password' },
            { key: 'from_addr', label: 'From Address', placeholder: 'alerts@example.com' },
            { key: 'to_addrs', label: 'To Addresses (comma-separated)', placeholder: 'admin@example.com, team@example.com' },
            { key: 'use_tls', label: 'Use TLS', type: 'checkbox', checked: true },
        ],
        slack: [
            { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...' },
        ],
        teams: [
            { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...' },
        ],
        webhook: [
            { key: 'url', label: 'Webhook URL', placeholder: 'https://example.com/webhook' },
            { key: 'method', label: 'HTTP Method', placeholder: 'POST' },
        ],
        syslog: [
            { key: 'host', label: 'Syslog Host', placeholder: '127.0.0.1' },
            { key: 'port', label: 'Syslog Port', placeholder: '514', type: 'number' },
        ],
        sms_twilio: [
            { key: 'account_sid', label: 'Account SID', placeholder: 'AC...' },
            { key: 'auth_token', label: 'Auth Token', placeholder: '', type: 'password' },
            { key: 'from_number', label: 'From Number', placeholder: '+15551234567' },
            { key: 'to_numbers', label: 'To Numbers (comma-separated)', placeholder: '+15559876543' },
        ],
        sms_sns: [
            { key: 'region', label: 'AWS Region', placeholder: 'us-east-1' },
            { key: 'access_key_id', label: 'Access Key ID', placeholder: 'AKIA...' },
            { key: 'secret_access_key', label: 'Secret Access Key', placeholder: '', type: 'password' },
            { key: 'topic_arn', label: 'Topic ARN (or leave blank for direct)', placeholder: 'arn:aws:sns:...' },
            { key: 'phone_numbers', label: 'Phone Numbers (comma-separated)', placeholder: '+15551234567' },
        ],
        sms_gateway: [
            { key: 'url', label: 'Gateway URL', placeholder: 'https://smsapi.example.com/send' },
            { key: 'method', label: 'HTTP Method', placeholder: 'POST' },
            { key: 'body_template', label: 'Body Template', placeholder: '{"to":"{to}","msg":"{body}"}' },
            { key: 'to_numbers', label: 'To Numbers (comma-separated)', placeholder: '+15551234567' },
        ],
        sms_email: [
            { key: 'smtp_host', label: 'SMTP Host', placeholder: 'smtp.example.com' },
            { key: 'smtp_port', label: 'SMTP Port', placeholder: '587', type: 'number' },
            { key: 'smtp_user', label: 'Username', placeholder: 'user@example.com' },
            { key: 'smtp_pass', label: 'Password', placeholder: '', type: 'password' },
            { key: 'from_addr', label: 'From Address', placeholder: 'alerts@example.com' },
            { key: 'use_tls', label: 'Use TLS', type: 'checkbox', checked: true },
            { key: 'addresses', label: 'Carrier Email Addresses (comma-separated)', placeholder: '5551234567@txt.att.net, 5559876543@tmomail.net' },
        ],
    };

    window.notifTypeChanged = function() {
        var type = $('notif-type').value;
        var fields = NOTIF_CONFIG_FIELDS[type] || [];
        var html = '';
        fields.forEach(function(f) {
            html += '<div class="form-group">';
            html += '<label>'+ escapeHtml(f.label) +'</label>';
            if (f.type === 'checkbox') {
                html += '<label class="toggle"><input type="checkbox" id="notif-cfg-'+ f.key +'" '+ (f.checked ? 'checked' : '') +'/><span class="toggle-slider"></span></label>';
            } else {
                var inputType = f.type || 'text';
                html += '<input type="'+ inputType +'" id="notif-cfg-'+ f.key +'" placeholder="'+ escapeHtml(f.placeholder || '') +'"/>';
            }
            html += '</div>';
        });
        $('notif-config-fields').innerHTML = html;
    };

    // Initialize config fields on page load
    setTimeout(function() { notifTypeChanged(); }, 0);

    window.addChannel = function() {
        var name = $('notif-name').value.trim();
        var type = $('notif-type').value;
        if (!name) { showToast('Channel name is required', 'error'); return; }
        var fields = NOTIF_CONFIG_FIELDS[type] || [];
        var config = {};
        fields.forEach(function(f) {
            var el = $('notif-cfg-' + f.key);
            if (!el) return;
            if (f.type === 'checkbox') {
                config[f.key] = el.checked;
            } else if (f.key === 'to_addrs' || f.key === 'to_numbers' || f.key === 'phone_numbers' || f.key === 'addresses') {
                config[f.key] = el.value.split(',').map(function(v) { return v.trim(); }).filter(Boolean);
            } else if (f.type === 'number') {
                config[f.key] = parseInt(el.value) || 0;
            } else {
                config[f.key] = el.value;
            }
        });
        fetchAPI('/notifications/channels', {
            method: 'POST',
            body: { name: name, channel_type: type, config: config }
        }).then(function(data) {
            if (!data) { showToast('Failed to add channel', 'error'); return; }
            if (data.error) { showToast(data.message || 'Error', 'error'); return; }
            showToast('Channel added: ' + name, 'success');
            $('notif-name').value = '';
            notifTypeChanged();
            loadChannelsList();
        });
    };

    function loadNotifications() {
        loadChannelsList();
        loadNotifStats();
        loadNotifHistory();
    }

    function loadChannelsList() {
        fetchAPI('/notifications/channels').then(function(data) {
            if (!data || !data.channels || data.channels.length === 0) {
                $('notif-channels-list').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No channels configured</div>';
                return;
            }
            var html = '';
            data.channels.forEach(function(ch) {
                html += '<div style="padding:12px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px">';
                html += '<div style="flex:1"><div style="font-weight:600">'+ escapeHtml(ch.name) +'</div>';
                html += '<div style="font-size:0.78rem;color:var(--text-muted)">'+ escapeHtml(ch.channel_type) +'</div></div>';
                html += '<label class="toggle"><input type="checkbox" '+ (ch.enabled ? 'checked' : '') +' onchange="toggleChannel(\''+ escapeHtml(ch.channel_id) +'\', this.checked)"/><span class="toggle-slider"></span></label>';
                html += '<button class="btn btn-outline btn-sm" onclick="testChannel(\''+ escapeHtml(ch.channel_id) +'\')">Test</button>';
                html += '<button class="btn btn-danger btn-sm" onclick="deleteChannel(\''+ escapeHtml(ch.channel_id) +'\')">Delete</button>';
                html += '</div>';
            });
            $('notif-channels-list').innerHTML = html;
        });
    }

    window.testChannel = function(id) {
        fetchAPI('/notifications/test', {
            method: 'POST',
            body: { channel_id: id }
        }).then(function(data) {
            if (data && data.success) showToast('Test notification sent!', 'success');
            else showToast('Test failed: ' + (data ? data.message : 'Unknown error'), 'error');
        });
    };

    window.toggleChannel = function(id, enabled) {
        fetchAPI('/notifications/channels/' + encodeURIComponent(id), {
            method: 'PUT',
            body: { enabled: enabled }
        }).then(function(data) {
            if (data && !data.error) showToast('Channel ' + (enabled ? 'enabled' : 'disabled'), 'success');
        });
    };

    window.deleteChannel = function(id) {
        if (!confirm('Delete this notification channel?')) return;
        fetchAPI('/notifications/channels/' + encodeURIComponent(id), { method: 'DELETE' }).then(function(data) {
            if (data && !data.error) { showToast('Channel deleted', 'success'); loadChannelsList(); }
            else showToast('Failed to delete channel', 'error');
        });
    };

    function loadNotifStats() {
        fetchAPI('/notifications/stats').then(function(data) {
            if (!data || data.error) { $('notif-stats').innerHTML = '<div class="loading">Unable to load stats</div>'; return; }
            var html = '<div class="grid grid-3" style="gap:10px">';
            [
                { label: 'Total Channels', value: data.total_channels || 0, color: 'var(--info)' },
                { label: 'Enabled', value: data.enabled_channels || 0, color: 'var(--resolved)' },
                { label: 'Disabled', value: data.disabled_channels || 0, color: 'var(--text-muted)' },
                { label: 'Total Sent', value: data.sent || 0, color: 'var(--resolved)' },
                { label: 'Failed', value: data.failed || 0, color: 'var(--critical)' },
                { label: 'Sent (24h)', value: data.sent_last_24h || 0, color: 'var(--info)' },
            ].forEach(function(s) {
                html += '<div style="text-align:center;padding:8px"><div style="font-size:1.4rem;font-weight:700;color:'+ s.color +';font-family:var(--font-data)">'+ s.value +'</div><div style="font-size:0.72rem;color:var(--text-muted);text-transform:uppercase">'+ s.label +'</div></div>';
            });
            html += '</div>';
            if (data.failure_rate_pct > 0) {
                html += '<div style="margin-top:10px;font-size:0.8rem;color:var(--text-muted)">Failure rate: <span style="color:var(--critical)">'+ data.failure_rate_pct +'%</span></div>';
            }
            $('notif-stats').innerHTML = html;
        });
    }

    function loadNotifHistory() {
        fetchAPI('/notifications/history?limit=20').then(function(data) {
            if (!data || !data.notifications || data.notifications.length === 0) {
                $('notif-history-body').innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No notification history</td></tr>';
                return;
            }
            var html = '';
            data.notifications.forEach(function(n) {
                var statusCls = n.status === 'sent' ? 'status-sent' : n.status === 'failed' ? 'status-failed' : 'status-pending';
                html += '<tr>';
                html += '<td style="font-size:0.78rem">'+ escapeHtml((n.created_at || '').substring(0,19)) +'</td>';
                html += '<td>'+ escapeHtml(n.event_type) +'</td>';
                html += '<td>'+ escapeHtml(n.channel_name || n.channel_type || '--') +'</td>';
                html += '<td><span class="status-pill '+ statusCls +'">'+ escapeHtml(n.status) +'</span></td>';
                html += '</tr>';
            });
            $('notif-history-body').innerHTML = html;
        });
    }

    // =====================================================================
    // AI ASSISTANT TAB
    // =====================================================================

    function loadAIStatus() {
        fetchAPI('/ai/status').then(function(data) {
            if (!data) {
                $('ai-status-badge').textContent = 'offline';
                $('ai-status-badge').className = 'status-pill status-failed';
                $('ai-status-detail').innerHTML = '<div style="color:var(--text-muted)">AI engine is not available. Run <code style="color:var(--accent)">python bin/setup-ai.py</code> to install local AI models.</div>';
                return;
            }
            if (data.available) {
                $('ai-status-badge').textContent = data.backend;
                $('ai-status-badge').className = 'status-pill status-sent';
                var html = '<div style="display:flex;flex-direction:column;gap:8px">';
                html += '<div><strong>Backend:</strong> '+ escapeHtml(data.backend) +'</div>';
                html += '<div><strong>Model:</strong> '+ escapeHtml(data.model || 'default') +'</div>';
                html += '<div><strong>Status:</strong> <span style="color:var(--resolved)">Ready</span></div>';
                html += '</div>';
                $('ai-status-detail').innerHTML = html;
            } else {
                $('ai-status-badge').textContent = 'offline';
                $('ai-status-badge').className = 'status-pill status-failed';
                $('ai-status-detail').innerHTML = '<div style="color:var(--text-muted)">'+ escapeHtml(data.message || 'AI not available') +'<br><br>Run <code style="color:var(--accent)">python bin/setup-ai.py</code> to set up local AI models for air-gapped operation.</div>';
            }
        });
    }

    window.aiSendMessage = function() {
        var input = $('ai-chat-input');
        var question = input.value.trim();
        if (!question) return;
        input.value = '';

        var messages = $('ai-chat-messages');
        messages.innerHTML += '<div class="chat-msg user">'+ escapeHtml(question) +'</div>';
        messages.innerHTML += '<div class="chat-msg ai" id="ai-thinking" style="opacity:0.6">Thinking...</div>';
        messages.scrollTop = messages.scrollHeight;

        fetchAPI('/ai/query', {
            method: 'POST',
            body: { question: question }
        }).then(function(data) {
            var thinking = $('ai-thinking');
            if (thinking) thinking.remove();
            var answer = (data && data.answer) ? data.answer : (data && data.message) ? data.message : 'Sorry, I was unable to process that request. Please check that the AI engine is configured.';
            messages.innerHTML += '<div class="chat-msg ai">'+ escapeHtml(answer) +'</div>';
            messages.scrollTop = messages.scrollHeight;
        });
    };

    window.aiQuickAction = function(question) {
        $('ai-chat-input').value = question;
        aiSendMessage();
    };

    // =====================================================================
    // REFRESH
    // =====================================================================

    function refreshActiveTab() {
        loadHealth();
        if (activeTab === 'overview') loadOverview();
        else if (activeTab === 'scan-center') loadScanCenterTable();
        else if (activeTab === 'schedules') loadSchedules();
        else if (activeTab === 'notifications') loadNotifications();
    }

    // Init
    loadOverview();
    tabLoaded.overview = true;
    setInterval(refreshActiveTab, REFRESH_INTERVAL);

})();
</script>

</body>
</html>"""

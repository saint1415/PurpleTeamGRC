#!/usr/bin/env python3
"""
Purple Team GRC - Self-Contained HTML Dashboard
Single-page application using inline CSS and JavaScript.
No external CDN dependencies (air-gapped operation).
Calls the REST API via fetch() for live data.
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
    margin-bottom: 20px;
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
        <!-- Findings by Severity -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Findings by Severity</span>
            </div>
            <div id="findings-chart">
                <div class="loading">Loading chart...</div>
            </div>
        </div>

        <!-- Remediation Status Donut -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Remediation Status</span>
            </div>
            <div id="remediation-chart">
                <div class="loading">Loading chart...</div>
            </div>
        </div>
    </div>

    <!-- Row: Risk Matrix + Asset Coverage -->
    <div class="grid grid-2">
        <!-- 5x5 Risk Matrix -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Risk Matrix</span>
            </div>
            <div id="risk-matrix-container">
                <div class="loading">Loading matrix...</div>
            </div>
        </div>

        <!-- Asset Coverage -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Asset Scan Coverage</span>
            </div>
            <div id="asset-coverage">
                <div class="loading">Loading coverage...</div>
            </div>
        </div>
    </div>

    <!-- Recent Scans Table -->
    <div class="card" style="margin-bottom:20px">
        <div class="card-header">
            <span class="card-title">Recent Scans</span>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Session ID</th>
                        <th>Type</th>
                        <th>Date</th>
                        <th>Status</th>
                        <th>Targets</th>
                    </tr>
                </thead>
                <tbody id="scans-table-body">
                    <tr><td colspan="5" class="loading">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Row: Top 10 Critical Findings + Compliance + Exceptions + Agents -->
    <div class="grid grid-2">
        <!-- Top 10 Critical Findings -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Top Critical Findings</span>
            </div>
            <div id="top-findings">
                <div class="loading">Loading...</div>
            </div>
        </div>

        <!-- Compliance Scores -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Compliance Scores</span>
            </div>
            <div id="compliance-scores">
                <div class="loading">Loading...</div>
            </div>
        </div>
    </div>

    <div class="grid grid-2">
        <!-- Active Exceptions -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Exception Status</span>
            </div>
            <div id="exception-status">
                <div class="loading">Loading...</div>
            </div>
        </div>

        <!-- Agent Status -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">Connected Agents</span>
            </div>
            <div id="agent-status">
                <div class="loading">Loading...</div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        Purple Team GRC v7.0 &mdash; Dashboard auto-refreshes every 60 seconds
    </div>

</div>

<!-- ================================================================
     JavaScript  -  All inline, no external dependencies
     ================================================================ -->
<script>
(function() {
    'use strict';

    // ---- Config --------------------------------------------------------
    var API_BASE = window.location.origin + '/api/v1';
    var REFRESH_INTERVAL = 60000;  // 60 seconds
    var API_KEY = '';  // Set if auth is enabled

    // ---- Helpers -------------------------------------------------------
    function fetchAPI(endpoint, opts) {
        opts = opts || {};
        var headers = { 'Accept': 'application/json' };
        if (API_KEY) headers['X-API-Key'] = API_KEY;
        return fetch(API_BASE + endpoint, {
            method: opts.method || 'GET',
            headers: headers,
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

    // ---- SVG Chart Generators ------------------------------------------

    function svgBarChart(data, width, height) {
        // data: [{label, value, color}]
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
            // Label
            svg += '<text x="'+ (marginLeft - 6) +'" y="'+ (y + barH * 0.72) +'" text-anchor="end" font-size="11" fill="var(--text-muted)" font-family="var(--font-ui)">'+ escapeHtml(d.label) +'</text>';
            // Bar
            svg += '<rect x="'+ marginLeft +'" y="'+ y +'" width="'+ bw.toFixed(1) +'" height="'+ barH +'" rx="3" fill="'+ color +'" opacity="0.85"/>';
            // Value
            svg += '<text x="'+ (marginLeft + bw + 6).toFixed(1) +'" y="'+ (y + barH * 0.72) +'" font-size="11" fill="var(--text)" font-family="var(--font-data)">'+ d.value +'</text>';
        });

        svg += '</svg>';
        return svg;
    }

    function svgDonut(data, size) {
        // data: [{label, value, color}]
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

        // Center number
        svg += '<text x="'+ cx +'" y="'+ (cy+6) +'" text-anchor="middle" font-size="22" font-weight="700" fill="var(--text-bright)" font-family="var(--font-data)">'+ total +'</text>';

        // Legend
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
        // matrix: 5 rows (likelihood 5 top -> 1 bottom), 5 cols (impact 1 -> 5)
        var html = '<div class="risk-matrix">';
        var liLabels = ['5','4','3','2','1'];
        var imLabels = ['1','2','3','4','5'];

        for (var row = 0; row < 5; row++) {
            // Y-axis label
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
        // Bottom axis labels
        html += '<div></div>';
        imLabels.forEach(function(l) {
            html += '<div class="risk-label-x">'+ l +'</div>';
        });
        html += '</div>';
        html += '<div style="text-align:center;font-size:0.7rem;color:var(--text-muted);margin-top:8px">Likelihood (Y) vs Impact (X)</div>';
        return html;
    }

    // ---- Data Loaders --------------------------------------------------

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

            // Assets
            if (data.assets) {
                $('stat-assets').textContent = data.assets.active || data.assets.total_assets || 0;
            }

            // Open findings
            $('stat-findings').textContent = data.open_findings || 0;

            // SLA
            if (data.remediation && data.remediation.sla_status) {
                var sla = data.remediation.sla_status;
                var pct = sla.overall ? sla.overall.pct_within_sla : 100;
                $('stat-sla').textContent = pct + '%';
                $('stat-sla').style.color = pct >= 80 ? 'var(--resolved)' : pct >= 50 ? 'var(--medium)' : 'var(--critical)';
            }

            // Risk score
            if (data.risks && data.risks.avg_risk_score !== undefined) {
                $('stat-risk').textContent = data.risks.avg_risk_score;
            }

            // Findings by severity bar chart
            if (data.findings_by_severity) {
                var sevData = [];
                var sevOrder = ['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
                sevOrder.forEach(function(s) {
                    var v = data.findings_by_severity[s] || 0;
                    if (v > 0 || s !== 'INFO') {
                        sevData.push({ label: s, value: v, color: sevColor(s) });
                    }
                });
                $('findings-chart').innerHTML = svgBarChart(sevData, 500, 200);
            } else {
                $('findings-chart').innerHTML = '<div class="loading">No findings data</div>';
            }

            // Remediation donut
            if (data.remediation && data.remediation.metrics && data.remediation.metrics.counts) {
                var counts = data.remediation.metrics.counts;
                var remData = [
                    { label: 'Open',        value: counts.open || 0,        color: 'var(--critical)' },
                    { label: 'In Progress', value: counts.in_progress || 0, color: 'var(--medium)' },
                    { label: 'Resolved',    value: counts.resolved || 0,    color: 'var(--resolved)' },
                    { label: 'Verified',    value: counts.verified || 0,    color: 'var(--low)' },
                    { label: 'Closed',      value: counts.closed || 0,      color: 'var(--info)' },
                    { label: 'Deferred',    value: counts.deferred || 0,    color: 'var(--text-muted)' },
                ];
                // Only show nonzero
                remData = remData.filter(function(d) { return d.value > 0; });
                $('remediation-chart').innerHTML = svgDonut(remData, 220);
            } else {
                var remFallback = [
                    { label: 'Open', value: data.remediation ? (data.remediation.open || 0) : 0, color: 'var(--critical)' },
                    { label: 'Resolved', value: data.remediation ? (data.remediation.resolved || 0) : 0, color: 'var(--resolved)' },
                    { label: 'Overdue', value: data.remediation ? (data.remediation.overdue || 0) : 0, color: 'var(--overdue)' },
                ];
                $('remediation-chart').innerHTML = svgDonut(remFallback, 220);
            }

            // Risk matrix
            if (data.risks && data.risks.matrix) {
                $('risk-matrix-container').innerHTML = renderRiskMatrix(data.risks.matrix);
            } else {
                $('risk-matrix-container').innerHTML = renderRiskMatrix(null);
            }

            // Asset coverage
            if (data.assets && data.assets.scan_coverage) {
                var cov = data.assets.scan_coverage;
                var covHtml = '';
                var periods = [
                    { key: 'last_7_days', label: 'Last 7 Days' },
                    { key: 'last_30_days', label: 'Last 30 Days' },
                    { key: 'last_90_days', label: 'Last 90 Days' },
                ];
                periods.forEach(function(p) {
                    var pct = cov[p.key] || 0;
                    var color = pct >= 80 ? 'var(--resolved)' : pct >= 50 ? 'var(--medium)' : 'var(--critical)';
                    covHtml += '<div style="margin-bottom:14px">';
                    covHtml += '<div style="display:flex;justify-content:space-between;font-size:0.85rem"><span>'+ p.label +'</span><span style="font-family:var(--font-data);color:'+ color +'">'+ pct +'%</span></div>';
                    covHtml += '<div class="progress-bar"><div class="progress-fill" style="width:'+ pct +'%;background:'+ color +'"></div></div>';
                    covHtml += '</div>';
                });
                if (cov.total_active !== undefined) {
                    covHtml += '<div style="font-size:0.8rem;color:var(--text-muted);text-align:center;margin-top:8px">Total active assets: '+ cov.total_active +'</div>';
                }
                $('asset-coverage').innerHTML = covHtml;
            } else {
                $('asset-coverage').innerHTML = '<div class="loading">No coverage data</div>';
            }

            // Exceptions
            if (data.exceptions) {
                var exc = data.exceptions;
                var excHtml = '<div class="grid grid-3" style="gap:10px">';
                var excCards = [
                    { label: 'Active', value: (exc.by_status && exc.by_status.approved) || 0, color: 'var(--info)' },
                    { label: 'Pending', value: (exc.by_status && exc.by_status.pending) || 0, color: 'var(--medium)' },
                    { label: 'Expiring Soon', value: exc.expiring_within_30_days || 0, color: 'var(--overdue)' },
                ];
                excCards.forEach(function(c) {
                    excHtml += '<div style="text-align:center;padding:10px"><div style="font-size:1.6rem;font-weight:700;color:'+ c.color +';font-family:var(--font-data)">'+ c.value +'</div><div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase">'+ c.label +'</div></div>';
                });
                excHtml += '</div>';
                if (exc.expiring_within_30_days > 0) {
                    excHtml += '<div style="background:rgba(252,92,101,0.1);border:1px solid var(--overdue);border-radius:var(--radius);padding:8px 12px;margin-top:10px;font-size:0.8rem;color:var(--overdue)">'+ exc.expiring_within_30_days +' exception(s) expiring within 30 days - review required</div>';
                }
                $('exception-status').innerHTML = excHtml;
            } else {
                $('exception-status').innerHTML = '<div class="loading">No exception data</div>';
            }

            // Agents
            if (data.agents) {
                var agents = data.agents;
                if (agents.connected === 0) {
                    $('agent-status').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No agents connected</div>';
                } else {
                    var agHtml = '<div style="font-size:0.9rem;margin-bottom:10px"><span style="font-family:var(--font-data);font-weight:700;color:var(--resolved)">'+ agents.connected +'</span> agent(s) connected</div>';
                    if (agents.agent_ids) {
                        agents.agent_ids.forEach(function(aid) {
                            agHtml += '<div class="agent-row"><div class="agent-dot online"></div><span class="agent-name">'+ escapeHtml(aid) +'</span></div>';
                        });
                    }
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
                try {
                    var t = JSON.parse(s.target_networks || '[]');
                    targets = Array.isArray(t) ? t.join(', ') : String(t);
                } catch(e) { targets = s.target_networks || ''; }

                var statusColor = s.status === 'completed' ? 'var(--resolved)' : s.status === 'running' ? 'var(--medium)' : 'var(--text-muted)';
                html += '<tr>';
                html += '<td style="font-family:var(--font-data);font-size:0.8rem">'+ escapeHtml(s.session_id) +'</td>';
                html += '<td>'+ escapeHtml(s.scan_type || '--') +'</td>';
                html += '<td>'+ escapeHtml((s.start_time || '').substring(0,19)) +'</td>';
                html += '<td style="color:'+ statusColor +'">'+ escapeHtml(s.status || '--') +'</td>';
                html += '<td style="font-size:0.8rem">'+ escapeHtml(targets) +'</td>';
                html += '</tr>';
            });
            $('scans-table-body').innerHTML = html;
        });
    }

    function loadTopFindings() {
        fetchAPI('/findings?severity=CRITICAL&limit=10').then(function(data) {
            if (!data || !data.findings || data.findings.length === 0) {
                // Try HIGH if no CRITICAL
                fetchAPI('/findings?severity=HIGH&limit=10').then(function(d2) {
                    if (!d2 || !d2.findings || d2.findings.length === 0) {
                        $('top-findings').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text-muted)">No critical or high findings</div>';
                        return;
                    }
                    renderFindings(d2.findings);
                });
                return;
            }
            renderFindings(data.findings);
        });
    }

    function renderFindings(findings) {
        var html = '';
        findings.slice(0, 10).forEach(function(f, idx) {
            html += '<div class="finding-item">';
            html += '<div class="finding-header" onclick="this.querySelector(\'.finding-arrow\').classList.toggle(\'open\');this.nextElementSibling.classList.toggle(\'open\')">';
            html += '<span class="finding-arrow">&#9654;</span>';
            html += '<span class="sev-badge '+ sevClass(f.severity) +'">'+ escapeHtml(f.severity) +'</span>';
            html += '<span style="flex:1">'+ escapeHtml(f.title) +'</span>';
            if (f.cvss_score) html += '<span style="font-family:var(--font-data);font-size:0.8rem;color:var(--text-muted)">CVSS '+ f.cvss_score +'</span>';
            html += '</div>';
            html += '<div class="finding-body">';
            if (f.description) html += '<div style="margin-bottom:6px">'+ escapeHtml(f.description) +'</div>';
            if (f.affected_asset) html += '<div><strong>Asset:</strong> '+ escapeHtml(f.affected_asset) +'</div>';
            if (f.remediation) html += '<div><strong>Remediation:</strong> '+ escapeHtml(f.remediation) +'</div>';
            html += '</div></div>';
        });
        $('top-findings').innerHTML = html;
    }

    function loadCompliance() {
        // We don't have a dedicated compliance list endpoint, so we check
        // what frameworks are available from stats
        fetchAPI('/stats').then(function(data) {
            if (!data) {
                $('compliance-scores').innerHTML = '<div class="loading">Unable to load</div>';
                return;
            }
            // If there is evidence data with framework info, we show it
            // Otherwise show placeholder with framework names
            var frameworks = ['NIST-800-53', 'HIPAA', 'PCI-DSS-v4', 'SOC2-Type2', 'ISO27001-2022'];
            var html = '';
            frameworks.forEach(function(fw) {
                // We don't have per-framework scores from /stats, so show bars
                // If the user clicks, they can go to /api/v1/reports/compliance/<fw>
                html += '<div style="margin-bottom:12px">';
                html += '<div style="display:flex;justify-content:space-between;font-size:0.85rem">';
                html += '<span>'+ escapeHtml(fw) +'</span>';
                html += '<a href="/api/v1/reports/compliance/'+ encodeURIComponent(fw) +'" target="_blank" style="font-size:0.75rem">View Report</a>';
                html += '</div>';
                html += '<div class="progress-bar"><div class="progress-fill" style="width:0%;background:var(--accent)"></div></div>';
                html += '</div>';
            });
            html += '<div style="font-size:0.75rem;color:var(--text-muted);margin-top:8px">Click "View Report" for detailed compliance assessment</div>';
            $('compliance-scores').innerHTML = html;
        });
    }

    // ---- Refresh all ---------------------------------------------------

    function refreshAll() {
        loadHealth();
        loadStats();
        loadScans();
        loadTopFindings();
        loadCompliance();
    }

    // ---- Init ----------------------------------------------------------

    refreshAll();
    setInterval(refreshAll, REFRESH_INTERVAL);

})();
</script>

</body>
</html>"""

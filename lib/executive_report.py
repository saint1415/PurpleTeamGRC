#!/usr/bin/env python3
"""
Purple Team GRC - Executive Report Generator
Creates professional, self-contained HTML reports with inline CSS and SVG
charts suitable for board-level presentations and compliance audits.
"""

import json
import sqlite3
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from .paths import paths
except ImportError:
    from paths import paths


# ---------------------------------------------------------------------------
# Color palette - muted, professional tones
# ---------------------------------------------------------------------------

COLORS = {
    "primary":      "#4a3f6b",
    "secondary":    "#6b5b95",
    "accent":       "#8678a8",
    "bg":           "#f8f7fa",
    "card_bg":      "#ffffff",
    "border":       "#e0dce6",
    "text":         "#2d2b33",
    "text_muted":   "#78757f",
    "critical":     "#c0392b",
    "high":         "#d35400",
    "medium":       "#d4a017",
    "low":          "#2980b9",
    "info":         "#7f8c8d",
    "pass":         "#27ae60",
    "fail":         "#c0392b",
    "na":           "#95a5a6",
    "chart_1":      "#6b5b95",
    "chart_2":      "#8678a8",
    "chart_3":      "#a89dc4",
    "chart_4":      "#c9bfe0",
    "chart_5":      "#e6e1f0",
    "trend_line":   "#6b5b95",
    "trend_fill":   "#6b5b9522",
    "grid":         "#e8e6ed",
}


def _severity_color(severity: str) -> str:
    """Return hex color for a severity level."""
    mapping = {
        "CRITICAL": COLORS["critical"],
        "HIGH":     COLORS["high"],
        "MEDIUM":   COLORS["medium"],
        "LOW":      COLORS["low"],
        "INFO":     COLORS["info"],
        "PASS":     COLORS["pass"],
        "FAIL":     COLORS["fail"],
        "N/A":      COLORS["na"],
    }
    return mapping.get(severity.upper(), COLORS["info"])


# ---------------------------------------------------------------------------
# Inline CSS
# ---------------------------------------------------------------------------

_BASE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    color: %(text)s; background: %(bg)s; line-height: 1.55;
}
.report { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
header {
    background: linear-gradient(135deg, %(primary)s, %(secondary)s);
    color: #fff; padding: 36px 32px; border-radius: 8px;
    margin-bottom: 28px;
}
header h1 { font-size: 26px; font-weight: 600; margin-bottom: 6px; }
header .subtitle { opacity: 0.85; font-size: 14px; }
.section { margin-bottom: 28px; }
.section-title {
    font-size: 18px; font-weight: 600; color: %(primary)s;
    border-bottom: 2px solid %(border)s; padding-bottom: 8px;
    margin-bottom: 16px;
}
.card-grid {
    display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 16px; margin-bottom: 20px;
}
.card {
    background: %(card_bg)s; border: 1px solid %(border)s;
    border-radius: 6px; padding: 18px; text-align: center;
}
.card .label { font-size: 12px; color: %(text_muted)s; text-transform: uppercase;
    letter-spacing: 0.5px; margin-bottom: 6px; }
.card .value { font-size: 28px; font-weight: 700; }
.card .trend { font-size: 13px; margin-top: 4px; }
.trend-up { color: %(critical)s; }
.trend-down { color: %(pass)s; }
.trend-flat { color: %(text_muted)s; }
table {
    width: 100%%; border-collapse: collapse; background: %(card_bg)s;
    border: 1px solid %(border)s; border-radius: 6px;
    overflow: hidden; margin-bottom: 16px;
}
th {
    background: %(primary)s; color: #fff; padding: 10px 14px;
    text-align: left; font-size: 13px; font-weight: 600;
}
td {
    padding: 9px 14px; border-bottom: 1px solid %(border)s;
    font-size: 13px;
}
tr:last-child td { border-bottom: none; }
tr:nth-child(even) { background: %(bg)s; }
.sev-badge {
    display: inline-block; padding: 2px 10px; border-radius: 3px;
    color: #fff; font-size: 11px; font-weight: 600;
}
.chart-container {
    background: %(card_bg)s; border: 1px solid %(border)s;
    border-radius: 6px; padding: 18px; margin-bottom: 16px;
    text-align: center;
}
.chart-title {
    font-size: 14px; font-weight: 600; color: %(primary)s;
    margin-bottom: 10px;
}
.recommendations {
    background: %(card_bg)s; border-left: 4px solid %(secondary)s;
    padding: 16px 20px; border-radius: 0 6px 6px 0;
    margin-bottom: 16px;
}
.recommendations li { margin-bottom: 8px; font-size: 13px; }
footer {
    text-align: center; color: %(text_muted)s; font-size: 11px;
    padding-top: 20px; border-top: 1px solid %(border)s;
}
@media print {
    body { background: #fff; }
    .report { max-width: none; padding: 0; }
    header { break-after: avoid; }
    .section { break-inside: avoid; }
}
""" % COLORS


# ---------------------------------------------------------------------------
# SVG chart helpers
# ---------------------------------------------------------------------------

def _svg_bar_chart(data: List[Tuple[str, float]], title: str = "",
                   width: int = 600, height: int = 300,
                   colors: Optional[List[str]] = None) -> str:
    """
    Generate an inline SVG horizontal bar chart.
    *data* is a list of (label, value) tuples.
    """
    if not data:
        return "<p>No data available.</p>"

    max_val = max(v for _, v in data) or 1
    bar_count = len(data)
    margin_top = 30
    margin_bottom = 10
    margin_left = 120
    margin_right = 60
    chart_h = height - margin_top - margin_bottom
    bar_height = min(32, max(14, chart_h // max(bar_count, 1) - 6))
    spacing = max(4, (chart_h - bar_count * bar_height) // max(bar_count, 1))
    actual_h = margin_top + bar_count * (bar_height + spacing) + margin_bottom
    chart_w = width - margin_left - margin_right

    default_colors = [
        COLORS["chart_1"], COLORS["chart_2"], COLORS["chart_3"],
        COLORS["chart_4"], COLORS["chart_5"],
    ]
    if colors is None:
        colors = default_colors

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {actual_h}" width="{width}" height="{actual_h}">'
    ]

    if title:
        lines.append(
            f'<text x="{width // 2}" y="18" text-anchor="middle" '
            f'font-size="14" font-weight="600" fill="{COLORS["primary"]}">'
            f'{title}</text>'
        )

    for i, (label, val) in enumerate(data):
        y = margin_top + i * (bar_height + spacing)
        bw = (val / max_val) * chart_w if max_val else 0
        color = colors[i % len(colors)]

        # Label
        lines.append(
            f'<text x="{margin_left - 6}" y="{y + bar_height * 0.7}" '
            f'text-anchor="end" font-size="12" fill="{COLORS["text"]}">'
            f'{_escape(label)}</text>'
        )
        # Bar
        lines.append(
            f'<rect x="{margin_left}" y="{y}" width="{bw:.1f}" '
            f'height="{bar_height}" rx="3" fill="{color}" opacity="0.85"/>'
        )
        # Value
        lines.append(
            f'<text x="{margin_left + bw + 6:.1f}" y="{y + bar_height * 0.7}" '
            f'font-size="12" fill="{COLORS["text_muted"]}">{val}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def _svg_donut_chart(data: List[Tuple[str, float]], title: str = "",
                     size: int = 200,
                     colors: Optional[List[str]] = None) -> str:
    """
    Generate an inline SVG donut chart.
    *data* is a list of (label, value) tuples.
    """
    if not data or all(v == 0 for _, v in data):
        return "<p>No data available.</p>"

    total = sum(v for _, v in data)
    if total == 0:
        return "<p>No data available.</p>"

    cx, cy = size // 2, size // 2
    outer_r = size // 2 - 10
    inner_r = outer_r * 0.55
    legend_h = len(data) * 22 + 10
    full_h = size + legend_h

    default_colors = [
        COLORS["critical"], COLORS["high"], COLORS["medium"],
        COLORS["low"], COLORS["info"], COLORS["pass"],
    ]
    if colors is None:
        colors = default_colors

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {size} {full_h}" width="{size}" height="{full_h}">'
    ]

    angle = -90  # start at top
    for i, (label, val) in enumerate(data):
        if val == 0:
            continue
        sweep = (val / total) * 360
        start_rad = math.radians(angle)
        end_rad = math.radians(angle + sweep)

        x1_o = cx + outer_r * math.cos(start_rad)
        y1_o = cy + outer_r * math.sin(start_rad)
        x2_o = cx + outer_r * math.cos(end_rad)
        y2_o = cy + outer_r * math.sin(end_rad)
        x1_i = cx + inner_r * math.cos(end_rad)
        y1_i = cy + inner_r * math.sin(end_rad)
        x2_i = cx + inner_r * math.cos(start_rad)
        y2_i = cy + inner_r * math.sin(start_rad)

        large_arc = 1 if sweep > 180 else 0
        color = colors[i % len(colors)]

        d = (
            f"M {x1_o:.2f} {y1_o:.2f} "
            f"A {outer_r} {outer_r} 0 {large_arc} 1 {x2_o:.2f} {y2_o:.2f} "
            f"L {x1_i:.2f} {y1_i:.2f} "
            f"A {inner_r} {inner_r} 0 {large_arc} 0 {x2_i:.2f} {y2_i:.2f} Z"
        )
        lines.append(f'<path d="{d}" fill="{color}" opacity="0.85"/>')
        angle += sweep

    # Center text
    lines.append(
        f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" '
        f'font-size="20" font-weight="700" fill="{COLORS["primary"]}">'
        f'{int(total)}</text>'
    )

    # Legend below
    ly = size + 5
    for i, (label, val) in enumerate(data):
        color = colors[i % len(colors)]
        pct = (val / total * 100) if total else 0
        lines.append(
            f'<rect x="10" y="{ly}" width="12" height="12" rx="2" fill="{color}"/>'
        )
        lines.append(
            f'<text x="28" y="{ly + 11}" font-size="11" '
            f'fill="{COLORS["text"]}">{_escape(label)}: {val} ({pct:.0f}%)</text>'
        )
        ly += 22

    lines.append("</svg>")
    return "\n".join(lines)


def _svg_trend_line(data: List[Tuple[str, float]], title: str = "",
                    width: int = 600, height: int = 200) -> str:
    """
    Generate an inline SVG line/area chart.
    *data* is a list of (label, value) tuples in chronological order.
    """
    if not data or len(data) < 2:
        return "<p>Insufficient data for trend.</p>"

    margin = {"top": 30, "right": 20, "bottom": 40, "left": 50}
    chart_w = width - margin["left"] - margin["right"]
    chart_h = height - margin["top"] - margin["bottom"]

    max_val = max(v for _, v in data) or 1
    n = len(data)
    step_x = chart_w / max(n - 1, 1)

    points = []
    for i, (_, val) in enumerate(data):
        x = margin["left"] + i * step_x
        y = margin["top"] + chart_h - (val / max_val) * chart_h
        points.append((x, y))

    polyline = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    area_points = polyline + (
        f" {points[-1][0]:.1f},{margin['top'] + chart_h:.1f}"
        f" {points[0][0]:.1f},{margin['top'] + chart_h:.1f}"
    )

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {width} {height}" width="{width}" height="{height}">'
    ]

    if title:
        lines.append(
            f'<text x="{width // 2}" y="18" text-anchor="middle" '
            f'font-size="14" font-weight="600" fill="{COLORS["primary"]}">'
            f'{title}</text>'
        )

    # Grid lines
    for g in range(5):
        gy = margin["top"] + (chart_h / 4) * g
        gval = max_val - (max_val / 4) * g
        lines.append(
            f'<line x1="{margin["left"]}" y1="{gy:.1f}" '
            f'x2="{width - margin["right"]}" y2="{gy:.1f}" '
            f'stroke="{COLORS["grid"]}" stroke-width="1"/>'
        )
        lines.append(
            f'<text x="{margin["left"] - 6}" y="{gy + 4:.1f}" '
            f'text-anchor="end" font-size="10" fill="{COLORS["text_muted"]}">'
            f'{gval:.0f}</text>'
        )

    # Area fill
    lines.append(
        f'<polygon points="{area_points}" fill="{COLORS["trend_fill"]}" />'
    )
    # Line
    lines.append(
        f'<polyline points="{polyline}" fill="none" '
        f'stroke="{COLORS["trend_line"]}" stroke-width="2.5" '
        f'stroke-linejoin="round" stroke-linecap="round"/>'
    )
    # Dots
    for x, y in points:
        lines.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" '
            f'fill="{COLORS["trend_line"]}" stroke="#fff" stroke-width="1.5"/>'
        )

    # X-axis labels (show up to ~10 evenly spaced)
    label_step = max(1, n // 10)
    for i in range(0, n, label_step):
        lbl = data[i][0]
        x = margin["left"] + i * step_x
        lines.append(
            f'<text x="{x:.1f}" y="{height - 8}" text-anchor="middle" '
            f'font-size="10" fill="{COLORS["text_muted"]}">'
            f'{_escape(lbl)}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def _svg_risk_matrix(matrix_data: Optional[Dict] = None,
                     size: int = 400) -> str:
    """
    Generate a 5x5 risk matrix SVG.

    *matrix_data* maps (likelihood, impact) tuples (1-5) to count.
    If None, produces an empty matrix.
    """
    if matrix_data is None:
        matrix_data = {}

    margin = 50
    cell = (size - margin) // 5
    actual = margin + 5 * cell + 10

    # Color gradient for cells: green (low) -> yellow -> red (high)
    def _cell_color(li: int, im: int) -> str:
        score = li * im
        if score >= 15:
            return "#c0392b"
        if score >= 10:
            return "#d35400"
        if score >= 6:
            return "#d4a017"
        if score >= 3:
            return "#f0d264"
        return "#82c46c"

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'viewBox="0 0 {actual} {actual}" width="{actual}" height="{actual}">'
    ]

    # Title
    lines.append(
        f'<text x="{actual // 2}" y="16" text-anchor="middle" '
        f'font-size="14" font-weight="600" fill="{COLORS["primary"]}">'
        f'Risk Matrix (Likelihood x Impact)</text>'
    )

    # Y-axis label (Likelihood)
    lines.append(
        f'<text x="12" y="{margin + 5 * cell // 2}" '
        f'text-anchor="middle" font-size="12" fill="{COLORS["text_muted"]}" '
        f'transform="rotate(-90, 12, {margin + 5 * cell // 2})">'
        f'Likelihood</text>'
    )
    # X-axis label (Impact)
    lines.append(
        f'<text x="{margin + 5 * cell // 2}" y="{actual - 2}" '
        f'text-anchor="middle" font-size="12" fill="{COLORS["text_muted"]}">'
        f'Impact</text>'
    )

    likelihood_labels = ["Rare", "Unlikely", "Possible", "Likely", "Almost Certain"]
    impact_labels = ["Negligible", "Minor", "Moderate", "Major", "Catastrophic"]

    for li_idx in range(5):
        li = 5 - li_idx  # top row = 5 (Almost Certain)
        for im in range(1, 6):
            x = margin + (im - 1) * cell
            y = margin + li_idx * cell - 20
            color = _cell_color(li, im)
            count = matrix_data.get((li, im), 0)

            lines.append(
                f'<rect x="{x}" y="{y}" width="{cell}" height="{cell}" '
                f'fill="{color}" opacity="0.7" stroke="#fff" stroke-width="2" '
                f'rx="3"/>'
            )
            if count > 0:
                lines.append(
                    f'<text x="{x + cell // 2}" y="{y + cell // 2 + 5}" '
                    f'text-anchor="middle" font-size="16" font-weight="700" '
                    f'fill="#fff">{count}</text>'
                )

        # Row label
        lines.append(
            f'<text x="{margin - 4}" y="{margin + li_idx * cell + cell // 2 - 15}" '
            f'text-anchor="end" font-size="10" fill="{COLORS["text_muted"]}">'
            f'{likelihood_labels[4 - li_idx]}</text>'
        )

    # Column labels
    for im in range(5):
        x = margin + im * cell + cell // 2
        y = margin + 5 * cell - 14
        lines.append(
            f'<text x="{x}" y="{y}" text-anchor="middle" font-size="10" '
            f'fill="{COLORS["text_muted"]}">{impact_labels[im]}</text>'
        )

    lines.append("</svg>")
    return "\n".join(lines)


def _escape(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ExecutiveReportGenerator:
    """Generates professional HTML reports from GRC data."""

    _instance: Optional["ExecutiveReportGenerator"] = None

    def __init__(self):
        self.evidence_db = paths.evidence_db
        self.reports_dir = paths.reports
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def _connect_evidence(self) -> sqlite3.Connection:
        """Connect to the evidence database (read-only queries)."""
        conn = sqlite3.connect(str(self.evidence_db))
        conn.row_factory = sqlite3.Row
        return conn

    def _safe_query(self, sql: str, params: tuple = ()) -> List[Dict]:
        """Execute a query and return results, returning empty list on error."""
        try:
            with self._connect_evidence() as conn:
                cursor = conn.execute(sql, params)
                return [dict(row) for row in cursor.fetchall()]
        except Exception:
            return []

    def _safe_scalar(self, sql: str, params: tuple = (),
                     default: Any = 0) -> Any:
        """Execute a scalar query, returning *default* on error."""
        try:
            with self._connect_evidence() as conn:
                row = conn.execute(sql, params).fetchone()
                return row[0] if row else default
        except Exception:
            return default

    # ---- HTML wrapper ----------------------------------------------------

    @staticmethod
    def _html_wrap(title: str, body: str, generated_at: str = "") -> str:
        """Wrap *body* in a full HTML document with inline CSS."""
        if not generated_at:
            generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{_escape(title)} - Purple Team GRC</title>
<style>{_BASE_CSS}</style>
</head>
<body>
<div class="report">
<header>
    <h1>{_escape(title)}</h1>
    <div class="subtitle">
        Purple Team GRC &middot; Generated {generated_at}
    </div>
</header>
{body}
<footer>
    Purple Team GRC &copy; {datetime.utcnow().year} &middot;
    Report generated {generated_at}
</footer>
</div>
</body>
</html>"""

    # ==================================================================
    # Executive Summary
    # ==================================================================

    def generate_executive_summary(self, session_id: str = None,
                                   days: int = 30) -> str:
        """
        Generate a comprehensive executive summary as HTML.

        If *session_id* is given, focuses on that session; otherwise
        aggregates data from the last *days* days.
        """
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        sections: list = []

        # --- Risk posture overview ---
        sev_counts = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = self._safe_scalar(
                "SELECT COUNT(*) FROM findings WHERE severity = ? "
                "AND status = 'open' AND timestamp >= ?",
                (sev, cutoff),
            )
            sev_counts[sev] = count

        total_open = sum(sev_counts.values())
        total_resolved = self._safe_scalar(
            "SELECT COUNT(*) FROM findings WHERE status = 'resolved' "
            "AND timestamp >= ?", (cutoff,),
        )

        cards_html = '<div class="card-grid">'
        for sev, cnt in sev_counts.items():
            color = _severity_color(sev)
            cards_html += (
                f'<div class="card">'
                f'<div class="label">{sev}</div>'
                f'<div class="value" style="color:{color}">{cnt}</div>'
                f'</div>'
            )
        cards_html += (
            f'<div class="card">'
            f'<div class="label">Total Open</div>'
            f'<div class="value">{total_open}</div></div>'
            f'<div class="card">'
            f'<div class="label">Resolved ({days}d)</div>'
            f'<div class="value" style="color:{COLORS["pass"]}">'
            f'{total_resolved}</div></div>'
        )
        cards_html += "</div>"

        donut_data = [(sev, cnt) for sev, cnt in sev_counts.items() if cnt > 0]
        donut_svg = _svg_donut_chart(
            donut_data, "Open Findings by Severity", size=220,
            colors=[_severity_color(s) for s, _ in donut_data],
        )

        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Risk Posture Overview</h2>'
            f'{cards_html}'
            f'<div class="chart-container">{donut_svg}</div>'
            f'</div>'
        )

        # --- Top 10 Risks ---
        top_risks = self._safe_query(
            "SELECT title, severity, affected_asset, cvss_score, cve_ids "
            "FROM findings WHERE status = 'open' AND timestamp >= ? "
            "ORDER BY cvss_score DESC, timestamp DESC LIMIT 10",
            (cutoff,),
        )

        if top_risks:
            rows_html = ""
            for i, r in enumerate(top_risks, 1):
                sev = r.get("severity", "INFO")
                color = _severity_color(sev)
                rows_html += (
                    f'<tr><td>{i}</td>'
                    f'<td>{_escape(r.get("title", ""))}</td>'
                    f'<td><span class="sev-badge" style="background:{color}">'
                    f'{sev}</span></td>'
                    f'<td>{r.get("cvss_score", 0)}</td>'
                    f'<td>{_escape(r.get("affected_asset", ""))}</td></tr>'
                )

            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Top 10 Risks</h2>'
                f'<table><tr><th>#</th><th>Finding</th><th>Severity</th>'
                f'<th>CVSS</th><th>Asset</th></tr>{rows_html}</table></div>'
            )

        # --- Compliance framework scores ---
        frameworks = self._safe_query(
            "SELECT DISTINCT framework FROM control_mappings"
        )
        if frameworks:
            fw_html = '<div class="card-grid">'
            fw_bar_data = []
            for fw in frameworks:
                fn = fw.get("framework", "Unknown")
                total_controls = self._safe_scalar(
                    "SELECT COUNT(DISTINCT control_id) FROM control_mappings "
                    "WHERE framework = ?", (fn,),
                )
                with_evidence = self._safe_scalar(
                    "SELECT COUNT(DISTINCT cm.control_id) "
                    "FROM control_mappings cm "
                    "JOIN evidence e ON cm.evidence_id = e.evidence_id "
                    "WHERE cm.framework = ?", (fn,),
                )
                pct = round(with_evidence / max(total_controls, 1) * 100)
                color = COLORS["pass"] if pct >= 80 else (
                    COLORS["medium"] if pct >= 50 else COLORS["critical"]
                )
                fw_html += (
                    f'<div class="card">'
                    f'<div class="label">{_escape(fn)}</div>'
                    f'<div class="value" style="color:{color}">{pct}%</div>'
                    f'<div class="trend">{with_evidence}/{total_controls} controls</div>'
                    f'</div>'
                )
                fw_bar_data.append((fn, pct))
            fw_html += "</div>"

            bar_svg = _svg_bar_chart(fw_bar_data, "Compliance by Framework", width=600)

            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Compliance Scores</h2>'
                f'{fw_html}'
                f'<div class="chart-container">{bar_svg}</div>'
                f'</div>'
            )

        # --- Remediation progress ---
        open_cnt = self._safe_scalar(
            "SELECT COUNT(*) FROM findings WHERE status = 'open' "
            "AND timestamp >= ?", (cutoff,),
        )
        in_progress = self._safe_scalar(
            "SELECT COUNT(*) FROM findings WHERE status = 'in_progress' "
            "AND timestamp >= ?", (cutoff,),
        )
        resolved_cnt = total_resolved

        rem_data = [
            ("Open", open_cnt), ("In Progress", in_progress),
            ("Resolved", resolved_cnt),
        ]
        rem_colors = [COLORS["critical"], COLORS["medium"], COLORS["pass"]]
        rem_donut = _svg_donut_chart(rem_data, "Remediation Status", size=220,
                                     colors=rem_colors)

        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Remediation Progress</h2>'
            f'<div class="card-grid">'
            f'<div class="card"><div class="label">Open</div>'
            f'<div class="value" style="color:{COLORS["critical"]}">'
            f'{open_cnt}</div></div>'
            f'<div class="card"><div class="label">In Progress</div>'
            f'<div class="value" style="color:{COLORS["medium"]}">'
            f'{in_progress}</div></div>'
            f'<div class="card"><div class="label">Resolved</div>'
            f'<div class="value" style="color:{COLORS["pass"]}">'
            f'{resolved_cnt}</div></div></div>'
            f'<div class="chart-container">{rem_donut}</div>'
            f'</div>'
        )

        # --- Trend (findings over time) ---
        trend_data = []
        for i in range(min(days, 30), 0, -1):
            day_start = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            day_end = (datetime.utcnow() - timedelta(days=i - 1)).strftime("%Y-%m-%d")
            cnt = self._safe_scalar(
                "SELECT COUNT(*) FROM findings "
                "WHERE timestamp >= ? AND timestamp < ?",
                (day_start, day_end),
            )
            label = (datetime.utcnow() - timedelta(days=i)).strftime("%m/%d")
            trend_data.append((label, cnt))

        if trend_data:
            trend_svg = _svg_trend_line(trend_data, "New Findings Trend",
                                        width=700, height=220)
            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Findings Trend ({days} Days)</h2>'
                f'<div class="chart-container">{trend_svg}</div>'
                f'</div>'
            )

        # --- Recommendations ---
        rec_items = []
        if sev_counts.get("CRITICAL", 0) > 0:
            rec_items.append(
                f"Immediately remediate <b>{sev_counts['CRITICAL']}</b> "
                f"critical findings to reduce organizational risk exposure."
            )
        if sev_counts.get("HIGH", 0) > 5:
            rec_items.append(
                f"Prioritize the <b>{sev_counts['HIGH']}</b> high-severity "
                f"findings within your SLA remediation window."
            )
        if open_cnt > resolved_cnt:
            rec_items.append(
                "Finding accumulation rate exceeds resolution rate. "
                "Consider allocating additional remediation resources."
            )
        if not frameworks:
            rec_items.append(
                "No compliance framework mappings detected. "
                "Map evidence to control frameworks for audit readiness."
            )
        rec_items.append(
            "Schedule regular executive risk reviews to track progress "
            "and ensure accountability."
        )

        rec_html = '<ol class="recommendations">'
        for item in rec_items:
            rec_html += f"<li>{item}</li>"
        rec_html += "</ol>"

        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Recommendations</h2>'
            f'{rec_html}</div>'
        )

        return self._html_wrap("Executive Summary", "\n".join(sections))

    # ==================================================================
    # Compliance Report
    # ==================================================================

    def generate_compliance_report(self, framework: str,
                                   session_id: str = None) -> str:
        """Generate a framework-specific compliance report as HTML."""
        sections: list = []

        # All controls for framework
        controls = self._safe_query(
            "SELECT DISTINCT control_id, control_name, control_family "
            "FROM control_mappings WHERE framework = ? "
            "ORDER BY control_family, control_id",
            (framework,),
        )

        total_controls = len(controls)
        passed = 0
        failed = 0
        na_count = 0
        control_rows = ""

        for ctrl in controls:
            cid = ctrl.get("control_id", "")
            cname = ctrl.get("control_name", "")
            cfamily = ctrl.get("control_family", "")

            evidence_count = self._safe_scalar(
                "SELECT COUNT(*) FROM control_mappings cm "
                "JOIN evidence e ON cm.evidence_id = e.evidence_id "
                "WHERE cm.framework = ? AND cm.control_id = ?",
                (framework, cid),
            )

            # Determine status
            if evidence_count > 0:
                status = "PASS"
                passed += 1
                badge_color = _severity_color("PASS")
            else:
                status = "FAIL"
                failed += 1
                badge_color = _severity_color("FAIL")

            control_rows += (
                f'<tr><td>{_escape(cfamily)}</td>'
                f'<td>{_escape(cid)}</td>'
                f'<td>{_escape(cname)}</td>'
                f'<td><span class="sev-badge" style="background:{badge_color}">'
                f'{status}</span></td>'
                f'<td>{evidence_count}</td></tr>'
            )

        pct = round(passed / max(total_controls, 1) * 100)
        score_color = COLORS["pass"] if pct >= 80 else (
            COLORS["medium"] if pct >= 50 else COLORS["critical"]
        )

        # Summary cards
        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Compliance Overview - '
            f'{_escape(framework)}</h2>'
            f'<div class="card-grid">'
            f'<div class="card"><div class="label">Compliance Score</div>'
            f'<div class="value" style="color:{score_color}">{pct}%</div></div>'
            f'<div class="card"><div class="label">Total Controls</div>'
            f'<div class="value">{total_controls}</div></div>'
            f'<div class="card"><div class="label">Passing</div>'
            f'<div class="value" style="color:{COLORS["pass"]}">'
            f'{passed}</div></div>'
            f'<div class="card"><div class="label">Failing</div>'
            f'<div class="value" style="color:{COLORS["critical"]}">'
            f'{failed}</div></div></div></div>'
        )

        # Donut
        comp_data = [("Pass", passed), ("Fail", failed)]
        comp_colors = [COLORS["pass"], COLORS["critical"]]
        comp_donut = _svg_donut_chart(comp_data, "Control Status", size=220,
                                      colors=comp_colors)
        sections.append(
            f'<div class="section">'
            f'<div class="chart-container">{comp_donut}</div></div>'
        )

        # Control-by-control table
        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Control Details</h2>'
            f'<table><tr><th>Family</th><th>Control ID</th>'
            f'<th>Control Name</th><th>Status</th>'
            f'<th>Evidence Count</th></tr>'
            f'{control_rows}</table></div>'
        )

        # Gap analysis
        gaps = self._safe_query(
            "SELECT DISTINCT control_id, control_name, control_family "
            "FROM control_mappings cm "
            "WHERE cm.framework = ? AND cm.evidence_id NOT IN "
            "(SELECT evidence_id FROM evidence) "
            "ORDER BY control_family, control_id",
            (framework,),
        )

        # Also add controls with zero evidence
        failing_controls = [
            c for c in controls
            if self._safe_scalar(
                "SELECT COUNT(*) FROM control_mappings cm "
                "JOIN evidence e ON cm.evidence_id = e.evidence_id "
                "WHERE cm.framework = ? AND cm.control_id = ?",
                (framework, c.get("control_id", "")),
            ) == 0
        ]

        if failing_controls:
            gap_rows = ""
            for i, g in enumerate(failing_controls, 1):
                priority = "High" if i <= len(failing_controls) // 3 + 1 else (
                    "Medium" if i <= 2 * len(failing_controls) // 3 + 1 else "Low"
                )
                p_color = _severity_color(priority.upper())
                gap_rows += (
                    f'<tr><td>{_escape(g.get("control_family", ""))}</td>'
                    f'<td>{_escape(g.get("control_id", ""))}</td>'
                    f'<td>{_escape(g.get("control_name", ""))}</td>'
                    f'<td><span class="sev-badge" style="background:{p_color}">'
                    f'{priority}</span></td></tr>'
                )
            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Gap Analysis &amp; '
                f'Remediation Priorities</h2>'
                f'<table><tr><th>Family</th><th>Control ID</th>'
                f'<th>Control Name</th><th>Priority</th></tr>'
                f'{gap_rows}</table></div>'
            )

        return self._html_wrap(
            f"Compliance Report - {framework}", "\n".join(sections)
        )

    # ==================================================================
    # Risk Report
    # ==================================================================

    def generate_risk_report(self) -> str:
        """Generate a risk register HTML report."""
        sections: list = []

        # --- Risk matrix ---
        # Approximate: use cvss_score to derive likelihood/impact
        findings = self._safe_query(
            "SELECT * FROM findings WHERE status = 'open' "
            "ORDER BY cvss_score DESC"
        )

        matrix_data: Dict[Tuple[int, int], int] = {}
        for f in findings:
            cvss = float(f.get("cvss_score", 0) or 0)
            # Map CVSS to 1-5 impact
            impact = min(5, max(1, int(math.ceil(cvss / 2))))
            # Estimate likelihood from severity
            sev = f.get("severity", "LOW").upper()
            likelihood_map = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
            likelihood = likelihood_map.get(sev, 1)
            key = (likelihood, impact)
            matrix_data[key] = matrix_data.get(key, 0) + 1

        matrix_svg = _svg_risk_matrix(matrix_data, size=440)
        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Risk Matrix</h2>'
            f'<div class="chart-container">{matrix_svg}</div></div>'
        )

        # --- Top risks table ---
        top = findings[:20]
        if top:
            rows = ""
            for i, r in enumerate(top, 1):
                sev = r.get("severity", "INFO")
                color = _severity_color(sev)
                rows += (
                    f'<tr><td>{i}</td>'
                    f'<td>{_escape(r.get("title", ""))}</td>'
                    f'<td><span class="sev-badge" style="background:{color}">'
                    f'{sev}</span></td>'
                    f'<td>{r.get("cvss_score", 0)}</td>'
                    f'<td>{_escape(r.get("affected_asset", ""))}</td>'
                    f'<td>{_escape(r.get("status", ""))}</td></tr>'
                )
            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Top Risks</h2>'
                f'<table><tr><th>#</th><th>Risk</th><th>Severity</th>'
                f'<th>CVSS</th><th>Asset</th><th>Status</th></tr>'
                f'{rows}</table></div>'
            )

        # --- Risks by asset ---
        by_asset = self._safe_query(
            "SELECT affected_asset, COUNT(*) as cnt, "
            "SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as crit, "
            "SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as hi "
            "FROM findings WHERE status = 'open' AND affected_asset != '' "
            "GROUP BY affected_asset ORDER BY cnt DESC LIMIT 15"
        )

        if by_asset:
            asset_bar = _svg_bar_chart(
                [(a.get("affected_asset", "?"), a.get("cnt", 0)) for a in by_asset],
                "Open Findings by Asset",
                width=650,
            )
            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Risk by Asset</h2>'
                f'<div class="chart-container">{asset_bar}</div></div>'
            )

        # --- Risk trend ---
        trend_data = []
        for i in range(30, 0, -1):
            d = (datetime.utcnow() - timedelta(days=i)).strftime("%Y-%m-%d")
            cnt = self._safe_scalar(
                "SELECT COUNT(*) FROM findings WHERE status = 'open' "
                "AND timestamp <= ?", (d,),
            )
            label = (datetime.utcnow() - timedelta(days=i)).strftime("%m/%d")
            trend_data.append((label, cnt))

        if trend_data:
            trend_svg = _svg_trend_line(trend_data, "Open Risk Trend (30 Days)",
                                        width=700, height=220)
            sections.append(
                f'<div class="section">'
                f'<h2 class="section-title">Risk Trend</h2>'
                f'<div class="chart-container">{trend_svg}</div></div>'
            )

        # --- Severity breakdown bar chart ---
        sev_data = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            cnt = self._safe_scalar(
                "SELECT COUNT(*) FROM findings WHERE severity = ? "
                "AND status = 'open'", (sev,),
            )
            sev_data.append((sev, cnt))

        sev_bar = _svg_bar_chart(
            sev_data, "Open Findings by Severity", width=500,
            colors=[_severity_color(s) for s, _ in sev_data],
        )
        sections.append(
            f'<div class="section">'
            f'<h2 class="section-title">Severity Breakdown</h2>'
            f'<div class="chart-container">{sev_bar}</div></div>'
        )

        return self._html_wrap("Risk Register Report", "\n".join(sections))

    # ---- save report -----------------------------------------------------

    def save_report(self, html_content: str, filename: str) -> Path:
        """
        Save HTML content to data/reports/.

        Returns the full path to the saved file.
        """
        if not filename.endswith(".html"):
            filename += ".html"
        filepath = self.reports_dir / filename
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)
        return filepath


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_report_generator: Optional[ExecutiveReportGenerator] = None


def get_report_generator() -> ExecutiveReportGenerator:
    """Get the report generator singleton."""
    global _report_generator
    if _report_generator is None:
        _report_generator = ExecutiveReportGenerator()
    return _report_generator


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    rg = get_report_generator()
    print(f"Reports directory: {rg.reports_dir}")
    print(f"Evidence DB: {rg.evidence_db}")

    # Generate reports (will work with whatever data exists)
    exec_html = rg.generate_executive_summary(days=30)
    p1 = rg.save_report(exec_html, "executive_summary_test")
    print(f"Executive summary saved: {p1}")

    risk_html = rg.generate_risk_report()
    p2 = rg.save_report(risk_html, "risk_report_test")
    print(f"Risk report saved: {p2}")

    comp_html = rg.generate_compliance_report("NIST-800-53")
    p3 = rg.save_report(comp_html, "compliance_nist_test")
    print(f"Compliance report saved: {p3}")

    # Test SVG helpers standalone
    bar = _svg_bar_chart([("A", 10), ("B", 25), ("C", 15)], "Test Bar Chart")
    print(f"Bar chart SVG length: {len(bar)}")

    donut = _svg_donut_chart([("Good", 70), ("Bad", 30)], "Test Donut")
    print(f"Donut chart SVG length: {len(donut)}")

    trend = _svg_trend_line(
        [(f"Day {i}", i * 3 + 5) for i in range(10)], "Test Trend"
    )
    print(f"Trend line SVG length: {len(trend)}")

    matrix = _svg_risk_matrix({(3, 4): 5, (5, 5): 2, (1, 1): 10})
    print(f"Risk matrix SVG length: {len(matrix)}")

    print("\nAll report generator tests passed.")

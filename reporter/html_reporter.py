"""
ADS – HTML Reporter (reporter) v2.5
Modern, dark-theme siber güvenlik raporu üretir.
Host sütunu eklenmiş, CSS kaçış karakterleri düzeltilmiştir.
"""

import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ScanReport, RiskLevel, PriorityLevel


_RISK_COLOR = {
    "high":   "#ef4444",
    "medium": "#f59e0b",
    "low":    "#22c55e",
}

_RISK_BG = {
    "high":   "rgba(239,68,68,0.12)",
    "medium": "rgba(245,158,11,0.12)",
    "low":    "rgba(34,197,94,0.12)",
}

_RISK_ICON = {
    "high":   "🔴",
    "medium": "🟡",
    "low":    "🟢",
}

_PRIORITY_COLOR = {
    "critical": "#ef4444",
    "high":     "#f59e0b",
    "medium":   "#3b82f6",
    "low":      "#22c55e",
}

_PRIORITY_ICON = {
    "critical": "⛔",
    "high":     "🔶",
    "medium":   "🔵",
    "low":      "🟢",
}


def _score_bar(score: int, max_score: int = 5) -> str:
    filled = score
    empty  = max_score - score
    return (
        f'<span class="score-bar">'
        + '<span class="bar-filled"></span>' * filled
        + '<span class="bar-empty"></span>' * empty
        + f'</span> <span class="score-num">{score}/{max_score}</span>'
    )


def _cve_badges(cves: list) -> str:
    if not cves:
        return '<span class="no-cve">—</span>'
    badges = []
    for c in cves:
        cvss = c.get("cvss_score", 0) if isinstance(c, dict) else c.cvss_score
        cve_id = c.get("cve_id", "") if isinstance(c, dict) else c.cve_id
        url    = c.get("url", "#") if isinstance(c, dict) else c.url
        color  = "#ef4444" if cvss >= 9 else "#f59e0b" if cvss >= 7 else "#3b82f6"
        badges.append(
            f'<a class="cve-badge" href="{url}" target="_blank" '
            f'style="border-color:{color};color:{color}" title="CVSS {cvss}">'
            f'{cve_id} ({cvss})</a>'
        )
    return " ".join(badges)


def _confidence_badge(confidence: str) -> str:
    colors = {"high": "#22c55e", "medium": "#f59e0b", "low": "#ef4444"}
    icons  = {"high": "✅", "medium": "⚠️", "low": "❓"}
    color = colors.get(confidence, "#94a3b8")
    icon  = icons.get(confidence, "⚪")
    return f'<span class="confidence-badge" style="color:{color}">{icon} {confidence.upper()}</span>'


def _priority_badge(priority: str) -> str:
    color = _PRIORITY_COLOR.get(priority, "#94a3b8")
    icon  = _PRIORITY_ICON.get(priority, "⚪")
    return (
        f'<span class="priority-badge" '
        f'style="background:{color}22;color:{color};border:1px solid {color}">'
        f'{icon} {priority.upper()}</span>'
    )


def _finding_row(item) -> str:
    risk  = item.risk.value if hasattr(item.risk, "value") else str(item.risk)
    color = _RISK_COLOR.get(risk, "#94a3b8")
    bg    = _RISK_BG.get(risk, "transparent")
    icon  = _RISK_ICON.get(risk, "⚪")
    score = item.final_score
    cves  = item.cves if hasattr(item, "cves") else []
    confidence = item.confidence.value if hasattr(item.confidence, "value") else str(item.confidence)
    priority = item.priority.value if hasattr(item.priority, "value") else str(item.priority)
    host   = item.host if item.host else "—"

    ufw_rule      = getattr(item, "ufw_rule", "—")
    iptables_rule = getattr(item, "iptables_rule", "—")
    rule_note     = getattr(item, "rule_note", "—")
    quick_fix     = getattr(item, "quick_fix", "—")
    proper_fix    = getattr(item, "proper_fix", "—")
    evidence      = getattr(item, "evidence", [])

    evidence_str = ""
    if evidence:
        evidence_str = '<div class="evidence-list">' + "".join(
            f'<span class="evidence-tag">{e}</span>' for e in evidence[:4]
        ) + '</div>'

    return f"""
    <tr class="finding-row" data-risk="{risk}" data-priority="{priority}" style="background:{bg}">
        <td class="td-host"><span class="host-ip">{host}</span></td>
        <td class="td-port">
            <span class="port-badge">{item.port}</span>
            <span class="proto-label">{item.protocol}</span>
        </td>
        <td class="td-service">
            <strong>{item.service}</strong>
            <span class="category-tag">{item.category}</span>
        </td>
        <td class="td-exposure">
            <span class="exposure-tag">{item.expected_exposure}</span>
        </td>
        <td class="td-risk">
            <span class="risk-pill" style="background:{bg};color:{color};border-color:{color}">
                {icon} {risk.upper()}
            </span>
        </td>
        <td class="td-priority">
            {_priority_badge(priority)}
        </td>
        <td class="td-confidence">
            {_confidence_badge(confidence)}
        </td>
        <td class="td-score">{_score_bar(score)}</td>
        <td class="td-cve">{_cve_badges(cves)}</td>
        <td class="td-reason">
            {item.reason}
            {evidence_str}
        </td>
        <td class="td-fix">
            <div class="fix-block">
                <div class="fix-label">⚡ Hızlı</div>
                <div class="fix-text">{quick_fix}</div>
            </div>
            <div class="fix-block proper">
                <div class="fix-label">✅ Doğru</div>
                <div class="fix-text">{proper_fix}</div>
            </div>
        </td>
        <td class="td-rules">
            <code class="rule-code">{ufw_rule}</code>
            <code class="rule-code">{iptables_rule}</code>
            <div class="rule-note">{rule_note}</div>
        </td>
    </tr>
    """


def _top_risks_section(report: ScanReport) -> str:
    items = report.top_risks[:5]
    cards = ""
    for i, item in enumerate(items, 1):
        risk     = item.risk.value if hasattr(item.risk, "value") else str(item.risk)
        priority = item.priority.value if hasattr(item.priority, "value") else str(item.priority)
        color    = _PRIORITY_COLOR.get(priority, _RISK_COLOR.get(risk, "#94a3b8"))
        host     = item.host if item.host else "?"
        cards += f"""
        <div class="top-risk-card" style="border-left-color:{color}">
            <div class="trc-rank">#{i}</div>
            <div class="trc-info">
                <div class="trc-title">{host} — Port {item.port} ({item.service})</div>
                <div class="trc-cat">{item.category} · {_priority_badge(priority)}</div>
            </div>
            <div class="trc-score" style="color:{color}">{item.final_score}/5</div>
        </div>
        """
    return cards


def generate_html_report(report: ScanReport) -> str:
    ctx         = report.context
    target      = ctx.target
    environment = ctx.environment.value if hasattr(ctx.environment, "value") else str(ctx.environment)
    criticality = ctx.criticality.value if hasattr(ctx.criticality, "value") else str(ctx.criticality)
    timestamp   = datetime.now().strftime("%d %B %Y, %H:%M")

    total     = len(report.findings)
    high      = report.high_count
    medium    = report.medium_count
    low       = report.low_count
    critical_p = report.critical_priority_count
    high_p    = report.high_priority_count
    overall   = report.overall_risk
    overall_p = report.overall_priority

    overall_color = _RISK_COLOR.get(overall.lower(), "#94a3b8")

    rows = "".join(_finding_row(item) for item in report.findings)
    top_risks = _top_risks_section(report)

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADS Güvenlik Raporu — {target}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');

        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

        :root {{
            --bg:         #0a0e1a;
            --bg2:        #0f1629;
            --bg3:        #1a2035;
            --border:     #1e2d4a;
            --border2:    #253350;
            --text:       #e2e8f0;
            --text2:      #94a3b8;
            --text3:      #64748b;
            --accent:     #3b82f6;
            --accent2:    #1d4ed8;
            --high:       #ef4444;
            --medium:     #f59e0b;
            --low:        #22c55e;
            --mono:       'JetBrains Mono', monospace;
            --sans:       'Inter', sans-serif;
        }}

        html {{ scroll-behavior: smooth; }}

        body {{
            font-family: var(--sans);
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            font-size: 14px;
            line-height: 1.6;
        }}

        /* ── HEADER ── */
        .header {{
            background: linear-gradient(135deg, #0d1b35 0%, #0a0e1a 60%);
            border-bottom: 1px solid var(--border);
            padding: 32px 48px;
            position: relative;
            overflow: hidden;
        }}
        .header::before {{
            content: '';
            position: absolute;
            top: -80px; right: -80px;
            width: 320px; height: 320px;
            background: radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%);
            pointer-events: none;
        }}
        .header-top {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }}
        .logo {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-icon {{
            width: 40px; height: 40px;
            background: linear-gradient(135deg, #1d4ed8, #3b82f6);
            border-radius: 8px;
            display: flex; align-items: center; justify-content: center;
            font-size: 20px;
        }}
        .logo-text {{
            font-size: 13px;
            color: var(--text2);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            font-weight: 500;
        }}
        .report-time {{
            font-family: var(--mono);
            font-size: 12px;
            color: var(--text3);
        }}
        .header-title {{
            font-size: 26px;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 8px;
        }}
        .header-title span {{
            color: var(--accent);
        }}
        .header-meta {{
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
        }}
        .meta-item {{
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            color: var(--text2);
        }}
        .meta-item .meta-label {{
            color: var(--text3);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}
        .meta-item .meta-val {{
            font-family: var(--mono);
            color: var(--text);
            font-weight: 600;
        }}

        /* ── OVERALL RISK BANNER ── */
        .overall-banner {{
            margin: 0 48px;
            transform: translateY(-1px);
            background: var(--bg3);
            border: 1px solid var(--border);
            border-top: 3px solid {overall_color};
            border-radius: 0 0 12px 12px;
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .overall-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text3);
            margin-bottom: 2px;
        }}
        .overall-value {{
            font-size: 22px;
            font-weight: 700;
            color: {overall_color};
            font-family: var(--mono);
        }}
        .overall-sub {{
            font-size: 12px;
            color: var(--text3);
        }}

        /* ── MAIN CONTENT ── */
        .main {{
            padding: 32px 48px;
            max-width: 1600px;
            margin: 0 auto;
        }}

        /* ── STATS ── */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
            position: relative;
            overflow: hidden;
        }}
        .stat-card::after {{
            content: '';
            position: absolute;
            bottom: 0; left: 0; right: 0;
            height: 2px;
        }}
        .stat-card.s-high::after   {{ background: var(--high); }}
        .stat-card.s-medium::after {{ background: var(--medium); }}
        .stat-card.s-low::after    {{ background: var(--low); }}
        .stat-card.s-total::after  {{ background: var(--accent); }}
        .stat-card.s-critical::after {{ background: var(--high); }}
        .stat-num {{
            font-size: 36px;
            font-weight: 700;
            font-family: var(--mono);
            line-height: 1;
            margin-bottom: 4px;
        }}
        .stat-card.s-high   .stat-num {{ color: var(--high); }}
        .stat-card.s-medium .stat-num {{ color: var(--medium); }}
        .stat-card.s-low    .stat-num {{ color: var(--low); }}
        .stat-card.s-total  .stat-num {{ color: var(--accent); }}
        .stat-card.s-critical .stat-num {{ color: var(--high); }}
        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text3);
            font-weight: 500;
        }}

        /* ── SECTION TITLE ── */
        .section-title {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.1em;
            color: var(--text3);
            font-weight: 600;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        /* ── TWO COL ── */
        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }}

        /* ── TOP RISKS ── */
        .top-risks-panel {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
        }}
        .top-risk-card {{
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 12px 0;
            border-bottom: 1px solid var(--border);
            border-left: 3px solid transparent;
            padding-left: 12px;
            margin-left: -12px;
            transition: background .15s;
        }}
        .top-risk-card:last-child {{ border-bottom: none; }}
        .trc-rank {{
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
            width: 20px;
            flex-shrink: 0;
        }}
        .trc-info {{ flex: 1; }}
        .trc-title {{ font-weight: 600; font-size: 13px; }}
        .trc-cat {{
            font-size: 11px;
            color: var(--text3);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}
        .trc-score {{
            font-family: var(--mono);
            font-size: 18px;
            font-weight: 700;
        }}

        /* ── EXECUTIVE SUMMARY ── */
        .exec-panel {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
        }}
        .exec-text {{
            font-size: 13px;
            color: var(--text2);
            line-height: 1.8;
        }}
        .exec-highlight {{
            color: var(--text);
            font-weight: 600;
        }}

        /* ── FILTERS ── */
        .filter-bar {{
            display: flex;
            gap: 8px;
            margin-bottom: 16px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .filter-label {{
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text3);
            letter-spacing: 0.08em;
            margin-right: 4px;
        }}
        .filter-btn {{
            padding: 6px 14px;
            border-radius: 20px;
            border: 1px solid var(--border2);
            background: var(--bg3);
            color: var(--text2);
            font-size: 12px;
            font-family: var(--sans);
            cursor: pointer;
            transition: all .15s;
            font-weight: 500;
        }}
        .filter-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
        .filter-btn.active {{ background: var(--accent); border-color: var(--accent); color: #fff; }}
        .filter-btn.f-high.active   {{ background: var(--high);   border-color: var(--high); }}
        .filter-btn.f-medium.active {{ background: var(--medium); border-color: var(--medium); }}
        .filter-btn.f-low.active    {{ background: var(--low);    border-color: var(--low); }}
        .filter-btn.f-critical.active {{ background: var(--high); border-color: var(--high); }}

        /* ── TABLE ── */
        .table-wrap {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        thead th {{
            background: var(--bg3);
            color: var(--text3);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 600;
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            white-space: nowrap;
        }}
        .finding-row td {{
            padding: 14px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}
        .finding-row:last-child td {{ border-bottom: none; }}
        .finding-row:hover {{ background: rgba(59,130,246,0.04) !important; }}

        /* Host */
        .td-host {{ min-width: 110px; }}
        .host-ip {{
            font-family: var(--mono);
            font-size: 12px;
            color: #93c5fd;
        }}

        /* Port */
        .port-badge {{
            display: inline-block;
            background: rgba(59,130,246,0.15);
            color: var(--accent);
            font-family: var(--mono);
            font-weight: 600;
            font-size: 13px;
            padding: 2px 8px;
            border-radius: 4px;
            margin-bottom: 4px;
        }}
        .proto-label {{
            display: block;
            font-size: 10px;
            color: var(--text3);
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-family: var(--mono);
        }}

        /* Service */
        .td-service strong {{ display: block; margin-bottom: 4px; }}
        .category-tag {{
            font-size: 10px;
            background: var(--bg3);
            border: 1px solid var(--border2);
            color: var(--text3);
            padding: 2px 6px;
            border-radius: 3px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-family: var(--mono);
        }}

        /* Exposure */
        .exposure-tag {{
            font-size: 11px;
            color: var(--text3);
            font-family: var(--mono);
            word-break: break-word;
        }}

        /* Risk pill */
        .risk-pill {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 10px;
            border-radius: 20px;
            border: 1px solid;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.06em;
            font-family: var(--mono);
            white-space: nowrap;
        }}

        /* Priority badge */
        .priority-badge {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            padding: 4px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.06em;
            font-family: var(--mono);
            white-space: nowrap;
        }}

        /* Confidence badge */
        .confidence-badge {{
            font-size: 12px;
            font-weight: 600;
            font-family: var(--mono);
        }}

        /* Score bar */
        .score-bar {{
            display: inline-flex;
            gap: 2px;
            vertical-align: middle;
        }}
        .bar-filled, .bar-empty {{
            width: 10px; height: 10px;
            border-radius: 2px;
        }}
        .bar-filled {{ background: var(--accent); }}
        .bar-empty  {{ background: var(--border2); }}
        .score-num {{
            font-family: var(--mono);
            font-size: 12px;
            color: var(--text2);
            vertical-align: middle;
            margin-left: 4px;
        }}

        /* CVE */
        .cve-badge {{
            display: inline-block;
            font-size: 10px;
            font-family: var(--mono);
            padding: 2px 6px;
            border-radius: 4px;
            border: 1px solid;
            text-decoration: none;
            margin: 2px 2px 2px 0;
            transition: opacity .15s;
        }}
        .cve-badge:hover {{ opacity: .75; }}
        .no-cve {{ color: var(--text3); font-size: 12px; }}

        /* Evidence */
        .evidence-list {{
            margin-top: 6px;
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
        }}
        .evidence-tag {{
            display: inline-block;
            font-size: 10px;
            background: rgba(59,130,246,0.12);
            color: #93c5fd;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: var(--mono);
        }}

        /* Reason */
        .td-reason {{
            font-size: 12px;
            color: var(--text2);
            max-width: 280px;
            line-height: 1.5;
        }}

        /* Fix */
        .td-fix {{ max-width: 240px; }}
        .fix-block {{
            margin-bottom: 10px;
        }}
        .fix-block:last-child {{ margin-bottom: 0; }}
        .fix-label {{
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text3);
            margin-bottom: 3px;
        }}
        .fix-block.proper .fix-label {{ color: #22c55e; }}
        .fix-text {{
            font-size: 12px;
            color: var(--text2);
            line-height: 1.5;
        }}

        /* Rules */
        .td-rules {{ max-width: 220px; }}
        .rule-code {{
            display: block;
            font-family: var(--mono);
            font-size: 11px;
            background: var(--bg3);
            border: 1px solid var(--border2);
            color: #93c5fd;
            padding: 4px 8px;
            border-radius: 4px;
            margin-bottom: 4px;
            word-break: break-all;
        }}
        .rule-note {{
            font-size: 11px;
            color: var(--text3);
            line-height: 1.4;
            margin-top: 4px;
        }}

        /* ── FOOTER ── */
        .footer {{
            margin-top: 48px;
            padding: 24px 48px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            color: var(--text3);
            font-size: 12px;
        }}
        .footer-brand {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--mono);
        }}

        /* ── RESPONSIVE ── */
        @media (max-width: 900px) {{
            .main {{ padding: 20px; }}
            .header {{ padding: 20px; }}
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .two-col {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>

<!-- HEADER -->
<header class="header">
    <div class="header-top">
        <div class="logo">
            <div class="logo-icon">🛡️</div>
            <div>
                <div style="font-weight:700;font-size:15px;">ADS</div>
                <div class="logo-text">Adaptive Defensive Scanner</div>
            </div>
        </div>
        <div class="report-time">Rapor tarihi: {timestamp}</div>
    </div>
    <div class="header-title">
        Güvenlik Tarama Raporu — <span>{target}</span>
    </div>
    <div class="header-meta">
        <div class="meta-item">
            <span class="meta-label">Hedef</span>
            <span class="meta-val">{target}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Ortam</span>
            <span class="meta-val">{environment.upper()}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Kritiklik</span>
            <span class="meta-val">{criticality.upper()}</span>
        </div>
        <div class="meta-item">
            <span class="meta-label">Toplam Bulgu</span>
            <span class="meta-val">{total}</span>
        </div>
    </div>
</header>

<!-- OVERALL RISK BANNER -->
<div class="overall-banner">
    <div>
        <div class="overall-label">Genel Risk / Öncelik</div>
        <div class="overall-value">{overall} / {overall_p}</div>
    </div>
    <div class="overall-sub">
        {critical_p} kritik · {high_p} yüksek öncelikli · {total} toplam bulgu
    </div>
</div>

<!-- MAIN -->
<main class="main">

    <!-- STATS -->
    <div class="stats-grid">
        <div class="stat-card s-total">
            <div class="stat-num">{total}</div>
            <div class="stat-label">Toplam Bulgu</div>
        </div>
        <div class="stat-card s-high">
            <div class="stat-num">{high}</div>
            <div class="stat-label">Yüksek Risk</div>
        </div>
        <div class="stat-card s-medium">
            <div class="stat-num">{medium}</div>
            <div class="stat-label">Orta Risk</div>
        </div>
        <div class="stat-card s-critical">
            <div class="stat-num">{critical_p}</div>
            <div class="stat-label">Kritik Öncelik</div>
        </div>
    </div>

    <!-- TOP RISKS + EXECUTIVE SUMMARY -->
    <div class="two-col">
        <div class="top-risks-panel">
            <div class="section-title">🎯 En Yüksek Öncelikli Bulgular</div>
            {top_risks}
        </div>
        <div class="exec-panel">
            <div class="section-title">📋 Yönetici Özeti</div>
            <div class="exec-text">
                {target} hedefine yönelik gerçekleştirilen taramada
                <span class="exec-highlight">{total} açık port</span> tespit edilmiştir.
                Bunlardan <span class="exec-highlight" style="color:{_RISK_COLOR['high']}">{high} tanesi yüksek</span>,
                <span class="exec-highlight" style="color:{_RISK_COLOR['medium']}">{medium} tanesi orta</span> ve
                <span class="exec-highlight" style="color:{_RISK_COLOR['low']}">{low} tanesi düşük</span> risk
                olarak sınıflandırılmıştır.
                <br><br>
                Aksiyon önceliğine göre
                <span class="exec-highlight" style="color:{_PRIORITY_COLOR['critical']}">{critical_p} bulgu kritik</span>,
                <span class="exec-highlight" style="color:{_PRIORITY_COLOR['high']}">{high_p} bulgu yüksek</span>
                öncelikli olarak işaretlenmiştir. Bu bulgulara acil müdahale planlanması önerilir.
                <br><br>
                Ortam <span class="exec-highlight">{environment.upper()}</span>, varlık kritikliği ise
                <span class="exec-highlight">{criticality.upper()}</span> olarak belirlenmiştir.
                Genel risk seviyesi <span class="exec-highlight" style="color:{overall_color}">{overall}</span>,
                genel öncelik <span class="exec-highlight" style="color:{_PRIORITY_COLOR.get(overall_p.lower(), '#94a3b8')}">{overall_p}</span>
                olarak değerlendirilmiştir.
            </div>
        </div>
    </div>

    <!-- FINDINGS TABLE -->
    <div class="section-title">🔍 Tüm Bulgular</div>

    <div class="filter-bar">
        <span class="filter-label">Filtrele:</span>
        <button class="filter-btn active"        onclick="filterRisk('all')">Tümü ({total})</button>
        <button class="filter-btn f-high"        onclick="filterRisk('high')">🔴 Yüksek Risk ({high})</button>
        <button class="filter-btn f-medium"      onclick="filterRisk('medium')">🟡 Orta Risk ({medium})</button>
        <button class="filter-btn f-low"         onclick="filterRisk('low')">🟢 Düşük Risk ({low})</button>
        <button class="filter-btn f-critical"    onclick="filterPriority('critical')">⛔ Kritik ({critical_p})</button>
    </div>

    <div class="table-wrap">
        <table id="findings-table">
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Servis</th>
                    <th>Exposure</th>
                    <th>Risk</th>
                    <th>Öncelik</th>
                    <th>Güven</th>
                    <th>Skor</th>
                    <th>CVE</th>
                    <th>Neden</th>
                    <th>Çözüm</th>
                    <th>Firewall Kuralı</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

</main>

<!-- FOOTER -->
<footer class="footer">
    <div class="footer-brand">
        🛡️ ADS v2.5 — Adaptive Defensive Scanner
    </div>
    <div>{timestamp} tarihinde oluşturuldu</div>
</footer>

<script>
    function filterRisk(level) {{
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
        document.querySelectorAll('.finding-row').forEach(row => {{
            if (level === 'all' || row.dataset.risk === level) {{
                row.style.display = '';
            }} else {{
                row.style.display = 'none';
            }}
        }});
    }}
    function filterPriority(level) {{
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
        document.querySelectorAll('.finding-row').forEach(row => {{
            if (row.dataset.priority === level) {{
                row.style.display = '';
            }} else {{
                row.style.display = 'none';
            }}
        }});
    }}
</script>

</body>
</html>"""

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "ads_report.html"
    report_path.write_text(html, encoding="utf-8")

    print(f"[Reporter] HTML raporu oluşturuldu: {report_path}")
    return str(report_path)
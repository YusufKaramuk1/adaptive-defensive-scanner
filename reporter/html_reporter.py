"""
ADS – HTML Reporter (reporter) v2.5
Modern dark-theme security report.

UI language: English
Finding metadata support:
- url
- status_code
- title
- webserver
- tech
"""

import sys
import os
from pathlib import Path
from datetime import datetime
from html import escape

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ScanReport


_RISK_COLOR = {
    "high": "#ef4444",
    "medium": "#f59e0b",
    "low": "#22c55e",
}

_RISK_BG = {
    "high": "rgba(239,68,68,0.12)",
    "medium": "rgba(245,158,11,0.12)",
    "low": "rgba(34,197,94,0.12)",
}

_RISK_ICON = {
    "high": "●",
    "medium": "▲",
    "low": "●",
}

_PRIORITY_COLOR = {
    "critical": "#ef4444",
    "high": "#f59e0b",
    "medium": "#3b82f6",
    "low": "#22c55e",
}

_PRIORITY_ICON = {
    "critical": "●",
    "high": "◆",
    "medium": "▲",
    "low": "●",
}


def _safe(value) -> str:
    if value is None:
        return ""
    return escape(str(value))


def _score_bar(score: int, max_score: int = 5) -> str:
    filled = max(0, min(score, max_score))
    empty = max_score - filled

    return (
        '<span class="score-bar">'
        + '<span class="bar-filled"></span>' * filled
        + '<span class="bar-empty"></span>' * empty
        + f'</span> <span class="score-num">{filled}/{max_score}</span>'
    )


def _cve_badges(cves: list) -> str:
    if not cves:
        return '<span class="muted">—</span>'

    badges = []

    for c in cves:
        cvss = c.get("cvss_score", 0) if isinstance(c, dict) else c.cvss_score
        cve_id = c.get("cve_id", "") if isinstance(c, dict) else c.cve_id
        url = c.get("url", "#") if isinstance(c, dict) else c.url

        color = "#ef4444" if cvss >= 9 else "#f59e0b" if cvss >= 7 else "#3b82f6"

        badges.append(
            f'<a class="cve-badge" href="{_safe(url)}" target="_blank" '
            f'style="border-color:{color};color:{color}" title="CVSS {cvss}">'
            f'{_safe(cve_id)} ({cvss})</a>'
        )

    return " ".join(badges)


def _confidence_badge(confidence: str) -> str:
    colors = {
        "high": "#22c55e",
        "medium": "#f59e0b",
        "low": "#ef4444",
    }

    color = colors.get(confidence, "#94a3b8")
    return f'<span class="confidence-badge" style="color:{color}">{_safe(confidence.upper())}</span>'


def _priority_badge(priority: str) -> str:
    color = _PRIORITY_COLOR.get(priority, "#94a3b8")
    icon = _PRIORITY_ICON.get(priority, "●")

    return (
        f'<span class="priority-badge" '
        f'style="background:{color}22;color:{color};border:1px solid {color}">'
        f'{icon} {_safe(priority.upper())}</span>'
    )


def _risk_badge(risk: str) -> str:
    color = _RISK_COLOR.get(risk, "#94a3b8")
    bg = _RISK_BG.get(risk, "transparent")
    icon = _RISK_ICON.get(risk, "●")

    return (
        f'<span class="risk-pill" style="background:{bg};color:{color};border-color:{color}">'
        f'{icon} {_safe(risk.upper())}</span>'
    )


def _metadata_chip(label: str, value) -> str:
    if value is None or value == "" or value == []:
        return ""

    if isinstance(value, list):
        value = ", ".join(str(v) for v in value if v)

    return (
        f'<span class="metadata-chip">'
        f'<span class="metadata-chip-label">{_safe(label)}</span>'
        f'{_safe(value)}'
        f'</span>'
    )


def _web_fingerprint_block(metadata: dict) -> str:
    if not metadata:
        return ""

    chips = [
        _metadata_chip("URL", metadata.get("url")),
        _metadata_chip("Status", metadata.get("status_code")),
        _metadata_chip("Title", metadata.get("title")),
        _metadata_chip("Server", metadata.get("webserver")),
        _metadata_chip("Tech", metadata.get("tech")),
    ]

    chips = [chip for chip in chips if chip]

    if not chips:
        return ""

    return f"""
    <div class="fingerprint-box">
        <div class="detail-title">Web Fingerprint</div>
        <div class="fingerprint-chips">
            {''.join(chips)}
        </div>
    </div>
    """


def _evidence_block(evidence: list) -> str:
    if not evidence:
        return '<span class="muted">No evidence provided.</span>'

    return '<div class="evidence-list">' + "".join(
        f'<span class="evidence-tag">{_safe(item)}</span>' for item in evidence[:6]
    ) + "</div>"


def _details_block(item) -> str:
    metadata = getattr(item, "metadata", {}) or {}
    evidence = getattr(item, "evidence", []) or []

    quick_fix = getattr(item, "quick_fix", "—")
    proper_fix = getattr(item, "proper_fix", "—")
    ufw_rule = getattr(item, "ufw_rule", "—")
    iptables_rule = getattr(item, "iptables_rule", "—")
    rule_note = getattr(item, "rule_note", "—")

    fingerprint = _web_fingerprint_block(metadata)

    return f"""
    <details class="finding-details">
        <summary>Details</summary>

        <div class="details-grid">
            <div class="detail-card">
                <div class="detail-title">Reason</div>
                <div class="detail-text">{_safe(item.reason)}</div>
            </div>

            <div class="detail-card">
                <div class="detail-title">Evidence</div>
                {_evidence_block(evidence)}
            </div>

            <div class="detail-card">
                <div class="detail-title">Quick Fix</div>
                <div class="detail-text">{_safe(quick_fix)}</div>
            </div>

            <div class="detail-card">
                <div class="detail-title">Proper Fix</div>
                <div class="detail-text">{_safe(proper_fix)}</div>
            </div>

            <div class="detail-card">
                <div class="detail-title">Firewall Rule</div>
                <code class="rule-code">{_safe(ufw_rule)}</code>
                <code class="rule-code">{_safe(iptables_rule)}</code>
                <div class="rule-note">{_safe(rule_note)}</div>
            </div>

            {fingerprint}
        </div>
    </details>
    """


def _short_context(item) -> str:
    metadata = getattr(item, "metadata", {}) or {}
    title = metadata.get("title")
    url = metadata.get("url")
    status = metadata.get("status_code")

    chunks = []

    if title:
        chunks.append(f"Title: {title}")

    if status:
        chunks.append(f"Status: {status}")

    if url:
        chunks.append(f"URL: {url}")

    if chunks:
        return " · ".join(chunks[:2])

    if item.reason:
        return item.reason.split("|")[0].strip()

    return "—"


def _finding_row(item) -> str:
    risk = item.risk.value if hasattr(item.risk, "value") else str(item.risk)
    confidence = item.confidence.value if hasattr(item.confidence, "value") else str(item.confidence)
    priority = item.priority.value if hasattr(item.priority, "value") else str(item.priority)

    host = item.host if item.host else "—"
    cves = item.cves if hasattr(item, "cves") else []

    details = _details_block(item)
    context = _short_context(item)

    return f"""
    <tr class="finding-row" data-risk="{_safe(risk)}" data-priority="{_safe(priority)}">
        <td class="td-host"><span class="host-ip">{_safe(host)}</span></td>

        <td class="td-port">
            <span class="port-badge">{_safe(item.port)}</span>
            <span class="proto-label">{_safe(item.protocol)}</span>
        </td>

        <td class="td-service">
            <strong>{_safe(item.service)}</strong>
            <span class="category-tag">{_safe(item.category)}</span>
        </td>

        <td class="td-exposure">
            <span class="exposure-tag">{_safe(item.expected_exposure)}</span>
        </td>

        <td class="td-risk">{_risk_badge(risk)}</td>
        <td class="td-priority">{_priority_badge(priority)}</td>
        <td class="td-confidence">{_confidence_badge(confidence)}</td>
        <td class="td-score">{_score_bar(item.final_score)}</td>
        <td class="td-cve">{_cve_badges(cves)}</td>

        <td class="td-context">
            <div class="context-text">{_safe(context)}</div>
            {details}
        </td>
    </tr>
    """


def _top_risks_section(report: ScanReport) -> str:
    cards = ""

    for i, item in enumerate(report.top_risks[:5], 1):
        risk = item.risk.value if hasattr(item.risk, "value") else str(item.risk)
        priority = item.priority.value if hasattr(item.priority, "value") else str(item.priority)
        color = _PRIORITY_COLOR.get(priority, _RISK_COLOR.get(risk, "#94a3b8"))

        metadata = getattr(item, "metadata", {}) or {}
        title = metadata.get("title")
        url = metadata.get("url")

        subline = f"{_safe(item.category)} · {_priority_badge(priority)}"

        if title:
            subline += f'<div class="trc-web-title">Title: {_safe(title)}</div>'
        elif url:
            subline += f'<div class="trc-web-title">URL: {_safe(url)}</div>'

        cards += f"""
        <div class="top-risk-card" style="border-left-color:{color}">
            <div class="trc-rank">#{i}</div>

            <div class="trc-info">
                <div class="trc-title">{_safe(item.host)} — Port {_safe(item.port)} ({_safe(item.service)})</div>
                <div class="trc-cat">{subline}</div>
            </div>

            <div class="trc-score" style="color:{color}">{_safe(item.final_score)}/5</div>
        </div>
        """

    return cards


def _metadata_card(label: str, value: str, highlight: bool = False) -> str:
    value_class = "metadata-value highlight" if highlight else "metadata-value"

    if value is None or value == "":
        value = "—"

    return f"""
    <div class="metadata-card">
        <div class="metadata-label">{_safe(label)}</div>
        <div class="{value_class}">{_safe(value)}</div>
    </div>
    """


def generate_html_report(report: ScanReport) -> str:
    ctx = report.context

    target = ctx.target
    environment = ctx.environment.value if hasattr(ctx.environment, "value") else str(ctx.environment)
    criticality = ctx.criticality.value if hasattr(ctx.criticality, "value") else str(ctx.criticality)

    scan_mode = getattr(ctx, "scan_mode", "unknown")
    mock = getattr(ctx, "mock", False)
    parallel = getattr(ctx, "parallel", False)
    workers = getattr(ctx, "workers", 1)

    source_tool = getattr(ctx, "source_tool", "") or "ads"
    source_file = getattr(ctx, "source_file", "")

    mock_text = "ON" if mock else "OFF"
    parallel_text = "ON" if parallel else "OFF"

    timestamp = datetime.now().strftime("%d %B %Y, %H:%M")

    total = len(report.findings)
    high = report.high_count
    medium = report.medium_count
    low = report.low_count
    critical_p = report.critical_priority_count
    high_p = report.high_priority_count
    overall = report.overall_risk
    overall_p = report.overall_priority

    overall_color = _RISK_COLOR.get(overall.lower(), "#94a3b8")

    rows = "".join(_finding_row(item) for item in report.findings)
    top_risks = _top_risks_section(report)

    metadata_cards = "".join([
        _metadata_card("Target", target, True),
        _metadata_card("Environment", environment.upper()),
        _metadata_card("Criticality", criticality.upper()),
        _metadata_card("Scan Mode", scan_mode, True),
        _metadata_card("Source Tool", source_tool, True),
        _metadata_card("Source File", source_file, True),
        _metadata_card("Mock", mock_text),
        _metadata_card("Parallel", parallel_text),
        _metadata_card("Workers", str(workers)),
    ])

    source_sentence = ""

    if source_file:
        source_sentence = (
            f'<br><br>Source tool: <span class="exec-highlight">{_safe(source_tool)}</span>. '
            f'Source file: <span class="exec-highlight">{_safe(source_file)}</span>.'
        )
    else:
        source_sentence = (
            f'<br><br>Source tool: <span class="exec-highlight">{_safe(source_tool)}</span>.'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADS Security Report — {_safe(target)}</title>

    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;500;600;700&display=swap');

        *, *::before, *::after {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}

        :root {{
            --bg: #0a0e1a;
            --bg2: #0f1629;
            --bg3: #1a2035;
            --border: #1e2d4a;
            --border2: #253350;
            --text: #e2e8f0;
            --text2: #94a3b8;
            --text3: #64748b;
            --accent: #3b82f6;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #22c55e;
            --mono: 'JetBrains Mono', monospace;
            --sans: 'Inter', sans-serif;
        }}

        body {{
            font-family: var(--sans);
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            font-size: 14px;
            line-height: 1.6;
        }}

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
            top: -80px;
            right: -80px;
            width: 320px;
            height: 320px;
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
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, #1d4ed8, #3b82f6);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
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

        .meta-label {{
            color: var(--text3);
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
        }}

        .meta-val {{
            font-family: var(--mono);
            color: var(--text);
            font-weight: 600;
        }}

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

        .main {{
            padding: 32px 48px;
            max-width: 1600px;
            margin: 0 auto;
        }}

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
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
        }}

        .s-total::after {{ background: var(--accent); }}
        .s-high::after {{ background: var(--high); }}
        .s-medium::after {{ background: var(--medium); }}
        .s-critical::after {{ background: var(--high); }}

        .stat-num {{
            font-size: 36px;
            font-weight: 700;
            font-family: var(--mono);
            line-height: 1;
            margin-bottom: 4px;
        }}

        .s-total .stat-num {{ color: var(--accent); }}
        .s-high .stat-num {{ color: var(--high); }}
        .s-medium .stat-num {{ color: var(--medium); }}
        .s-critical .stat-num {{ color: var(--high); }}

        .stat-label {{
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text3);
            font-weight: 500;
        }}

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

        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-bottom: 32px;
        }}

        .metadata-card {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 14px 16px;
            min-width: 0;
        }}

        .metadata-label {{
            font-size: 10px;
            color: var(--text3);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 4px;
        }}

        .metadata-value {{
            font-family: var(--mono);
            font-size: 12px;
            color: var(--text);
            font-weight: 600;
            overflow-wrap: anywhere;
        }}

        .metadata-value.highlight {{
            color: #93c5fd;
        }}

        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 32px;
        }}

        .top-risks-panel,
        .exec-panel {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px 24px;
        }}

        .top-risk-card {{
            display: flex;
            align-items: flex-start;
            gap: 14px;
            padding: 12px 0 12px 12px;
            border-bottom: 1px solid var(--border);
            border-left: 3px solid transparent;
        }}

        .top-risk-card:last-child {{
            border-bottom: none;
        }}

        .trc-rank {{
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text3);
            width: 20px;
            flex-shrink: 0;
        }}

        .trc-info {{
            flex: 1;
            min-width: 0;
        }}

        .trc-title {{
            font-weight: 600;
            font-size: 13px;
        }}

        .trc-cat {{
            font-size: 11px;
            color: var(--text3);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}

        .trc-web-title {{
            margin-top: 4px;
            color: #93c5fd;
            font-family: var(--mono);
            text-transform: none;
            letter-spacing: 0;
            overflow-wrap: anywhere;
        }}

        .trc-score {{
            font-family: var(--mono);
            font-size: 18px;
            font-weight: 700;
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

        .filter-btn:hover {{
            border-color: var(--accent);
            color: var(--accent);
        }}

        .filter-btn.active {{
            background: var(--accent);
            border-color: var(--accent);
            color: #fff;
        }}

        .f-high.active,
        .f-critical.active {{
            background: var(--high);
            border-color: var(--high);
        }}

        .f-medium.active {{
            background: var(--medium);
            border-color: var(--medium);
        }}

        .f-low.active {{
            background: var(--low);
            border-color: var(--low);
        }}

        .table-wrap {{
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow-x: auto;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            min-width: 1180px;
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

        .finding-row:last-child td {{
            border-bottom: none;
        }}

        .finding-row:hover {{
            background: rgba(59,130,246,0.04) !important;
        }}

        .host-ip {{
            font-family: var(--mono);
            font-size: 12px;
            color: #93c5fd;
            white-space: nowrap;
        }}

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

        .td-service strong {{
            display: block;
            margin-bottom: 4px;
        }}

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

        .exposure-tag {{
            font-size: 11px;
            color: var(--text3);
            font-family: var(--mono);
            overflow-wrap: anywhere;
        }}

        .risk-pill,
        .priority-badge {{
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

        .confidence-badge {{
            font-size: 12px;
            font-weight: 600;
            font-family: var(--mono);
            white-space: nowrap;
        }}

        .score-bar {{
            display: inline-flex;
            gap: 2px;
            vertical-align: middle;
        }}

        .bar-filled,
        .bar-empty {{
            width: 10px;
            height: 10px;
            border-radius: 2px;
        }}

        .bar-filled {{
            background: var(--accent);
        }}

        .bar-empty {{
            background: var(--border2);
        }}

        .score-num {{
            font-family: var(--mono);
            font-size: 12px;
            color: var(--text2);
            vertical-align: middle;
            margin-left: 4px;
        }}

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
            white-space: nowrap;
        }}

        .cve-badge:hover {{
            opacity: .75;
        }}

        .muted {{
            color: var(--text3);
        }}

        .td-context {{
            min-width: 280px;
            max-width: 420px;
        }}

        .context-text {{
            color: var(--text2);
            font-size: 12px;
            margin-bottom: 6px;
            overflow-wrap: anywhere;
        }}

        .finding-details {{
            margin-top: 6px;
        }}

        .finding-details summary {{
            cursor: pointer;
            color: #93c5fd;
            font-family: var(--mono);
            font-size: 11px;
            user-select: none;
        }}

        .finding-details[open] summary {{
            margin-bottom: 10px;
        }}

        .details-grid {{
            display: grid;
            grid-template-columns: 1fr;
            gap: 8px;
            margin-top: 8px;
        }}

        .detail-card,
        .fingerprint-box {{
            padding: 10px;
            background: rgba(59,130,246,0.06);
            border: 1px solid rgba(59,130,246,0.18);
            border-radius: 8px;
        }}

        .detail-title {{
            font-size: 10px;
            color: #93c5fd;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            font-weight: 700;
            margin-bottom: 6px;
        }}

        .detail-text {{
            font-size: 12px;
            color: var(--text2);
            line-height: 1.5;
            overflow-wrap: anywhere;
        }}

        .evidence-list {{
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

        .fingerprint-chips {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }}

        .metadata-chip {{
            display: inline-flex;
            gap: 5px;
            align-items: center;
            font-size: 10px;
            background: var(--bg3);
            border: 1px solid var(--border2);
            color: var(--text2);
            padding: 3px 6px;
            border-radius: 4px;
            font-family: var(--mono);
            max-width: 100%;
            overflow-wrap: anywhere;
        }}

        .metadata-chip-label {{
            color: var(--text3);
            text-transform: uppercase;
            letter-spacing: 0.06em;
        }}

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

        @media (max-width: 1200px) {{
            .metadata-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}

            .two-col {{
                grid-template-columns: 1fr;
            }}
        }}

        @media (max-width: 900px) {{
            .main {{
                padding: 20px;
            }}

            .header {{
                padding: 20px;
            }}

            .overall-banner {{
                margin: 0 20px;
            }}

            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        @media (max-width: 600px) {{
            .metadata-grid,
            .stats-grid {{
                grid-template-columns: 1fr;
            }}

            .header-meta {{
                gap: 12px;
            }}

            .overall-banner {{
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }}
        }}
    </style>
</head>

<body>

<header class="header">
    <div class="header-top">
        <div class="logo">
            <div class="logo-icon">🛡️</div>

            <div>
                <div style="font-weight:700;font-size:15px;">ADS</div>
                <div class="logo-text">Adaptive Defensive Scanner</div>
            </div>
        </div>

        <div class="report-time">Report time: {_safe(timestamp)}</div>
    </div>

    <div class="header-title">
        Security Scan Report — <span>{_safe(target)}</span>
    </div>

    <div class="header-meta">
        <div class="meta-item"><span class="meta-label">Target</span><span class="meta-val">{_safe(target)}</span></div>
        <div class="meta-item"><span class="meta-label">Environment</span><span class="meta-val">{_safe(environment.upper())}</span></div>
        <div class="meta-item"><span class="meta-label">Criticality</span><span class="meta-val">{_safe(criticality.upper())}</span></div>
        <div class="meta-item"><span class="meta-label">Scan Mode</span><span class="meta-val">{_safe(scan_mode)}</span></div>
        <div class="meta-item"><span class="meta-label">Source</span><span class="meta-val">{_safe(source_tool)}</span></div>
        <div class="meta-item"><span class="meta-label">Findings</span><span class="meta-val">{total}</span></div>
    </div>
</header>

<div class="overall-banner">
    <div>
        <div class="overall-label">Overall Risk / Priority</div>
        <div class="overall-value">{_safe(overall)} / {_safe(overall_p)}</div>
    </div>

    <div class="overall-sub">
        {critical_p} critical · {high_p} high priority · {total} total findings
    </div>
</div>

<main class="main">

    <div class="stats-grid">
        <div class="stat-card s-total">
            <div class="stat-num">{total}</div>
            <div class="stat-label">Total Findings</div>
        </div>

        <div class="stat-card s-high">
            <div class="stat-num">{high}</div>
            <div class="stat-label">High Risk</div>
        </div>

        <div class="stat-card s-medium">
            <div class="stat-num">{medium}</div>
            <div class="stat-label">Medium Risk</div>
        </div>

        <div class="stat-card s-critical">
            <div class="stat-num">{critical_p}</div>
            <div class="stat-label">Critical Priority</div>
        </div>
    </div>

    <div class="section-title">Scan Metadata</div>

    <div class="metadata-grid">
        {metadata_cards}
    </div>

    <div class="two-col">
        <div class="top-risks-panel">
            <div class="section-title">Top Priority Findings</div>
            {top_risks}
        </div>

        <div class="exec-panel">
            <div class="section-title">Executive Summary</div>

            <div class="exec-text">
                The scan identified <span class="exec-highlight">{total} open service findings</span>
                for <span class="exec-highlight">{_safe(target)}</span>.
                <span class="exec-highlight" style="color:{_RISK_COLOR['high']}">{high}</span> are high risk,
                <span class="exec-highlight" style="color:{_RISK_COLOR['medium']}">{medium}</span> are medium risk,
                and <span class="exec-highlight" style="color:{_RISK_COLOR['low']}">{low}</span> are low risk.

                <br><br>

                From an action perspective,
                <span class="exec-highlight" style="color:{_PRIORITY_COLOR['critical']}">{critical_p}</span> findings are critical priority
                and <span class="exec-highlight" style="color:{_PRIORITY_COLOR['high']}">{high_p}</span> findings are high priority.

                <br><br>

                Environment is <span class="exec-highlight">{_safe(environment.upper())}</span>,
                asset criticality is <span class="exec-highlight">{_safe(criticality.upper())}</span>,
                and scan mode is <span class="exec-highlight">{_safe(scan_mode)}</span>.

                {source_sentence}

                <br><br>

                Overall risk is
                <span class="exec-highlight" style="color:{overall_color}">{_safe(overall)}</span>,
                and overall priority is
                <span class="exec-highlight" style="color:{_PRIORITY_COLOR.get(overall_p.lower(), '#94a3b8')}">{_safe(overall_p)}</span>.
            </div>
        </div>
    </div>

    <div class="section-title">All Findings</div>

    <div class="filter-bar">
        <span class="filter-label">Filter:</span>
        <button class="filter-btn active" onclick="filterRisk(event, 'all')">All ({total})</button>
        <button class="filter-btn f-high" onclick="filterRisk(event, 'high')">High Risk ({high})</button>
        <button class="filter-btn f-medium" onclick="filterRisk(event, 'medium')">Medium Risk ({medium})</button>
        <button class="filter-btn f-low" onclick="filterRisk(event, 'low')">Low Risk ({low})</button>
        <button class="filter-btn f-critical" onclick="filterPriority(event, 'critical')">Critical ({critical_p})</button>
    </div>

    <div class="table-wrap">
        <table id="findings-table">
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Exposure</th>
                    <th>Risk</th>
                    <th>Priority</th>
                    <th>Confidence</th>
                    <th>Score</th>
                    <th>CVE</th>
                    <th>Context / Details</th>
                </tr>
            </thead>

            <tbody>
                {rows}
            </tbody>
        </table>
    </div>

</main>

<footer class="footer">
    <div class="footer-brand">
        🛡️ ADS v2.5 — Adaptive Defensive Scanner
    </div>

    <div>Generated at {_safe(timestamp)}</div>
</footer>

<script>
    function setActiveButton(event) {{
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');
    }}

    function filterRisk(event, level) {{
        setActiveButton(event);

        document.querySelectorAll('.finding-row').forEach(row => {{
            if (level === 'all' || row.dataset.risk === level) {{
                row.style.display = '';
            }} else {{
                row.style.display = 'none';
            }}
        }});
    }}

    function filterPriority(event, level) {{
        setActiveButton(event);

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

    print(f"[Reporter] HTML report created: {report_path}")
    return str(report_path)
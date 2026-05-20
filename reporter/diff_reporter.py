"""
ADS – Diff Reporter (reporter)
İki tarama arasındaki farkları gösteren dark-theme HTML raporu üretir.
"""

import sys
import os
from pathlib import Path
from datetime import datetime
from html import escape

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import DiffReport


def _change_badge(change_type: str) -> tuple[str, str]:
    """Değişim tipine göre badge HTML'i ve satır class'ı döndürür."""
    if change_type == "new":
        return '<span class="badge badge-new">🆕 YENİ</span>', "row-new"

    if change_type == "removed":
        return '<span class="badge badge-removed">🚫 KAPANDI</span>', "row-removed"

    if change_type == "risk_increased":
        return '<span class="badge badge-risk-up">🔺 RİSK ARTTI</span>', "row-risk-up"

    if change_type == "risk_decreased":
        return '<span class="badge badge-risk-down">🔻 RİSK AZALDI</span>', "row-risk-down"

    return '<span class="badge badge-unchanged">➖ DEĞİŞMEDİ</span>', "row-unchanged"


def generate_diff_html(report: DiffReport) -> str:
    """Diff raporunu HTML olarak üretir."""

    timestamp = datetime.now().strftime("%d %B %Y, %H:%M")
    prev = escape(report.previous_report_path)
    curr = escape(report.current_report_path)
    s = report.summary

    rows = ""
    for change in report.changes:
        badge, row_class = _change_badge(change.change_type)
        host = escape(change.host or "—")
        port_proto = escape(f"{change.port}/{change.protocol}")
        service = escape(change.service or "unknown")
        old_risk = escape(change.old_risk or "—")
        new_risk = escape(change.new_risk or "—")
        details = escape(change.details or "")

        rows += f"""
        <tr class="{row_class}">
            <td><span class="host-badge">{host}</span></td>
            <td><span class="port-badge">{port_proto}</span></td>
            <td>{service}</td>
            <td>{badge}</td>
            <td>{old_risk}</td>
            <td>{new_risk}</td>
            <td>{details}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ADS Tarama Karşılaştırma Raporu</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #0a0e1a; color: #e2e8f0; padding: 40px; }}
        h1 {{ color: #3b82f6; border-bottom: 1px solid #1e2d4a; padding-bottom: 10px; }}
        code {{ color: #93c5fd; }}
        .summary {{ background: #0f1629; border: 1px solid #1e2d4a; border-radius: 12px; padding: 20px; margin: 20px 0; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; }}
        .stat {{ text-align: center; }}
        .stat-num {{ font-size: 28px; font-weight: 700; }}
        .stat-label {{ font-size: 12px; color: #64748b; }}
        table {{ width: 100%; border-collapse: collapse; background: #0f1629; border-radius: 12px; overflow: hidden; }}
        th {{ background: #1a2035; color: #64748b; font-size: 11px; text-transform: uppercase; padding: 12px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #1e2d4a; vertical-align: top; }}
        .host-badge {{ background: rgba(148,163,184,0.15); color: #cbd5e1; padding: 3px 8px; border-radius: 4px; font-family: monospace; white-space: nowrap; }}
        .port-badge {{ background: rgba(59,130,246,0.15); color: #3b82f6; padding: 3px 8px; border-radius: 4px; font-family: monospace; white-space: nowrap; }}
        .badge {{ padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; white-space: nowrap; }}
        .badge-new {{ background: #22c55e22; color: #22c55e; }}
        .badge-removed {{ background: #ef444422; color: #ef4444; }}
        .badge-risk-up {{ background: #ef444422; color: #ef4444; }}
        .badge-risk-down {{ background: #22c55e22; color: #22c55e; }}
        .badge-unchanged {{ background: #64748b22; color: #64748b; }}
        .row-new {{ background: #22c55e08; }}
        .row-removed {{ background: #ef444408; }}
        .row-risk-up {{ background: #f59e0b08; }}
        .row-risk-down {{ background: #3b82f608; }}
    </style>
</head>
<body>
    <h1>🔍 ADS Tarama Karşılaştırma Raporu</h1>
    <p><small>Oluşturulma: {timestamp}</small></p>

    <div class="summary">
        <h3>Özet</h3>
        <p>Önceki rapor: <code>{prev}</code></p>
        <p>Şimdiki rapor: <code>{curr}</code></p>
        <div class="summary-grid">
            <div class="stat"><div class="stat-num" style="color:#e2e8f0;">{s.get('total_changes', 0)}</div><div class="stat-label">Toplam Değişim</div></div>
            <div class="stat"><div class="stat-num" style="color:#22c55e;">{s.get('new_ports', 0)}</div><div class="stat-label">Yeni Port</div></div>
            <div class="stat"><div class="stat-num" style="color:#ef4444;">{s.get('removed_ports', 0)}</div><div class="stat-label">Kapanan Port</div></div>
            <div class="stat"><div class="stat-num" style="color:#f59e0b;">{s.get('risk_increased', 0)}</div><div class="stat-label">Risk Artan</div></div>
            <div class="stat"><div class="stat-num" style="color:#22c55e;">{s.get('risk_decreased', 0)}</div><div class="stat-label">Risk Azalan</div></div>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Host</th>
                <th>Port/Protokol</th>
                <th>Servis</th>
                <th>Değişim</th>
                <th>Eski Risk</th>
                <th>Yeni Risk</th>
                <th>Detay</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>"""

    output_dir = Path("reports")
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = output_dir / "ads_diff_report.html"
    report_path.write_text(html, encoding="utf-8")
    print(f"[Reporter] Diff report created: {report_path}")
    return str(report_path)
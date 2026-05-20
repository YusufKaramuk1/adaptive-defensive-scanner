"""
ADS – Scan Diff Engine (analyzer)
İki JSON raporu karşılaştırarak port değişimlerini ve risk farklarını tespit eder.
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import DiffReport, PortChange


def _load_report(report_path: str) -> dict:
    """JSON rapor dosyasını yükler, yoksa hata verir."""
    if not Path(report_path).exists():
        raise FileNotFoundError(f"Rapor dosyası bulunamadı: {report_path}")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _build_index(findings: list) -> dict:
    """Port+protokol bazında bulguları indeksler. Key: 'port/protocol'"""
    index = {}
    for f in findings:
        key = f"{f['port']}/{f['protocol']}"
        index[key] = f
    return index


def _determine_risk_change(old, new) -> str:
    """Eski ve yeni risk seviyesine göre değişim tipini belirler."""
    if old is None and new is not None:
        return "new"
    if old is not None and new is None:
        return "removed"
    if old == new:
        return "unchanged"
    risk_order = {"low": 1, "medium": 2, "high": 3}
    if risk_order.get(new, 0) > risk_order.get(old, 0):
        return "risk_increased"
    return "risk_decreased"


def compare_scans(previous_path: str, current_path: str) -> DiffReport:
    """
    İki tarama raporunu karşılaştırır ve DiffReport döner.

    Args:
        previous_path (str): Önceki JSON rapor dosyası
        current_path (str): Şimdiki JSON rapor dosyası

    Returns:
        DiffReport: Değişiklikleri içeren rapor
    """
    # Raporları yükle
    prev_report = _load_report(previous_path)
    curr_report = _load_report(current_path)

    prev_findings = prev_report.get("findings", [])
    curr_findings = curr_report.get("findings", [])

    # İndeksle
    prev_index = _build_index(prev_findings)
    curr_index = _build_index(curr_findings)

    all_keys = set(list(prev_index.keys()) + list(curr_index.keys()))

    changes = []
    new_count = 0
    removed_count = 0
    risk_inc = 0
    risk_dec = 0

    for key in sorted(all_keys):
        old = prev_index.get(key)
        new = curr_index.get(key)

        old_risk = old["risk"] if old else None
        new_risk = new["risk"] if new else None
        old_priority = old.get("priority") if old else None
        new_priority = new.get("priority") if new else None

        change_type = _determine_risk_change(old_risk, new_risk)

        if change_type == "new":
            new_count += 1
        elif change_type == "removed":
            removed_count += 1
        elif change_type == "risk_increased":
            risk_inc += 1
        elif change_type == "risk_decreased":
            risk_dec += 1

        service = new["service"] if new else old["service"]
        port = new["port"] if new else old["port"]
        protocol = new["protocol"] if new else old["protocol"]

        cves = new.get("cves", []) if new else old.get("cves", [])
        details = ""
        if change_type in ("risk_increased", "risk_decreased"):
            details = f"Risk: {old_risk} → {new_risk}, Öncelik: {old_priority} → {new_priority}"
        elif change_type == "new":
            details = f"Yeni servis: {service}, Risk: {new_risk}, Öncelik: {new_priority}"
        elif change_type == "removed":
            details = f"Kapanan servis: {service}, Önceki risk: {old_risk}"

        changes.append(PortChange(
            port=port,
            protocol=protocol,
            service=service,
            change_type=change_type,
            old_risk=old_risk,
            new_risk=new_risk,
            old_priority=old_priority,
            new_priority=new_priority,
            cves=cves,
            details=details,
        ))

    summary = {
        "total_changes": len(changes) - changes.count(None),  # unchanged hariç
        "new_ports": new_count,
        "removed_ports": removed_count,
        "risk_increased": risk_inc,
        "risk_decreased": risk_dec,
        "unchanged": len(changes) - new_count - removed_count - risk_inc - risk_dec,
    }

    return DiffReport(
        previous_report_path=previous_path,
        current_report_path=current_path,
        timestamp=datetime.now().isoformat(),
        summary=summary,
        changes=changes,
    )
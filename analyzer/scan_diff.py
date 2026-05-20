"""
ADS – Scan Diff Engine (analyzer)
İki JSON raporu karşılaştırarak host-aware port değişimlerini ve risk farklarını tespit eder.
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import DiffReport, PortChange


RISK_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def _load_report(report_path: str) -> dict:
    """JSON rapor dosyasını yükler, yoksa hata verir."""
    if not Path(report_path).exists():
        raise FileNotFoundError(f"Rapor dosyası bulunamadı: {report_path}")

    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _finding_identity(finding: dict[str, Any]) -> str:
    """
    Bir bulguyu benzersiz şekilde temsil eden key üretir.

    Önemli:
    Eski diff motoru sadece port/protocol kullanıyordu. Subnet taramada aynı port
    farklı hostlarda açık olduğunda bu yanlış eşleşmeye sebep oluyordu.

    Yeni key:
        host:port/protocol
    """
    host = str(finding.get("host", "")).strip().lower()
    port = finding.get("port")
    protocol = str(finding.get("protocol", "tcp")).strip().lower()
    return f"{host}:{port}/{protocol}"


def _build_index(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Host+port+protocol bazında bulguları indeksler."""
    index: dict[str, dict[str, Any]] = {}

    for finding in findings:
        key = _finding_identity(finding)
        index[key] = finding

    return index


def _determine_risk_change(old_risk: str | None, new_risk: str | None) -> str:
    """Eski ve yeni risk seviyesine göre değişim tipini belirler."""
    if old_risk is None and new_risk is not None:
        return "new"

    if old_risk is not None and new_risk is None:
        return "removed"

    if old_risk == new_risk:
        return "unchanged"

    old_value = RISK_ORDER.get(str(old_risk).lower(), 0)
    new_value = RISK_ORDER.get(str(new_risk).lower(), 0)

    if new_value > old_value:
        return "risk_increased"

    return "risk_decreased"


def _pick_value(new: dict[str, Any] | None, old: dict[str, Any] | None, field: str, default=None):
    """Yeni bulgu varsa ondan, yoksa eski bulgudan alan değerini alır."""
    if new is not None:
        return new.get(field, default)
    if old is not None:
        return old.get(field, default)
    return default


def _build_details(
    change_type: str,
    host: str,
    service: str,
    old_risk: str | None,
    new_risk: str | None,
    old_priority: str | None,
    new_priority: str | None,
) -> str:
    """Değişim tipine göre okunabilir açıklama üretir."""
    host_part = f"{host} üzerinde " if host else ""

    if change_type in ("risk_increased", "risk_decreased"):
        return f"{host_part}Risk: {old_risk} → {new_risk}, Öncelik: {old_priority} → {new_priority}"

    if change_type == "new":
        return f"{host_part}Yeni servis: {service}, Risk: {new_risk}, Öncelik: {new_priority}"

    if change_type == "removed":
        return f"{host_part}Kapanan servis: {service}, Önceki risk: {old_risk}, Önceki öncelik: {old_priority}"

    return f"{host_part}Değişiklik yok"


def compare_scans(previous_path: str, current_path: str) -> DiffReport:
    """
    İki tarama raporunu karşılaştırır ve DiffReport döner.

    Args:
        previous_path (str): Önceki JSON rapor dosyası
        current_path (str): Şimdiki JSON rapor dosyası

    Returns:
        DiffReport: Değişiklikleri içeren rapor
    """
    prev_report = _load_report(previous_path)
    curr_report = _load_report(current_path)

    prev_findings = prev_report.get("findings", [])
    curr_findings = curr_report.get("findings", [])

    prev_index = _build_index(prev_findings)
    curr_index = _build_index(curr_findings)

    all_keys = sorted(set(prev_index.keys()) | set(curr_index.keys()))

    changes: list[PortChange] = []
    new_count = 0
    removed_count = 0
    risk_inc = 0
    risk_dec = 0
    unchanged_count = 0

    for key in all_keys:
        old = prev_index.get(key)
        new = curr_index.get(key)

        old_risk = old.get("risk") if old else None
        new_risk = new.get("risk") if new else None
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
        else:
            unchanged_count += 1

        host = _pick_value(new, old, "host", "")
        port = _pick_value(new, old, "port", 0)
        protocol = _pick_value(new, old, "protocol", "tcp")
        service = _pick_value(new, old, "service", "unknown")
        cves = _pick_value(new, old, "cves", [])

        details = _build_details(
            change_type=change_type,
            host=host,
            service=service,
            old_risk=old_risk,
            new_risk=new_risk,
            old_priority=old_priority,
            new_priority=new_priority,
        )

        changes.append(PortChange(
            host=host,
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
        "total_changes": new_count + removed_count + risk_inc + risk_dec,
        "new_ports": new_count,
        "removed_ports": removed_count,
        "risk_increased": risk_inc,
        "risk_decreased": risk_dec,
        "unchanged": unchanged_count,
    }

    return DiffReport(
        previous_report_path=previous_path,
        current_report_path=current_path,
        timestamp=datetime.now().isoformat(),
        summary=summary,
        changes=changes,
    )
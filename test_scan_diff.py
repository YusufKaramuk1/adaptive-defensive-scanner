#!/usr/bin/env python3
"""
Scan Diff Engine Test Scripti v2.0
İki JSON raporu karşılaştırarak diff motorunun doğru çalıştığını kontrol eder.
Host alanı artık JSON çıktılarında da var.
"""

import json
import sys
from pathlib import Path
import tempfile

sys.path.insert(0, str(Path(__file__).parent))

from analyzer.scan_diff import compare_scans

# ─── Test verileri ──────────────────────────────────────────

PREVIOUS_REPORT = {
    "meta": {"tool": "ADS", "version": "2.4"},
    "context": {"target": "192.168.1.0/24", "environment": "external", "criticality": "high"},
    "summary": {"total": 3, "high": 2, "medium": 0, "low": 1, "overall_risk": "HIGH", "overall_priority": "CRITICAL"},
    "findings": [
        {
            "host": "192.168.1.1", "port": 22, "protocol": "tcp", "service": "ssh", "state": "open",
            "category": "remote_admin", "expected_exposure": "restricted_admin_only",
            "base_score": 3, "final_score": 5, "risk": "high", "priority": "critical",
            "cves": [{"cve_id": "CVE-2023-38408", "cvss_score": 9.8}],
            "evidence": ["OpenSSH 8.2"], "reason": "SSH dışarıda"
        },
        {
            "host": "192.168.1.1", "port": 80, "protocol": "tcp", "service": "http", "state": "open",
            "category": "web", "expected_exposure": "public_allowed",
            "base_score": 2, "final_score": 3, "risk": "medium", "priority": "medium",
            "cves": [], "evidence": ["HTTP portu"], "reason": "Web sunucusu"
        },
        {
            "host": "192.168.1.2", "port": 445, "protocol": "tcp", "service": "microsoft-ds", "state": "open",
            "category": "file_sharing", "expected_exposure": "internal_only",
            "base_score": 5, "final_score": 5, "risk": "high", "priority": "critical",
            "cves": [{"cve_id": "CVE-2017-0144", "cvss_score": 9.8}],
            "evidence": ["SMBv1 açık"], "reason": "SMB dışarıda"
        },
    ]
}

CURRENT_REPORT = {
    "meta": {"tool": "ADS", "version": "2.4"},
    "context": {"target": "192.168.1.0/24", "environment": "external", "criticality": "high"},
    "summary": {"total": 3, "high": 2, "medium": 0, "low": 1, "overall_risk": "HIGH", "overall_priority": "CRITICAL"},
    "findings": [
        # Aynı SSH (unchanged)
        {
            "host": "192.168.1.1", "port": 22, "protocol": "tcp", "service": "ssh", "state": "open",
            "category": "remote_admin", "expected_exposure": "restricted_admin_only",
            "base_score": 3, "final_score": 5, "risk": "high", "priority": "critical",
            "cves": [{"cve_id": "CVE-2023-38408", "cvss_score": 9.8}],
            "evidence": ["OpenSSH 8.2"], "reason": "SSH dışarıda"
        },
        # HTTP riski arttı (medium → high) ve host aynı
        {
            "host": "192.168.1.1", "port": 80, "protocol": "tcp", "service": "http", "state": "open",
            "category": "web", "expected_exposure": "public_allowed",
            "base_score": 2, "final_score": 5, "risk": "high", "priority": "high",
            "cves": [{"cve_id": "CVE-2021-41773", "cvss_score": 7.5}],
            "evidence": ["Apache 2.4.49", "TLS yok"], "reason": "Web sunucusu güncel değil"
        },
        # SMB kapandı (removed)
        # Yeni RDP açıldı (new) farklı hostta
        {
            "host": "192.168.1.3", "port": 3389, "protocol": "tcp", "service": "ms-wbt-server", "state": "open",
            "category": "remote_admin", "expected_exposure": "restricted_admin_only",
            "base_score": 5, "final_score": 5, "risk": "high", "priority": "critical",
            "cves": [{"cve_id": "CVE-2019-0708", "cvss_score": 9.8}],
            "evidence": ["RDP dışarıda"], "reason": "RDP dışarıda"
        },
    ]
}


def main():
    with tempfile.TemporaryDirectory() as tmp:
        prev_path = Path(tmp) / "previous.json"
        curr_path = Path(tmp) / "current.json"

        with open(prev_path, "w") as f: json.dump(PREVIOUS_REPORT, f)
        with open(curr_path, "w") as f: json.dump(CURRENT_REPORT, f)

        diff = compare_scans(str(prev_path), str(curr_path))

        print("Diff Test Sonuçları")
        print("=" * 55)
        print(f"Yeni port sayısı: {diff.summary['new_ports']} (beklenen: 1)")
        print(
            f"   {'✅' if diff.summary['new_ports'] == 1 else '❌'} 3389/RDP eklendi mi? {any(c.port == 3389 and c.change_type == 'new' for c in diff.changes)}")
        print(f"Kapanan port sayısı: {diff.summary['removed_ports']} (beklenen: 1)")
        print(
            f"   {'✅' if diff.summary['removed_ports'] == 1 else '❌'} 445/SMB kapandı mı? {any(c.port == 445 and c.change_type == 'removed' for c in diff.changes)}")
        print(f"Risk artan: {diff.summary['risk_increased']} (beklenen: 1)")
        print(
            f"   {'✅' if diff.summary['risk_increased'] == 1 else '❌'} HTTP riski arttı mı? {any(c.port == 80 and c.change_type == 'risk_increased' for c in diff.changes)}")
        print(f"Değişmeyen: {diff.summary['unchanged']} (beklenen: 1)")

        # Host kontrolü
        new_items = [c for c in diff.changes if c.change_type == 'new']
        if new_items:
            print(f"\nYeni bulgu host: {new_items[0].port}/{new_items[0].protocol} @ {new_items[0].details}")


if __name__ == "__main__":
    main()
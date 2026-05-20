"""
ADS – Scan Diff Test

This test verifies that analyzer/scan_diff.py correctly detects:
- new ports
- removed ports
- increased risk
- unchanged findings

Run:
    python test_scan_diff.py
"""

import json
from pathlib import Path

from analyzer.scan_diff import compare_scans


PREVIOUS_REPORT = {
    "context": {
        "target": "test-network",
        "environment": "internal",
        "criticality": "medium",
        "scan_mode": "test",
    },
    "summary": {},
    "findings": [
        {
            "host": "192.168.1.1",
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "risk": "low",
            "priority": "medium",
            "cves": [],
        },
        {
            "host": "192.168.1.2",
            "port": 445,
            "protocol": "tcp",
            "service": "microsoft-ds",
            "risk": "high",
            "priority": "high",
            "cves": [],
        },
        {
            "host": "192.168.1.4",
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "risk": "medium",
            "priority": "medium",
            "cves": [],
        },
    ],
}


CURRENT_REPORT = {
    "context": {
        "target": "test-network",
        "environment": "external",
        "criticality": "high",
        "scan_mode": "test",
    },
    "summary": {},
    "findings": [
        {
            "host": "192.168.1.1",
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "risk": "medium",
            "priority": "high",
            "cves": [],
        },
        {
            "host": "192.168.1.3",
            "port": 3389,
            "protocol": "tcp",
            "service": "ms-wbt-server",
            "risk": "high",
            "priority": "critical",
            "cves": [],
        },
        {
            "host": "192.168.1.4",
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "risk": "medium",
            "priority": "medium",
            "cves": [],
        },
    ],
}


def write_report(path: Path, data: dict) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def test_scan_diff():
    test_dir = Path("test_data")
    previous_path = test_dir / "diff_previous.json"
    current_path = test_dir / "diff_current.json"

    write_report(previous_path, PREVIOUS_REPORT)
    write_report(current_path, CURRENT_REPORT)

    diff_report = compare_scans(str(previous_path), str(current_path))
    summary = diff_report.summary

    print("Scan Diff Test Results")
    print("=" * 55)

    print(f"New ports: {summary.get('new_ports')} (expected: 1)")
    assert summary.get("new_ports") == 1

    new_items = [c for c in diff_report.changes if c.change_type == "new"]
    added_rdp = any(c.host == "192.168.1.3" and c.port == 3389 for c in new_items)
    print(f"   ✅ 3389/RDP detected as new? {added_rdp}")
    assert added_rdp is True

    print(f"Removed ports: {summary.get('removed_ports')} (expected: 1)")
    assert summary.get("removed_ports") == 1

    removed_items = [c for c in diff_report.changes if c.change_type == "removed"]
    removed_smb = any(c.host == "192.168.1.2" and c.port == 445 for c in removed_items)
    print(f"   ✅ 445/SMB detected as removed? {removed_smb}")
    assert removed_smb is True

    print(f"Risk increased: {summary.get('risk_increased')} (expected: 1)")
    assert summary.get("risk_increased") == 1

    risk_increased_items = [c for c in diff_report.changes if c.change_type == "risk_increased"]
    http_risk_increased = any(c.host == "192.168.1.1" and c.port == 80 for c in risk_increased_items)
    print(f"   ✅ HTTP risk increase detected? {http_risk_increased}")
    assert http_risk_increased is True

    print(f"Unchanged: {summary.get('unchanged')} (expected: 1)")
    assert summary.get("unchanged") == 1

    new_finding = new_items[0]
    print(
        f"\nNew finding host: {new_finding.port}/{new_finding.protocol} @ "
        f"{new_finding.host} | Service: {new_finding.service}, "
        f"Risk: {new_finding.new_risk}, Priority: {new_finding.new_priority}"
    )

    print("\n✅ Scan diff test passed.")


if __name__ == "__main__":
    test_scan_diff()
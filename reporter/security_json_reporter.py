"""
ADS – Security JSON Reporter

Generates JSON reports for analyzed security findings.

Used for tools like:
- Nuclei
- future Tsunami importer
- future validated vulnerability importers
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _count_by_value(findings: list, attr_name: str, value: str) -> int:
    count = 0

    for finding in findings:
        attr = getattr(finding, attr_name, "")

        if hasattr(attr, "value"):
            attr = attr.value

        if str(attr).lower() == value.lower():
            count += 1

    return count


def _overall_risk(findings: list) -> str:
    if _count_by_value(findings, "risk", "high") > 0:
        return "HIGH"

    if _count_by_value(findings, "risk", "medium") > 0:
        return "MEDIUM"

    return "LOW"


def _overall_priority(findings: list) -> str:
    if _count_by_value(findings, "priority", "critical") > 0:
        return "CRITICAL"

    if _count_by_value(findings, "priority", "high") > 0:
        return "HIGH"

    if _count_by_value(findings, "priority", "medium") > 0:
        return "MEDIUM"

    return "LOW"


def generate_security_json_report(
    context,
    findings: list,
    output_dir: str = "reports",
) -> str:
    """
    Generate timestamped JSON report for analyzed security findings.

    Args:
        context: ScanContext
        findings: list[AnalyzedSecurityFinding]
        output_dir: report directory

    Returns:
        Generated JSON report path
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = Path(output_dir) / f"ads_security_report_{timestamp}.json"

    data = {
        "context": context.to_dict(),
        "summary": {
            "total": len(findings),
            "critical_severity": _count_by_value(findings, "severity", "critical"),
            "high_severity": _count_by_value(findings, "severity", "high"),
            "medium_severity": _count_by_value(findings, "severity", "medium"),
            "low_severity": _count_by_value(findings, "severity", "low"),
            "info_severity": _count_by_value(findings, "severity", "info"),
            "high_risk": _count_by_value(findings, "risk", "high"),
            "medium_risk": _count_by_value(findings, "risk", "medium"),
            "low_risk": _count_by_value(findings, "risk", "low"),
            "critical_priority": _count_by_value(findings, "priority", "critical"),
            "high_priority": _count_by_value(findings, "priority", "high"),
            "medium_priority": _count_by_value(findings, "priority", "medium"),
            "low_priority": _count_by_value(findings, "priority", "low"),
            "overall_risk": _overall_risk(findings),
            "overall_priority": _overall_priority(findings),
        },
        "security_findings": [finding.to_dict() for finding in findings],
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    print(f"[Reporter] Security JSON report created: {report_path}")
    return str(report_path)
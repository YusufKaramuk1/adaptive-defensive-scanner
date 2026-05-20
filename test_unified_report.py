"""
Test ScanReport's unified handling of scan findings and security findings.

Covers:
- Empty report defaults.
- Scan-only behavior is unchanged (regression check).
- Security-only counts and overall.
- Combined overall takes the higher of either list.
- top_priority merges and sorts both kinds together.
- to_dict() emits both summary blocks and both finding lists.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from models import (
    ScanContext, ScanReport,
    AnalyzedFinding, AnalyzedSecurityFinding,
    Environment, Criticality,
    RiskLevel, PriorityLevel, ConfidenceLevel, SecuritySeverity,
)


def _ctx() -> ScanContext:
    return ScanContext(
        target="example.com",
        environment=Environment.EXTERNAL,
        criticality=Criticality.HIGH,
    )


def _scan_finding(risk: RiskLevel, priority: PriorityLevel, final_score: int = 3) -> AnalyzedFinding:
    return AnalyzedFinding(
        host="10.0.0.1",
        port=80,
        service="http",
        risk=risk,
        priority=priority,
        final_score=final_score,
    )


def _sec_finding(
    risk: RiskLevel,
    priority: PriorityLevel,
    severity: SecuritySeverity,
    final_score: int = 3,
) -> AnalyzedSecurityFinding:
    return AnalyzedSecurityFinding(
        host="10.0.0.1",
        port=80,
        template_id="t",
        name="t",
        risk=risk,
        priority=priority,
        severity=severity,
        final_score=final_score,
    )


def test_empty_report():
    r = ScanReport(context=_ctx(), findings=[])
    assert r.security_findings == [], "default security_findings must be empty list"
    assert r.overall_risk == "LOW"
    assert r.overall_priority == "LOW"
    assert r.top_priority == []
    print("   ✅ Empty report defaults work.")


def test_scan_only_unchanged():
    f = _scan_finding(RiskLevel.HIGH, PriorityLevel.CRITICAL)
    r = ScanReport(context=_ctx(), findings=[f])
    assert r.overall_risk == "HIGH"
    assert r.overall_priority == "CRITICAL"
    assert r.high_count == 1
    assert r.critical_priority_count == 1
    assert len(r.top_risks) == 1
    assert len(r.top_priority) == 1
    print("   ✅ Scan-only report behaves as before (regression OK).")


def test_security_only_counts_and_overall():
    sf = _sec_finding(RiskLevel.HIGH, PriorityLevel.CRITICAL, SecuritySeverity.CRITICAL)
    r = ScanReport(context=_ctx(), findings=[], security_findings=[sf])
    assert r.overall_risk == "HIGH"
    assert r.overall_priority == "CRITICAL"
    assert r.security_high_count == 1
    assert r.security_critical_priority_count == 1
    assert r.security_critical_severity_count == 1
    assert len(r.top_priority) == 1
    print("   ✅ Security-only report computes counts and overall correctly.")


def test_severity_counts_by_level():
    sfs = [
        _sec_finding(RiskLevel.HIGH,   PriorityLevel.CRITICAL, SecuritySeverity.CRITICAL),
        _sec_finding(RiskLevel.HIGH,   PriorityLevel.HIGH,     SecuritySeverity.HIGH),
        _sec_finding(RiskLevel.MEDIUM, PriorityLevel.MEDIUM,   SecuritySeverity.MEDIUM),
        _sec_finding(RiskLevel.LOW,    PriorityLevel.LOW,      SecuritySeverity.LOW),
        _sec_finding(RiskLevel.LOW,    PriorityLevel.LOW,      SecuritySeverity.INFO),
    ]
    r = ScanReport(context=_ctx(), findings=[], security_findings=sfs)
    assert r.security_critical_severity_count == 1
    assert r.security_high_severity_count == 1
    assert r.security_medium_severity_count == 1
    assert r.security_low_severity_count == 1
    assert r.security_info_severity_count == 1
    print("   ✅ Severity counts split per level correctly.")


def test_combined_overall_takes_higher():
    f_low = _scan_finding(RiskLevel.LOW, PriorityLevel.LOW, 1)
    sf_high = _sec_finding(RiskLevel.HIGH, PriorityLevel.CRITICAL, SecuritySeverity.CRITICAL, 5)
    r = ScanReport(context=_ctx(), findings=[f_low], security_findings=[sf_high])
    assert r.overall_risk == "HIGH", "security HIGH must elevate overall_risk"
    assert r.overall_priority == "CRITICAL", "security CRITICAL must elevate overall_priority"
    print("   ✅ Overall risk/priority elevated by security findings.")


def test_top_priority_merges_and_sorts():
    f_low = _scan_finding(RiskLevel.LOW,    PriorityLevel.LOW,    1)
    f_med = _scan_finding(RiskLevel.MEDIUM, PriorityLevel.MEDIUM, 3)
    sf_crit = _sec_finding(RiskLevel.HIGH, PriorityLevel.CRITICAL, SecuritySeverity.CRITICAL, 5)
    sf_high = _sec_finding(RiskLevel.HIGH, PriorityLevel.HIGH,     SecuritySeverity.HIGH,     4)

    r = ScanReport(
        context=_ctx(),
        findings=[f_low, f_med],
        security_findings=[sf_crit, sf_high],
    )
    top = r.top_priority

    assert len(top) == 4
    assert top[0] is sf_crit, "CRITICAL security finding must be first"
    assert top[1] is sf_high, "HIGH security finding must be second"
    assert top[2] is f_med,   "MEDIUM scan finding must come before LOW"
    assert top[3] is f_low,   "LOW scan finding must be last"
    print("   ✅ top_priority merges and sorts both kinds correctly.")


def test_to_dict_includes_security_blocks():
    sf = _sec_finding(RiskLevel.HIGH, PriorityLevel.CRITICAL, SecuritySeverity.CRITICAL)
    r = ScanReport(context=_ctx(), findings=[], security_findings=[sf])
    d = r.to_dict()

    assert "security_summary" in d
    assert "security_findings" in d
    assert d["security_summary"]["total"] == 1
    assert d["security_summary"]["critical_severity"] == 1
    assert d["security_summary"]["critical_priority"] == 1
    assert d["security_summary"]["high_risk"] == 1
    assert len(d["security_findings"]) == 1
    # Existing scan summary must still be present and intact.
    assert "summary" in d
    assert d["summary"]["total"] == 0
    print("   ✅ to_dict() emits security_summary and security_findings.")


if __name__ == "__main__":
    print("Unified ScanReport Test Results")
    print("=" * 60)
    test_empty_report()
    test_scan_only_unchanged()
    test_security_only_counts_and_overall()
    test_severity_counts_by_level()
    test_combined_overall_takes_higher()
    test_top_priority_merges_and_sorts()
    test_to_dict_includes_security_blocks()
    print()
    print("✅ Unified report test passed.")

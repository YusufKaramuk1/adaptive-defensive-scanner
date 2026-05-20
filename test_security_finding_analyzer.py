"""
ADS – Security Finding Analyzer Test

This test verifies that analyzer/security_finding_analyzer.py correctly
analyzes Nuclei-style SecurityFinding objects.

Run:
    python test_security_finding_analyzer.py
"""

from models import SecurityFinding, SecuritySeverity, RiskLevel, PriorityLevel, ConfidenceLevel
from analyzer.security_finding_analyzer import analyze_security_findings


def make_finding(
    template_id: str,
    name: str,
    severity: SecuritySeverity,
    host: str,
    cve_ids: list | None = None,
    extracted_results: list | None = None,
    tags: list | None = None,
) -> SecurityFinding:
    return SecurityFinding(
        source_tool="nuclei",
        finding_type="http",
        template_id=template_id,
        name=name,
        severity=severity,
        host=host,
        matched_at=host,
        port=443 if host.startswith("https") else 80,
        scheme="https" if host.startswith("https") else "http",
        description=name,
        tags=tags or [],
        cve_ids=cve_ids or [],
        matcher_name="test-matcher",
        extracted_results=extracted_results or [],
    )


def test_security_finding_analyzer():
    findings = [
        make_finding(
            template_id="apache-path-traversal",
            name="Apache Path Traversal and File Disclosure",
            severity=SecuritySeverity.CRITICAL,
            host="http://admin.example.com:8080",
            cve_ids=["CVE-2021-41773"],
            extracted_results=["root:x:0:0:root:/root:/bin/bash"],
            tags=["cve", "apache", "lfi"],
        ),
        make_finding(
            template_id="exposed-panel",
            name="Exposed Admin Panel",
            severity=SecuritySeverity.MEDIUM,
            host="https://panel.example.com",
            tags=["panel", "admin", "login"],
        ),
        make_finding(
            template_id="tech-detect",
            name="Technology Detection",
            severity=SecuritySeverity.INFO,
            host="https://www.example.com",
            tags=["tech"],
        ),
    ]

    analyzed = analyze_security_findings(
        findings=findings,
        environment="external",
        criticality="high",
    )

    print("Security Finding Analyzer Test Results")
    print("=" * 65)

    print(f"Analyzed finding count: {len(analyzed)} (expected: 3)")
    assert len(analyzed) == 3

    critical = next(item for item in analyzed if item.template_id == "apache-path-traversal")

    assert critical.risk == RiskLevel.HIGH
    assert critical.priority == PriorityLevel.CRITICAL
    assert critical.confidence == ConfidenceLevel.HIGH
    assert critical.final_score == 5
    assert "CVE-2021-41773" in critical.cve_ids
    assert critical.quick_fix
    assert critical.proper_fix

    print("   ✅ Critical Nuclei CVE finding analyzed as HIGH risk / CRITICAL priority.")

    panel = next(item for item in analyzed if item.template_id == "exposed-panel")

    assert panel.risk == RiskLevel.HIGH
    assert panel.priority == PriorityLevel.HIGH
    assert panel.confidence == ConfidenceLevel.MEDIUM
    assert panel.final_score == 5

    print("   ✅ Medium exposed panel finding elevated correctly in external/high context.")

    info = next(item for item in analyzed if item.template_id == "tech-detect")

    assert info.risk == RiskLevel.LOW
    assert info.priority == PriorityLevel.LOW
    assert info.confidence == ConfidenceLevel.LOW

    print("   ✅ Informational finding remains LOW priority.")

    assert analyzed[0].priority == PriorityLevel.CRITICAL

    print("   ✅ Findings are sorted by priority and score.")

    print("\n✅ Security finding analyzer test passed.")


if __name__ == "__main__":
    test_security_finding_analyzer()
"""
ADS – Priority Engine Test

This test verifies that recommender/priority_engine.py assigns
the expected priority levels for representative findings.

Run:
    python test_priority.py
"""

from models import AnalyzedFinding, RiskLevel, ConfidenceLevel, PriorityLevel
from recommender.priority_engine import calculate_priority


def make_finding(
    service: str,
    port: int,
    risk: RiskLevel,
    confidence: ConfidenceLevel,
    final_score: int,
    category: str,
    expected_exposure: str,
    cves: list | None = None,
) -> AnalyzedFinding:
    return AnalyzedFinding(
        host="127.0.0.1",
        port=port,
        service=service,
        protocol="tcp",
        risk=risk,
        confidence=confidence,
        final_score=final_score,
        category=category,
        expected_exposure=expected_exposure,
        cves=cves or [],
    )


def run_case(
    label: str,
    finding: AnalyzedFinding,
    environment: str,
    criticality: str,
    expected: PriorityLevel,
) -> None:
    result = calculate_priority(finding, environment, criticality)

    status = "✅" if result == expected else "❌"

    print(f"{status} {label:<55} → {result.value.upper():<10} (expected: {expected.value.upper()})")

    assert result == expected


def test_priority_engine():
    high_conf_cve = [
        {
            "cve_id": "CVE-TEST-0001",
            "description": "Test CVE",
            "cvss_score": 9.8,
            "url": "https://example.com",
            "match_type": "version",
        }
    ]

    cases = [
        (
            "External SMB + version CVE (HIGH confidence)",
            make_finding(
                service="microsoft-ds",
                port=445,
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                final_score=5,
                category="file_sharing",
                expected_exposure="internal_only",
                cves=high_conf_cve,
            ),
            "external",
            "high",
            PriorityLevel.CRITICAL,
        ),
        (
            "Internal SSH + version CVE (HIGH confidence)",
            make_finding(
                service="ssh",
                port=22,
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                final_score=5,
                category="remote_admin",
                expected_exposure="restricted_admin_only",
                cves=high_conf_cve,
            ),
            "internal",
            "medium",
            PriorityLevel.CRITICAL,
        ),
        (
            "Internal web, low confidence, port-only",
            make_finding(
                service="http",
                port=80,
                risk=RiskLevel.MEDIUM,
                confidence=ConfidenceLevel.LOW,
                final_score=3,
                category="web",
                expected_exposure="public_allowed",
                cves=[],
            ),
            "internal",
            "medium",
            PriorityLevel.MEDIUM,
        ),
        (
            "External Telnet (HIGH confidence)",
            make_finding(
                service="telnet",
                port=23,
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                final_score=5,
                category="legacy_remote",
                expected_exposure="should_not_be_exposed",
                cves=[],
            ),
            "external",
            "high",
            PriorityLevel.CRITICAL,
        ),
        (
            "External Redis + version CVE (HIGH confidence)",
            make_finding(
                service="redis",
                port=6379,
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                final_score=5,
                category="database",
                expected_exposure="should_not_be_exposed",
                cves=high_conf_cve,
            ),
            "external",
            "medium",
            PriorityLevel.CRITICAL,
        ),
        (
            "Internal dev port, low risk",
            make_finding(
                service="unknown",
                port=3000,
                risk=RiskLevel.LOW,
                confidence=ConfidenceLevel.LOW,
                final_score=2,
                category="unknown",
                expected_exposure="internal_or_dev",
                cves=[],
            ),
            "internal",
            "low",
            PriorityLevel.LOW,
        ),
        (
            "Internal HTTPS + version CVE (HIGH confidence, high criticality)",
            make_finding(
                service="https",
                port=443,
                risk=RiskLevel.HIGH,
                confidence=ConfidenceLevel.HIGH,
                final_score=5,
                category="web",
                expected_exposure="public_allowed",
                cves=high_conf_cve,
            ),
            "internal",
            "high",
            PriorityLevel.CRITICAL,
        ),
    ]

    for label, finding, environment, criticality, expected in cases:
        run_case(label, finding, environment, criticality, expected)

    print("\n✅ Priority engine test passed.")


if __name__ == "__main__":
    test_priority_engine()
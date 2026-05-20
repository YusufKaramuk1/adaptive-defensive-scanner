"""
ADS – Security Finding Analyzer

Analyzes SecurityFinding objects produced by tools like Nuclei.

This layer is separate from the port/service risk mapper because Nuclei
usually reports direct vulnerability or misconfiguration findings rather than
only open ports or service fingerprints.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    SecurityFinding,
    AnalyzedSecurityFinding,
    SecuritySeverity,
    RiskLevel,
    PriorityLevel,
    ConfidenceLevel,
)


_SEVERITY_BASE_SCORE = {
    SecuritySeverity.CRITICAL: 5,
    SecuritySeverity.HIGH: 4,
    SecuritySeverity.MEDIUM: 3,
    SecuritySeverity.LOW: 2,
    SecuritySeverity.INFO: 1,
    SecuritySeverity.UNKNOWN: 2,
}


def _score_to_risk(score: int) -> RiskLevel:
    if score >= 5:
        return RiskLevel.HIGH

    if score >= 3:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def _calculate_base_score(finding: SecurityFinding) -> int:
    return _SEVERITY_BASE_SCORE.get(finding.severity, 2)


def _apply_context(
    score: int,
    finding: SecurityFinding,
    environment: str,
    criticality: str,
) -> int:
    severity = finding.severity

    if environment == "external":
        if severity in {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH, SecuritySeverity.MEDIUM}:
            score += 1

    elif environment == "production":
        if severity in {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH, SecuritySeverity.MEDIUM}:
            score += 1

    if criticality == "high":
        if severity != SecuritySeverity.INFO:
            score += 1
    elif criticality == "low":
        if severity in {SecuritySeverity.LOW, SecuritySeverity.INFO, SecuritySeverity.UNKNOWN}:
            score -= 1

    if finding.cve_ids and severity in {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH, SecuritySeverity.MEDIUM}:
        score += 1

    if finding.extracted_results and severity != SecuritySeverity.INFO:
        score += 1

    return max(1, min(score, 5))


def _calculate_priority(
    finding: SecurityFinding,
    risk: RiskLevel,
    environment: str,
    criticality: str,
) -> PriorityLevel:
    severity = finding.severity
    has_cve = bool(finding.cve_ids)
    has_extracted_evidence = bool(finding.extracted_results)

    if severity == SecuritySeverity.CRITICAL:
        return PriorityLevel.CRITICAL

    if severity == SecuritySeverity.HIGH:
        if environment in {"external", "production"} or criticality == "high" or has_cve:
            return PriorityLevel.CRITICAL
        return PriorityLevel.HIGH

    if severity == SecuritySeverity.MEDIUM:
        if environment == "external" and (criticality == "high" or has_cve or has_extracted_evidence):
            return PriorityLevel.HIGH
        if environment == "production" and criticality != "low":
            return PriorityLevel.HIGH
        return PriorityLevel.MEDIUM

    if severity == SecuritySeverity.LOW:
        if environment == "external" and criticality == "high":
            return PriorityLevel.MEDIUM
        return PriorityLevel.LOW

    if severity == SecuritySeverity.INFO:
        return PriorityLevel.LOW

    if risk == RiskLevel.HIGH:
        return PriorityLevel.HIGH

    if risk == RiskLevel.MEDIUM:
        return PriorityLevel.MEDIUM

    return PriorityLevel.LOW


def _calculate_confidence(finding: SecurityFinding) -> ConfidenceLevel:
    """
    Confidence means how actionable/reliable the security impact is.

    Informational findings are intentionally kept LOW confidence because they
    usually represent inventory or technology-detection context, not validated
    exploitable weakness.
    """
    if finding.severity == SecuritySeverity.INFO:
        return ConfidenceLevel.LOW

    if finding.severity in {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH} and finding.extracted_results:
        return ConfidenceLevel.HIGH

    if finding.cve_ids:
        return ConfidenceLevel.HIGH

    if finding.matcher_name or finding.matched_at:
        return ConfidenceLevel.MEDIUM

    if finding.severity == SecuritySeverity.LOW:
        return ConfidenceLevel.LOW

    return ConfidenceLevel.MEDIUM


def _build_evidence(finding: SecurityFinding) -> list[str]:
    evidence = []

    if finding.source_tool:
        evidence.append(f"Source tool: {finding.source_tool}")

    if finding.template_id:
        evidence.append(f"Template ID: {finding.template_id}")

    if finding.name:
        evidence.append(f"Finding name: {finding.name}")

    if finding.severity:
        evidence.append(f"Nuclei severity: {finding.severity.value}")

    if finding.matched_at:
        evidence.append(f"Matched at: {finding.matched_at}")

    if finding.matcher_name:
        evidence.append(f"Matcher: {finding.matcher_name}")

    if finding.cve_ids:
        evidence.append(f"CVE IDs: {', '.join(finding.cve_ids)}")

    if finding.extracted_results:
        preview = "; ".join(str(item) for item in finding.extracted_results[:2])
        evidence.append(f"Extracted result evidence: {preview}")

    if finding.tags:
        evidence.append(f"Tags: {', '.join(str(tag) for tag in finding.tags[:6])}")

    return evidence


def _build_reason(
    finding: SecurityFinding,
    environment: str,
    criticality: str,
) -> str:
    parts = [
        f"Nuclei reported a {finding.severity.value.upper()} severity finding.",
    ]

    if finding.name:
        parts.append(f"Finding: {finding.name}")

    if finding.template_id:
        parts.append(f"Template: {finding.template_id}")

    if finding.cve_ids:
        parts.append(f"Related CVE(s): {', '.join(finding.cve_ids)}")

    if finding.matched_at:
        parts.append(f"Matched at: {finding.matched_at}")

    if environment == "external":
        parts.append("The affected target is evaluated in an external exposure context.")
    elif environment == "production":
        parts.append("The affected target is evaluated in a production context.")
    else:
        parts.append("The affected target is evaluated in an internal context.")

    if criticality == "high":
        parts.append("High asset criticality increases remediation urgency.")
    elif criticality == "low":
        parts.append("Low asset criticality reduces expected business impact.")

    if finding.extracted_results and finding.severity != SecuritySeverity.INFO:
        parts.append("The finding includes extracted evidence, increasing confidence.")

    return " | ".join(parts)


def _build_quick_fix(finding: SecurityFinding) -> str:
    if finding.severity in {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH}:
        return (
            "Restrict external access immediately, validate exploitability, "
            "and apply the vendor-recommended patch or configuration change."
        )

    if finding.severity == SecuritySeverity.MEDIUM:
        return (
            "Review exposure, validate whether the finding is reachable by unauthorized users, "
            "and apply the recommended configuration hardening."
        )

    if finding.severity == SecuritySeverity.LOW:
        return "Review the finding and fix it during the next regular hardening cycle."

    if finding.severity == SecuritySeverity.INFO:
        return "Use this finding as inventory/context information."

    return "Review the finding manually and determine the appropriate remediation action."


def _build_proper_fix(finding: SecurityFinding) -> str:
    if finding.cve_ids:
        return (
            "Track the affected asset, verify the vulnerable component/version, "
            "apply the official security update, and confirm remediation with a follow-up scan."
        )

    if "panel" in " ".join(str(tag).lower() for tag in finding.tags):
        return (
            "Move administrative interfaces behind VPN, SSO, IP allowlisting, "
            "and strong authentication controls."
        )

    if finding.severity == SecuritySeverity.INFO:
        return (
            "Keep this finding as asset inventory context and correlate it with "
            "higher-severity findings when available."
        )

    return (
        "Document ownership, validate the finding with the application/system owner, "
        "apply a permanent configuration or patch-level fix, and monitor for recurrence."
    )


def analyze_security_findings(
    findings: list[SecurityFinding],
    environment: str,
    criticality: str,
) -> list[AnalyzedSecurityFinding]:
    analyzed_findings: list[AnalyzedSecurityFinding] = []

    for finding in findings:
        base_score = _calculate_base_score(finding)
        final_score = _apply_context(base_score, finding, environment, criticality)
        risk = _score_to_risk(final_score)
        priority = _calculate_priority(finding, risk, environment, criticality)
        confidence = _calculate_confidence(finding)

        analyzed = AnalyzedSecurityFinding(
            source_tool=finding.source_tool,
            finding_type=finding.finding_type,
            template_id=finding.template_id,
            name=finding.name,
            severity=finding.severity,
            host=finding.host,
            matched_at=finding.matched_at,
            ip=finding.ip,
            port=finding.port,
            scheme=finding.scheme,
            description=finding.description,
            tags=finding.tags,
            references=finding.references,
            cve_ids=finding.cve_ids,
            matcher_name=finding.matcher_name,
            extracted_results=finding.extracted_results,
            curl_command=finding.curl_command,
            base_score=base_score,
            final_score=final_score,
            risk=risk,
            priority=priority,
            confidence=confidence,
            reason=_build_reason(finding, environment, criticality),
            evidence=_build_evidence(finding),
            quick_fix=_build_quick_fix(finding),
            proper_fix=_build_proper_fix(finding),
            raw=finding.raw,
        )

        analyzed_findings.append(analyzed)

    priority_order = {
        PriorityLevel.CRITICAL: 0,
        PriorityLevel.HIGH: 1,
        PriorityLevel.MEDIUM: 2,
        PriorityLevel.LOW: 3,
    }

    return sorted(
        analyzed_findings,
        key=lambda item: (
            priority_order.get(item.priority, 99),
            -item.final_score,
            item.template_id,
        ),
    )
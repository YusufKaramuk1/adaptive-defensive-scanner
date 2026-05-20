"""
ADS – Risk Mapper v2.5

Combines normalized scan/import findings with contextual defensive risk analysis.

Responsibilities:
- Service classification
- Context-aware risk scoring
- CVE enrichment
- Confidence scoring
- Evidence generation
- Importer metadata-aware reasoning
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    ScanFinding,
    AnalyzedFinding,
    ServiceClassification,
    RiskLevel,
    ConfidenceLevel,
)
from knowledge_base.service_classifier import classify_service
from knowledge_base.cve_enrichment import get_cves, get_max_cvss


_EXPOSURE_BASE_SCORE: dict[str, int] = {
    "public_allowed": 2,
    "restricted_only": 3,
    "restricted_admin_only": 3,
    "internal_only": 2,
    "internal_or_dev": 2,
    "controlled": 2,
    "restricted_relay_only": 2,
    "depends_on_application": 2,
    "should_not_be_exposed": 5,
    "needs_review": 3,
}

_CATEGORY_SCORE_BOOST: dict[str, int] = {
    "file_sharing": 2,
    "remote_admin": 2,
    "legacy_remote": 3,
    "windows_mgmt": 1,
    "database": 2,
    "container_mgmt": 2,
    "file_transfer": 1,
    "web": 0,
    "app_realtime": 0,
    "mail": 1,
    "network_service": 1,
    "vpn": 0,
    "service_mesh": 1,
    "unknown": 1,
}


def _calculate_base_score(classification: ServiceClassification) -> int:
    base = _EXPOSURE_BASE_SCORE.get(classification.expected_exposure, 2)
    boost = _CATEGORY_SCORE_BOOST.get(classification.category, 0)

    return min(base + boost, 5)


def _apply_context(
    score: int,
    environment: str,
    criticality: str,
    classification: ServiceClassification,
    max_cvss: float,
) -> int:
    if environment == "external":
        if classification.expected_exposure in {
            "internal_only",
            "restricted_admin_only",
            "should_not_be_exposed",
            "internal_or_dev",
        }:
            score += 2
        else:
            score += 1

    elif environment == "production":
        score += 1

    if criticality == "high":
        score += 1
    elif criticality == "low":
        score -= 1

    if max_cvss >= 9.0:
        score += 2
    elif max_cvss >= 7.0:
        score += 1

    return max(1, min(score, 5))


def _score_to_label(score: int) -> RiskLevel:
    if score >= 5:
        return RiskLevel.HIGH

    if score >= 3:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def _metadata_evidence(finding: ScanFinding) -> list[str]:
    metadata = finding.metadata or {}
    evidence = []

    url = metadata.get("url")
    status_code = metadata.get("status_code")
    title = metadata.get("title")
    tech = metadata.get("tech")
    webserver = metadata.get("webserver")

    if url:
        evidence.append(f"URL: {url}")

    if status_code:
        evidence.append(f"HTTP status code: {status_code}")

    if title:
        lowered_title = str(title).lower()

        if any(keyword in lowered_title for keyword in ["admin", "login", "dashboard", "panel"]):
            evidence.append(f"Title indicates a possible admin/login surface: {title}")
        else:
            evidence.append(f"Title: {title}")

    if webserver:
        evidence.append(f"Web server fingerprint: {webserver}")

    if isinstance(tech, list) and tech:
        evidence.append(f"Technology fingerprint: {', '.join(str(t) for t in tech[:4])}")

    return evidence


def _gather_evidence(
    finding: ScanFinding,
    classification: ServiceClassification,
    cves: list,
) -> list[str]:
    evidence = []
    service = finding.service.lower()
    product = finding.product.lower()
    version = finding.version

    if classification.expected_exposure == "should_not_be_exposed":
        evidence.append("This service is not expected to be exposed.")
    elif classification.expected_exposure == "internal_only":
        evidence.append("This service is classified as internal-only.")

    if version:
        evidence.append(
            f"Detected version: {product} {version}"
            if product
            else f"Detected version: {version}"
        )

    if cves:
        high_cves = [c for c in cves if c.cvss_score >= 7.0]

        if high_cves:
            evidence.append(f"{len(high_cves)} critical/high CVE match(es) found.")
        else:
            evidence.append("Known low-impact CVE match(es) found.")

    if service in ["http", "https"] and classification.expected_exposure == "public_allowed":
        evidence.append("HTTP/HTTPS service; security headers and TLS posture should be validated separately.")

    if "mysql" in service or "postgres" in service or "ms-sql" in service:
        evidence.append("Database service detected; verify exposure and default-port usage.")

    evidence.extend(_metadata_evidence(finding))

    return evidence


def _calculate_confidence(
    finding: ScanFinding,
    cves: list,
    cve_match_confidence: str,
) -> ConfidenceLevel:
    has_version = bool(finding.version)
    has_product = bool(finding.product)
    has_cve = bool(cves)

    if has_cve and cve_match_confidence == "high":
        return ConfidenceLevel.HIGH

    if has_version or has_product:
        return ConfidenceLevel.MEDIUM

    if has_cve and cve_match_confidence == "low":
        return ConfidenceLevel.LOW

    if finding.metadata:
        return ConfidenceLevel.MEDIUM

    return ConfidenceLevel.LOW


def _build_reason(
    finding: ScanFinding,
    environment: str,
    criticality: str,
    classification: ServiceClassification,
    cves: list,
    max_cvss: float,
) -> str:
    parts = [
        classification.description,
        f"Category: {classification.category}",
        f"Expected exposure: {classification.expected_exposure}",
    ]

    if finding.product or finding.version:
        parts.append(f"Product/version: {finding.product} {finding.version}".strip())

    metadata = finding.metadata or {}

    if metadata.get("url"):
        parts.append(f"URL: {metadata.get('url')}")

    if metadata.get("status_code"):
        parts.append(f"HTTP status: {metadata.get('status_code')}")

    if metadata.get("title"):
        parts.append(f"Title: {metadata.get('title')}")

    if environment == "external":
        if classification.expected_exposure in {
            "internal_only",
            "restricted_admin_only",
            "should_not_be_exposed",
            "internal_or_dev",
        }:
            parts.append("This service is normally expected to stay restricted/internal but appears externally exposed.")
        else:
            parts.append("External exposure may be acceptable for this service type, but security controls should be validated.")

    elif environment == "production":
        parts.append("Production environment increases potential business impact.")

    else:
        parts.append("Internal exposure reduces public attack surface but does not remove lateral movement risk.")

    if criticality == "high":
        parts.append("High asset criticality increases potential business impact.")
    elif criticality == "low":
        parts.append("Low asset criticality limits expected business impact.")

    if cves:
        cve_ids = ", ".join(c.cve_id for c in cves[:2])
        parts.append(f"Known CVE match(es): {cve_ids} (max CVSS: {max_cvss:.1f})")

    return " | ".join(parts)


def analyze(
    findings: list[ScanFinding],
    environment: str,
    criticality: str,
) -> list[AnalyzedFinding]:
    results: list[AnalyzedFinding] = []

    for finding in findings:
        port = finding.port
        service = finding.service

        classification = classify_service(port, service)
        cves, cve_match_confidence = get_cves(
            port,
            service,
            finding.version,
            finding.product,
        )
        max_cvss = get_max_cvss(cves)

        base_score = _calculate_base_score(classification)
        final_score = _apply_context(
            base_score,
            environment,
            criticality,
            classification,
            max_cvss,
        )

        confidence = _calculate_confidence(
            finding,
            cves,
            cve_match_confidence,
        )

        evidence = _gather_evidence(
            finding,
            classification,
            cves,
        )

        analyzed = AnalyzedFinding(
            host=finding.host,
            port=port,
            service=service,
            protocol=finding.protocol,
            state=finding.state,
            product=finding.product,
            version=finding.version,
            category=classification.category,
            expected_exposure=classification.expected_exposure,
            base_score=base_score,
            final_score=final_score,
            risk=_score_to_label(final_score),
            confidence=confidence,
            reason=_build_reason(
                finding,
                environment,
                criticality,
                classification,
                cves,
                max_cvss,
            ),
            evidence=evidence,
            metadata=finding.metadata or {},
            cves=[
                {
                    "cve_id": c.cve_id,
                    "description": c.description,
                    "cvss_score": c.cvss_score,
                    "url": c.url,
                    "match_type": c.match_type,
                }
                for c in cves
            ],
        )

        results.append(analyzed)

    return sorted(results, key=lambda x: x.final_score, reverse=True)
"""
ADS – Risk Mapper v2.1 (analyzer)
Tarama bulgularını bağlamsal risk analiziyle birleştirir.
Versiyon bilgisi kullanır, confidence skoru ve kanıt üretir.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    ScanFinding, AnalyzedFinding, ServiceClassification, RiskLevel, ConfidenceLevel
)
from knowledge_base.service_classifier import classify_service
from knowledge_base.cve_enrichment import get_cves, get_max_cvss

# ─────────────────────────────────────────────
# Exposure ağırlıkları ve kategori boostları (sabit)
# ─────────────────────────────────────────────
_EXPOSURE_BASE_SCORE: dict[str, int] = {
    "public_allowed": 2, "restricted_only": 3, "restricted_admin_only": 3,
    "internal_only": 2, "internal_or_dev": 2, "controlled": 2,
    "restricted_relay_only": 2, "depends_on_application": 2,
    "should_not_be_exposed": 5, "needs_review": 3,
}
_CATEGORY_SCORE_BOOST: dict[str, int] = {
    "file_sharing": 2, "remote_admin": 2, "legacy_remote": 3,
    "windows_mgmt": 1, "database": 2, "container_mgmt": 2,
    "file_transfer": 1, "web": 0, "app_realtime": 0, "mail": 1,
    "network_service": 1, "vpn": 0, "service_mesh": 1, "unknown": 1,
}

def _calculate_base_score(classification: ServiceClassification) -> int:
    base = _EXPOSURE_BASE_SCORE.get(classification.expected_exposure, 2)
    boost = _CATEGORY_SCORE_BOOST.get(classification.category, 0)
    return min(base + boost, 5)

def _apply_context(score: int, environment: str, criticality: str,
                   classification: ServiceClassification, max_cvss: float) -> int:
    # ... (öncekiyle aynı, değişiklik yok) ...
    if environment == "external":
        if classification.expected_exposure in {"internal_only", "restricted_admin_only", "should_not_be_exposed", "internal_or_dev"}:
            score += 2
        else:
            score += 1
    elif environment == "production":
        score += 1
    if criticality == "high": score += 1
    elif criticality == "low": score -= 1
    if max_cvss >= 9.0: score += 2
    elif max_cvss >= 7.0: score += 1
    return max(1, min(score, 5))

def _score_to_label(score: int) -> RiskLevel:
    if score >= 5: return RiskLevel.HIGH
    if score >= 3: return RiskLevel.MEDIUM
    return RiskLevel.LOW

def _gather_evidence(finding: ScanFinding, classification: ServiceClassification, cves: list) -> list[str]:
    """Servis ve versiyona dayalı otomatik kanıt toplar."""
    evidence = []
    service = finding.service.lower()
    product = finding.product.lower()
    version = finding.version

    # Temel maruziyet kanıtı
    if classification.expected_exposure == "should_not_be_exposed":
        evidence.append("Servis maruziyeti asla beklenmiyor.")
    elif classification.expected_exposure == "internal_only":
        evidence.append("Servis internal olarak sınıflandırılmış.")

    # Versiyon kanıtı
    if version:
        evidence.append(f"Versiyon tespit edildi: {product} {version}" if product else f"Versiyon: {version}")

    # CVE kanıtı
    if cves:
        high_cves = [c for c in cves if c.cvss_score >= 7.0]
        if high_cves:
            evidence.append(f"{len(high_cves)} kritik/yüksek CVE bulundu.")
        else:
            evidence.append("Bilinen düşük etkili CVE'ler eşleşti.")

    # Ek kontroller (port bazlı)
    if service in ["http", "https"] and classification.expected_exposure == "public_allowed":
        evidence.append("HTTP/HTTPS servisi; güvenlik başlıkları ve TLS durumu ayrıca kontrol edilmeli.")
    if "mysql" in service or "postgres" in service or "ms-sql" in service:
        evidence.append("Veritabanı servisi; varsayılan portta çalışıyor olabilir.")

    return evidence

def _calculate_confidence(finding: ScanFinding, cves: list, classification: ServiceClassification) -> ConfidenceLevel:
    """Bilgi derinliğine göre güven seviyesini belirler."""
    has_version = bool(finding.version)
    has_product = bool(finding.product)
    has_cve = bool(cves)

    # Versiyona özel CVE eşleşmesi en yüksek güveni verir
    if has_version and has_cve:
        return ConfidenceLevel.HIGH
    # Versiyon var ama CVE yoksa veya ürün tespiti varsa orta
    if has_version or has_product:
        return ConfidenceLevel.MEDIUM
    # Sadece port açık
    return ConfidenceLevel.LOW

def _build_reason(finding: ScanFinding, environment: str, criticality: str,
                  classification: ServiceClassification, cves: list, max_cvss: float) -> str:
    # ... (önceki _build_reason ile büyük ölçüde aynı, sadece version/product bilgisi eklenecek) ...
    parts = [
        classification.description,
        f"Kategori: {classification.category}",
        f"Beklenen exposure: {classification.expected_exposure}",
    ]
    if finding.product or finding.version:
        parts.append(f"Ürün/versiyon: {finding.product} {finding.version}".strip())

    if environment == "external":
        if classification.expected_exposure in {"internal_only", "restricted_admin_only", "should_not_be_exposed", "internal_or_dev"}:
            parts.append("Bu servis normalde kısıtlı/internal kalmalıyken dışarıya açık — ciddi risk.")
        else:
            parts.append("Dış erişim bu servis türü için kabul edilebilir olabilir; ancak güvenlik kontrolleri doğrulanmalı.")
    elif environment == "production":
        parts.append("Üretim ortamı, olası iş etkisini artırır.")
    else:
        parts.append("Internal ortam genel erişimi azaltır; ancak lateral movement veya kötüye kullanım riskini ortadan kaldırmaz.")

    if criticality == "high": parts.append("Yüksek kritiklik: ele geçirilmesinin iş etkisi büyük.")
    elif criticality == "low": parts.append("Düşük kritiklik: beklenen iş etkisi sınırlı.")

    if cves:
        cve_ids = ", ".join(c.cve_id for c in cves[:2])
        parts.append(f"Bilinen CVE'ler: {cve_ids} (max CVSS: {max_cvss:.1f})")

    return " | ".join(parts)

def analyze(findings: list[ScanFinding], environment: str, criticality: str) -> list[AnalyzedFinding]:
    results: list[AnalyzedFinding] = []

    for finding in findings:
        port    = finding.port
        service = finding.service

        classification = classify_service(port, service)
        # YENİ: Versiyon ve ürün bilgisini CVE eşleşmesine dahil et
        cves     = get_cves(port, service, finding.version, finding.product)
        max_cvss = get_max_cvss(cves)

        base_score  = _calculate_base_score(classification)
        final_score = _apply_context(base_score, environment, criticality, classification, max_cvss)

        # YENİ: Confidence ve Evidence
        confidence = _calculate_confidence(finding, cves, classification)
        evidence   = _gather_evidence(finding, classification, cves)

        # risk_mapper.py içindeki analyze fonksiyonunda şu satırı güncelleyin:

        analyzed = AnalyzedFinding(
            host=finding.host,  # YENİ
            port=port,
            service=service,
            protocol=finding.protocol,
            state=finding.state,
            category=classification.category,
            expected_exposure=classification.expected_exposure,
            base_score=base_score,
            final_score=final_score,
            risk=_score_to_label(final_score),
            confidence=confidence,
            reason=_build_reason(finding, environment, criticality, classification, cves, max_cvss),
            evidence=evidence,
            cves=[{"cve_id": c.cve_id, "description": c.description, "cvss_score": c.cvss_score, "url": c.url,
                   "match_type": c.match_type} for c in cves],
        )
        results.append(analyzed)

    return sorted(results, key=lambda x: x.final_score, reverse=True)
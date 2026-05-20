"""
ADS – Priority Engine (recommender)
Risk, güven, CVE ve bağlamı birleştirerek aksiyon önceliği üretir.
Her bulgu için CRITICAL / HIGH / MEDIUM / LOW öncelik seviyesi belirler.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import AnalyzedFinding, PriorityLevel, RiskLevel, ConfidenceLevel


def _get_max_cvss(finding: AnalyzedFinding) -> float:
    """Bir bulguya ait en yüksek CVSS skorunu döner."""
    max_cvss = 0.0
    for cve in finding.cves:
        cvss = cve["cvss_score"] if isinstance(cve, dict) else cve.cvss_score
        max_cvss = max(max_cvss, cvss)
    return max_cvss


def _count_evidence(finding: AnalyzedFinding) -> float:
    """Kanıt sayısına göre bonus puan verir (0-1 arası)."""
    count = len(finding.evidence)
    if count >= 4:
        return 1.0
    elif count >= 2:
        return 0.5
    return 0.0


def calculate_priority(finding: AnalyzedFinding, environment: str, criticality: str) -> PriorityLevel:
    """
    Ağırlıklandırılmış çok boyutlu skor ile aksiyon önceliği belirle.

    Kriterler ve ağırlıkları:
      - final_score       : 0-5  → × 2.0  (maks 10 puan)
      - confidence        : LOW=1, MEDIUM=2, HIGH=3 puan
      - max_cvss          : 0-10 → × 0.5  (maks 5 puan)
      - environment       : external → +1.0, production → +0.5
      - criticality       : high → +1.0, low → -0.5
      - expected_exposure : should_not_be_exposed → +2.0
      - category boost    : legacy_remote +1.5, remote_admin/file_sharing +1.0
      - evidence count    : ≥4 → +1.0, ≥2 → +0.5

    Eşik değerleri:
      - CRITICAL: ≥ 12.0
      - HIGH    : ≥ 8.0
      - MEDIUM  : ≥ 5.0
      - LOW     : < 5.0
    """
    score = 0.0

    # 1. Temel risk skoru (0-5 → 0-10)
    score += finding.final_score * 2.0

    # 2. Güven seviyesi
    conf_map = {
        ConfidenceLevel.HIGH:   3.0,
        ConfidenceLevel.MEDIUM: 2.0,
        ConfidenceLevel.LOW:    1.0,
    }
    score += conf_map.get(finding.confidence, 1.0)

    # 3. CVSS maks skoru (0-10 → 0-5)
    max_cvss = _get_max_cvss(finding)
    score += max_cvss * 0.5

    # 4. Ortam bağlamı
    env_map = {
        "external":   1.0,
        "production": 0.5,
        "internal":   0.0,
    }
    score += env_map.get(environment, 0.0)

    # 5. Varlık kritikliği
    crit_map = {
        "high":   1.0,
        "medium": 0.0,
        "low":   -0.5,
    }
    score += crit_map.get(criticality, 0.0)

    # 6. Beklenen maruziyet (exposure)
    if finding.expected_exposure == "should_not_be_exposed":
        score += 2.0

    # 7. Kategori bonusu
    category_boost_map = {
        "legacy_remote": 1.5,
        "remote_admin":  1.0,
        "file_sharing":  1.0,
        "database":      0.5,
        "container_mgmt": 0.5,
        "windows_mgmt":  0.5,
    }
    score += category_boost_map.get(finding.category, 0.0)

    # 8. Kanıt sayısı bonusu (0-1 arası, düşürüldü)
    score += _count_evidence(finding)

    # 9. Score → PriorityLevel dönüşümü
    if score >= 12.0:
        return PriorityLevel.CRITICAL
    elif score >= 8.0:
        return PriorityLevel.HIGH
    elif score >= 5.0:
        return PriorityLevel.MEDIUM
    else:
        return PriorityLevel.LOW
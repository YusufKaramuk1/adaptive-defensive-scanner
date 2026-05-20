#!/usr/bin/env python3
"""
Priority Engine Test Scripti v2.2
Farklı senaryolarda doğru öncelik seviyesini üretip üretmediğini kontrol eder.
Host alanı artık her bulguda zorunlu.
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from models import AnalyzedFinding, ConfidenceLevel, RiskLevel, PriorityLevel
from recommender.priority_engine import calculate_priority


def test_case(name: str, finding: AnalyzedFinding, env: str, crit: str, expected: PriorityLevel):
    result = calculate_priority(finding, env, crit)
    status = "✅" if result == expected else "❌"
    print(f"{status} {name:40s} → {result.value.upper():10s} (beklenen: {expected.value.upper()})")
    if result != expected:
        print(f"   KONTROL ET: {result} != {expected}")


# ─── Test Senaryoları ────────────────────────────────────────

# 1. Dış ortamda SMB + CVE → CRITICAL
finding_smb = AnalyzedFinding(
    host="192.168.1.10",
    port=445, service="microsoft-ds", protocol="tcp", state="open",
    category="file_sharing", expected_exposure="internal_only",
    base_score=5, final_score=5, risk=RiskLevel.HIGH,
    confidence=ConfidenceLevel.HIGH,
    cves=[{"cve_id": "CVE-2020-0796", "description": "SMBGhost", "cvss_score": 10.0, "url": "", "match_type": "version"}],
    evidence=["SMBv3 açık", "Auth yok"],
    reason="SMB dışarıda"
)
test_case("Dış ortam SMB + CVE", finding_smb, "external", "high", PriorityLevel.CRITICAL)

# 2. İç ortamda SSH + kritik CVE → CRITICAL
finding_ssh = AnalyzedFinding(
    host="10.0.0.5",
    port=22, service="ssh", protocol="tcp", state="open",
    category="remote_admin", expected_exposure="restricted_admin_only",
    base_score=3, final_score=3, risk=RiskLevel.MEDIUM,
    confidence=ConfidenceLevel.MEDIUM,
    cves=[{"cve_id": "CVE-2023-38408", "description": "OpenSSH RCE", "cvss_score": 9.8, "url": "", "match_type": "version"}],
    evidence=["OpenSSH 8.2"],
    reason="SSH iç ağda"
)
test_case("İç ortam SSH + kritik CVE", finding_ssh, "internal", "medium", PriorityLevel.CRITICAL)

# 3. Web sunucusu iç ortamda güven düşük → MEDIUM
finding_web = AnalyzedFinding(
    host="10.0.0.1",
    port=80, service="http", protocol="tcp", state="open",
    category="web", expected_exposure="public_allowed",
    base_score=2, final_score=3, risk=RiskLevel.MEDIUM,
    confidence=ConfidenceLevel.LOW,
    cves=[],
    evidence=["HTTP portu"],
    reason="Web sunucusu"
)
test_case("İç ortam web düşük güven", finding_web, "internal", "low", PriorityLevel.MEDIUM)

# 4. Telnet dış ortam → CRITICAL
finding_telnet = AnalyzedFinding(
    host="203.0.113.1",
    port=23, service="telnet", protocol="tcp", state="open",
    category="legacy_remote", expected_exposure="should_not_be_exposed",
    base_score=5, final_score=5, risk=RiskLevel.HIGH,
    confidence=ConfidenceLevel.HIGH,
    cves=[],
    evidence=["Cleartext protokol"],
    reason="Telnet dışarıda"
)
test_case("Dış ortam telnet", finding_telnet, "external", "high", PriorityLevel.CRITICAL)

# 5. Dış ortamda Redis + yüksek CVE → CRITICAL
finding_redis = AnalyzedFinding(
    host="203.0.113.5",
    port=6379, service="redis", protocol="tcp", state="open",
    category="database", expected_exposure="should_not_be_exposed",
    base_score=5, final_score=5, risk=RiskLevel.HIGH,
    confidence=ConfidenceLevel.HIGH,
    cves=[{"cve_id": "CVE-2022-0543", "description": "Redis sandbox escape", "cvss_score": 10.0, "url": "", "match_type": "version"}],
    evidence=["Auth yok", "Dış erişime açık"],
    reason="Redis dışarıda"
)
test_case("Dış ortam Redis + CVE", finding_redis, "external", "high", PriorityLevel.CRITICAL)

# 6. İç ortamda düşük risk + düşük güven → LOW
finding_low = AnalyzedFinding(
    host="10.0.0.55",
    port=8080, service="http-alt", protocol="tcp", state="open",
    category="web", expected_exposure="internal_or_dev",
    base_score=2, final_score=2, risk=RiskLevel.LOW,
    confidence=ConfidenceLevel.LOW,
    cves=[],
    evidence=["Alternatif HTTP"],
    reason="Geliştirme portu"
)
test_case("İç ortam dev portu düşük risk", finding_low, "internal", "low", PriorityLevel.LOW)

# 7. İç ortam HTTPS + CVE yüksek kritik → CRITICAL
finding_web_critical = AnalyzedFinding(
    host="10.0.0.10",
    port=443, service="https", protocol="tcp", state="open",
    category="web", expected_exposure="public_allowed",
    base_score=3, final_score=3, risk=RiskLevel.MEDIUM,
    confidence=ConfidenceLevel.MEDIUM,
    cves=[{"cve_id": "CVE-2021-41773", "description": "Apache path traversal", "cvss_score": 7.5, "url": "", "match_type": "version"}],
    evidence=["Apache 2.4.49", "TLS aktif"],
    reason="HTTPS yüksek kritik asset"
)
test_case("İç ortam HTTPS + CVE yüksek kritik", finding_web_critical, "internal", "high", PriorityLevel.CRITICAL)

print("\n✅ Test tamamlandı.")
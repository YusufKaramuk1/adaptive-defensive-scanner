"""
ADS – CVE Enrichment (knowledge_base) v2.0
Servis, port, ürün VE versiyon bilgisine dayalı, yüksek doğruluklu CVE eşleştirme.
Semantik versiyon karşılaştırma ve güven skoru ile false positive'leri azaltır.
"""

import re
from models import CVEInfo
from utils.helpers import parse_version, version_in_range


# ─────────────────────────────────────────────────────────────
# Versiyon-tabanlı CVE Veritabanı
# Her CVE artık: ürün adı, versiyon kısıtı, CVSS içerir.
# ─────────────────────────────────────────────────────────────
_VERSIONED_CVE_DB: list[dict] = [
    # --- SMB ---
    {
        "cve_id": "CVE-2017-0144",
        "description": "EternalBlue — SMBv1 uzaktan kod çalıştırma.",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "product_regex": r"^(smb|microsoft-ds|windows)$",
        "version_constraint": "<2.0",    # SMBv1 etkilenir
        "affected_service": "smb",
    },
    {
        "cve_id": "CVE-2020-0796",
        "description": "SMBGhost — SMBv3 sıkıştırma açığı (wormable RCE).",
        "cvss_score": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "product_regex": r"^(smb|microsoft-ds|windows)$",
        "version_constraint": ">=3.0,<=3.1.1",
        "affected_service": "smb",
    },
    # --- OpenSSH ---
    {
        "cve_id": "CVE-2023-38408",
        "description": "OpenSSH ssh-agent remote code execution.",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        "product_regex": r"^openssh$",
        "version_constraint": ">=8.0,<9.4",
        "affected_service": "ssh",
    },
    # --- Apache HTTPD ---
    {
        "cve_id": "CVE-2021-41773",
        "description": "Apache HTTP Server path traversal ve RCE (2.4.49).",
        "cvss_score": 7.5,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        "product_regex": r"^(apache|httpd|apache http server)$",
        "version_constraint": "==2.4.49",
        "affected_service": "http",
    },
    {
        "cve_id": "CVE-2021-42013",
        "description": "Apache HTTP Server path traversal (2.4.49-2.4.50).",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        "product_regex": r"^(apache|httpd|apache http server)$",
        "version_constraint": ">=2.4.49,<=2.4.50",
        "affected_service": "http",
    },
    # --- vsftpd ---
    {
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 backdoor — uzaktan shell.",
        "cvss_score": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        "product_regex": r"^vsftpd$",
        "version_constraint": "==2.3.4",
        "affected_service": "ftp",
    },
    # --- Redis ---
    {
        "cve_id": "CVE-2022-0543",
        "description": "Redis Lua sandbox escape (Debian özelinde).",
        "cvss_score": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
        "product_regex": r"^redis$",
        "version_constraint": None,  # Debian spesifik, version check yapma
        "affected_service": "redis",
    },
    # --- ProFTPD ---
    {
        "cve_id": "CVE-2015-3306",
        "description": "ProFTPD 1.3.5 mod_copy RCE.",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
        "product_regex": r"^proftpd$",
        "version_constraint": "==1.3.5",
        "affected_service": "ftp",
    },
]

# Port tabanlı fallback veritabanı (versiyon YOKSA kullanılır, düşük güvenilirlik)
_PORT_BASED_CVE_DB: dict[int, list[CVEInfo]] = {
    445: [
        CVEInfo(cve_id="CVE-2017-0144", description="EternalBlue (port açık, versiyon bilinmiyor)", cvss_score=9.8, url="https://nvd.nist.gov/vuln/detail/CVE-2017-0144", match_type="port"),
    ],
    3389: [
        CVEInfo(cve_id="CVE-2019-0708", description="BlueKeep (port açık, versiyon bilinmiyor)", cvss_score=9.8, url="https://nvd.nist.gov/vuln/detail/CVE-2019-0708", match_type="port"),
    ],
}


def get_cves(port: int, service: str, version: str = "", product: str = "") -> tuple[list[CVEInfo], str]:
    """
    Bir servis için bilinen CVE'leri döner ve eşleşme tipini belirtir.

    Returns:
        (cve_listesi, match_confidence: "high"/"medium"/"low")
    """
    matched_cves = []
    service_lower = service.lower()
    product_lower = product.lower()
    clean_version = parse_version(version) if version else ""

    # 1. Aşama: Versiyon/Ürün bazlı yüksek doğruluklu eşleştirme
    for cve_entry in _VERSIONED_CVE_DB:
        # Servis adı kontrolü
        if cve_entry.get("affected_service") and cve_entry["affected_service"] not in service_lower:
            continue

        # Ürün adı regex kontrolü
        if "product_regex" in cve_entry:
            if not re.search(cve_entry["product_regex"], product_lower, re.IGNORECASE) and \
               not re.search(cve_entry["product_regex"], service_lower, re.IGNORECASE):
                continue

        # Versiyon kısıtı kontrolü
        if cve_entry.get("version_constraint"):
            if not clean_version:
                continue  # Versiyon yoksa version-based CVE verme
            if not version_in_range(clean_version, cve_entry["version_constraint"]):
                continue

        matched_cves.append(CVEInfo(
            cve_id=cve_entry["cve_id"],
            description=cve_entry["description"],
            cvss_score=cve_entry["cvss_score"],
            url=cve_entry["url"],
            match_type="version" if clean_version else "product"
        ))

    if matched_cves:
        return matched_cves, "high"

    # 2. Aşama: Port tabanlı düşük güvenilirlikli fallback (versiyon YOKSA)
    if port in _PORT_BASED_CVE_DB:
        return _PORT_BASED_CVE_DB[port], "low"

    return [], "none"


def get_max_cvss(cves: list[CVEInfo]) -> float:
    """CVE listesindeki en yüksek CVSS skorunu döner."""
    if not cves:
        return 0.0
    return max(c.cvss_score for c in cves)
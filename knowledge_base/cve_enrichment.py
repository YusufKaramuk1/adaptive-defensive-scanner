"""
ADS – CVE Enrichment (knowledge_base) v2.0
Servis, port VE versiyon bilgisine dayalı, yüksek doğruluklu CVE eşleştirmesi yapar.
Yanlış pozitifleri azaltmak için versiyon ve ürün eşleştirmesi zorunludur.
"""

import re
from models import CVEInfo

# ─────────────────────────────────────────────────────────────
# Version-Aware CVE Veritabanı
# Artık her CVE, hangi ürün ve versiyon aralığında geçerli olduğunu bilir.
# ─────────────────────────────────────────────────────────────
_VERSIONED_CVE_DB: list[dict] = [
    # --- SMB ---
    {
        "cve_id": "CVE-2017-0144",
        "description": "EternalBlue — SMBv1 uzaktan kod çalıştırma açığı.",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2017-0144",
        "product_regex": r"^smb$|^microsoft-ds$|^windows$",
        "version_range": ("0", "1.0"),
        "affected_service": "smb",
    },
    {
        "cve_id": "CVE-2020-0796",
        "description": "SMBGhost — SMBv3 sıkıştırma işleyicisinde buffer overflow (wormable RCE).",
        "cvss_score": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-0796",
        "product_regex": r"^smb$|^microsoft-ds$|^windows$",
        "version_range": ("3.0", "3.1.1"),
        "affected_service": "smb",
    },
    # --- OpenSSH ---
    {
        "cve_id": "CVE-2023-38408",
        "description": "OpenSSH ssh-agent remote code execution.",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        "product_regex": r"^openssh$",
        "version_regex": r"^8\.[2-6]$",  # Örnek, gerçek aralık daha geniş olabilir
        "affected_service": "ssh",
    },
    # --- Apache HTTPD ---
    {
        "cve_id": "CVE-2021-41773",
        "description": "Apache HTTP Server path traversal ve RCE (2.4.49).",
        "cvss_score": 7.5,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        "product_regex": r"^apache$|^httpd$|^apache http server$",
        "version_regex": r"^2\.4\.49$",
        "affected_service": "http",
    },
    {
        "cve_id": "CVE-2021-42013",
        "description": "Apache HTTP Server path traversal (2.4.49-2.4.50).",
        "cvss_score": 9.8,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
        "product_regex": r"^apache$|^httpd$|^apache http server$",
        "version_regex": r"^2\.4\.(49|50)$",
        "affected_service": "http",
    },
    # --- Redis ---
    {
        "cve_id": "CVE-2022-0543",
        "description": "Redis Lua sandbox escape (Debian özelinde).",
        "cvss_score": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-0543",
        "product_regex": r"^redis$",
        "version_regex": r"^.*$",  # Tüm versiyonlar etkilenmez, Debian'a özel ama flag için
        "affected_service": "redis",
    },
    # --- ProFTPD ---
    {
        "cve_id": "CVE-2011-2523",
        "description": "vsftpd 2.3.4 backdoor — uzaktan shell.",
        "cvss_score": 10.0,
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        "product_regex": r"^vsftpd$",
        "version_regex": r"^2\.3\.4$",
        "affected_service": "ftp",
    },
]

# Port tabanlı fallback veritabanı (versiyon bilgisi YOKSA kullanılır, düşük güvenilirlik)
_PORT_BASED_CVE_DB: dict[int, list[CVEInfo]] = {
    445: [
        CVEInfo(cve_id="CVE-2017-0144", description="EternalBlue (port açık, versiyon bilinmiyor)", cvss_score=9.8, url="...", match_type="service"),
    ],
    3389: [
        CVEInfo(cve_id="CVE-2019-0708", description="BlueKeep (port açık, versiyon bilinmiyor)", cvss_score=9.8, url="...", match_type="service"),
    ],
}

def _match_version(version: str, constraint: str | tuple) -> bool:
    """Basit bir versiyon eşleştirici. Regex veya tuple aralık olabilir."""
    if not version:
        return False
    if isinstance(constraint, tuple):
        # tuple: (min, max) string karşılaştırması
        return constraint[0] <= version <= constraint[1]
    elif isinstance(constraint, str):
        return bool(re.search(constraint, version, re.IGNORECASE))
    return False

def get_cves(port: int, service: str, version: str = "", product: str = "") -> list[CVEInfo]:
    """
    Bir servis için bilinen CVE'leri döner.
    Öncelik: Versiyon/Ürün eşleşmesi (YÜKSEK GÜVEN) > Port eşleşmesi (DÜŞÜK GÜVEN)
    """
    matched_cves = []
    service_lower = service.lower()
    product_lower = product.lower()
    version_str = version.strip()

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

        # Versiyon kontrolü
        if "version_regex" in cve_entry:
            if not re.search(cve_entry["version_regex"], version_str, re.IGNORECASE):
                continue
        elif "version_range" in cve_entry:
            if not _match_version(version_str, cve_entry["version_range"]):
                continue
        else:
            # Versiyon kontrolü yoksa, servis ve ürün eşleşmesi yeterli
            pass

        matched_cves.append(CVEInfo(
            cve_id=cve_entry["cve_id"],
            description=cve_entry["description"],
            cvss_score=cve_entry["cvss_score"],
            url=cve_entry["url"],
            match_type="version" if version_str else "product"
        ))

    # 2. Aşama: Port tabanlı düşük güvenilirlikli fallback (versiyon YOKSA)
    if not matched_cves and port in _PORT_BASED_CVE_DB:
        matched_cves.extend(_PORT_BASED_CVE_DB[port])

    return matched_cves

def get_max_cvss(cves: list[CVEInfo]) -> float:
    """CVE listesindeki en yüksek CVSS skorunu döner."""
    if not cves:
        return 0.0
    return max(c.cvss_score for c in cves)
"""
ADS – Fix Generator (recommender)
Her bulgu için quick fix ve proper fix önerileri üretir.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import AnalyzedFinding, Fixes


# ─────────────────────────────────────────────────────────────
# Servis bazlı fix veritabanı
# ─────────────────────────────────────────────────────────────
_FIX_DB: list[dict] = [
    # SMB / File Sharing
    {
        "match": lambda p, s, c: p in {445, 139} or "smb" in s or "microsoft-ds" in s or "netbios" in s,
        "quick": "SMB erişimini yalnızca güvenilir iç IP aralıklarıyla kısıtla; SMBv1'i derhal devre dışı bırak.",
        "proper": "SMB gerekli değilse kapat. Gerekiyorsa: VPN/segmentasyon arkasına al, SMBv2+ zorunlu kıl, "
                  "erişim denetim listelerini uygula, tüm SMB trafiğini logla ve düzenli olarak gözden geçir.",
    },
    # RDP
    {
        "match": lambda p, s, c: p == 3389 or "rdp" in s or "ms-wbt-server" in s,
        "quick": "RDP'yi internete asla açık bırakma; yalnızca VPN üzerinden veya belirli yönetici IP'lerine izin ver.",
        "proper": "RDP için: VPN + bastion host mimarisi kur, MFA zorunlu yap, NLA (Network Level Authentication) etkinleştir, "
                  "account lockout politikası uygula, RDP gateway kullan, tüm oturumları logla.",
    },
    # SSH
    {
        "match": lambda p, s, c: p == 22 or "ssh" in s,
        "quick": "SSH erişimini yalnızca gerekli IP'lerle kısıtla; parola ile girişi devre dışı bırakmayı değerlendir.",
        "proper": "SSH sertleştirme: key-based auth zorunlu yap, root login kapat, fail2ban veya rate limiting uygula, "
                  "MFA ekle, idle timeout ayarla, protokol sürümünü SSHv2'ye kısıtla, merkezi loglama kur.",
    },
    # VNC
    {
        "match": lambda p, s, c: p == 5900 or "vnc" in s,
        "quick": "VNC'yi internete asla açık bırakma; SSH tüneli veya VPN üzerinden kullan.",
        "proper": "VNC kullanımı zorunlu değilse kapat. Zorunluysa: SSH tünel zorunlu kıl, güçlü parola uygula, "
                  "IP kısıtlaması ekle, erişimi logla. Uzun vadede RDP veya SSH yönetimine geç.",
    },
    # HTTP (port 80)
    {
        "match": lambda p, s, c: p == 80 or (s == "http"),
        "quick": "HTTP'yi HTTPS'e yönlendir (301 redirect); sunucu başlıklarında versiyon bilgisini gizle.",
        "proper": "Web sertleştirme: TLS 1.2+ zorunlu kıl, HSTS ekle, WAF (Web Application Firewall) kur, "
                  "güvenli HTTP başlıkları uygula (CSP, X-Frame-Options, CORS), rate limiting ekle, düzenli DAST tara.",
    },
    # HTTPS
    {
        "match": lambda p, s, c: p == 443 or s == "https",
        "quick": "TLS sertifikasının geçerliliğini ve sürümünü kontrol et (TLS 1.2+); zayıf cipher suite'leri kapat.",
        "proper": "TLS sertleştirme: TLS 1.3 önceliklendir, HSTS + preload ekle, certificate pinning değerlendir, "
                  "WAF kur, güvenlik başlıklarını kontrol et, düzenli pentest yaptır.",
    },
    # MySQL / PostgreSQL / MSSQL / Oracle
    {
        "match": lambda p, s, c: p in {3306, 5432, 1433, 1521} or any(k in s for k in ("mysql", "postgresql", "postgres", "ms-sql", "oracle")),
        "quick": "Veritabanı portunu yalnızca uygulama sunucularına aç; genel erişimi derhal kapat.",
        "proper": "Veritabanı güvenliği: network seviyesinde firewall kısıtlaması, yalnızca uygulama kullanıcısına minimum yetki, "
                  "şifreli bağlantı (SSL/TLS) zorunlu, audit logging etkin, düzenli yedek + şifreli depolama.",
    },
    # Redis
    {
        "match": lambda p, s, c: p == 6379 or "redis" in s,
        "quick": "Redis'e dış erişimi hemen kapat; auth şifresini zorunlu kıl (requirepass).",
        "proper": "Redis sertleştirme: bind 127.0.0.1, requirepass + ACL kullan, TLS etkinleştir, "
                  "tehlikeli komutları devre dışı bırak (FLUSHALL, CONFIG, DEBUG), ağ seviyesinde izole et.",
    },
    # MongoDB
    {
        "match": lambda p, s, c: p == 27017 or "mongo" in s,
        "quick": "MongoDB'ye dış erişimi derhal kapat; --auth flag ile authentication zorunlu kıl.",
        "proper": "MongoDB sertleştirme: authentication + authorization etkinleştir, TLS/SSL zorunlu kıl, "
                  "ağ seviyesinde izole et, audit logging aç, field-level encryption değerlendir.",
    },
    # Elasticsearch
    {
        "match": lambda p, s, c: p == 9200 or "elasticsearch" in s or "elastic" in s,
        "quick": "Elasticsearch'ü dış erişime kapat; X-Pack Security veya OpenSearch security aktif et.",
        "proper": "Elasticsearch sertleştirme: authentication + TLS zorunlu kıl, network firewall ile izole et, "
                  "rol tabanlı erişim kontrolü (RBAC) uygula, audit log etkin, hassas index'leri şifrele.",
    },
    # FTP
    {
        "match": lambda p, s, c: p in {21, 990} or "ftp" in s,
        "quick": "FTP kullanımını sonlandır; mümkün olan en kısa sürede SFTP veya FTPS'e geç.",
        "proper": "FTP kullanımı zorunluysa FTPS (TLS üzerinden FTP) veya SFTP'ye geç. Anonim girişi kapat, "
                  "erişimi logla, chroot ile izole et. Uzun vadede FTP'yi tamamen kaldır.",
    },
    # Telnet / Legacy
    {
        "match": lambda p, s, c: p in {23, 512, 513, 514} or "telnet" in s or "rsh" in s or "rlogin" in s,
        "quick": "Bu servisi derhal kapat — cleartext protokol, hiçbir koşulda üretime açık olmamalı.",
        "proper": "Telnet/rsh/rlogin tamamen kaldır. SSH ile değiştir. Neden hâlâ açık olduğunu araştır — "
                  "eski sistem bağımlılığı varsa migration planı oluştur.",
    },
    # MSRPC / Windows Management
    {
        "match": lambda p, s, c: p in {135, 137, 138, 593} or "msrpc" in s or "netbios" in s,
        "quick": "Windows yönetim portlarına dış erişimi kapat; yalnızca iç ağdan erişime izin ver.",
        "proper": "Windows hardening: host tabanlı firewall ile yalnızca yönetim subnet'ine aç, "
                  "gereksiz RPC endpoint'lerini devre dışı bırak, Windows Firewall politikasını GPO ile yönet.",
    },
    # SMTP
    {
        "match": lambda p, s, c: p in {25, 465, 587} or "smtp" in s,
        "quick": "Açık SMTP relay kontrolü yap; yalnızca auth edilmiş kullanıcıların mail gönderebileceğinden emin ol.",
        "proper": "Mail sertleştirme: SPF, DKIM, DMARC yapılandır, TLS zorunlu kıl, açık relay'i kapat, "
                  "gelen/giden mail'i logla, mail gateway/anti-spam uygula.",
    },
    # DNS
    {
        "match": lambda p, s, c: p == 53 or "domain" in s or "dns" in s,
        "quick": "DNS recursive resolver'ı dış IP'lere açık bırakma; yalnızca internal queryler.",
        "proper": "DNS sertleştirme: recursion'ı sadece güvenilir kaynaklara izin ver, DNSSEC etkinleştir, "
                  "rate limiting uygula, DNS logging aç, ayrı recursive ve authoritative server kullan.",
    },
    # SNMP
    {
        "match": lambda p, s, c: p in {161, 162} or "snmp" in s,
        "quick": "SNMP'yi dış erişime kapat; default community string'i ('public', 'private') derhal değiştir.",
        "proper": "SNMP sertleştirme: SNMPv3 kullan (auth + privacy), eski SNMPv1/v2c'yi kapat, "
                  "erişimi yalnızca monitoring subnet'ine izin ver, read-only community string kullan.",
    },
    # Docker
    {
        "match": lambda p, s, c: p in {2375, 2376} or "docker" in s,
        "quick": "Docker API'yi dış erişime derhal kapat — auth olmadan tam root erişimi anlamına gelir.",
        "proper": "Docker güvenliği: TCP socket yerine Unix socket kullan, TLS mutual auth zorunlu kıl, "
                  "rootless Docker değerlendir, Docker daemon'ı yalnızca gerekli kullanıcılara açık tut.",
    },
    # Kubernetes
    {
        "match": lambda p, s, c: p == 6443 or "kubernetes" in s or "k8s" in s,
        "quick": "Kubernetes API Server'a dış erişimi kısıtla; yalnızca yönetici subnet'ine izin ver.",
        "proper": "Kubernetes sertleştirme: RBAC uygula, audit logging aç, network policy ile pod izolasyonu sağla, "
                  "admission controller kullan, etcd şifrele, CIS benchmark uygula.",
    },
]

_DEFAULT_FIX = Fixes(
    quick_fix  = "Servisin gerçekten gerekli olup olmadığını doğrula; gereksizse kapat.",
    proper_fix = "Servis gerekliyse: erişim kontrolü uygula, loglama ekle, düzenli güvenlik değerlendirmesi yap.",
)


def generate_fixes(finding: AnalyzedFinding) -> Fixes:
    port    = finding.port
    service = finding.service.lower()
    risk    = finding.risk.value if hasattr(finding.risk, "value") else str(finding.risk)
    category = finding.category

    for rule in _FIX_DB:
        try:
            if rule["match"](port, service, category):
                return Fixes(
                    quick_fix  = rule["quick"],
                    proper_fix = rule["proper"],
                )
        except Exception:
            continue

    # Risk seviyesine göre genel fallback
    if risk == "high":
        return Fixes(
            quick_fix  = "Bu servise erişimi geçici olarak kısıtla veya yalnızca güvenilir kaynaklara izin ver.",
            proper_fix = "Servisin iş gerekliliğini doğrula, minimum erişim prensibine göre yeniden yapılandır ve izleme ekle.",
        )

    return _DEFAULT_FIX

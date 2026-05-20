"""
ADS – Service Classifier (knowledge_base)
Servisleri kategori, exposure beklentisi ve açıklamayla eşleştirir.
Yeni servisler buraya eklenerek kolayca genişletilebilir.
"""

from models import ServiceClassification


# ─────────────────────────────────────────────
# Servis bilgi tabanı: port → classification
# ─────────────────────────────────────────────
_PORT_MAP: dict[int, dict] = {
    # Web
    80:   {"category": "web",               "expected_exposure": "public_allowed",          "description": "HTTP — şifrelenmemiş web trafiği taşır; HTTPS'e yönlendirme önerilir."},
    443:  {"category": "web",               "expected_exposure": "public_allowed",          "description": "HTTPS — TLS ile şifrelenmiş web trafiği; standart web servisi."},
    8080: {"category": "web",               "expected_exposure": "internal_or_dev",         "description": "Alternatif HTTP portu; genellikle geliştirme/proxy ortamlarında kullanılır."},
    8443: {"category": "web",               "expected_exposure": "internal_or_dev",         "description": "Alternatif HTTPS portu; üretime açıksa dikkatli incelenmelidir."},

    # Remote Admin
    22:   {"category": "remote_admin",      "expected_exposure": "restricted_admin_only",   "description": "SSH — uzaktan yönetim için kullanılır; key tabanlı auth ve IP kısıtlaması zorunlu."},
    3389: {"category": "remote_admin",      "expected_exposure": "restricted_admin_only",   "description": "RDP — Windows uzak masaüstü; internete açık olması kritik risk oluşturur."},
    5900: {"category": "remote_admin",      "expected_exposure": "restricted_admin_only",   "description": "VNC — grafik uzak masaüstü; şifreleme zayıftır, VPN arkasında olmalı."},

    # File Sharing
    445:  {"category": "file_sharing",      "expected_exposure": "internal_only",           "description": "SMB — Windows dosya paylaşımı; EternalBlue gibi kritik açıklara tarihsel hedef."},
    139:  {"category": "file_sharing",      "expected_exposure": "internal_only",           "description": "NetBIOS — eski SMB oturumu; mümkünse devre dışı bırakılmalı."},
    2049: {"category": "file_sharing",      "expected_exposure": "internal_only",           "description": "NFS — Unix/Linux dosya paylaşımı; auth zayıflıkları varsa kritik risk."},

    # Windows Management
    135:  {"category": "windows_mgmt",      "expected_exposure": "internal_only",           "description": "MSRPC — Windows bileşen haberleşmesi; dışarıya açılması saldırı yüzeyini büyük ölçüde artırır."},
    137:  {"category": "windows_mgmt",      "expected_exposure": "internal_only",           "description": "NetBIOS Name Service — Windows isim çözümleme; dışarıya açılmamalı."},
    138:  {"category": "windows_mgmt",      "expected_exposure": "internal_only",           "description": "NetBIOS Datagram — Windows ağ servisi; external erişime kapatılmalı."},
    593:  {"category": "windows_mgmt",      "expected_exposure": "internal_only",           "description": "RPC over HTTP — bazı Windows servislerinde kullanılır; dikkatli incelenmeli."},

    # Database
    3306: {"category": "database",          "expected_exposure": "internal_only",           "description": "MySQL/MariaDB — veritabanı servisi; internete açık olması ciddi veri sızıntısı riski."},
    5432: {"category": "database",          "expected_exposure": "internal_only",           "description": "PostgreSQL — veritabanı servisi; yalnızca uygulama katmanı erişebilmeli."},
    1433: {"category": "database",          "expected_exposure": "internal_only",           "description": "MSSQL — Microsoft SQL Server; internete açık olması kritik risktir."},
    1521: {"category": "database",          "expected_exposure": "internal_only",           "description": "Oracle DB — üretim veritabanı; mutlaka iç ağda kalmalı."},
    6379: {"category": "database",          "expected_exposure": "should_not_be_exposed",   "description": "Redis — varsayılan kurulumda auth yok; internete açıksa kritik RCE/veri sızıntısı riski."},
    27017:{"category": "database",          "expected_exposure": "should_not_be_exposed",   "description": "MongoDB — auth kapalıysa tüm veriye açık erişim; dışarıya kesinlikle açılmamalı."},
    9200: {"category": "database",          "expected_exposure": "should_not_be_exposed",   "description": "Elasticsearch — auth olmadan tüm index okunabilir; internete açılmamalı."},

    # File Transfer
    21:   {"category": "file_transfer",     "expected_exposure": "restricted_only",         "description": "FTP — şifrelenmemiş dosya transferi; SFTP veya FTPS ile değiştirilmeli."},
    990:  {"category": "file_transfer",     "expected_exposure": "restricted_only",         "description": "FTPS — TLS üzerinden FTP; hâlâ SFTP tercih edilmeli."},

    # Legacy / Tehlikeli
    23:   {"category": "legacy_remote",     "expected_exposure": "should_not_be_exposed",   "description": "Telnet — cleartext protokol; kesinlikle SSH ile değiştirilmeli."},
    512:  {"category": "legacy_remote",     "expected_exposure": "should_not_be_exposed",   "description": "rexec — şifresiz remote exec; production'da bulunmamalı."},
    513:  {"category": "legacy_remote",     "expected_exposure": "should_not_be_exposed",   "description": "rlogin — şifresiz remote login; kullanımdan kaldırılmış, kapat."},
    514:  {"category": "legacy_remote",     "expected_exposure": "should_not_be_exposed",   "description": "rsh — şifresiz remote shell; kullanımdan kaldırılmış, kapat."},

    # Mail
    25:   {"category": "mail",              "expected_exposure": "restricted_relay_only",   "description": "SMTP — e-posta iletimi; açık relay olmaması kritik, SPF/DKIM/DMARC uygulanmalı."},
    465:  {"category": "mail",              "expected_exposure": "restricted_relay_only",   "description": "SMTPS — TLS üzerinden SMTP; doğru yapılandırılmalı."},
    587:  {"category": "mail",              "expected_exposure": "restricted_relay_only",   "description": "SMTP Submission — auth zorunlu; açık relay olmaması için kontrol et."},
    110:  {"category": "mail",              "expected_exposure": "internal_only",           "description": "POP3 — e-posta alma; şifrelenmemiş, IMAPS/POP3S tercih edilmeli."},
    143:  {"category": "mail",              "expected_exposure": "internal_only",           "description": "IMAP — e-posta erişimi; TLS ile korunmalı."},
    993:  {"category": "mail",              "expected_exposure": "restricted_only",         "description": "IMAPS — TLS üzerinden IMAP; kullanıcı auth politikaları gözden geçirilmeli."},

    # DNS / Network Services
    53:   {"category": "network_service",   "expected_exposure": "controlled",              "description": "DNS — name resolution; recursive açık resolver internete açılmamalı."},
    67:   {"category": "network_service",   "expected_exposure": "internal_only",           "description": "DHCP — IP dağıtımı; dışarıya açılmamalı."},
    161:  {"category": "network_service",   "expected_exposure": "internal_only",           "description": "SNMP — ağ yönetimi; community string zayıflıkları ciddi veri sızıntısına yol açar."},
    162:  {"category": "network_service",   "expected_exposure": "internal_only",           "description": "SNMP Trap — ağ olayları; dışarıya açılmamalı."},

    # Monitoring / Management
    2375: {"category": "container_mgmt",    "expected_exposure": "should_not_be_exposed",   "description": "Docker API (HTTP, auth yok) — tam container kontrolü; internete açıksa kritik RCE riski."},
    2376: {"category": "container_mgmt",    "expected_exposure": "restricted_admin_only",   "description": "Docker API (TLS) — TLS ile güvenli Docker API; yine de sadece admin erişimi olmalı."},
    6443: {"category": "container_mgmt",    "expected_exposure": "restricted_admin_only",   "description": "Kubernetes API Server — cluster yönetimi; geniş erişime açılmamalı."},
    8500: {"category": "service_mesh",      "expected_exposure": "internal_only",           "description": "Consul HTTP API — service discovery; dışarıya açık olmamalı."},
    4646: {"category": "service_mesh",      "expected_exposure": "internal_only",           "description": "Nomad HTTP API — iş scheduler; internal erişimle sınırlı olmalı."},

    # App / Realtime
    9010: {"category": "app_realtime",      "expected_exposure": "depends_on_application",  "description": "WebSocket servisi — uygulama gerçek zamanlı iletişimi; exposure uygulamaya göre değişir."},
    9000: {"category": "app_realtime",      "expected_exposure": "depends_on_application",  "description": "Uygulama portu — genellikle custom servisler; inceleme gerektirir."},

    # VPN
    1194: {"category": "vpn",              "expected_exposure": "controlled",              "description": "OpenVPN — güvenli tünel; açık olması beklenir, config sertleştirilmeli."},
    1723: {"category": "vpn",              "expected_exposure": "controlled",              "description": "PPTP — eski VPN; zayıf şifreleme, L2TP/OpenVPN ile değiştirilmeli."},
    500:  {"category": "vpn",              "expected_exposure": "controlled",              "description": "IKE/IPSec — VPN anahtar değişimi; güvenli yapılandırma kritik."},
}

_SERVICE_NAME_MAP: dict[str, dict] = {
    "http":         _PORT_MAP[80],
    "https":        _PORT_MAP[443],
    "ssh":          _PORT_MAP[22],
    "rdp":          _PORT_MAP[3389],
    "ms-wbt-server":_PORT_MAP[3389],
    "vnc":          _PORT_MAP[5900],
    "smb":          _PORT_MAP[445],
    "microsoft-ds": _PORT_MAP[445],
    "netbios-ssn":  _PORT_MAP[139],
    "msrpc":        _PORT_MAP[135],
    "mysql":        _PORT_MAP[3306],
    "postgresql":   _PORT_MAP[5432],
    "postgres":     _PORT_MAP[5432],
    "ms-sql-s":     _PORT_MAP[1433],
    "ftp":          _PORT_MAP[21],
    "telnet":       _PORT_MAP[23],
    "redis":        _PORT_MAP[6379],
    "mongodb":      _PORT_MAP[27017],
    "smtp":         _PORT_MAP[25],
    "pop3":         _PORT_MAP[110],
    "imap":         _PORT_MAP[143],
    "domain":       _PORT_MAP[53],
    "snmp":         _PORT_MAP[161],
    "docker":       _PORT_MAP[2375],
}

_UNKNOWN: dict = {
    "category":          "unknown",
    "expected_exposure": "needs_review",
    "description":       "Bilinmeyen veya sınıflandırılamamış servis — manuel doğrulama önerilir.",
}


def classify_service(port: int, service: str) -> ServiceClassification:
    """
    Port ve/veya servis adına göre sınıflandırma döner.
    Port eşleşmesi servis adı eşleşmesine göre önceliklidir.
    """
    service_lower = service.lower().strip()

    # Özel durum: tcpwrapped
    if "tcpwrapped" in service_lower:
        return ServiceClassification(
            category="unknown",
            expected_exposure="needs_review",
            description=(
                "Nmap bağlantıyı tamamlayamadı (tcpwrapped). "
                "Servis bir güvenlik duvarı, TCP wrapper veya erişim kısıtlaması arkasında olabilir. "
                "Manuel doğrulama gerekli."
            ),
        )

    # Önce port'a bak
    if port in _PORT_MAP:
        data = _PORT_MAP[port]
        return ServiceClassification(**data)

def generate_fixes(finding: dict) -> dict:
    port = finding["port"]
    service = finding["service"].lower()
    risk = finding["risk"]

    if port == 445 or "smb" in service or "microsoft-ds" in service:
        return {
            "quick_fix": "SMB erişimini sadece güvenilir internal IP aralıklarıyla sınırla.",
            "proper_fix": "SMB servisi gereksizse kapat; gerekiyorsa VPN/segmentasyon arkasına al ve erişim/loglama politikalarını sıkılaştır."
        }

    if port == 3389 or "rdp" in service:
        return {
            "quick_fix": "RDP erişimini internete açık bırakma; sadece VPN veya belirli yönetici IP’lerine izin ver.",
            "proper_fix": "RDP için VPN/bastion host, MFA, account lockout ve güçlü logging yapısı uygula."
        }

    if port == 22 or "ssh" in service:
        return {
            "quick_fix": "SSH erişimini sadece gerekli IP adresleriyle sınırla ve parola girişini kapatmayı değerlendir.",
            "proper_fix": "SSH için key-based authentication, fail2ban/rate limiting, MFA ve merkezi loglama uygula."
        }

    if port in {80, 443} or "http" in service:
        return {
            "quick_fix": "Web servisini güncel tut; gereksiz endpointleri kapat ve temel güvenlik başlıklarını kontrol et.",
            "proper_fix": "Web uygulaması için TLS hardening, WAF, güvenli header’lar, düzenli vulnerability assessment ve logging uygula."
        }

    if risk == "high":
        return {
            "quick_fix": "Bu servise erişimi geçici olarak kısıtla veya sadece güvenilir kaynaklara izin ver.",
            "proper_fix": "Servisin iş ihtiyacını doğrula, minimum erişim prensibine göre yeniden yapılandır ve izleme ekle."
        }

    return {
        "quick_fix": "Servisin gerçekten gerekli olup olmadığını doğrula.",
        "proper_fix": "Gereksiz servisleri kapat; gerekli servisler için erişim kontrolü ve loglama uygula."
    }
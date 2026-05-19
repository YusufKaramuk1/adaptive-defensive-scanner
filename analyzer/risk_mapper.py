def calculate_base_risk(port: int, service: str) -> int:
    service = service.lower()

    # High risk services
    if service in ["smb", "microsoft-ds"]:
        return 5

    if service in ["rdp", "ms-wbt-server"]:
        return 5

    if service == "telnet":
        return 5

    # Medium risk services
    if service == "ssh":
        return 3

    if service == "msrpc":
        return 3

    if service == "ftp":
        return 3

    if service in ["mysql", "postgresql", "postgres"]:
        return 3

    # Low / conditional services
    if service in ["http", "https"]:
        return 2

    if "websocket" in service:
        return 2

    # Port-based fallback
    if port in {21, 23, 445, 3389}:
        return 5

    if port in {22, 135, 3306, 5432}:
        return 3

    return 2


def apply_context(score: int, environment: str, criticality: str) -> int:
    if environment in ["external", "production"]:
        score += 1

    if criticality == "high":
        score += 1
    elif criticality == "low":
        score -= 1

    return max(1, min(score, 5))


def score_to_label(score: int) -> str:
    if score >= 5:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def build_reason(port: int, service: str, environment: str, criticality: str) -> str:
    service = service.lower()
    reasons = []

    if service in ["smb", "microsoft-ds"] or port == 445:
        reasons.append(
            "SMB servisi açık; yanlış yapılandırılırsa dosya paylaşımı, kimlik bilgisi sızıntısı ve lateral movement riski oluşturabilir"
        )

    elif service == "msrpc" or port == 135:
        reasons.append(
            "MSRPC servisi Windows iç iletişiminde kullanılır; yanlış yapılandırma durumunda keşif ve lateral movement için saldırı yüzeyini artırabilir"
        )

    elif service in ["rdp", "ms-wbt-server"] or port == 3389:
        reasons.append(
            "RDP servisi açık; brute force, credential stuffing ve yetkisiz uzaktan erişim riski oluşturabilir"
        )

    elif service == "ssh" or port == 22:
        reasons.append(
            "SSH yönetim servisi açık; erişim kontrolü ve brute force açısından izlenmelidir"
        )

    elif service == "telnet" or port == 23:
        reasons.append(
            "Telnet şifrelenmemiş uzak erişim sağlar; kullanıcı adı ve parola ağ üzerinde açık metin taşınabilir"
        )

    elif service == "ftp" or port == 21:
        reasons.append(
            "FTP servisi açık; şifrelenmemiş kimlik doğrulama ve dosya transferi riski oluşturabilir"
        )

    elif service in ["http", "https"] or port in {80, 443}:
        reasons.append(
            "Web servisi açık; uygulama katmanı güvenliği, endpointler ve güvenlik başlıkları ayrıca incelenmelidir"
        )

    elif "websocket" in service:
        reasons.append(
            "WebSocket servisi açık; gerçek zamanlı bağlantılar üzerinden uygulama katmanı riskleri oluşabilir"
        )

    else:
        reasons.append(
            f"{service} servisi açık ve saldırı yüzeyini artırabilir"
        )

    if environment == "external":
        reasons.append(
            "servis external ortamda olduğu için internet üzerinden erişim ihtimali riski artırır"
        )
    elif environment == "production":
        reasons.append(
            "servis production ortamda olduğu için iş etkisi daha yüksek olabilir"
        )
    else:
        reasons.append(
            "servis internal ortamda olduğu için risk bağlama göre daha sınırlı olabilir"
        )

    if criticality == "high":
        reasons.append(
            "asset criticality high olduğu için olası etkinin seviyesi artar"
        )
    elif criticality == "low":
        reasons.append(
            "asset criticality low olduğu için iş etkisi daha düşük kabul edilir"
        )

    return "; ".join(reasons)


def analyze(findings: list[dict], environment: str, criticality: str) -> list[dict]:
    results = []

    for finding in findings:
        base_score = calculate_base_risk(
            finding["port"],
            finding["service"]
        )

        final_score = apply_context(
            base_score,
            environment,
            criticality
        )

        results.append({
            "port": finding["port"],
            "protocol": finding.get("protocol", "tcp"),
            "service": finding["service"],
            "state": finding.get("state", "open"),
            "base_score": base_score,
            "final_score": final_score,
            "risk": score_to_label(final_score),
            "reason": build_reason(
                finding["port"],
                finding["service"],
                environment,
                criticality
            )
        })

    return results
def calculate_base_risk(port: int, service: str) -> int:
    if port in {21, 23, 445, 3389}:
        return 5
    if port in {22, 3306, 5432}:
        return 3
    if port in {80, 443}:
        return 2
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
    reasons = []

    if port in {21, 23}:
        reasons.append(f"{service} clear-text authentication risk taşıyabilir")

    elif port == 445:
        reasons.append("SMB servisi açık; yanlış yapılandırılırsa dosya paylaşımı ve lateral movement riski oluşturabilir")

    elif port == 3389:
        reasons.append("RDP servisi açık; brute force ve yetkisiz uzaktan erişim riski oluşturabilir")

    elif port == 22:
        reasons.append("SSH yönetim servisi açık; erişim kontrolü ve brute force açısından izlenmelidir")

    elif port in {80, 443}:
        reasons.append("Web servisi açık; uygulama katmanı güvenliği ayrıca incelenmelidir")

    else:
        reasons.append(f"{service} servisi açık ve saldırı yüzeyini artırabilir")

    if environment == "external":
        reasons.append("servis external ortamda olduğu için internet üzerinden erişim ihtimali riski artırır")
    elif environment == "production":
        reasons.append("servis production ortamda olduğu için iş etkisi daha yüksek olabilir")
    else:
        reasons.append("servis internal ortamda olduğu için risk bağlama göre daha sınırlı olabilir")

    if criticality == "high":
        reasons.append("asset criticality high olduğu için olası etkinin seviyesi artar")
    elif criticality == "low":
        reasons.append("asset criticality low olduğu için iş etkisi daha düşük kabul edilir")

    return "; ".join(reasons)


def analyze(findings: list[dict], environment: str, criticality: str) -> list[dict]:
    results = []

    for f in findings:
        base = calculate_base_risk(f["port"], f["service"])
        final = apply_context(base, environment, criticality)

        results.append({
            "port": f["port"],
            "service": f["service"],
            "base_score": base,
            "final_score": final,
            "risk": score_to_label(final),
            "reason": build_reason(
                f["port"],
                f["service"],
                environment,
                criticality
            )
        })

    return results
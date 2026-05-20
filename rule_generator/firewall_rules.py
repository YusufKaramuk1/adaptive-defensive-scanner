"""
ADS – Firewall Rule Generator (rule_generator)
Context-aware UFW ve iptables kuralları üretir.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import AnalyzedFinding, FirewallRules


def _make_rules(port: int, proto: str, action: str, source: str = "") -> tuple[str, str]:
    if action == "deny":
        ufw      = f"ufw deny {port}/{proto}"
        iptables = f"iptables -A INPUT -p {proto} --dport {port} -j DROP"
    elif action == "allow_all":
        ufw      = f"ufw allow {port}/{proto}"
        iptables = f"iptables -A INPUT -p {proto} --dport {port} -j ACCEPT"
    elif action == "allow_from" and source:
        ufw      = f"ufw allow from {source} to any port {port} proto {proto}"
        iptables = f"iptables -A INPUT -p {proto} -s {source} --dport {port} -j ACCEPT"
    else:
        ufw      = f"ufw allow from <trusted_ip> to any port {port} proto {proto}"
        iptables = f"iptables -A INPUT -p {proto} -s <trusted_ip> --dport {port} -j ACCEPT"

    return ufw, iptables


# Kategorilere göre kural politikaları
_POLICY: dict[str, dict] = {
    # Her ortamda izin verilir (web)
    "web_public": {
        "action": "allow_all",
        "note":   "Genel web servisi. WAF, TLS hardening, doğru auth, loglama ve düzenli güvenlik testi sağlanmalı.",
    },
    # Dışarıdan gelmemeli — engelle
    "block_external": {
        "action": "deny",
        "note":   "Dış erişim tespit edildi. Bu management/internal servisin engellenmesi önerilir.",
    },
    # Sadece yönetici IP'sine izin ver
    "admin_only": {
        "action": "allow_from",
        "source": "<admin_ip>",
        "note":   "Yalnızca onaylı yönetici IP adreslerine erişim izni ver; diğerlerini engelle.",
    },
    # İç subnet'e izin ver
    "internal_subnet": {
        "action": "allow_from",
        "source": "<internal_subnet>",
        "note":   "İç ağ servisi. Yalnızca güvenilir iç subnet'e erişim izni ver.",
    },
    # Onaylı kaynak
    "approved_source": {
        "action": "allow_from",
        "source": "<approved_source>",
        "note":   "Üretim ortamı. En az ayrıcalık ilkesiyle yalnızca onaylı kaynaklara izin ver.",
    },
    # Güvenilir IP
    "trusted_ip": {
        "action": "allow_from",
        "source": "<trusted_ip>",
        "note":   "Erişimi güvenilir kaynaklarla kısıtla; servisin gerekliliğini doğrula.",
    },
    # Hiç açık olmamalı
    "should_not_exist": {
        "action": "deny",
        "note":   "Bu servis hiçbir ortamda açık olmamalı. Derhal kapat ve nedenini araştır.",
    },
}


def generate_firewall_rules(finding: AnalyzedFinding, environment: str) -> FirewallRules:
    port     = finding.port
    proto    = finding.protocol if hasattr(finding, "protocol") else "tcp"
    service  = finding.service.lower()
    category = finding.category
    exposure = finding.expected_exposure
    risk     = finding.risk.value if hasattr(finding.risk, "value") else str(finding.risk)

    # ── Özel durumlar ──────────────────────────────────────────

    # Asla açık olmaması gerekenler
    if exposure == "should_not_be_exposed":
        policy = _POLICY["should_not_exist"]
        ufw, iptables = _make_rules(port, proto, "deny")
        return FirewallRules(ufw=ufw, iptables=iptables, note=policy["note"])

    # Düşük risk — kural gerekmeyebilir
    if risk == "low" and environment == "internal":
        return FirewallRules(
            ufw      = f"# Düşük risk — kural gerekmeyebilir; servis ihtiyacını doğrula",
            iptables = f"# Düşük risk — kural gerekmeyebilir; servis ihtiyacını doğrula",
            note     = "Düşük riskli servis. İzleme ve servis doğrulaması önerilir.",
        )

    # ── Web servisleri ─────────────────────────────────────────
    if category == "web" and exposure == "public_allowed":
        ufw, iptables = _make_rules(port, proto, "allow_all")
        return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["web_public"]["note"])

    # ── External ortam ─────────────────────────────────────────
    if environment == "external":
        if exposure in {"internal_only", "internal_or_dev", "should_not_be_exposed"}:
            ufw, iptables = _make_rules(port, proto, "deny")
            return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["block_external"]["note"])

        if exposure == "restricted_admin_only":
            ufw, iptables = _make_rules(port, proto, "allow_from", "<admin_ip>")
            return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["admin_only"]["note"])

        if category == "mail" and exposure == "restricted_relay_only":
            ufw, iptables = _make_rules(port, proto, "allow_from", "<mail_relay_ip>")
            return FirewallRules(
                ufw=ufw, iptables=iptables,
                note="Mail relay servisi. Yalnızca onaylı mail relay IP'lerine izin ver; açık relay olmamasını doğrula."
            )

        # Diğer external servisler
        ufw, iptables = _make_rules(port, proto, "allow_from", "<trusted_ip>")
        return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["trusted_ip"]["note"])

    # ── Internal ortam ─────────────────────────────────────────
    if environment == "internal":
        if exposure in {"internal_only", "restricted_only"}:
            ufw, iptables = _make_rules(port, proto, "allow_from", "<internal_subnet>")
            return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["internal_subnet"]["note"])

        if exposure == "restricted_admin_only":
            ufw, iptables = _make_rules(port, proto, "allow_from", "<admin_subnet>")
            return FirewallRules(
                ufw=ufw, iptables=iptables,
                note="Uzak yönetim servisi. Yalnızca yönetim ağlarıyla sınırlı tut."
            )

        ufw, iptables = _make_rules(port, proto, "allow_from", "<trusted_ip>")
        return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["trusted_ip"]["note"])

    # ── Production ortam ───────────────────────────────────────
    if environment == "production":
        if exposure in {"internal_only", "restricted_admin_only", "restricted_only"}:
            ufw, iptables = _make_rules(port, proto, "allow_from", "<approved_source>")
            return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["approved_source"]["note"])

        ufw, iptables = _make_rules(port, proto, "allow_from", "<approved_source>")
        return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["approved_source"]["note"])

    # ── Fallback ───────────────────────────────────────────────
    ufw, iptables = _make_rules(port, proto, "allow_from", "<trusted_ip>")
    return FirewallRules(ufw=ufw, iptables=iptables, note=_POLICY["trusted_ip"]["note"])

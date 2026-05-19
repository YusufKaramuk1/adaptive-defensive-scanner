def generate_firewall_rules(finding: dict) -> dict:
    port = finding["port"]
    protocol = finding.get("protocol", "tcp")
    service = finding["service"].lower()
    risk = finding["risk"]

    if risk == "low":
        return {
            "ufw": "No immediate firewall rule required. Review service necessity.",
            "iptables": "No immediate firewall rule required. Review service necessity."
        }

    if port == 445 or "smb" in service or "microsoft-ds" in service:
        return {
            "ufw": f"ufw deny {port}/{protocol}",
            "iptables": f"iptables -A INPUT -p {protocol} --dport {port} -j DROP"
        }

    if port == 3389 or "rdp" in service:
        return {
            "ufw": f"ufw deny {port}/{protocol}",
            "iptables": f"iptables -A INPUT -p {protocol} --dport {port} -j DROP"
        }

    if port == 22 or "ssh" in service:
        return {
            "ufw": f"ufw allow from <trusted_ip> to any port {port} proto {protocol}",
            "iptables": f"iptables -A INPUT -p {protocol} -s <trusted_ip> --dport {port} -j ACCEPT"
        }

    return {
        "ufw": f"ufw allow from <trusted_ip> to any port {port} proto {protocol}",
        "iptables": f"iptables -A INPUT -p {protocol} -s <trusted_ip> --dport {port} -j ACCEPT"
    }
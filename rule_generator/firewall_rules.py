def generate_firewall_rules(finding: dict, environment: str) -> dict:
    port = finding["port"]
    protocol = finding.get("protocol", "tcp")
    service = finding["service"].lower()
    risk = finding["risk"]

    is_smb = port == 445 or "smb" in service or "microsoft-ds" in service
    is_rdp = port == 3389 or "rdp" in service or "ms-wbt-server" in service
    is_ssh = port == 22 or "ssh" in service
    is_msrpc = port == 135 or "msrpc" in service

    # HTTP/HTTPS special case
    if service in ["http", "https"] and environment == "external":
        return {
            "ufw": f"ufw allow {port}/{protocol}",
            "iptables": f"iptables -A INPUT -p {protocol} --dport {port} -j ACCEPT",
            "note": "Public web service detected. Ensure WAF, TLS hardening, proper authentication, logging and regular security testing."
        }
    
    if risk == "low":
        return {
            "ufw": "No immediate firewall rule required. Review service necessity.",
            "iptables": "No immediate firewall rule required. Review service necessity.",
            "note": "Low risk service. Monitoring and service validation are recommended."
        }

    if environment == "external":
        if is_smb or is_rdp or is_msrpc:
            return {
                "ufw": f"ufw deny {port}/{protocol}",
                "iptables": f"iptables -A INPUT -p {protocol} --dport {port} -j DROP",
                "note": "External exposure detected. Blocking this management/internal service is recommended."
            }

        if is_ssh:
            return {
                "ufw": f"ufw allow from <trusted_admin_ip> to any port {port} proto {protocol}",
                "iptables": f"iptables -A INPUT -p {protocol} -s <trusted_admin_ip> --dport {port} -j ACCEPT",
                "note": "SSH should not be open to all sources. Restrict access to trusted admin IPs."
            }

    if environment == "internal":
        if is_smb or is_msrpc:
            return {
                "ufw": f"ufw allow from <trusted_internal_subnet> to any port {port} proto {protocol}",
                "iptables": f"iptables -A INPUT -p {protocol} -s <trusted_internal_subnet> --dport {port} -j ACCEPT",
                "note": "Internal service detected. Restrict access to trusted internal subnets instead of exposing broadly."
            }

        if is_rdp or is_ssh:
            return {
                "ufw": f"ufw allow from <admin_subnet> to any port {port} proto {protocol}",
                "iptables": f"iptables -A INPUT -p {protocol} -s <admin_subnet> --dport {port} -j ACCEPT",
                "note": "Remote administration service should be limited to admin networks."
            }

    if environment == "production":
        if is_smb or is_rdp or is_msrpc or is_ssh:
            return {
                "ufw": f"ufw allow from <approved_source> to any port {port} proto {protocol}",
                "iptables": f"iptables -A INPUT -p {protocol} -s <approved_source> --dport {port} -j ACCEPT",
                "note": "Production asset detected. Apply least-privilege access and validate business impact before changes."
            }

    return {
        "ufw": f"ufw allow from <trusted_ip> to any port {port} proto {protocol}",
        "iptables": f"iptables -A INPUT -p {protocol} -s <trusted_ip> --dport {port} -j ACCEPT",
        "note": "Restrict access to trusted sources and validate whether the service is required."
    }
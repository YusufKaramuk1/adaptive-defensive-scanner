import nmap


def run_scan(target: str) -> list[dict]:
    print(f"[Scanner] Target {target} taranıyor (Nmap)...")

    scanner = nmap.PortScanner()
    scanner.scan(hosts=target, arguments="-sV -T4")

    findings = []

    for host in scanner.all_hosts():
        tcp = scanner[host].get("tcp", {})

        for port, port_data in tcp.items():
            if port_data.get("state") == "open":
                findings.append({
                    "port": port,
                    "protocol": "tcp",
                    "service": port_data.get("name", "unknown"),
                    "state": port_data.get("state", "unknown")
                })

    return findings
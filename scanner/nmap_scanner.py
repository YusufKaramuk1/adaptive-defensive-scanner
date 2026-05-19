def run_scan(target: str) -> list[dict]:
    """
    Fake scanner (MVP için)
    Gerçek Nmap yerine test verisi döner.
    """

    print(f"[Scanner] Target {target} taranıyor...")

    findings = [
        {"port": 22, "protocol": "tcp", "service": "ssh", "state": "open"},
        {"port": 80, "protocol": "tcp", "service": "http", "state": "open"},
        {"port": 445, "protocol": "tcp", "service": "smb", "state": "open"},
    ]

    return findings
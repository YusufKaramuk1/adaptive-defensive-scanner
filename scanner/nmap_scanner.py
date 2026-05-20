"""
ADS – Nmap Scanner (scanner)
Gerçek Nmap taraması yapar ve normalize edilmiş ScanFinding listesi döner.
Nmap yoksa veya erişim reddedilirse mock veri kullanılır (--mock flag).
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ScanFinding


def _mock_findings(host_ip: str = "127.0.0.1") -> list[ScanFinding]:
    """Geliştirme/test ortamı için sahte bulgular."""
    return [
        ScanFinding(host=host_ip, port=22,    service="ssh",          protocol="tcp", state="open"),
        ScanFinding(host=host_ip, port=80,    service="http",         protocol="tcp", state="open"),
        ScanFinding(host=host_ip, port=443,   service="https",        protocol="tcp", state="open"),
        ScanFinding(host=host_ip, port=445,   service="microsoft-ds", protocol="tcp", state="open"),
        ScanFinding(host=host_ip, port=3389,  service="ms-wbt-server",protocol="tcp", state="open"),
        ScanFinding(host=host_ip, port=3306,  service="mysql",        protocol="tcp", state="open"),
        ScanFinding(host=host_ip, port=6379,  service="redis",        protocol="tcp", state="open"),
    ]


def run_scan(target: str, mock: bool = False) -> list[ScanFinding]:
    """
    Belirtilen hedefe Nmap -sV taraması yapar.
    mock=True ise gerçek tarama yapılmaz; geliştirme verisi döner.
    """
    if mock:
        print("[Scanner] Mock mod — gerçek tarama yapılmıyor.")
        return _mock_findings(host_ip=target)

    try:
        import nmap
    except ImportError:
        print("[Scanner] python-nmap bulunamadı. Mock veriye geçiliyor.")
        return _mock_findings(host_ip=target)

    print(f"[Scanner] {target} taranıyor (Nmap -sV -T4)...")

    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=target, arguments="-sV -T4 --open")
    except nmap.PortScannerError as e:
        print(f"[Scanner] Nmap hatası: {e}")
        return []
    except Exception as e:
        print(f"[Scanner] Beklenmeyen hata: {e}")
        return []

    findings: list[ScanFinding] = []

    for host in scanner.all_hosts():
        tcp_ports = scanner[host].get("tcp", {})
        for port, port_data in tcp_ports.items():
            if port_data.get("state") == "open":
                findings.append(ScanFinding(
                    host     = host,  # YENİ: IP adresi
                    port     = int(port),
                    service  = port_data.get("name", "unknown"),
                    protocol = "tcp",
                    state    = "open",
                    version  = port_data.get("version", ""),
                    product  = port_data.get("product", ""),
                ))

    print(f"[Scanner] {len(findings)} açık port bulundu.")
    return findings
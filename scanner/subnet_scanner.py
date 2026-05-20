"""
ADS – Parallel Subnet Scanner (scanner)
Bir subnet'i paralel olarak tarar ve tüm bulguları birleştirir.
"""

import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.nmap_scanner import run_scan
from models import ScanFinding
from utils.helpers import expand_subnet


def run_parallel_scan(subnet: str, max_workers: int = 10, mock: bool = False) -> list[ScanFinding]:
    """
    Subnet'i IP'lerine ayırır, her IP'yi paralel olarak tarar.

    Args:
        subnet (str): Subnet CIDR (örn: 192.168.1.0/24)
        max_workers (int): Maksimum eşzamanlı tarama sayısı
        mock (bool): Mock modda mı çalışılsın

    Returns:
        list[ScanFinding]: Tüm IP'lerden gelen bulguların birleşimi
    """
    ip_list = expand_subnet(subnet)

    if not ip_list:
        print(f"[SubnetScanner] Geçersiz veya boş subnet: {subnet}")
        return []

    print(f"[SubnetScanner] {subnet} → {len(ip_list)} IP bulundu.")
    print(f"[SubnetScanner] Paralel tarama başlıyor (max worker: {max_workers})...")

    all_findings: list[ScanFinding] = []
    completed = 0
    total = len(ip_list)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {
            executor.submit(run_scan, ip, mock): ip for ip in ip_list
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            completed += 1
            try:
                findings = future.result()
                if findings:
                    all_findings.extend(findings)
                if completed % 10 == 0 or completed == total:
                    print(f"[SubnetScanner] İlerleme: {completed}/{total} IP tarandı.")
            except Exception as e:
                print(f"[SubnetScanner] {ip} taranırken hata: {e}")

    print(f"[SubnetScanner] Paralel tarama tamamlandı. Toplam {len(all_findings)} bulgu birleştirildi.")
    return all_findings
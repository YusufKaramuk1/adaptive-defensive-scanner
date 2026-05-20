"""
ADS – Nmap XML Importer

Nmap XML çıktısını okuyup ADS'nin ortak ScanFinding modeline çevirir.

Örnek kullanım:
    python main.py --import-nmap-xml scans/nmap_result.xml --environment external --criticality high

Beklenen Nmap XML üretimi:
    nmap -sV -oX scans/nmap_result.xml 192.168.1.1
    nmap -sV -oX scans/nmap_subnet.xml 192.168.1.0/24
"""

import sys
import os
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ScanFinding


def _get_host_address(host_node: ET.Element) -> str:
    """
    Nmap host node içinden IP adresini bulur.

    Öncelik:
    1. ipv4
    2. ipv6
    3. mac
    4. ilk address
    """
    addresses = host_node.findall("address")

    if not addresses:
        return ""

    for addr in addresses:
        if addr.attrib.get("addrtype") == "ipv4":
            return addr.attrib.get("addr", "")

    for addr in addresses:
        if addr.attrib.get("addrtype") == "ipv6":
            return addr.attrib.get("addr", "")

    for addr in addresses:
        if addr.attrib.get("addrtype") == "mac":
            return addr.attrib.get("addr", "")

    return addresses[0].attrib.get("addr", "")


def _get_hostname(host_node: ET.Element) -> str:
    """Nmap XML içindeki hostname bilgisini döndürür."""
    hostnames_node = host_node.find("hostnames")

    if hostnames_node is None:
        return ""

    hostname_node = hostnames_node.find("hostname")

    if hostname_node is None:
        return ""

    return hostname_node.attrib.get("name", "")


def _is_host_up(host_node: ET.Element) -> bool:
    """Host açık mı kontrol eder."""
    status_node = host_node.find("status")

    if status_node is None:
        return True

    return status_node.attrib.get("state", "").lower() == "up"


def _parse_port(host: str, port_node: ET.Element) -> ScanFinding | None:
    """Nmap port node içinden ScanFinding üretir."""
    protocol = port_node.attrib.get("protocol", "tcp")
    port_id = port_node.attrib.get("portid", "0")

    try:
        port = int(port_id)
    except ValueError:
        return None

    state_node = port_node.find("state")
    state = "unknown"

    if state_node is not None:
        state = state_node.attrib.get("state", "unknown")

    # ADS şu an sadece açık portları analiz ediyor.
    if state.lower() != "open":
        return None

    service_node = port_node.find("service")

    service = "unknown"
    product = ""
    version = ""

    if service_node is not None:
        service = service_node.attrib.get("name", "unknown")
        product = service_node.attrib.get("product", "")
        version = service_node.attrib.get("version", "")

        # Bazı Nmap çıktılarında versiyon parçalı gelebiliyor.
        extrainfo = service_node.attrib.get("extrainfo", "")
        if not version and extrainfo:
            version = extrainfo

    return ScanFinding(
        host=host,
        port=port,
        protocol=protocol,
        service=service,
        state=state,
        product=product,
        version=version,
    )


def import_nmap_xml(xml_path: str) -> list[ScanFinding]:
    """
    Nmap XML dosyasını okuyup ScanFinding listesi döndürür.

    Args:
        xml_path: Nmap XML dosya yolu

    Returns:
        list[ScanFinding]
    """
    path = Path(xml_path)

    if not path.exists():
        raise FileNotFoundError(f"Nmap XML file not found: {xml_path}")

    if path.is_dir():
        raise IsADirectoryError(f"Expected an Nmap XML file but got a directory: {xml_path}")

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Invalid Nmap XML file: {xml_path} ({e})")
    except UnicodeDecodeError as e:
        raise ValueError(f"Nmap XML file is not valid UTF-8 / ASCII: {xml_path} ({e})")
    except PermissionError as e:
        raise PermissionError(f"Permission denied reading Nmap XML file: {xml_path} ({e})")

    findings: list[ScanFinding] = []

    for host_node in root.findall("host"):
        if not _is_host_up(host_node):
            continue

        host_addr = _get_host_address(host_node)
        hostname = _get_hostname(host_node)

        host = host_addr or hostname

        if not host:
            continue

        ports_node = host_node.find("ports")

        if ports_node is None:
            continue

        for port_node in ports_node.findall("port"):
            finding = _parse_port(host, port_node)

            if finding is not None:
                findings.append(finding)

    return findings


def infer_target_label_from_findings(findings: list[ScanFinding], source_path: str) -> str:
    """
    Import edilen bulgulardan rapor target label üretir.

    Tek host varsa:
        192.168.1.1

    Birkaç host varsa:
        192.168.1.1, 192.168.1.2

    Çok host varsa:
        nmap_xml:result.xml (12 hosts)
    """
    hosts = sorted({f.host for f in findings if f.host})

    if not hosts:
        return f"nmap_xml:{Path(source_path).name}"

    if len(hosts) <= 3:
        return ", ".join(hosts)

    return f"nmap_xml:{Path(source_path).name} ({len(hosts)} hosts)"
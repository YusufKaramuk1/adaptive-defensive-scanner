"""
ADS – Nmap XML Importer Test

This test verifies that integrations/nmap_xml_importer.py
correctly converts Nmap XML output into ScanFinding objects.

Run:
    python test_nmap_xml_importer.py
"""

from pathlib import Path

from integrations.nmap_xml_importer import (
    import_nmap_xml,
    infer_target_label_from_findings,
)


TEST_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX test.xml 127.0.0.1">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="localhost" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Microsoft IIS httpd" version="10.0"/>
      </port>

      <port protocol="tcp" portid="135">
        <state state="open" reason="syn-ack"/>
        <service name="msrpc" product="Microsoft Windows RPC"/>
      </port>

      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds"/>
      </port>

      <port protocol="tcp" portid="3389">
        <state state="closed" reason="reset"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def write_test_xml() -> Path:
    """Create a temporary XML test file."""
    test_dir = Path("test_data")
    test_dir.mkdir(exist_ok=True)

    xml_path = test_dir / "nmap_import_test.xml"
    xml_path.write_text(TEST_XML, encoding="utf-8")

    return xml_path


def test_nmap_xml_importer():
    xml_path = write_test_xml()

    findings = import_nmap_xml(str(xml_path))

    print("Nmap XML Importer Test Results")
    print("=" * 55)

    print(f"Imported open port count: {len(findings)} (expected: 3)")
    assert len(findings) == 3

    ports = sorted([f.port for f in findings])
    print(f"Ports: {ports} (expected: [80, 135, 445])")
    assert ports == [80, 135, 445]

    assert 3389 not in ports
    print("   ✅ Closed port was ignored correctly.")

    http = next(f for f in findings if f.port == 80)
    assert http.host == "127.0.0.1"
    assert http.protocol == "tcp"
    assert http.service == "http"
    assert http.product == "Microsoft IIS httpd"
    assert http.version == "10.0"

    print("   ✅ HTTP service/product/version parsed correctly.")

    msrpc = next(f for f in findings if f.port == 135)
    assert msrpc.service == "msrpc"
    assert msrpc.product == "Microsoft Windows RPC"

    print("   ✅ MSRPC product parsed correctly.")

    smb = next(f for f in findings if f.port == 445)
    assert smb.service == "microsoft-ds"
    assert smb.product == ""
    assert smb.version == ""

    print("   ✅ SMB imported correctly with empty product/version fields.")

    target_label = infer_target_label_from_findings(findings, str(xml_path))
    print(f"Target label: {target_label} (expected: 127.0.0.1)")
    assert target_label == "127.0.0.1"

    print("\n✅ Nmap XML importer test passed.")


if __name__ == "__main__":
    test_nmap_xml_importer()
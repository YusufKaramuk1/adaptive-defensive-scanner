"""
ADS – httpx / Osmedeus JSONL Importer Test

This test verifies that integrations/osmedeus_httpx_importer.py
correctly converts httpx / Osmedeus JSONL output into ScanFinding objects.

Run:
    python test_httpx_jsonl_importer.py
"""

from pathlib import Path

from integrations.osmedeus_httpx_importer import (
    import_httpx_jsonl,
    infer_target_label_from_httpx_findings,
)


TEST_JSONL = """
{"url":"https://example.com","host":"example.com","port":443,"scheme":"https","status-code":200,"title":"Example Domain","webserver":"nginx/1.18.0","tech":["Nginx"]}
{"url":"http://admin.example.com:8080","status_code":200,"title":"Admin Login","webserver":"Apache/2.4.49","tech":["Apache HTTP Server"]}
{"input":"dev.example.com","scheme":"http","port":80,"status-code":403,"title":"Forbidden","tech":["IIS"]}
{"url":"https://bad-json.example.com","port":443
{"url":"https://cloud.example.com","webserver":"cloudflare","status-code":200}
"""


def write_test_jsonl() -> Path:
    """Create a temporary JSONL test file."""
    test_dir = Path("test_data")
    test_dir.mkdir(exist_ok=True)

    jsonl_path = test_dir / "httpx_import_test.jsonl"
    jsonl_path.write_text(TEST_JSONL.strip() + "\n", encoding="utf-8")

    return jsonl_path


def test_httpx_jsonl_importer():
    jsonl_path = write_test_jsonl()

    findings = import_httpx_jsonl(str(jsonl_path))

    print("httpx JSONL Importer Test Results")
    print("=" * 60)

    print(f"Imported finding count: {len(findings)} (expected: 4)")
    assert len(findings) == 4

    ports = sorted([f.port for f in findings])
    print(f"Ports: {ports} (expected: [80, 443, 443, 8080])")
    assert ports == [80, 443, 443, 8080]

    example = next(f for f in findings if f.host == "example.com")
    assert example.service == "https"
    assert example.port == 443
    assert example.product == "nginx"
    assert example.version == "1.18.0"
    assert example.metadata["url"] == "https://example.com"
    assert example.metadata["status_code"] == 200
    assert example.metadata["title"] == "Example Domain"
    assert example.metadata["webserver"] == "nginx/1.18.0"
    assert example.metadata["tech"] == ["Nginx"]

    print("   ✅ example.com nginx/1.18.0 + metadata parsed correctly.")

    admin = next(f for f in findings if f.host == "admin.example.com")
    assert admin.service == "http"
    assert admin.port == 8080
    assert admin.product == "Apache"
    assert admin.version == "2.4.49"
    assert admin.metadata["url"] == "http://admin.example.com:8080"
    assert admin.metadata["status_code"] == 200
    assert admin.metadata["title"] == "Admin Login"

    print("   ✅ admin.example.com Apache/2.4.49 + title parsed correctly.")

    dev = next(f for f in findings if f.host == "dev.example.com")
    assert dev.service == "http"
    assert dev.port == 80
    assert dev.product == "IIS"
    assert dev.version == ""
    assert dev.metadata["status_code"] == 403
    assert dev.metadata["title"] == "Forbidden"
    assert dev.metadata["tech"] == ["IIS"]

    print("   ✅ input/scheme/tech fallback + metadata works correctly.")

    cloud = next(f for f in findings if f.host == "cloud.example.com")
    assert cloud.service == "https"
    assert cloud.port == 443
    assert cloud.product == "cloudflare"
    assert cloud.metadata["webserver"] == "cloudflare"
    assert cloud.metadata["status_code"] == 200

    print("   ✅ port/scheme inference from URL works correctly.")

    target_label = infer_target_label_from_httpx_findings(findings, str(jsonl_path))
    print(f"Target label: {target_label}")

    assert target_label == "httpx:httpx_import_test.jsonl (4 hosts)"

    print("\n✅ httpx JSONL importer test passed.")


if __name__ == "__main__":
    test_httpx_jsonl_importer()
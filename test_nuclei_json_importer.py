"""
ADS – Nuclei JSON / JSONL Importer Test

This test verifies that integrations/nuclei_json_importer.py correctly
converts Nuclei JSONL output into SecurityFinding objects.

Run:
    python test_nuclei_json_importer.py
"""

from pathlib import Path

from integrations.nuclei_json_importer import (
    import_nuclei_json,
    infer_target_label_from_nuclei_findings,
)
from models import SecuritySeverity


TEST_JSONL = """
{"template-id":"apache-path-traversal","info":{"name":"Apache Path Traversal and File Disclosure","severity":"critical","description":"Apache 2.4.49 path traversal vulnerability.","tags":["cve","apache","lfi"],"classification":{"cve-id":["CVE-2021-41773"]},"reference":["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]},"type":"http","host":"http://admin.example.com:8080","matched-at":"http://admin.example.com:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd","ip":"10.0.0.10","port":"8080","scheme":"http","matcher-name":"status-200","extracted-results":["root:x:0:0:root:/root:/bin/bash"],"curl-command":"curl -s http://admin.example.com:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"}
{"template-id":"exposed-panel","info":{"name":"Exposed Admin Panel","severity":"medium","description":"An exposed administrative panel was detected.","tags":"panel,admin,login","reference":"https://example.com/reference"},"type":"http","host":"https://panel.example.com","matched-at":"https://panel.example.com/login","ip":"10.0.0.11","port":443,"scheme":"https","matcher-name":"word-login"}
{"template-id":"tech-detect","info":{"name":"Technology Detection","severity":"info","tags":["tech"]},"type":"http","host":"https://www.example.com","matched-at":"https://www.example.com","scheme":"https"}
{"template-id":"bad-json","info":{"name":"Broken"
"""


def write_test_jsonl() -> Path:
    test_dir = Path("test_data")
    test_dir.mkdir(exist_ok=True)

    jsonl_path = test_dir / "nuclei_import_test.jsonl"
    jsonl_path.write_text(TEST_JSONL.strip() + "\n", encoding="utf-8")

    return jsonl_path


def test_nuclei_json_importer():
    jsonl_path = write_test_jsonl()

    findings = import_nuclei_json(str(jsonl_path))

    print("Nuclei JSON Importer Test Results")
    print("=" * 60)

    print(f"Imported security finding count: {len(findings)} (expected: 3)")
    assert len(findings) == 3

    critical = next(f for f in findings if f.template_id == "apache-path-traversal")

    assert critical.source_tool == "nuclei"
    assert critical.finding_type == "http"
    assert critical.name == "Apache Path Traversal and File Disclosure"
    assert critical.severity == SecuritySeverity.CRITICAL
    assert critical.host == "http://admin.example.com:8080"
    assert critical.port == 8080
    assert critical.scheme == "http"
    assert critical.matcher_name == "status-200"
    assert critical.cve_ids == ["CVE-2021-41773"]
    assert "root:x:0:0:root:/root:/bin/bash" in critical.extracted_results

    print("   ✅ Critical Apache CVE finding parsed correctly.")

    panel = next(f for f in findings if f.template_id == "exposed-panel")

    assert panel.severity == SecuritySeverity.MEDIUM
    assert panel.host == "https://panel.example.com"
    assert panel.port == 443
    assert panel.tags == ["panel", "admin", "login"]
    assert panel.references == ["https://example.com/reference"]

    print("   ✅ Exposed panel finding parsed correctly.")

    info = next(f for f in findings if f.template_id == "tech-detect")

    assert info.severity == SecuritySeverity.INFO
    assert info.host == "https://www.example.com"
    assert info.tags == ["tech"]

    print("   ✅ Informational finding parsed correctly.")

    target_label = infer_target_label_from_nuclei_findings(findings, str(jsonl_path))
    print(f"Target label: {target_label}")

    assert target_label == "http://admin.example.com:8080, https://panel.example.com, https://www.example.com"

    print("\n✅ Nuclei JSON importer test passed.")


if __name__ == "__main__":
    test_nuclei_json_importer()
"""
Test that the three importers fail with clear, expected exceptions
on bad input, rather than leaking a raw stack trace.

Covers:
- Missing file               → FileNotFoundError
- Directory instead of file  → IsADirectoryError
- Malformed XML / JSON       → ValueError
- Empty file                 → empty list (no crash) where appropriate
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from integrations.nmap_xml_importer import import_nmap_xml
from integrations.osmedeus_httpx_importer import import_httpx_jsonl
from integrations.nuclei_json_importer import import_nuclei_json


def _expect_exception(label: str, callable_, exc_type):
    try:
        callable_()
    except exc_type as e:
        print(f"   ✅ {label} → {exc_type.__name__}: {str(e)[:80]}")
        return
    except Exception as e:
        print(f"   ❌ {label} → wrong exception type: {type(e).__name__}: {e}")
        raise AssertionError(f"{label} raised {type(e).__name__}, expected {exc_type.__name__}")

    raise AssertionError(f"{label} did not raise; expected {exc_type.__name__}")


def test_missing_file_each_importer():
    _expect_exception(
        "Nmap XML missing file",
        lambda: import_nmap_xml("does_not_exist_42.xml"),
        FileNotFoundError,
    )
    _expect_exception(
        "httpx JSONL missing file",
        lambda: import_httpx_jsonl("does_not_exist_42.jsonl"),
        FileNotFoundError,
    )
    _expect_exception(
        "Nuclei JSON missing file",
        lambda: import_nuclei_json("does_not_exist_42.jsonl"),
        FileNotFoundError,
    )


def test_directory_each_importer():
    with tempfile.TemporaryDirectory() as tmpdir:
        _expect_exception(
            "Nmap XML directory input",
            lambda: import_nmap_xml(tmpdir),
            IsADirectoryError,
        )
        _expect_exception(
            "httpx JSONL directory input",
            lambda: import_httpx_jsonl(tmpdir),
            IsADirectoryError,
        )
        _expect_exception(
            "Nuclei directory input",
            lambda: import_nuclei_json(tmpdir),
            IsADirectoryError,
        )


def test_malformed_nmap_xml():
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".xml", delete=False, encoding="utf-8"
    ) as f:
        f.write("this is not <valid> xml at all <<<")
        tmp_path = f.name

    try:
        _expect_exception(
            "Nmap XML malformed content",
            lambda: import_nmap_xml(tmp_path),
            ValueError,
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_empty_jsonl_returns_empty_list():
    """Empty JSONL is a legitimate input; importers should return [] without crashing."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        tmp_path = f.name

    try:
        httpx_result = import_httpx_jsonl(tmp_path)
        nuclei_result = import_nuclei_json(tmp_path)

        assert httpx_result == [], f"httpx empty file must yield [], got {httpx_result}"
        assert nuclei_result == [], f"nuclei empty file must yield [], got {nuclei_result}"

        print("   ✅ httpx empty JSONL  → empty list, no crash")
        print("   ✅ nuclei empty JSONL → empty list, no crash")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_malformed_jsonl_skipped_with_warning():
    """Individual bad lines must be skipped, not crash the whole import."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        f.write('{"host":"a.example.com","port":80,"scheme":"http"}\n')
        f.write('this is not json at all\n')
        f.write('{"host":"b.example.com","port":443,"scheme":"https"}\n')
        tmp_path = f.name

    try:
        result = import_httpx_jsonl(tmp_path)
        assert len(result) == 2, f"expected 2 findings, got {len(result)}"
        print(f"   ✅ httpx JSONL with one bad line → {len(result)} findings parsed (bad line skipped)")
    finally:
        Path(tmp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    print("Importer Error Handling Test Results")
    print("=" * 60)
    test_missing_file_each_importer()
    test_directory_each_importer()
    test_malformed_nmap_xml()
    test_empty_jsonl_returns_empty_list()
    test_malformed_jsonl_skipped_with_warning()
    print()
    print("✅ Importer error handling test passed.")

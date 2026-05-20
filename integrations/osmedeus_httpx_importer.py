"""
ADS – Osmedeus / httpx JSONL Importer

Reads HTTP fingerprint JSONL output produced by httpx or Osmedeus
and converts it into ADS ScanFinding objects.

This importer preserves web fingerprint information inside ScanFinding.metadata.

Example metadata:
{
  "source_type": "httpx_jsonl",
  "url": "https://example.com",
  "status_code": 200,
  "title": "Example Domain",
  "webserver": "nginx/1.18.0",
  "tech": ["Nginx"],
  "scheme": "https"
}
"""

import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import ScanFinding


def _safe_str(value, default: str = "") -> str:
    if value is None:
        return default

    if isinstance(value, str):
        return value.strip()

    return str(value).strip()


def _safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_version_from_webserver(webserver: str) -> tuple[str, str]:
    webserver = _safe_str(webserver)

    if not webserver:
        return "", ""

    match = re.match(r"^([^/\s]+)\/([0-9][^\s]*)", webserver)

    if match:
        return match.group(1), match.group(2)

    return webserver, ""


def _get_url(data: dict) -> str:
    return _safe_str(
        data.get("url")
        or data.get("matched-at")
        or data.get("input")
        or data.get("host")
    )


def _get_scheme(data: dict, parsed) -> str:
    scheme = _safe_str(data.get("scheme"))

    if scheme:
        return scheme.lower()

    if parsed.scheme:
        return parsed.scheme.lower()

    return "http"


def _get_host(data: dict, parsed) -> str:
    host = _safe_str(data.get("host"))

    if host:
        if "://" in host:
            parsed_host = urlparse(host)
            return parsed_host.hostname or host

        if ":" in host and not host.startswith("["):
            return host.split(":", 1)[0]

        return host

    if parsed.hostname:
        return parsed.hostname

    input_value = _safe_str(data.get("input"))

    if input_value:
        if "://" in input_value:
            parsed_input = urlparse(input_value)
            return parsed_input.hostname or input_value

        if ":" in input_value and not input_value.startswith("["):
            return input_value.split(":", 1)[0]

        return input_value

    return ""


def _get_port(data: dict, parsed, scheme: str) -> int:
    port = _safe_int(data.get("port"), 0)

    if port:
        return port

    if parsed.port:
        return parsed.port

    if scheme == "https":
        return 443

    if scheme == "http":
        return 80

    return 0


def _get_status_code(data: dict) -> int:
    return _safe_int(
        data.get("status-code")
        or data.get("status_code")
        or data.get("status")
        or data.get("code"),
        0,
    )


def _get_tech(data: dict) -> list[str]:
    tech = data.get("tech") or data.get("technologies") or []

    if isinstance(tech, list):
        return [_safe_str(t) for t in tech if _safe_str(t)]

    if isinstance(tech, str):
        return [t.strip() for t in tech.split(",") if t.strip()]

    return []


def _build_product_and_version(data: dict) -> tuple[str, str]:
    webserver = _safe_str(data.get("webserver") or data.get("server"))

    product, version = _extract_version_from_webserver(webserver)

    if product:
        return product, version

    tech = _get_tech(data)

    if tech:
        return tech[0], ""

    return "", ""


def _parse_json_line(line: str, line_no: int) -> dict | None:
    line = line.strip()

    if not line:
        return None

    try:
        parsed = json.loads(line)
    except json.JSONDecodeError:
        print(f"[httpx-importer] Warning: line {line_no} is invalid JSON and was skipped.")
        return None

    if not isinstance(parsed, dict):
        print(f"[httpx-importer] Warning: line {line_no} is not a JSON object and was skipped.")
        return None

    return parsed


def _build_metadata(
    data: dict,
    url: str,
    host: str,
    port: int,
    scheme: str,
) -> dict:
    status_code = _get_status_code(data)
    title = _safe_str(data.get("title"))
    webserver = _safe_str(data.get("webserver") or data.get("server"))
    tech = _get_tech(data)

    metadata = {
        "source_type": "httpx_jsonl",
        "url": url,
        "host": host,
        "port": port,
        "scheme": scheme,
        "status_code": status_code,
        "title": title,
        "webserver": webserver,
        "tech": tech,
    }

    return {
        key: value
        for key, value in metadata.items()
        if value not in ("", None, [], 0)
    }


def _httpx_record_to_finding(data: dict) -> ScanFinding | None:
    url = _get_url(data)
    parsed = urlparse(url if "://" in url else f"http://{url}")

    scheme = _get_scheme(data, parsed)
    host = _get_host(data, parsed)
    port = _get_port(data, parsed, scheme)

    if not host or not port:
        return None

    service = "https" if scheme == "https" else "http"
    product, version = _build_product_and_version(data)
    metadata = _build_metadata(data, url, host, port, scheme)

    return ScanFinding(
        host=host,
        port=port,
        protocol="tcp",
        service=service,
        state="open",
        product=product,
        version=version,
        metadata=metadata,
    )


def import_httpx_jsonl(jsonl_path: str) -> list[ScanFinding]:
    path = Path(jsonl_path)

    if not path.exists():
        raise FileNotFoundError(f"httpx JSONL file not found: {jsonl_path}")

    findings: list[ScanFinding] = []

    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            data = _parse_json_line(line, line_no)

            if data is None:
                continue

            finding = _httpx_record_to_finding(data)

            if finding is not None:
                findings.append(finding)

    return findings


def infer_target_label_from_httpx_findings(findings: list[ScanFinding], source_path: str) -> str:
    hosts = sorted({f.host for f in findings if f.host})

    if not hosts:
        return f"httpx:{Path(source_path).name}"

    if len(hosts) <= 3:
        return ", ".join(hosts)

    return f"httpx:{Path(source_path).name} ({len(hosts)} hosts)"
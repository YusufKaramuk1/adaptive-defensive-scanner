"""
ADS – Nuclei JSON / JSONL Importer

Reads Nuclei JSON or JSONL output and converts it into ADS SecurityFinding objects.

Supported input styles:
- JSONL: one Nuclei finding per line
- JSON array: list of Nuclei findings

This importer does not yet connect to the main ADS risk pipeline.
Current goal:
- parse Nuclei output safely
- normalize fields
- preserve raw evidence
- prepare for SecurityFinding analysis layer
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import SecurityFinding, SecuritySeverity


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


def _as_list(value) -> list:
    if value is None:
        return []

    if isinstance(value, list):
        return [item for item in value if item not in ("", None)]

    if isinstance(value, str):
        if not value.strip():
            return []

        if "," in value:
            return [item.strip() for item in value.split(",") if item.strip()]

        return [value.strip()]

    return [value]


def _normalize_severity(value) -> SecuritySeverity:
    severity = _safe_str(value).lower()

    if severity == "critical":
        return SecuritySeverity.CRITICAL

    if severity == "high":
        return SecuritySeverity.HIGH

    if severity == "medium":
        return SecuritySeverity.MEDIUM

    if severity == "low":
        return SecuritySeverity.LOW

    if severity in {"info", "informational"}:
        return SecuritySeverity.INFO

    return SecuritySeverity.UNKNOWN


def _extract_info(record: dict) -> dict:
    info = record.get("info")

    if isinstance(info, dict):
        return info

    return {}


def _extract_classification(info: dict) -> dict:
    classification = info.get("classification")

    if isinstance(classification, dict):
        return classification

    return {}


def _extract_cve_ids(info: dict) -> list:
    classification = _extract_classification(info)

    candidates = []

    candidates.extend(_as_list(classification.get("cve-id")))
    candidates.extend(_as_list(classification.get("cve_id")))
    candidates.extend(_as_list(classification.get("cve")))

    tags = _as_list(info.get("tags"))

    for tag in tags:
        tag_str = str(tag).upper()

        if tag_str.startswith("CVE-"):
            candidates.append(tag_str)

    normalized = []

    for cve in candidates:
        cve_str = str(cve).upper().strip()

        if cve_str and cve_str not in normalized:
            normalized.append(cve_str)

    return normalized


def _extract_references(info: dict) -> list:
    references = []

    references.extend(_as_list(info.get("reference")))
    references.extend(_as_list(info.get("references")))

    cleaned = []

    for ref in references:
        ref_str = str(ref).strip()

        if ref_str and ref_str not in cleaned:
            cleaned.append(ref_str)

    return cleaned


def _record_to_security_finding(record: dict) -> SecurityFinding | None:
    if not isinstance(record, dict):
        return None

    info = _extract_info(record)

    template_id = _safe_str(
        record.get("template-id")
        or record.get("template_id")
        or record.get("template")
    )

    name = _safe_str(info.get("name") or record.get("name") or template_id)
    severity = _normalize_severity(info.get("severity") or record.get("severity"))

    matched_at = _safe_str(
        record.get("matched-at")
        or record.get("matched_at")
        or record.get("url")
        or record.get("host")
    )

    host = _safe_str(record.get("host"))

    if not host and matched_at:
        host = matched_at

    finding = SecurityFinding(
        source_tool="nuclei",
        finding_type=_safe_str(record.get("type") or "vulnerability"),
        template_id=template_id,
        name=name,
        severity=severity,
        host=host,
        matched_at=matched_at,
        ip=_safe_str(record.get("ip")),
        port=_safe_int(record.get("port"), 0),
        scheme=_safe_str(record.get("scheme")),
        description=_safe_str(info.get("description")),
        tags=_as_list(info.get("tags")),
        references=_extract_references(info),
        cve_ids=_extract_cve_ids(info),
        matcher_name=_safe_str(record.get("matcher-name") or record.get("matcher_name")),
        extracted_results=_as_list(record.get("extracted-results") or record.get("extracted_results")),
        curl_command=_safe_str(record.get("curl-command") or record.get("curl_command")),
        raw=record,
    )

    if not finding.template_id and not finding.name and not finding.matched_at:
        return None

    return finding


def _parse_jsonl_file(path: Path) -> list[dict]:
    records = []

    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()

            if not line:
                continue

            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                print(f"[nuclei-importer] Warning: line {line_no} is invalid JSON and was skipped.")
                continue

            if isinstance(parsed, dict):
                records.append(parsed)
            else:
                print(f"[nuclei-importer] Warning: line {line_no} is not a JSON object and was skipped.")

    return records


def _parse_json_file(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        parsed = json.load(f)

    if isinstance(parsed, list):
        return [item for item in parsed if isinstance(item, dict)]

    if isinstance(parsed, dict):
        return [parsed]

    return []


def import_nuclei_json(path_value: str) -> list[SecurityFinding]:
    """
    Import Nuclei JSON or JSONL output.

    Args:
        path_value: file path

    Returns:
        list[SecurityFinding]
    """
    path = Path(path_value)

    if not path.exists():
        raise FileNotFoundError(f"Nuclei JSON/JSONL file not found: {path_value}")

    if path.is_dir():
        raise IsADirectoryError(f"Expected a Nuclei JSON/JSONL file but got a directory: {path_value}")

    records: list[dict]

    try:
        if path.suffix.lower() == ".jsonl":
            records = _parse_jsonl_file(path)
        else:
            try:
                records = _parse_json_file(path)
            except json.JSONDecodeError:
                records = _parse_jsonl_file(path)
    except UnicodeDecodeError as e:
        raise ValueError(f"Nuclei file is not valid UTF-8: {path_value} ({e})")
    except PermissionError as e:
        raise PermissionError(f"Permission denied reading Nuclei file: {path_value} ({e})")

    findings = []

    for record in records:
        finding = _record_to_security_finding(record)

        if finding is not None:
            findings.append(finding)

    return findings


def infer_target_label_from_nuclei_findings(findings: list[SecurityFinding], source_path: str) -> str:
    hosts = sorted({f.host for f in findings if f.host})

    if not hosts:
        return f"nuclei:{Path(source_path).name}"

    if len(hosts) <= 3:
        return ", ".join(hosts)

    return f"nuclei:{Path(source_path).name} ({len(hosts)} hosts)"
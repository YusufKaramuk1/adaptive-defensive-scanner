"""
ADS – Storage Utilities (utils)
Tarama geçmişini yönetir: en son taramayı saklama, liste alma, son iki taramayı bulma.

v1.0.0 notes:
- History içine path kaydederken POSIX formatı kullanılır: reports/file.json
- Okurken Windows/Linux farkı normalize edilir.
- Eski history kayıtlarında metadata yoksa, JSON raporun context alanından geriye dönük doldurulmaya çalışılır.
- Import source bilgisi history içine alınır: source_tool / source_file
"""

import json
from pathlib import Path
from datetime import datetime


REPORTS_DIR = Path("reports")
HISTORY_FILE = REPORTS_DIR / "scan_history.json"
LATEST_SCAN_FILE = REPORTS_DIR / "latest_scan.json"
MAX_HISTORY_ITEMS = 20


def ensure_reports_dir() -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _normalize_path_for_storage(path_value: str | Path) -> str:
    raw = str(path_value).replace("\\", "/")
    return Path(raw).as_posix()


def _path_exists(path_value: str | Path) -> bool:
    normalized = _normalize_path_for_storage(path_value)
    return Path(normalized).exists()


def _read_json_file(path_value: str | Path):
    normalized = _normalize_path_for_storage(path_value)

    with open(normalized, "r", encoding="utf-8") as f:
        return json.load(f)


def _write_json_file(path_value: str | Path, data) -> None:
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _extract_context_from_report(report_path: str | Path) -> dict:
    default_context = {
        "target": "unknown",
        "environment": "unknown",
        "criticality": "unknown",
        "scan_mode": "unknown",
        "source_tool": "",
        "source_file": "",
    }

    try:
        data = _read_json_file(report_path)
        context = data.get("context", {})

        return {
            "target": context.get("target", default_context["target"]),
            "environment": context.get("environment", default_context["environment"]),
            "criticality": context.get("criticality", default_context["criticality"]),
            "scan_mode": context.get("scan_mode", default_context["scan_mode"]),
            "source_tool": context.get("source_tool", default_context["source_tool"]),
            "source_file": context.get("source_file", default_context["source_file"]),
        }

    except Exception:
        return default_context


def _enrich_history_entry(entry: dict) -> dict:
    enriched = dict(entry)
    path = _normalize_path_for_storage(enriched.get("path", ""))
    enriched["path"] = path

    needs_backfill = (
        enriched.get("target", "unknown") == "unknown"
        or enriched.get("environment", "unknown") == "unknown"
        or enriched.get("criticality", "unknown") == "unknown"
        or enriched.get("scan_mode", "unknown") == "unknown"
        or "source_tool" not in enriched
        or "source_file" not in enriched
    )

    if needs_backfill and path and _path_exists(path):
        report_context = _extract_context_from_report(path)

        for key in ("target", "environment", "criticality", "scan_mode", "source_tool", "source_file"):
            current = enriched.get(key, "unknown")

            if current in ("unknown", None, ""):
                enriched[key] = report_context.get(key, "")

    enriched.setdefault("source_tool", "")
    enriched.setdefault("source_file", "")

    return enriched


def save_latest_scan(report_path: str) -> None:
    ensure_reports_dir()

    normalized_report_path = _normalize_path_for_storage(report_path)

    if not _path_exists(normalized_report_path):
        print(f"[Storage] Source report not found: {normalized_report_path}")
        return

    _add_to_history(normalized_report_path)

    data = _read_json_file(normalized_report_path)
    _write_json_file(LATEST_SCAN_FILE, data)

    print(f"[Storage] Latest scan updated: {_normalize_path_for_storage(LATEST_SCAN_FILE)}")


def _add_to_history(report_path: str) -> None:
    history = load_history()
    normalized_report_path = _normalize_path_for_storage(report_path)

    for entry in history:
        if _normalize_path_for_storage(entry.get("path", "")) == normalized_report_path:
            return

    context = _extract_context_from_report(normalized_report_path)

    history.append({
        "path": normalized_report_path,
        "target": context.get("target", "unknown"),
        "environment": context.get("environment", "unknown"),
        "criticality": context.get("criticality", "unknown"),
        "scan_mode": context.get("scan_mode", "unknown"),
        "source_tool": context.get("source_tool", ""),
        "source_file": _normalize_path_for_storage(context.get("source_file", "")) if context.get("source_file") else "",
        "timestamp": datetime.now().isoformat(),
    })

    if len(history) > MAX_HISTORY_ITEMS:
        history = history[-MAX_HISTORY_ITEMS:]

    _write_json_file(HISTORY_FILE, history)


def load_history() -> list:
    ensure_reports_dir()

    if not HISTORY_FILE.exists():
        return []

    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            history = json.load(f)

        normalized_history = []

        for entry in history:
            normalized_history.append(_enrich_history_entry(entry))

        return normalized_history

    except (json.JSONDecodeError, FileNotFoundError):
        return []


def get_previous_scan_path() -> str | None:
    history = load_history()

    existing_history = [
        entry for entry in history
        if _path_exists(entry.get("path", ""))
    ]

    if len(existing_history) >= 2:
        return existing_history[-2]["path"]

    return None


def list_history() -> list:
    history = load_history()
    result = []

    for i, entry in enumerate(history):
        normalized_path = _normalize_path_for_storage(entry.get("path", ""))

        if not _path_exists(normalized_path):
            continue

        path = Path(normalized_path)
        size = path.stat().st_size

        source_file = entry.get("source_file", "")
        if source_file:
            source_file = _normalize_path_for_storage(source_file)

        result.append({
            "index": i + 1,
            "target": entry.get("target", "unknown"),
            "environment": entry.get("environment", "unknown"),
            "criticality": entry.get("criticality", "unknown"),
            "scan_mode": entry.get("scan_mode", "unknown"),
            "source_tool": entry.get("source_tool", ""),
            "source_file": source_file,
            "path": normalized_path,
            "timestamp": entry.get("timestamp", "unknown"),
            "size_kb": round(size / 1024, 1),
        })

    return result
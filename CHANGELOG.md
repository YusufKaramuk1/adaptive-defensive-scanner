# Changelog

All notable changes to Adaptive Defensive Scanner (ADS) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-05-18

First stable release.

ADS can ingest output from Nmap, httpx / Osmedeus, and Nuclei, normalize it
through a defensive interpretation pipeline, and produce a single unified HTML
and JSON report per run.

### Added

**Unified report architecture**
- `ScanReport` holds both scan findings (`AnalyzedFinding`) and security findings (`AnalyzedSecurityFinding`) in a single container.
- HTML report renders "Open Service Findings" and "Security Findings" as conditional subsections under one "Findings Overview".
- Merged "Top Priority Findings" panel tags cards as `PORT` or `SEC`.
- JSON report carries both `summary` / `security_summary` and `findings` / `security_findings` blocks.

**Integration layer**
- Nmap XML importer (`--import-nmap-xml`).
- httpx / Osmedeus JSONL importer (`--import-httpx-jsonl`) with web-fingerprint metadata.
- Nuclei JSON / JSONL importer (`--import-nuclei-json`).
- Malformed JSONL lines are skipped with a warning instead of aborting the run.

**Security finding pipeline**
- `SecurityFinding` and `AnalyzedSecurityFinding` models.
- `analyzer/security_finding_analyzer.py` with context-aware risk, priority, confidence, evidence, and fix.
- Severity-aware rendering (info / low / medium / high / critical).
- Standalone Nuclei JSON reporter retained for backward compatibility.

**Scan pipeline**
- Nmap live scan, mock scan, sequential and parallel subnet scan.
- Host-aware findings.
- Service classification with expected-exposure semantics.
- Context-aware risk scoring (environment + criticality).
- Local CVE enrichment with version awareness.
- Confidence scoring (LOW / MEDIUM / HIGH).
- Priority engine (CRITICAL / HIGH / MEDIUM / LOW).
- Quick-fix and proper-fix recommendations.
- UFW and iptables firewall rule suggestions.

**Reporting and tracking**
- Modern dark-theme HTML report.
- Timestamped JSON reports plus `reports/latest_scan.json`.
- Scan history (last 20 runs) via `--history`.
- Host-aware scan diff via `--compare last` or `--diff <path>`.
- POSIX-style path normalization for Windows / Linux interoperability.

**Tests**
- `test_subnet_expand`, `test_priority`, `test_scan_diff`, `test_nmap_xml_importer`, `test_httpx_jsonl_importer`, `test_nuclei_json_importer`, `test_security_finding_analyzer`, `test_unified_report`.

**Documentation**
- README (English) covering pipeline, models, importers, unified report, history, diff, and testing.
- ROADMAP (English) detailing near-term priorities: Real CVE API + cache, EPSS integration, Exposure-Aware Priority, Diff-Driven Priority Boost, and "Why this priority?" trace.

### Changed
- HTML report UI and terminal output converted to English.
- `ScanFinding` extended with a `metadata` dict so importers can preserve source-specific context (URL, status code, title, web server, tech).
- `ScanContext` extended with `scan_mode`, `source_tool`, and `source_file` for traceability.

### Notes

ADS is intentionally a single-binary, local-first tool. It does not require a
SaaS backend or a database. Generated reports live in `reports/` and are
gitignored.

Future direction (see `ROADMAP.md`):
- Real CVE enrichment + local cache.
- EPSS integration (FIRST.org exploit-probability scoring).
- Exposure-aware priority lift.
- Diff-driven priority boost.
- Auditable "why this priority?" trace.

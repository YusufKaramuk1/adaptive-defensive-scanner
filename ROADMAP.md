# Adaptive Defensive Scanner — Roadmap

## 1. Project Identity

Adaptive Defensive Scanner (ADS) is not a "do-everything" scanner.

```text
Technical finding → Security meaning → Defensive action
```

ADS does not aim to merely list open ports or vulnerabilities. The goal is to take the technical output of other security tools, interpret it defensively, score risk and priority, and turn it into actionable guidance.

Short definition:
`ADS is a defensive reasoning and action engine.`

Full definition:
ADS is a defensive analysis engine that normalizes the output of tools such as Nmap, Osmedeus, httpx, Nuclei, and Tsunami, and converts those findings into risk, priority, fixes, firewall rules, and reports.

---

## 2. Core Pipeline

```text
Input → Scan / Import → Normalize Finding → Service Classification
     → CVE Enrichment → Context-Aware Risk Analysis → Confidence / Evidence
     → Priority Engine → Fix Recommendation → Firewall Rule Suggestion
     → Unified HTML / JSON Report → History / Diff
```

---

## 3. Completed Capabilities

**Active scanning and analysis**
- Nmap-based live scanning
- Mock scanning for development
- Subnet scanning (sequential + parallel)
- Host-aware findings
- Service classification with expected-exposure semantics
- Context-aware risk scoring (environment + criticality)
- Local CVE enrichment with version awareness
- Confidence scoring (LOW / MEDIUM / HIGH)
- Evidence generation
- Priority engine (CRITICAL / HIGH / MEDIUM / LOW)
- Quick-fix and proper-fix recommendation
- UFW and iptables rule suggestion

**Reporting and tracking**
- HTML report with dark UI, badges, expandable details
- Timestamped JSON reports
- Scan history (last 20 runs)
- Host-aware scan diff
- POSIX-style path normalization (Windows + Linux/Kali friendly)

**Integration layer**
- Nmap XML importer
- httpx / Osmedeus JSONL importer with web-fingerprint metadata
- Nuclei JSON / JSONL importer
- Import source metadata (source_tool, source_file, scan_mode)

**Security finding pipeline (Nuclei / Tsunami-style inputs)**
- `SecurityFinding` and `AnalyzedSecurityFinding` models
- Dedicated security analyzer with context-aware risk / priority / confidence
- Severity-aware rendering (info / low / medium / high / critical)

**Unified report architecture**
- A single `ScanReport` can carry both scan findings and security findings
- One HTML and one JSON artifact per run regardless of source
- "Top Priority Findings" merges both kinds and sorts by priority
- Per-section conditional rendering (each section appears only when populated)
- Legacy `ads_security_report_*.json` still produced for backward compatibility

---

## 4. Active Direction

The current direction is **deeper interpretation, not more scanners**. The integration layer is in good shape; the next investment is in the engine that interprets those findings.

---

## 5. Next Up

### 5.1 Real CVE Enrichment + Cache

Replace the local/static CVE table with a real CVE data source (e.g. NVD or Vulners API), backed by a local cache so runs are reproducible offline.

Outcome:
- Much wider CVE coverage than today's hardcoded examples
- Versioned local cache (`knowledge_base/cve_cache/`)
- Graceful offline fallback to local cache
- Foundation for EPSS layering (see 5.2)

### 5.2 EPSS Integration

EPSS (Exploit Prediction Scoring System, from FIRST.org) gives the probability that a given CVE will be exploited in the next 30 days. Layering EPSS on top of CVSS prevents the classic "CVSS 9.8 but never exploited in the wild" overprioritization.

Outcome:
- Each CVE-enriched finding gets `epss_score` and `epss_percentile`
- Priority engine considers EPSS when ranking
- HTML report shows EPSS alongside CVSS

### 5.3 Exposure-Aware Priority

`service_classifier` already produces `expected_exposure`. The next step is to feed that signal aggressively into the priority engine.

Examples:
- Redis on an `external` host with `should_not_be_exposed` → automatic CRITICAL
- HTTP service on a `public_allowed` and actually-public host → priority capped at MEDIUM unless other signals push it higher

Outcome:
- Priority decisions explicitly reflect the "expected vs actual exposure" mismatch
- This concept is widely recognized in blue-team and pentest framings and becomes part of ADS's identity

### 5.4 Diff-Driven Priority Boost

`scan_diff` already detects new ports and risk increases. The next step is for `priority_engine` to consume that signal:

- A finding that appeared since the last scan gets +1 priority
- A finding whose risk has increased since the last scan gets +1 priority

Outcome:
- "It wasn't there yesterday, it's there today" becomes a first-class priority signal
- Positions ADS for continuous monitoring use cases

### 5.5 "Why This Priority?" Trace

Add a `priority_trace: list[str]` field on `AnalyzedFinding` and `AnalyzedSecurityFinding` capturing every step of the priority calculation:

```text
[
  "base: HIGH (CVSS 7.5)",
  "+1 external-facing",
  "+1 unexpected exposure",
  "+1 new since last scan",
  "= CRITICAL"
]
```

Outcome:
- Full auditability of how each priority was assigned
- HTML report can surface this as a tooltip or expanded detail
- Counters "AI black box" criticism — every priority is explainable

---

## 6. Medium-Term

### 6.1 Detector Layer

Compose normalized findings into higher-level "defensive events":

```text
detectors/
├── exposed_smb.py
├── public_rdp.py
├── exposed_database.py
├── exposed_admin_panel.py
├── weak_tls.py
├── missing_security_headers.py
└── nuclei_high_confidence.py
```

Goal: `Normalized findings → Defensive events`.

Example: ScanFinding(port=3389, environment=external) → Detector public_rdp → Event "Public RDP exposure" → Priority CRITICAL.

### 6.2 Tsunami JSON Importer

Once the Nuclei / SecurityFinding pattern stabilizes, the Tsunami importer becomes a straightforward addition that reuses `SecurityFinding` and the security analyzer.

### 6.3 Amass / Subfinder Asset Importer

Asset-discovery output (subdomains, IP ranges) feeds an emerging asset-inventory layer.

### 6.4 Scan + Security Correlation

Same host, same port: an httpx fingerprint says "Apache 2.4.49" and a Nuclei template says "apache-path-traversal". The unified report should link these so the security finding inherits high confidence from the scan evidence.

Implementation:
- `AnalyzedSecurityFinding.related_scan_finding_ids: list[str]`
- `AnalyzedFinding.related_security_finding_ids: list[str]`
- A correlator runs after both pipelines and writes the cross-links

### 6.5 Security Finding Diff

Today `scan_diff` works on port findings only. Mirror it for security findings so reruns surface newly-appeared / resolved vulnerabilities.

### 6.6 Workspace System

A "workspace" represents an engagement or environment: it has its own asset inventory, scan history, configuration, and report folder. Useful when ADS is used across multiple clients / projects.

---

## 7. Long-Term

- YAML workflow / configuration files
- Plugin system for custom analyzers and detectors
- Go scanner worker for very large subnet sweeps
- Dashboard (web UI on top of JSON reports)
- SIEM export (CEF / LEEF / generic JSON)
- Notifications (Slack / email / webhook)
- AI-assisted **reporting** only (executive summaries, remediation phrasing) — never AI-assigned risk or priority

---

## 8. AI Stance

ADS keeps the core deterministic.

```text
Deterministic risk / priority engine
        ↓
AI-assisted explanation / reporting
```

AI is a useful **writer**. It is not the **scorer**. The README states this explicitly so the project's identity stays clear.

---

## 9. What ADS Will Not Become

- A replacement for Nmap, Nuclei, Osmedeus, Tsunami, or Amass
- A tool that automatically applies firewall rules
- A tool that blindly trusts scanner output without confidence weighting
- An AI-only risk scoring system

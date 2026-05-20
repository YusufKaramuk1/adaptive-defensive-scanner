# Adaptive Defensive Scanner (ADS)

Adaptive Defensive Scanner (ADS) is a defensive reasoning and action engine for security findings.

ADS is not designed to replace tools such as Nmap, Osmedeus, httpx, Nuclei, Tsunami, Amass, or Subfinder.

Instead, ADS is designed to sit above those tools and interpret their technical outputs from a defensive perspective.

```text
Technical finding → Security meaning → Defensive action
```

In practice, ADS takes scanner outputs, normalizes them, enriches them with context, calculates risk and priority, generates remediation guidance, suggests firewall rules, creates reports, and tracks changes over time.

---

## Project Purpose

Most security tools are good at detecting technical facts:

```text
Port 445 is open.
Apache 2.4.49 is detected.
A web service returns HTTP 200.
A Nuclei template matched.
A subdomain exists.
```

ADS focuses on the next question:

```text
What does this mean defensively?
```

ADS tries to answer:

```text
Is this expected?
Is this exposed in the wrong environment?
Is there version or CVE evidence?
How confident is the finding?
How urgent is the action?
What should be fixed quickly?
What is the proper long-term fix?
What firewall rule could reduce exposure?
Did this exposure appear recently?
```

ADS therefore acts as a defensive interpretation layer.

---

## Core Concept

```text
Scan / Import
  ↓
Normalize Finding
  ↓
Service Classification
  ↓
CVE Enrichment
  ↓
Context-Aware Risk Analysis
  ↓
Confidence / Evidence
  ↓
Priority Engine
  ↓
Fix Recommendation
  ↓
Firewall Rule Suggestion
  ↓
HTML / JSON Report
  ↓
History / Diff
```

Short version:

```text
Find → Understand → Prioritize → Fix → Report → Track Change
```

---

## What ADS Currently Does

ADS currently supports:

- Nmap-based live scanning
- Mock scanning for development and testing
- Subnet scanning
- Parallel subnet scanning
- Host-aware findings
- Nmap XML import
- httpx / Osmedeus JSONL import
- Service classification
- Context-aware risk scoring
- Local CVE enrichment
- Version-aware CVE matching
- Confidence scoring
- Evidence generation
- Priority calculation
- Quick fix recommendation
- Proper fix recommendation
- UFW firewall rule suggestion
- iptables firewall rule suggestion
- HTML report generation
- JSON report generation
- Scan history
- Scan diff
- Host-aware diff
- Import source metadata tracking
- Web fingerprint metadata reporting

---

## What ADS Is Not

ADS is not:

- A replacement for Nmap
- A replacement for Nuclei
- A replacement for Osmedeus
- A replacement for Tsunami
- A full vulnerability scanner by itself
- A tool that automatically applies firewall rules
- A tool that blindly trusts scanner output
- An AI-only risk scoring system

ADS is the defensive reasoning layer above scanner outputs.

---

## Current Project Structure

```text
ADS/
├── main.py
├── models.py
├── requirements.txt
├── README.md
├── ROADMAP.md
│
├── scanner/
│   ├── nmap_scanner.py
│   └── subnet_scanner.py
│
├── integrations/
│   ├── __init__.py
│   ├── nmap_xml_importer.py
│   └── osmedeus_httpx_importer.py
│
├── analyzer/
│   ├── risk_mapper.py
│   └── scan_diff.py
│
├── knowledge_base/
│   ├── service_classifier.py
│   └── cve_enrichment.py
│
├── recommender/
│   ├── fix_generator.py
│   └── priority_engine.py
│
├── rule_generator/
│   └── firewall_rules.py
│
├── reporter/
│   ├── html_reporter.py
│   ├── json_reporter.py
│   └── diff_reporter.py
│
├── utils/
│   ├── helpers.py
│   └── storage.py
│
├── reports/
│   ├── ads_report.html
│   ├── ads_diff_report.html
│   ├── latest_scan.json
│   └── scan_history.json
│
├── scans/
│   └── nmap_test.xml
│
├── test_data/
│   └── httpx_import_test.jsonl
│
├── test_priority.py
├── test_scan_diff.py
├── test_subnet_expand.py
├── test_nmap_xml_importer.py
└── test_httpx_jsonl_importer.py
```

---

## Main Components

### `main.py`

Main CLI entry point.

Responsibilities:

- Parse command-line arguments
- Select scan or import mode
- Run Nmap scanner or external importer
- Build scan context
- Send raw findings to analyzer
- Generate fixes
- Generate firewall rules
- Calculate priority
- Generate JSON report
- Generate HTML report
- Save scan history
- Run scan comparison / diff

---

### `models.py`

Central data model file.

Important models:

| Model | Purpose |
|---|---|
| `ScanFinding` | Raw normalized finding before analysis |
| `AnalyzedFinding` | Finding after ADS risk, evidence, priority, fix, and rule enrichment |
| `ScanContext` | Scan metadata such as target, environment, criticality, scan mode, source tool |
| `ScanReport` | Full report object |
| `PortChange` | Diff item for changed ports/findings |
| `DiffReport` | Full diff report |

Current `ScanFinding` fields:

```text
host
port
service
protocol
state
product
version
metadata
```

`metadata` is used to preserve importer-specific details such as httpx web fingerprint information.

Example metadata:

```json
{
  "source_type": "httpx_jsonl",
  "url": "https://example.com",
  "status_code": 200,
  "title": "Example Domain",
  "webserver": "nginx/1.18.0",
  "tech": ["Nginx"],
  "scheme": "https"
}
```

---

### `scanner/`

Contains ADS-native scanner logic.

Current files:

```text
scanner/nmap_scanner.py
scanner/subnet_scanner.py
```

`nmap_scanner.py` runs Nmap or mock scan.

`subnet_scanner.py` supports subnet expansion and parallel scanning.

---

### `integrations/`

Contains importers for external security tool outputs.

Current files:

```text
integrations/
├── __init__.py
├── nmap_xml_importer.py
└── osmedeus_httpx_importer.py
```

Goal:

```text
External tool output
  ↓
Importer
  ↓
ADS normalized finding
  ↓
ADS analysis pipeline
```

Current supported importers:

| Importer | Status | Purpose |
|---|---:|---|
| Nmap XML Importer | Complete | Reads Nmap XML and converts open ports into `ScanFinding` |
| httpx / Osmedeus JSONL Importer | Complete first version | Reads HTTP fingerprint JSONL and converts it into `ScanFinding` with metadata |

---

### `analyzer/`

Contains risk and diff logic.

Current files:

```text
analyzer/risk_mapper.py
analyzer/scan_diff.py
```

`risk_mapper.py` performs:

- Service classification
- Base risk calculation
- Context-aware risk adjustment
- CVE enrichment
- Confidence scoring
- Evidence generation
- Metadata-aware reasoning

`scan_diff.py` compares previous and current JSON reports.

Diff is host-aware.

It compares findings using:

```text
host + port + protocol
```

This prevents false matching when scanning subnets where the same port may appear on multiple hosts.

---

### `knowledge_base/`

Contains local knowledge used by ADS.

Current files:

```text
knowledge_base/service_classifier.py
knowledge_base/cve_enrichment.py
```

`service_classifier.py` maps services into categories and expected exposure.

Example categories:

```text
web
remote_admin
file_sharing
database
windows_mgmt
app_realtime
network_service
unknown
```

Example expected exposure values:

```text
public_allowed
internal_only
restricted_admin_only
should_not_be_exposed
internal_or_dev
needs_review
```

`cve_enrichment.py` currently provides local/static CVE matching.

Future improvement:

```text
Real CVE API + local cache
```

---

### `recommender/`

Contains remediation and priority logic.

Current files:

```text
recommender/fix_generator.py
recommender/priority_engine.py
```

`fix_generator.py` creates:

```text
Quick Fix
Proper Fix
```

`priority_engine.py` calculates action priority:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

Risk and priority are intentionally separate.

| Concept | Meaning |
|---|---|
| Risk | Technical severity |
| Priority | Action urgency |

Example:

```text
Risk: MEDIUM
Priority: HIGH
```

A finding can be technically medium-risk but still high-priority because of exposure, business context, evidence, or operational urgency.

---

### `rule_generator/`

Contains firewall rule recommendation logic.

Current file:

```text
rule_generator/firewall_rules.py
```

ADS suggests firewall rules but does not apply them automatically.

Example outputs:

```bash
ufw deny 445/tcp
iptables -A INPUT -p tcp --dport 445 -j DROP
```

---

### `reporter/`

Contains report generation logic.

Current files:

```text
reporter/html_reporter.py
reporter/json_reporter.py
reporter/diff_reporter.py
```

Reports include:

- Target
- Environment
- Criticality
- Scan mode
- Source tool
- Source file
- Overall risk
- Overall priority
- Top priority findings
- All findings
- CVEs
- Confidence
- Evidence
- Web fingerprint metadata
- Remediation
- Firewall rules

HTML report uses English UI labels.

---

### `utils/`

Contains helper and storage logic.

Current files:

```text
utils/helpers.py
utils/storage.py
```

`storage.py` manages:

```text
reports/latest_scan.json
reports/scan_history.json
reports/ads_report_YYYYMMDD_HHMMSS.json
```

History paths are normalized to POSIX style:

```text
reports/ads_report_20260513_165618.json
```

This improves compatibility between Windows and Linux/Kali environments.

---

## Scan Modes

ADS currently supports these scan modes:

| Scan Mode | Description |
|---|---|
| `nmap_live` | Live Nmap scan |
| `mock` | Mock scan for testing |
| `nmap_subnet_parallel` | Parallel subnet scan |
| `nmap_subnet_sequential` | Sequential subnet scan |
| `nmap_xml_import` | Import from Nmap XML |
| `httpx_jsonl_import` | Import from httpx / Osmedeus JSONL |

---

## Basic Usage

### Live Nmap Scan

```powershell
python main.py --target 192.168.1.1 --environment external --criticality high
```

### Mock Scan

```powershell
python main.py --target 192.168.1.1 --environment external --criticality high --mock
```

### Subnet Scan

```powershell
python main.py --target 192.168.1.0/29 --environment internal --criticality medium
```

### Parallel Subnet Scan

```powershell
python main.py --target 192.168.1.0/29 --environment internal --criticality medium --parallel --workers 5
```

---

## Import Modes

### Nmap XML Import

Generate Nmap XML:

```powershell
nmap -sV -oX scans\nmap_test.xml 127.0.0.1
```

Import into ADS:

```powershell
python main.py --import-nmap-xml scans\nmap_test.xml --environment internal --criticality medium --json
```

Expected scan mode:

```text
nmap_xml_import
```

Expected source metadata:

```text
source_tool: nmap
source_file: scans/nmap_test.xml
```

---

### httpx / Osmedeus JSONL Import

Import httpx JSONL:

```powershell
python main.py --import-httpx-jsonl test_data\httpx_import_test.jsonl --environment external --criticality medium --json
```

Expected scan mode:

```text
httpx_jsonl_import
```

Expected source metadata:

```text
source_tool: httpx
source_file: test_data/httpx_import_test.jsonl
```

---

## Example httpx JSONL Input

```json
{"url":"https://example.com","host":"example.com","port":443,"scheme":"https","status-code":200,"title":"Example Domain","webserver":"nginx/1.18.0","tech":["Nginx"]}
{"url":"http://admin.example.com:8080","status_code":200,"title":"Admin Login","webserver":"Apache/2.4.49","tech":["Apache HTTP Server"]}
```

ADS extracts:

```text
host
port
protocol
service
product
version
metadata
```

Example normalized finding:

```text
host: admin.example.com
port: 8080
protocol: tcp
service: http
product: Apache
version: 2.4.49
metadata.title: Admin Login
metadata.status_code: 200
metadata.webserver: Apache/2.4.49
```

ADS can then enrich this with CVE data.

Example result:

```text
admin.example.com Port 8080 http
Product: Apache
Version: 2.4.49
CVE: CVE-2021-41773, CVE-2021-42013
Risk: HIGH
Priority: CRITICAL
```

This shows the main ADS value:

```text
httpx fingerprint → product/version → CVE enrichment → defensive action
```

---

## Context-Aware Risk

ADS does not score findings only by port.

It considers:

- Environment
- Criticality
- Service category
- Expected exposure
- Product
- Version
- CVE match
- CVSS score
- Confidence
- Metadata

Example:

| Finding | Context | Result |
|---|---|---|
| `80/http` | internal | LOW |
| `80/http` | external | MEDIUM |
| `445/smb` | internal | HIGH |
| `445/smb` | external | HIGH risk / CRITICAL priority |
| `Apache 2.4.49` | external web | HIGH risk / CRITICAL priority |

---

## Confidence

ADS assigns confidence levels:

```text
LOW
MEDIUM
HIGH
```

Examples:

| Evidence | Confidence |
|---|---|
| Only port/service exists | LOW |
| Product or version exists | MEDIUM |
| Product/version with strong CVE match | HIGH |
| Importer metadata exists | MEDIUM |
| Validated vulnerability in future | HIGH |

---

## Priority

ADS separates risk and priority.

Risk means technical severity.

Priority means action urgency.

Example:

```text
Risk: MEDIUM
Priority: HIGH
```

This is intentional.

A finding can be medium-risk technically but high-priority operationally due to exposure, business context, evidence, or operational urgency.

---

## Reports

### HTML Report

Generated at:

```text
reports/ads_report.html
```

The HTML report includes:

- Security Scan Report
- Overall Risk / Priority
- Scan Metadata
- Top Priority Findings
- Executive Summary
- All Findings
- Context / Details
- Web Fingerprint
- Remediation
- Firewall Rule

The current HTML report uses a summary table with expandable details.

Main table columns:

```text
Host
Port
Service
Exposure
Risk
Priority
Confidence
Score
CVE
Context / Details
```

Detailed information is available under each finding through the `Details` dropdown.

---

### JSON Report

Generated as timestamped files:

```text
reports/ads_report_YYYYMMDD_HHMMSS.json
```

Also copied to:

```text
reports/latest_scan.json
```

JSON reports are used for:

- History
- Diff
- Future API
- Future dashboard
- SIEM export
- Automation

---

## History

Show scan history:

```powershell
python main.py --history
```

Example:

```text
#15  2026-05-13T16:56:18  Hedef: httpx:httpx_import_test.jsonl (4 hosts)
     Ortam: external   | Kritiklik: medium   | Mode: httpx_jsonl_import
     Source: httpx (test_data/httpx_import_test.jsonl)
     reports/ads_report_20260513_165618.json  (6.7 KB)
```

Note:

Some older history records may show `unknown` for scan mode or source fields because they were created before metadata support was added.

---

## Diff

Compare current scan with the last scan:

```powershell
python main.py --target 192.168.1.1 --environment external --criticality high --mock --compare last
```

Diff can detect:

- New ports
- Removed ports
- Risk increased
- Risk decreased
- Unchanged findings

Diff is host-aware.

It compares:

```text
host + port + protocol
```

This prevents subnet scan comparison mistakes.

---

## Testing

Run all current tests:

```powershell
python test_httpx_jsonl_importer.py
python test_nmap_xml_importer.py
python test_scan_diff.py
python test_priority.py
python test_subnet_expand.py
```

Expected result:

```text
All tests should pass.
```

Current tests:

| Test File | Purpose |
|---|---|
| `test_httpx_jsonl_importer.py` | Tests httpx / Osmedeus JSONL importer |
| `test_nmap_xml_importer.py` | Tests Nmap XML importer |
| `test_scan_diff.py` | Tests scan diff logic |
| `test_priority.py` | Tests priority engine behavior |
| `test_subnet_expand.py` | Tests subnet expansion helper |

---

## Current Stable Capabilities

```text
Nmap live scan
Mock scan
Subnet scan
Parallel scan
Host-aware findings
Context-aware risk
CVE enrichment
Confidence scoring
Evidence generation
Priority engine
Fix recommendation
Firewall rule suggestion
HTML report
JSON report
History
Host-aware diff
Nmap XML importer
httpx / Osmedeus JSONL importer
Web fingerprint metadata in reports
```

---

## Roadmap Summary

Short-term:

- Convert terminal labels to English
- Add compact / verbose terminal output
- Improve terminal readability for long evidence strings
- Add SecurityFinding model discussion
- Start Nuclei JSON importer

Medium-term:

- Nuclei JSON importer
- Tsunami JSON importer
- Amass / Subfinder asset importer
- Detector layer
- Asset inventory
- Workspace system
- Real CVE API + local cache

Long-term:

- YAML workflow/config
- Plugin system
- Go scanner worker
- Dashboard
- SIEM export
- Notification
- AI-assisted reporting

---

## Tool Output Interpretation Layer

This is the main long-term ADS direction.

Goal:

```text
Read output from external security tools and turn it into defensive interpretation.
```

Planned integrations:

- Nmap XML
- httpx / Osmedeus JSONL
- Nuclei JSON
- Tsunami JSON
- Amass / Subfinder outputs

Future flow:

```text
Nmap / Osmedeus / httpx / Nuclei / Tsunami / Amass
        ↓
ADS Importer / Normalizer
        ↓
ADS Risk & Priority Engine
        ↓
Fix / Firewall Rule / Report
```

ADS should not compete with those tools.

ADS should interpret their outputs defensively.

---

## Detector Layer Plan

Future detector layer example:

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

Detector layer goal:

```text
Normalized findings → Defensive events
```

Example:

```text
ScanFinding(port=3389, environment=external)
        ↓
Detector: public_rdp
        ↓
Finding: Public RDP exposure
        ↓
Priority: CRITICAL
```

---

## AI-Assisted Reporting

AI can be used later for:

- Executive summary generation
- Better remediation wording
- Report polishing
- Finding explanation
- Natural-language report export

But ADS core scoring should remain deterministic.

Correct approach:

```text
Deterministic risk/priority engine
        ↓
AI-assisted explanation/reporting
```

Wrong approach:

```text
AI randomly decides the risk score
```

---

## Recommended Next Step

The next strong technical step is:

```text
Nuclei JSON Importer
```

Nuclei introduces direct vulnerability and misconfiguration findings.

This may require a new model such as:

```text
SecurityFinding
VulnerabilityFinding
ImportedFinding
```

Nmap and httpx can continue using `ScanFinding`.

Nuclei and Tsunami should probably use a dedicated security finding model.
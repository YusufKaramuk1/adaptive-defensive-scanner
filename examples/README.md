# ADS Examples

Ready-to-run sample inputs for the three ADS import modes. Each file uses
non-routable hostnames and TEST-NET-1 IPs (RFC 5737), so nothing here will
touch a real network.

These examples are the fastest way to see ADS produce a real HTML and JSON
report on your machine. Pick any of the three commands below.

---

## 1. Nmap XML import

Imports a fingerprinted Nmap XML scan of a web/database/SMB host.

```powershell
ads --import-nmap-xml examples\sample_nmap.xml --environment external --criticality high
```

Or without the installed entry point:

```powershell
python main.py --import-nmap-xml examples\sample_nmap.xml --environment external --criticality high
```

Expected outcome:

- 5 open ports (SSH, HTTP, HTTPS, SMB, MySQL)
- CRITICAL priority on Apache 2.4.49 (CVE-2021-41773)
- HIGH priority on exposed SMB
- HTML report written to `reports/ads_report.html`

---

## 2. httpx / Osmedeus JSONL import

Imports an httpx fingerprint sweep of four web targets.

```powershell
ads --import-httpx-jsonl examples\sample_httpx.jsonl --environment external --criticality medium
```

Expected outcome:

- 4 findings (example.com nginx, admin.example.com Apache 2.4.49, api on Cloudflare, IIS dev host)
- Web fingerprint metadata visible in the HTML report (URL, status, title, server, tech)
- admin.example.com Apache 2.4.49 enriched with CVE-2021-41773

---

## 3. Nuclei JSON / JSONL import

Imports four Nuclei findings spanning all severity tiers.

```powershell
ads --import-nuclei-json examples\sample_nuclei.jsonl --environment external --criticality high
```

Expected outcome:

- `apache-path-traversal` → CRITICAL priority, HIGH risk, with `extracted-results`
  showing `/etc/passwd` content
- `exposed-panel` → HIGH priority in external context
- `missing-strict-transport-security` → LOW priority
- `tech-detect` → INFO severity, kept as inventory
- Unified HTML report with a "Security Findings" section and a merged
  "Top Priority Findings" panel

---

## What you should see

After any of the three commands:

```text
reports/ads_report.html        ← open in a browser
reports/ads_report_<ts>.json   ← unified JSON
reports/latest_scan.json       ← pointer to the most recent run
```

For the Nuclei run an additional legacy file is produced for backward
compatibility:

```text
reports/ads_security_report_<ts>.json
```

---

## Notes

- All hostnames are `*.example.com` (IANA-reserved for documentation).
- All IPs are in `192.0.2.0/24` (TEST-NET-1, non-routable).
- `examples/` is intentionally kept separate from `test_data/`, which
  contains slightly-broken inputs used to exercise the error-handling
  code paths.

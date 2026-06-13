# 🛠️ Tools & Scripts

**Maintained by:** [ThreatSignal](https://threatsignal.in)  
**Language:** Python 3.8+ (unless noted)

Scripts we actually use in our research workflow — open-sourced for the community.

---

## Scripts

### `ioc_extractor.py` — IOC Extraction from Unstructured Text

Extracts IPv4, IPv6, domains, URLs, hashes (MD5/SHA1/SHA256), CVE IDs, and emails from any text input. Filters private IPs and common false-positive domains.

```bash
# Install (no external deps — stdlib only)
python3 ioc_extractor.py --help

# Extract from a threat report PDF (convert to text first)
pdftotext report.pdf - | python3 ioc_extractor.py -f /dev/stdin

# Extract from text, defang output, save to CSV
python3 ioc_extractor.py -f paste.txt --defang --csv results.csv

# Only extract IPs and domains
python3 ioc_extractor.py -t "evil.com contacted 1.2.3.4" --types ipv4 domain
```

**Output:**
```
============================================================
  ThreatSignal IOC Extractor — 2026-05-16 10:00:00
  Found 3 indicators across 2 types
============================================================

[IPV4] (1 found)
  1.2.3.4

[DOMAIN] (1 found)
  evil.com
```

---

---

### `cve_enricher.py` — CVE Triage with CVSS + EPSS + CISA KEV

Enriches a list of CVE IDs with data from three authoritative sources simultaneously:
- **NVD (NIST)** — CVSS v3.1 score, severity, vector string, affected CPEs, description
- **EPSS (FIRST)** — Exploit Prediction Scoring System score + percentile
- **CISA KEV** — Whether the CVE is in the Known Exploited Vulnerabilities catalog

```bash
pip install requests

# Single CVE
python3 cve_enricher.py CVE-2025-0282

# Triage a patch list from file
python3 cve_enricher.py -f cves.txt --csv report.csv

# Only show critical / KEV-listed CVEs
python3 cve_enricher.py -f cves.txt --min-cvss 9.0 --kev-only
```

**Output:**
```
────────────────────────────────────────────────────────────────
  CVE-2025-0282  [CRITICAL 9.0]  ⚠ IN CISA KEV
────────────────────────────────────────────────────────────────
  Published : 2025-01-08  |  Modified: 2025-01-15
  CVSS      : 9.0 (3.1)  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  EPSS      : 0.9412  94.1th percentile
  Summary   : Stack-based buffer overflow in Ivanti Connect Secure...
```

---

### `subdomain_monitor.py` — Subdomain Discovery & Change Detection

Discovers subdomains via **certificate transparency logs** (crt.sh) and **passive DNS** (HackerTarget), resolves each with live DNS, and optionally HTTP-probes alive hosts. Includes a **baseline/monitor mode** to alert on newly appearing subdomains.

```bash
pip install requests dnspython

# Basic discovery
python3 subdomain_monitor.py example.com

# Full scan: discovery + DNS + HTTP probe + save results
python3 subdomain_monitor.py example.com --probe --csv results.csv

# Save a baseline today...
python3 subdomain_monitor.py example.com --save-baseline baseline.txt

# ...then alert on new subdomains tomorrow (great for cron jobs)
python3 subdomain_monitor.py example.com --baseline baseline.txt --alert-new
```

**Output:**
```
════════════════════════════════════════════════════════════════════════════════
  ThreatSignal Subdomain Monitor  —  example.com
  2026-05-16 10:00:00  |  47 subdomains to resolve
════════════════════════════════════════════════════════════════════════════════
  SUBDOMAIN                                          STATUS    IP / CNAME
  ──────────────────────────────────────────────────────────────────────────
  api.example.com                                    HTTPS     93.184.216.34
  staging.example.com                                NEW HTTP  93.184.216.99
  legacy.example.com                                 DNS-ONLY  93.184.216.11
```

---

### `fetch_feeds.py` — Threat Intelligence IOC Feed Aggregator

Fetches, cleans, deduplicates, and formats threat intelligence indicators from multiple public OSINT feeds (OpenPhish, URLhaus, Feodo Tracker, Threatview.io, and Tor Project exit nodes). Integrates authenticated MalwareBazaar and ThreatFox querying dynamically if an `abuse.ch` Auth-Key is supplied.

```bash
# Aggregates feeds and saves top 250 indicators (default) to ../ioc-feeds/
python3 fetch_feeds.py

# Aggregates feeds with a custom limit and path
python3 fetch_feeds.py --limit 100 --output-dir ../ioc-feeds/

# Fetch live, high-fidelity MalwareBazaar hashes using your free Auth-Key
python3 fetch_feeds.py --key YOUR_ABUSE_CH_AUTH_KEY
```

**Output Files updated in `ioc-feeds/`:**
*   `malicious-ips.txt` (IPs only, one per line)
*   `phishing-domains.txt` (Defanged domains, sorted)
*   `malware-hashes.csv` (hashes, type, malware family, first seen, source)
*   `c2-infrastructure.csv` (indicator, type, confidence, attribution, etc.)

---

## Planned Scripts

- [ ] `sigma_rule_validator.py` — Validate Sigma rules against schema
- [ ] `phish_checker.py` — Check URLs against PhishTank + OpenPhish + URLScan

---

## Requirements

| Script | Dependencies |
|--------|-------------|
| `ioc_extractor.py` | None (stdlib only) |
| `fetch_feeds.py` | None (stdlib only) |
| `cve_enricher.py` | `pip install requests` |
| `subdomain_monitor.py` | `pip install requests dnspython` |

---

*Found a bug? Open an issue. Want to contribute a script? Open a PR.*

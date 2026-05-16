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

## Planned Scripts

- [ ] `sigma_rule_validator.py` — Validate Sigma rules against schema
- [ ] `cve_enricher.py` — Pull CVSS, EPSS, KEV status for a CVE list
- [ ] `subdomain_monitor.py` — Monitor a domain for new subdomains (cert transparency)
- [ ] `phish_checker.py` — Check URLs against PhishTank + OpenPhish + URLScan

---

## Requirements

Scripts use Python stdlib unless a `requirements.txt` is present in the script's folder. Check individual script headers for dependencies.

---

*Found a bug? Open an issue. Want to contribute a script? Open a PR.*

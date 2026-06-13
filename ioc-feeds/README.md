# 🔴 IOC Feeds

**Maintained by:** [ThreatSignal](https://threatsignal.in)  
**Update Cadence:** As new research is published  
**Format:** Plain text + CSV + STIX 2.1 (where applicable)

---

## How to Use

These IOC lists are meant to be ingested into your SIEM, firewall, EDR, or threat intel platform.

```bash
# Download a feed
wget https://raw.githubusercontent.com/threatsignal/threatsignal/main/ioc-feeds/malicious-ips.txt

# Use with iptables (use with caution — validate first)
while read ip; do iptables -A INPUT -s "$ip" -j DROP; done < malicious-ips.txt
```

---

## Files in This Folder

| File | Description | Format |
|------|-------------|--------|
| `malicious-ips.txt` | Malicious IP addresses (for firewall blocklists) | Plain text, one IP per line |
| `malicious-ips.csv` | Enriched IPs with threat classification & actor attribution | CSV |
| `phishing-domains.txt` | Defanged phishing and typosquatting domains | Plain text |
| `phishing-domains.csv` | Enriched domains with threat classification & actor attribution | CSV |
| `malware-hashes.csv` | File hashes of malware samples (MD5, SHA1, SHA256) | CSV |
| `c2-infrastructure.csv` | Known C2 IPs/domains with attribution & configuration details | CSV |

---

## ⚡ Autopilot (Auto-Updates)

These feeds are updated automatically every day at **midnight (00:00 UTC)** using a GitHub Actions cron job defined in [update-feeds.yml](file:///Users/atlas/Documents/Tools/Intel_repo_analysis/.github/workflows/update-feeds.yml). 

The automated pipeline performs the following steps:
1. Downloads indicators from authoritative public threat intelligence feeds (Feodo Tracker, Threatview, OpenPhish, and URLhaus).
2. Deduplicates indicators and removes common false positives.
3. Automatically classifies threats and attributes indicators to threat actors (where mapping is available).
4. Commits and pushes the updated feeds back to the repository.

---

## 🏷️ Classification & Attribution

To provide maximum context for threat validation and triage:
*   **Classifications**: Indicators are categorized into:
    *   `c2`: Active command and control infrastructure.
    *   `phishing`: Credential harvesting/phishing delivery sites.
    *   `malware_delivery`: Sites hosting malicious payloads.
    *   `tor_exit_node`: Benign proxies/exit nodes often abused for scanning/relaying.
    *   `malware_distribution`: Attacker IPs distributing payloads.
*   **Attribution**: Known malware families are mapped to active threat actors (e.g., QakBot is attributed to `TA551 / Gold Lagoon`, Emotet to `TA542 / Mummy Spider`, and Cobalt Strike C2s to `Multiple (APT29 / FIN7 / Ransomware)`).

---

## Attribution & Confidence

Each CSV includes `confidence` (High/Med/Low) and `source` fields. Always validate IOCs before blocking in production — false positives can impact legitimate traffic.

---

## Limitations

- IOCs have a shelf life. Attacker infrastructure rotates frequently.
- We publish only what we've independently observed or verified.
- This is **not** a replacement for commercial threat intel feeds.

---

*For enrichment, cross-reference with [VirusTotal](https://virustotal.com), [AlienVault OTX](https://otx.alienvault.com), and [Pulsedive](https://pulsedive.com).*

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
| `malicious-ips.txt` | Malicious IP addresses observed in ThreatSignal research | Plain text, one IP per line |
| `phishing-domains.txt` | Phishing and typosquatting domains | Plain text |
| `malware-hashes.csv` | SHA256 hashes of malware samples (no binaries) | CSV |
| `c2-infrastructure.csv` | Known C2 IPs/domains with attribution notes | CSV |

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

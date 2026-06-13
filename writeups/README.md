# 📝 Writeups & Research

**Maintained by:** [ThreatSignal](https://threatsignal.in)

Detailed technical writeups from our research: malware analysis, campaign breakdowns, incident retrospectives, and technique deep-dives. These are longer-form companions to our blog posts.

---

## Index

| Title | Category | Date |
|-------|----------|------|
| [Deep Dive: Exploitation of CVE-2026-50751 (Check Point VPN Auth Bypass)](2026-06-checkpoint-vpn-bypass/README.md) | Vulnerability Research | 2026-06-13 |
| *(More coming - follow [threatsignal.in](https://threatsignal.in) for new research)* | | |

---

## Writeup Format

Each writeup follows this structure:

```
writeups/
└── YYYY-MM-topic-name/
    ├── README.md          ← Main writeup
    ├── ioc/               ← Indicators of compromise directory
    │   ├── host-iocs.csv
    │   └── network-iocs.csv
    ├── detection/         ← Detection rules and queries directory
    │   ├── sigma/         ← Sigma rules
    │   ├── kql/           ← KQL queries
    │   └── suricata/      ← Suricata network signatures
    └── samples/           ← Hashes only, never binaries
        └── hashes.txt
```

---

## Contributing

If you've done original security research and want to publish it here under ThreatSignal:

1. Follow the folder structure above
2. Include IOCs with confidence ratings
3. Include at least one detection rule (Sigma preferred)
4. Open a PR with `[Writeup]` in the title

---

*All writeups at [threatsignal.in](https://threatsignal.in)*

<!-- Update Writeups summary checklist -->

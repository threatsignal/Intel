# 📝 Writeups & Research

**Maintained by:** [ThreatSignal](https://threatsignal.in)

Detailed technical writeups from our research: malware analysis, campaign breakdowns, incident retrospectives, and technique deep-dives. These are longer-form companions to our blog posts.

---

## Index

| Title | Category | Date |
|-------|----------|------|
| *(More coming — follow [threatsignal.in](https://threatsignal.in) for new research)* | | |

---

## Writeup Format

Each writeup follows this structure:

```
writeups/
└── YYYY-MM-topic-name/
    ├── README.md          ← Main writeup
    ├── iocs.csv           ← IOCs extracted from this research
    ├── sigma/             ← Detection rules (if any)
    │   └── rule.yml
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

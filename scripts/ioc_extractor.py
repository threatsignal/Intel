#!/usr/bin/env python3
"""
ioc_extractor.py — ThreatSignal IOC Extraction Utility
=======================================================
Extracts Indicators of Compromise (IOCs) from unstructured text:
reports, emails, paste dumps, log snippets, etc.

Extracts: IPv4, IPv6, domains, URLs, MD5/SHA1/SHA256 hashes, CVE IDs, email addresses

Usage:
    python3 ioc_extractor.py -f report.txt
    python3 ioc_extractor.py -t "Malicious IP 192.168.1.1 found in logs"
    python3 ioc_extractor.py -f report.txt --defang --csv output.csv

Author: ThreatSignal (https://threatsignal.in)
License: MIT
"""

import re
import argparse
import json
import csv
import sys
from pathlib import Path
from datetime import datetime


# ─── Regex Patterns ───────────────────────────────────────────────────────────

PATTERNS = {
    "ipv4": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    "ipv6": re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
        r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
        r'\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b'
    ),
    "domain": re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+(?:com|net|org|io|gov|edu|mil|info|biz|xyz|ru|cn|in|uk|de|fr|br|au|co)\b',
        re.IGNORECASE
    ),
    "url": re.compile(
        r'https?://[^\s\'"<>\]]+',
        re.IGNORECASE
    ),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'
    ),
    "md5": re.compile(r'\b[0-9a-fA-F]{32}\b'),
    "sha1": re.compile(r'\b[0-9a-fA-F]{40}\b'),
    "sha256": re.compile(r'\b[0-9a-fA-F]{64}\b'),
    "cve": re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE),
}

# Private / reserved IP ranges to exclude
PRIVATE_IP_PATTERNS = [
    re.compile(r'^10\.'),
    re.compile(r'^192\.168\.'),
    re.compile(r'^172\.(1[6-9]|2[0-9]|3[01])\.'),
    re.compile(r'^127\.'),
    re.compile(r'^0\.'),
    re.compile(r'^255\.'),
]

# Common false-positive domains to exclude
FP_DOMAINS = {
    "example.com", "test.com", "localhost.com", "domain.com",
    "google.com", "microsoft.com", "apple.com", "amazon.com"
}


# ─── Helpers ──────────────────────────────────────────────────────────────────

def defang(indicator: str, ioc_type: str) -> str:
    """Defang an IOC for safe sharing."""
    if ioc_type in ("ipv4", "ipv6"):
        return indicator.replace(".", "[.]")
    if ioc_type in ("domain", "url", "email"):
        indicator = indicator.replace(".", "[.]")
        indicator = indicator.replace("http", "hxxp")
        return indicator
    return indicator


def is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in PRIVATE_IP_PATTERNS)


def extract_iocs(text: str, exclude_private: bool = True) -> dict:
    """Extract all IOC types from text, return deduplicated dict."""
    results = {}

    for ioc_type, pattern in PATTERNS.items():
        matches = set(pattern.findall(text))

        if ioc_type == "ipv4" and exclude_private:
            matches = {ip for ip in matches if not is_private_ip(ip)}

        if ioc_type == "domain":
            matches = {d.lower() for d in matches if d.lower() not in FP_DOMAINS}

        # Remove emails that were caught as domains
        if ioc_type == "domain" and "email" in results:
            email_domains = {e.split("@")[1] for e in results["email"]}
            matches -= email_domains

        if matches:
            results[ioc_type] = sorted(matches)

    return results


# ─── Output Functions ─────────────────────────────────────────────────────────

def print_results(results: dict, do_defang: bool = False):
    total = sum(len(v) for v in results.values())
    print(f"\n{'='*60}")
    print(f"  ThreatSignal IOC Extractor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Found {total} indicators across {len(results)} types")
    print(f"{'='*60}\n")

    for ioc_type, indicators in results.items():
        print(f"[{ioc_type.upper()}] ({len(indicators)} found)")
        for ioc in indicators:
            display = defang(ioc, ioc_type) if do_defang else ioc
            print(f"  {display}")
        print()


def save_csv(results: dict, filepath: str, do_defang: bool = False):
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["indicator", "type", "defanged", "extracted_at"])
        ts = datetime.now().isoformat()
        for ioc_type, indicators in results.items():
            for ioc in indicators:
                defanged = defang(ioc, ioc_type)
                display = defanged if do_defang else ioc
                writer.writerow([display, ioc_type, do_defang, ts])
    print(f"[+] Saved CSV to {filepath}")


def save_json(results: dict, filepath: str, do_defang: bool = False):
    output = {
        "extracted_at": datetime.now().isoformat(),
        "source": "ThreatSignal IOC Extractor",
        "iocs": {}
    }
    for ioc_type, indicators in results.items():
        output["iocs"][ioc_type] = [
            defang(i, ioc_type) if do_defang else i for i in indicators
        ]
    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Saved JSON to {filepath}")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ThreatSignal IOC Extractor — extract indicators from text"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Input file path")
    group.add_argument("-t", "--text", help="Input text string")

    parser.add_argument("--defang", action="store_true", help="Defang indicators in output")
    parser.add_argument("--include-private", action="store_true",
                        help="Include private/reserved IP ranges")
    parser.add_argument("--csv", metavar="FILE", help="Save results to CSV")
    parser.add_argument("--json", metavar="FILE", help="Save results to JSON")
    parser.add_argument("--types", nargs="+",
                        choices=list(PATTERNS.keys()),
                        help="Only extract specific IOC types")

    args = parser.parse_args()

    # Load input
    if args.file:
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="ignore")
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
    else:
        text = args.text

    # Extract
    results = extract_iocs(text, exclude_private=not args.include_private)

    # Filter by type if requested
    if args.types:
        results = {k: v for k, v in results.items() if k in args.types}

    if not results:
        print("[*] No indicators found.")
        sys.exit(0)

    # Output
    print_results(results, do_defang=args.defang)

    if args.csv:
        save_csv(results, args.csv, do_defang=args.defang)

    if args.json:
        save_json(results, args.json, do_defang=args.defang)


if __name__ == "__main__":
    main()

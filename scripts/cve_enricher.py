#!/usr/bin/env python3
"""
cve_enricher.py - ThreatSignal CVE Enrichment Utility
======================================================
Enriches a list of CVE IDs with data from three authoritative sources:

  1. NVD (NIST)  - CVSS v3.1 score, vector, severity, description, affected CPEs
  2. EPSS (FIRST) - Exploit Prediction Scoring System score + percentile
  3. CISA KEV    - Whether the CVE is in CISA's Known Exploited Vulnerabilities catalog

Use this to quickly triage a patch list, prioritise a vuln backlog, or enrich
IOC reports with context about the CVEs referenced.

Requirements:
    pip install requests

Usage:
    # Single CVE
    python3 cve_enricher.py CVE-2025-0282

    # Multiple CVEs
    python3 cve_enricher.py CVE-2024-3400 CVE-2023-44487 CVE-2021-44228

    # From a file (one CVE per line)
    python3 cve_enricher.py -f cves.txt

    # Save to CSV or JSON
    python3 cve_enricher.py -f cves.txt --csv report.csv
    python3 cve_enricher.py -f cves.txt --json report.json

    # Filter: only critical / KEV-listed
    python3 cve_enricher.py -f cves.txt --min-cvss 9.0
    python3 cve_enricher.py -f cves.txt --kev-only

Author: ThreatSignal (https://threatsignal.in)
License: MIT
"""

import sys
import re
import json
import csv
import time
import argparse
from datetime import datetime
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] 'requests' library not found. Install with: pip install requests")
    sys.exit(1)


# ─── Config ───────────────────────────────────────────────────────────────────

NVD_API       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API      = "https://api.first.org/data/v1/epss"
KEV_URL       = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
REQUEST_DELAY = 0.7   # seconds between NVD calls (rate limit: ~50 req/30s without key)
TIMEOUT       = 15    # seconds per request

CVE_PATTERN   = re.compile(r'^CVE-\d{4}-\d{4,7}$', re.IGNORECASE)

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[33m",  # yellow
    "MEDIUM":   "\033[93m",  # light yellow
    "LOW":      "\033[92m",  # green
    "NONE":     "\033[0m",
}
RESET = "\033[0m"


# ─── Data Fetching ────────────────────────────────────────────────────────────

def fetch_kev_catalog() -> set:
    """Download CISA KEV catalog and return a set of CVE IDs."""
    try:
        r = requests.get(KEV_URL, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()
        return {v["cveID"].upper() for v in data.get("vulnerabilities", [])}
    except Exception as e:
        print(f"[!] Failed to fetch CISA KEV catalog: {e}", file=sys.stderr)
        return set()


def fetch_epss_bulk(cve_ids: list) -> dict:
    """Fetch EPSS scores for multiple CVEs in one call (API supports comma-separated)."""
    results = {}
    chunk_size = 100  # API limit per request
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i:i + chunk_size]
        try:
            r = requests.get(
                EPSS_API,
                params={"cve": ",".join(chunk), "envelope": "true"},
                timeout=TIMEOUT
            )
            r.raise_for_status()
            data = r.json()
            for item in data.get("data", []):
                results[item["cve"].upper()] = {
                    "score": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
        except Exception as e:
            print(f"[!] EPSS fetch error for chunk: {e}", file=sys.stderr)
    return results


def fetch_nvd(cve_id: str) -> dict:
    """Fetch CVE details from NVD API v2."""
    try:
        r = requests.get(
            NVD_API,
            params={"cveId": cve_id.upper()},
            timeout=TIMEOUT,
            headers={"Accept": "application/json"}
        )
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return {}
        return vulns[0].get("cve", {})
    except Exception as e:
        print(f"  [!] NVD fetch error for {cve_id}: {e}", file=sys.stderr)
        return {}


# ─── Parsing ──────────────────────────────────────────────────────────────────

def parse_nvd(cve_data: dict) -> dict:
    """Extract the fields we care about from the NVD CVE object."""
    out = {
        "description": "N/A",
        "cvss_score": None,
        "cvss_severity": "UNKNOWN",
        "cvss_vector": "N/A",
        "cvss_version": "N/A",
        "published": "N/A",
        "modified": "N/A",
        "cpes": [],
    }

    if not cve_data:
        return out

    # Description (English preferred)
    descs = cve_data.get("descriptions", [])
    for d in descs:
        if d.get("lang") == "en":
            out["description"] = d.get("value", "N/A")
            break

    # Published / modified dates
    out["published"] = cve_data.get("published", "N/A")[:10]
    out["modified"]  = cve_data.get("lastModified", "N/A")[:10]

    # CVSS - prefer v3.1, fall back to v3.0, then v2
    metrics = cve_data.get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key, [])
        if entries:
            m = entries[0]
            cvss = m.get("cvssData", {})
            out["cvss_score"]    = cvss.get("baseScore")
            out["cvss_severity"] = cvss.get("baseSeverity", "UNKNOWN").upper()
            out["cvss_vector"]   = cvss.get("vectorString", "N/A")
            out["cvss_version"]  = cvss.get("version", "N/A")
            break

    # CPEs (affected products)
    configs = cve_data.get("configurations", [])
    cpes = set()
    for config in configs:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    cpes.add(match.get("criteria", ""))
    out["cpes"] = sorted(cpes)[:10]  # cap at 10

    return out


# ─── Display ──────────────────────────────────────────────────────────────────

def severity_badge(severity: str, score) -> str:
    color = SEVERITY_COLORS.get(severity, "")
    score_str = f"{score:.1f}" if score else "N/A"
    return f"{color}[{severity} {score_str}]{RESET}"


def print_result(cve_id: str, result: dict, use_color: bool = True):
    nvd   = result["nvd"]
    epss  = result["epss"]
    in_kev = result["kev"]

    sev    = nvd["cvss_severity"]
    score  = nvd["cvss_score"]
    badge  = severity_badge(sev, score) if use_color else f"[{sev} {score}]"
    kev_str = "\033[91m⚠ IN CISA KEV\033[0m" if in_kev else "Not in KEV"

    epss_score = f"{epss['score']:.4f}" if epss else "N/A"
    epss_pct   = f"{epss['percentile']*100:.1f}th percentile" if epss else ""

    print(f"\n{'─'*64}")
    print(f"  {cve_id.upper()}  {badge}  {kev_str}")
    print(f"{'─'*64}")
    print(f"  Published : {nvd['published']}  |  Modified: {nvd['modified']}")
    print(f"  CVSS      : {score} ({nvd['cvss_version']})  {nvd['cvss_vector']}")
    print(f"  EPSS      : {epss_score}  {epss_pct}")

    desc = nvd["description"]
    if len(desc) > 200:
        desc = desc[:200] + "…"
    print(f"  Summary   : {desc}")

    if nvd["cpes"]:
        print(f"  Affected  : {nvd['cpes'][0]}")
        if len(nvd["cpes"]) > 1:
            print(f"              (+{len(nvd['cpes'])-1} more CPEs)")


def print_summary(results: dict):
    total = len(results)
    kev_count = sum(1 for r in results.values() if r["kev"])
    crits = sum(1 for r in results.values() if r["nvd"]["cvss_severity"] == "CRITICAL")
    highs = sum(1 for r in results.values() if r["nvd"]["cvss_severity"] == "HIGH")
    no_data = sum(1 for r in results.values() if r["nvd"]["cvss_score"] is None)

    print(f"\n{'='*64}")
    print(f"  SUMMARY - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*64}")
    print(f"  Total CVEs   : {total}")
    print(f"  Critical     : {crits}")
    print(f"  High         : {highs}")
    print(f"  In CISA KEV  : {kev_count}  {'⚠ Patch immediately' if kev_count else ''}")
    print(f"  No NVD data  : {no_data}")
    print(f"{'='*64}\n")


# ─── Output ───────────────────────────────────────────────────────────────────

def save_csv(results: dict, filepath: str):
    fields = [
        "cve_id", "cvss_score", "cvss_severity", "cvss_version",
        "cvss_vector", "epss_score", "epss_percentile",
        "in_kev", "published", "modified", "description"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for cve_id, r in results.items():
            nvd  = r["nvd"]
            epss = r["epss"] or {}
            w.writerow({
                "cve_id":           cve_id.upper(),
                "cvss_score":       nvd["cvss_score"] or "",
                "cvss_severity":    nvd["cvss_severity"],
                "cvss_version":     nvd["cvss_version"],
                "cvss_vector":      nvd["cvss_vector"],
                "epss_score":       epss.get("score", ""),
                "epss_percentile":  epss.get("percentile", ""),
                "in_kev":           r["kev"],
                "published":        nvd["published"],
                "modified":         nvd["modified"],
                "description":      nvd["description"][:300],
            })
    print(f"[+] Saved CSV: {filepath}")


def save_json(results: dict, filepath: str):
    output = {
        "generated_at": datetime.now().isoformat(),
        "source": "ThreatSignal CVE Enricher (threatsignal.in)",
        "count": len(results),
        "cves": results
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Saved JSON: {filepath}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def load_cves_from_file(path: str) -> list:
    cves = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip().split("#")[0].strip()  # strip inline comments
        if CVE_PATTERN.match(line):
            cves.append(line.upper())
        elif line:
            print(f"[!] Skipping invalid line: {line}", file=sys.stderr)
    return cves


def main():
    parser = argparse.ArgumentParser(
        description="ThreatSignal CVE Enricher - CVSS + EPSS + CISA KEV in one shot"
    )
    parser.add_argument("cves", nargs="*", help="CVE IDs (e.g. CVE-2024-1234)")
    parser.add_argument("-f", "--file", help="File with one CVE ID per line")
    parser.add_argument("--csv",  metavar="FILE", help="Save results to CSV")
    parser.add_argument("--json", metavar="FILE", help="Save results to JSON")
    parser.add_argument("--min-cvss", type=float, default=0.0,
                        help="Only show CVEs with CVSS >= threshold (e.g. 9.0)")
    parser.add_argument("--kev-only", action="store_true",
                        help="Only show CVEs listed in CISA KEV")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    args = parser.parse_args()

    # Gather CVE list
    cve_ids = [c.upper() for c in args.cves if CVE_PATTERN.match(c)]
    if args.file:
        cve_ids += load_cves_from_file(args.file)
    cve_ids = list(dict.fromkeys(cve_ids))  # deduplicate, preserve order

    if not cve_ids:
        print("[!] No valid CVE IDs provided. Use --help for usage.")
        sys.exit(1)

    print(f"[*] Enriching {len(cve_ids)} CVE(s)...")

    # Step 1: CISA KEV (single bulk download)
    print("[*] Fetching CISA KEV catalog...", end=" ", flush=True)
    kev_set = fetch_kev_catalog()
    print(f"{len(kev_set)} entries loaded")

    # Step 2: EPSS (bulk)
    print("[*] Fetching EPSS scores...", end=" ", flush=True)
    epss_data = fetch_epss_bulk(cve_ids)
    print(f"{len(epss_data)} scores returned")

    # Step 3: NVD (one by one - rate limited)
    print("[*] Fetching NVD data (rate-limited)...")
    results = {}
    for i, cve_id in enumerate(cve_ids, 1):
        print(f"  [{i}/{len(cve_ids)}] {cve_id}", end="  ", flush=True)
        nvd_raw = fetch_nvd(cve_id)
        nvd     = parse_nvd(nvd_raw)
        results[cve_id] = {
            "nvd":  nvd,
            "epss": epss_data.get(cve_id),
            "kev":  cve_id in kev_set,
        }
        print(f"CVSS {nvd['cvss_score'] or 'N/A'}  EPSS {epss_data.get(cve_id, {}).get('score', 'N/A')}")
        if i < len(cve_ids):
            time.sleep(REQUEST_DELAY)

    # Apply filters
    filtered = {
        k: v for k, v in results.items()
        if (v["nvd"]["cvss_score"] or 0) >= args.min_cvss
        and (not args.kev_only or v["kev"])
    }

    if not filtered:
        print("[*] No results after filtering.")
        sys.exit(0)

    # Display
    for cve_id, result in filtered.items():
        print_result(cve_id, result, use_color=not args.no_color)

    print_summary(filtered)

    # Save outputs
    if args.csv:
        save_csv(filtered, args.csv)
    if args.json:
        save_json(filtered, args.json)


if __name__ == "__main__":
    main()

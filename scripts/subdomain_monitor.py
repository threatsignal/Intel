#!/usr/bin/env python3
"""
subdomain_monitor.py — ThreatSignal Subdomain Discovery & Monitor
=================================================================
Discovers subdomains for a target domain using certificate transparency
logs (crt.sh) and passive DNS sources, then performs live DNS resolution
and optional HTTP probing to identify active attack surface.

Use cases:
  - Attack surface mapping before a pentest or bug bounty
  - Monitoring for newly registered subdomains (typosquatting, brand abuse)
  - Tracking your own infrastructure exposure
  - Threat intel: mapping adversary infrastructure by pivot domain

Requirements:
    pip install requests dnspython

Usage:
    # Basic discovery
    python3 subdomain_monitor.py example.com

    # Include HTTP probing (checks if hosts are alive on 80/443)
    python3 subdomain_monitor.py example.com --probe

    # Save results
    python3 subdomain_monitor.py example.com --csv results.csv --json results.json

    # Monitor mode: compare against a known baseline, alert on new subdomains
    python3 subdomain_monitor.py example.com --baseline baseline.txt --alert-new

    # Save current results as a baseline for future monitoring
    python3 subdomain_monitor.py example.com --save-baseline baseline.txt

    # Quiet: only print new/alive subdomains
    python3 subdomain_monitor.py example.com --probe --quiet

Author: ThreatSignal (https://threatsignal.in)
License: MIT
"""

import sys
import json
import csv
import socket
import argparse
import time
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

try:
    import requests
    import dns.resolver
    import dns.exception
except ImportError as e:
    missing = str(e).split("'")[1] if "'" in str(e) else str(e)
    print(f"[!] Missing dependency: {missing}")
    print("    Install with: pip install requests dnspython")
    sys.exit(1)


# ─── Config ───────────────────────────────────────────────────────────────────

CRTSH_URL     = "https://crt.sh/?q=%25.{domain}&output=json"
HACKERTARGET  = "https://api.hackertarget.com/hostsearch/?q={domain}"
TIMEOUT       = 10
HTTP_TIMEOUT  = 5
MAX_WORKERS   = 30
DNS_TIMEOUT   = 3.0
PROBE_PORTS   = [80, 443]


# ─── Discovery Sources ────────────────────────────────────────────────────────

def fetch_crtsh(domain: str) -> set:
    """Query crt.sh certificate transparency logs."""
    subdomains = set()
    try:
        r = requests.get(
            CRTSH_URL.format(domain=domain),
            timeout=TIMEOUT,
            headers={"Accept": "application/json"}
        )
        r.raise_for_status()
        data = r.json()
        for entry in data:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name.lower())
    except requests.exceptions.JSONDecodeError:
        pass  # crt.sh sometimes returns HTML on rate limit
    except Exception as e:
        print(f"  [!] crt.sh error: {e}", file=sys.stderr)
    return subdomains


def fetch_hackertarget(domain: str) -> set:
    """Query HackerTarget passive DNS (free tier: 100 req/day)."""
    subdomains = set()
    try:
        r = requests.get(
            HACKERTARGET.format(domain=domain),
            timeout=TIMEOUT
        )
        if "API count exceeded" in r.text or "error" in r.text.lower()[:30]:
            print("  [!] HackerTarget rate limit hit — skipping this source", file=sys.stderr)
            return subdomains
        for line in r.text.splitlines():
            parts = line.split(",")
            if parts:
                name = parts[0].strip().lower()
                if name.endswith(f".{domain}") or name == domain:
                    subdomains.add(name)
    except Exception as e:
        print(f"  [!] HackerTarget error: {e}", file=sys.stderr)
    return subdomains


# ─── DNS Resolution ───────────────────────────────────────────────────────────

def resolve_dns(subdomain: str) -> dict:
    """Resolve a subdomain — A, AAAA, CNAME records."""
    result = {
        "subdomain": subdomain,
        "resolved": False,
        "ips": [],
        "cname": None,
        "record_type": None,
    }
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    # Try A record
    try:
        answers = resolver.resolve(subdomain, "A")
        result["resolved"] = True
        result["ips"] = [str(r) for r in answers]
        result["record_type"] = "A"
        return result
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    except Exception:
        pass

    # Try CNAME
    try:
        answers = resolver.resolve(subdomain, "CNAME")
        result["resolved"] = True
        result["cname"] = str(answers[0].target).rstrip(".")
        result["record_type"] = "CNAME"
        return result
    except Exception:
        pass

    # Try AAAA
    try:
        answers = resolver.resolve(subdomain, "AAAA")
        result["resolved"] = True
        result["ips"] = [str(r) for r in answers]
        result["record_type"] = "AAAA"
    except Exception:
        pass

    return result


# ─── HTTP Probing ─────────────────────────────────────────────────────────────

def probe_http(subdomain: str, ips: list) -> dict:
    """Check if a subdomain responds on HTTP/HTTPS."""
    probe = {
        "http_alive": False,
        "https_alive": False,
        "status_code": None,
        "title": None,
        "redirect": None,
        "server": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            r = requests.get(
                url,
                timeout=HTTP_TIMEOUT,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "ThreatSignal-Monitor/1.0 (+https://threatsignal.in)"}
            )
            alive_key = f"{scheme}_alive"
            probe[alive_key] = True
            probe["status_code"] = r.status_code
            probe["server"] = r.headers.get("Server", "")

            # Extract title
            if "<title>" in r.text.lower():
                start = r.text.lower().find("<title>") + 7
                end   = r.text.lower().find("</title>", start)
                probe["title"] = r.text[start:end].strip()[:80]

            # Detect redirect
            if r.url != url:
                probe["redirect"] = r.url

            break  # if HTTPS works, skip HTTP

        except requests.exceptions.SSLError:
            probe["https_alive"] = False
        except Exception:
            pass

    return probe


# ─── Display ──────────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def fmt_status(resolved: bool, http_alive: bool, https_alive: bool, new: bool) -> str:
    parts = []
    if new:
        parts.append(f"{YELLOW}NEW{RESET}")
    if resolved:
        if https_alive:
            parts.append(f"{GREEN}HTTPS{RESET}")
        elif http_alive:
            parts.append(f"{CYAN}HTTP{RESET}")
        else:
            parts.append(f"{BOLD}DNS-ONLY{RESET}")
    else:
        parts.append(f"{RED}DEAD{RESET}")
    return " ".join(parts) if parts else ""


def print_result(r: dict, do_probe: bool, new_set: set, quiet: bool):
    sub    = r["subdomain"]
    dns_r  = r["dns"]
    probe  = r.get("probe", {})
    is_new = sub in new_set

    if quiet and not is_new and not dns_r["resolved"]:
        return
    if quiet and not dns_r["resolved"] and not probe.get("http_alive") and not probe.get("https_alive"):
        return

    status = fmt_status(
        dns_r["resolved"],
        probe.get("http_alive", False),
        probe.get("https_alive", False),
        is_new
    )

    ips = ", ".join(dns_r["ips"]) if dns_r["ips"] else (dns_r["cname"] or "")
    print(f"  {sub:<50} {status:<30} {ips}")

    if do_probe and probe.get("title"):
        print(f"    {'':50} Title: {probe['title']}")
    if do_probe and probe.get("redirect"):
        print(f"    {'':50} → {probe['redirect']}")


def print_header(domain: str, total: int, do_probe: bool):
    print(f"\n{'='*80}")
    print(f"  {BOLD}ThreatSignal Subdomain Monitor{RESET}  —  {domain}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  {total} subdomains to resolve")
    if do_probe:
        print(f"  HTTP probing: enabled")
    print(f"{'='*80}")
    print(f"  {'SUBDOMAIN':<50} {'STATUS':<30} {'IP / CNAME'}")
    print(f"  {'-'*78}")


def print_summary(results: list, new_count: int, elapsed: float):
    alive   = sum(1 for r in results if r["dns"]["resolved"])
    https_c = sum(1 for r in results if r.get("probe", {}).get("https_alive"))
    http_c  = sum(1 for r in results if r.get("probe", {}).get("http_alive") and not r.get("probe", {}).get("https_alive"))
    dead    = len(results) - alive

    print(f"\n{'='*80}")
    print(f"  SUMMARY")
    print(f"{'='*80}")
    print(f"  Total discovered : {len(results)}")
    print(f"  DNS resolving    : {alive}")
    print(f"  HTTPS alive      : {https_c}")
    print(f"  HTTP-only alive  : {http_c}")
    print(f"  Dead (no DNS)    : {dead}")
    if new_count:
        print(f"  {YELLOW}New subdomains   : {new_count}  ← investigate these{RESET}")
    print(f"  Completed in     : {elapsed:.1f}s")
    print(f"{'='*80}\n")


# ─── Output ───────────────────────────────────────────────────────────────────

def save_csv(results: list, filepath: str):
    fields = [
        "subdomain", "resolved", "record_type", "ips", "cname",
        "http_alive", "https_alive", "status_code", "title", "redirect", "server"
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in results:
            dns_r = r["dns"]
            probe = r.get("probe", {})
            w.writerow({
                "subdomain":   dns_r["subdomain"],
                "resolved":    dns_r["resolved"],
                "record_type": dns_r["record_type"] or "",
                "ips":         "|".join(dns_r["ips"]),
                "cname":       dns_r["cname"] or "",
                "http_alive":  probe.get("http_alive", ""),
                "https_alive": probe.get("https_alive", ""),
                "status_code": probe.get("status_code", ""),
                "title":       probe.get("title", ""),
                "redirect":    probe.get("redirect", ""),
                "server":      probe.get("server", ""),
            })
    print(f"[+] Saved CSV: {filepath}")


def save_json(results: list, filepath: str, domain: str):
    output = {
        "generated_at": datetime.now().isoformat(),
        "domain": domain,
        "source": "ThreatSignal Subdomain Monitor (threatsignal.in)",
        "count": len(results),
        "results": results
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"[+] Saved JSON: {filepath}")


def save_baseline(results: list, filepath: str):
    subdomains = sorted({r["dns"]["subdomain"] for r in results if r["dns"]["resolved"]})
    Path(filepath).write_text("\n".join(subdomains) + "\n", encoding="utf-8")
    print(f"[+] Baseline saved: {filepath}  ({len(subdomains)} live subdomains)")


def load_baseline(filepath: str) -> set:
    return {line.strip() for line in Path(filepath).read_text().splitlines() if line.strip()}


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    # Suppress InsecureRequestWarning from urllib3
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(
        description="ThreatSignal Subdomain Monitor — cert transparency + DNS + HTTP probing"
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--probe", action="store_true",
                        help="HTTP/HTTPS probe each resolved subdomain")
    parser.add_argument("--csv",  metavar="FILE", help="Save results to CSV")
    parser.add_argument("--json", metavar="FILE", help="Save results to JSON")
    parser.add_argument("--baseline",      metavar="FILE",
                        help="Baseline file to compare against (monitor mode)")
    parser.add_argument("--save-baseline", metavar="FILE",
                        help="Save live subdomains to a baseline file")
    parser.add_argument("--alert-new", action="store_true",
                        help="Print only new subdomains (requires --baseline)")
    parser.add_argument("--threads", type=int, default=MAX_WORKERS,
                        help=f"DNS/probe threads (default: {MAX_WORKERS})")
    parser.add_argument("--no-hackertarget", action="store_true",
                        help="Skip HackerTarget source (saves API quota)")
    parser.add_argument("--quiet", action="store_true",
                        help="Only print alive / new subdomains")
    args = parser.parse_args()

    domain = args.domain.lower().strip().rstrip("/")
    start  = time.time()

    # ── Discovery ──
    print(f"\n[*] Starting subdomain discovery for: {BOLD}{domain}{RESET}")

    print("[*] Querying crt.sh (certificate transparency)...", end=" ", flush=True)
    found = fetch_crtsh(domain)
    print(f"{len(found)} results")

    if not args.no_hackertarget:
        print("[*] Querying HackerTarget passive DNS...", end=" ", flush=True)
        ht = fetch_hackertarget(domain)
        found |= ht
        print(f"{len(ht)} results")

    # Always include the apex domain
    found.add(domain)

    print(f"[*] Total unique subdomains to check: {len(found)}")

    # ── Baseline comparison ──
    baseline = set()
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
            print(f"[*] Baseline loaded: {len(baseline)} known live subdomains")
        except FileNotFoundError:
            print(f"[!] Baseline file not found: {args.baseline}", file=sys.stderr)

    # ── DNS Resolution (threaded) ──
    print(f"[*] Resolving DNS with {args.threads} threads...")
    sorted_subs = sorted(found)
    dns_results = []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(resolve_dns, sub): sub for sub in sorted_subs}
        for future in as_completed(futures):
            dns_results.append(future.result())

    # Sort: resolved first, then alphabetical
    dns_results.sort(key=lambda r: (not r["resolved"], r["subdomain"]))

    # ── HTTP Probing (optional, threaded) ──
    results = []
    if args.probe:
        print(f"[*] HTTP probing {sum(1 for r in dns_results if r['resolved'])} live hosts...")
        with ThreadPoolExecutor(max_workers=args.threads) as ex:
            def probe_entry(dns_r):
                probe = probe_http(dns_r["subdomain"], dns_r["ips"]) if dns_r["resolved"] else {}
                return {"dns": dns_r, "probe": probe}
            futures = {ex.submit(probe_entry, r): r for r in dns_results}
            for future in as_completed(futures):
                results.append(future.result())
        results.sort(key=lambda r: (not r["dns"]["resolved"], r["dns"]["subdomain"]))
    else:
        results = [{"dns": r} for r in dns_results]

    # ── Identify new subdomains ──
    resolved_now = {r["dns"]["subdomain"] for r in results if r["dns"]["resolved"]}
    new_subs     = resolved_now - baseline if baseline else set()

    # ── Display ──
    if not args.quiet or not args.alert_new:
        print_header(domain, len(results), args.probe)
        for r in results:
            print_result(r, args.probe, new_subs, args.quiet)

    if args.alert_new and new_subs:
        print(f"\n{YELLOW}{'!'*60}{RESET}")
        print(f"{YELLOW}  ⚠  {len(new_subs)} NEW SUBDOMAIN(S) DETECTED:{RESET}")
        print(f"{YELLOW}{'!'*60}{RESET}")
        for sub in sorted(new_subs):
            dns_r = next((r["dns"] for r in results if r["dns"]["subdomain"] == sub), {})
            print(f"  {sub}  →  {', '.join(dns_r.get('ips', [])) or dns_r.get('cname', '')}")

    elapsed = time.time() - start
    print_summary(results, len(new_subs), elapsed)

    # ── Save outputs ──
    if args.csv:
        save_csv(results, args.csv)
    if args.json:
        save_json(results, args.json, domain)
    if args.save_baseline:
        save_baseline(results, args.save_baseline)


if __name__ == "__main__":
    main()

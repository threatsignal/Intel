#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_feeds.py — ThreatSignal IOC Feed Aggregator (with Autopilot & Attribution)
================================================================================
Aggregates indicators from various public threat intelligence feeds:
- Feodo Tracker (Botnet C2 IPs)
- Threatview (Cobalt Strike C2, MD5/SHA hashes)
- OpenPhish & URLhaus (Phishing URLs/domains)
- Proofpoint ET & Binary Defense (Malicious/Compromised IPs)
- MalwareBazaar (Optional, requires abuse.ch Auth-Key)

Outputs clean, deduplicated, and classified feeds in the ioc-feeds/ directory:
- malicious-ips.txt / .csv
- phishing-domains.txt / .csv
- malware-hashes.csv
- c2-infrastructure.csv

Author: ThreatSignal (https://threatsignal.in)
License: MIT
"""

import os
import sys
import re
import csv
import json
import argparse
from urllib.request import Request, urlopen
from urllib.parse import urlparse
from urllib.error import URLError
from datetime import datetime

# ─── Configuration & Defaults ─────────────────────────────────────────────────

# False-positive / top-level noise domains to exclude
FP_DOMAINS = {
    "example.com", "test.com", "localhost", "localhost.localdomain",
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "facebook.com", "twitter.com", "instagram.com", "youtube.com", "linkedin.com",
    "roblox.com", "netflix.com", "cloudflare.com", "fastly.net", "akamai.net",
    "android.com", "googleusercontent.com", "googleapis.com"
}

# Regex helper to check if indicator is an IP address
IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def is_public_ip(ip: str) -> bool:
    """Checks if an IPv4 address is a valid, publicly routable address (filters private/reserved blocks)."""
    if not IP_RE.match(ip):
        return False
    parts = [int(p) for p in ip.split('.')]
    if len(parts) != 4:
        return False
    
    # 0.0.0.0/8 (Local network / broadcast source)
    if parts[0] == 0:
        return False
    # 10.0.0.0/8 (Private network)
    if parts[0] == 10:
        return False
    # 127.0.0.0/8 (Loopback)
    if parts[0] == 127:
        return False
    # 169.254.0.0/16 (Link-local)
    if parts[0] == 169 and parts[1] == 254:
        return False
    # 172.16.0.0/12 (Private network)
    if parts[0] == 172 and (16 <= parts[1] <= 31):
        return False
    # 192.0.0.0/24 (IETF Reserved)
    if parts[0] == 192 and parts[1] == 0 and parts[2] == 0:
        return False
    # 192.0.2.0/24 (TEST-NET-1 for documentation)
    if parts[0] == 192 and parts[1] == 0 and parts[2] == 2:
        return False
    # 192.168.0.0/16 (Private network)
    if parts[0] == 192 and parts[1] == 168:
        return False
    # 198.18.0.0/15 (Network benchmarking)
    if parts[0] == 198 and (18 <= parts[1] <= 19):
        return False
    # 198.51.100.0/24 (TEST-NET-2)
    if parts[0] == 198 and parts[1] == 51 and parts[2] == 100:
        return False
    # 203.0.113.0/24 (TEST-NET-3)
    if parts[0] == 203 and parts[1] == 0 and parts[2] == 113:
        return False
    # 224.0.0.0/4 (Multicast)
    if parts[0] >= 224:
        return False
        
    return True

# ─── Threat Actor Attribution Map ──────────────────────────────────────────────
# Maps common malware families (lowercase) to known threat actors and normalized family names
ATTRIBUTION_MAP = {
    "qakbot": {"actor": "TA551 / Gold Lagoon", "family": "QakBot"},
    "qbot": {"actor": "TA551 / Gold Lagoon", "family": "QakBot"},
    "emotet": {"actor": "TA542 / Mummy Spider", "family": "Emotet"},
    "cobalt strike": {"actor": "Multiple (APT29 / FIN7 / Ransomware)", "family": "Cobalt Strike"},
    "agenttesla": {"actor": "Multiple (Crimeware)", "family": "AgentTesla"},
    "agent tesla": {"actor": "Multiple (Crimeware)", "family": "AgentTesla"},
    "formbook": {"actor": "Multiple (Crimeware)", "family": "Formbook"},
    "redline stealer": {"actor": "Unknown (Crimeware)", "family": "RedLine Stealer"},
    "redline": {"actor": "Unknown (Crimeware)", "family": "RedLine Stealer"},
    "asyncrat": {"actor": "Multiple (Crimeware)", "family": "AsyncRAT"},
    "lokibot": {"actor": "Multiple (Crimeware)", "family": "LokiBot"},
    "njrat": {"actor": "Multiple (Crimeware)", "family": "njRAT"},
    "remcos": {"actor": "Multiple (Crimeware)", "family": "Remcos RAT"},
    "remcosrat": {"actor": "Multiple (Crimeware)", "family": "Remcos RAT"},
    "nanocore": {"actor": "Multiple (Crimeware)", "family": "NanoCore"},
    "icedid": {"actor": "TA551 / Lunar Spider", "family": "IcedID"},
    "trickbot": {"actor": "Wizard Spider", "family": "TrickBot"},
    "bumblebee": {"actor": "Exotic Lily / Mummy Spider", "family": "Bumblebee"},
    "smokeloader": {"actor": "Unknown (Crimeware)", "family": "SmokeLoader"},
    "socgholish": {"actor": "Indrik Spider / Evil Corp", "family": "SocGholish"},
    "dcrath": {"actor": "Multiple (Crimeware)", "family": "DcRAT"},
    "dc rat": {"actor": "Multiple (Crimeware)", "family": "DcRAT"},
    "lumma": {"actor": "Unknown (Crimeware)", "family": "Lumma Stealer"},
    "lummastealer": {"actor": "Unknown (Crimeware)", "family": "Lumma Stealer"},
    "pikabot": {"actor": "Unknown (Crimeware)", "family": "Pikabot"},
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def defang_domain(domain: str) -> str:
    """Defangs a domain name (e.g., example.com -> example[.]com)."""
    return domain.replace(".", "[.]")


def extract_domain(url: str) -> str:
    """Extracts host/domain from a URL and removes ports or credentials."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        return netloc.lower().strip()
    except Exception:
        return ""


def clean_indicator(indicator: str) -> str:
    """Cleans up leading/trailing whitespaces and characters."""
    return indicator.strip().strip('"').strip("'")


def get_attribution(malware_name: str) -> tuple:
    """Returns (threat_actor, normalized_malware_family) based on attribution map."""
    if not malware_name:
        return ("Unknown", "Unknown")
    name_lower = malware_name.lower().strip()
    # Direct match
    if name_lower in ATTRIBUTION_MAP:
        mapping = ATTRIBUTION_MAP[name_lower]
        return (mapping["actor"], mapping["family"])
    
    # Substring search
    for key, mapping in ATTRIBUTION_MAP.items():
        if key in name_lower or name_lower in key:
            return (mapping["actor"], mapping["family"])
            
    return ("Unknown", malware_name)


def is_attributed(threat_actor: str, malware_family: str) -> bool:
    """Returns True if the indicator is attributed (at least one of threat_actor or malware_family is known)."""
    clean_actor = (threat_actor or "").strip().lower()
    clean_family = (malware_family or "").strip().lower()
    
    actor_unknown = clean_actor in ("", "unknown", "unknown (crimeware)", "none")
    family_unknown = clean_family in ("", "unknown", "unknown (crimeware)", "none")
    
    return not (actor_unknown and family_unknown)


def fetch_url(url: str, post_data: bytes = None, headers: dict = None) -> bytes:
    """Fetches URL contents using standard library urllib, with timeouts & User-Agent."""
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)"
    }
    if headers:
        req_headers.update(headers)

    req = Request(url, data=post_data, headers=req_headers)
    try:
        with urlopen(req, timeout=15) as response:
            return response.read()
    except URLError as e:
        print(f"[-] Warning: Failed to fetch {url}. Reason: {e}", file=sys.stderr)
        return b""
    except Exception as e:
        print(f"[-] Warning: Unexpected error fetching {url}. Reason: {e}", file=sys.stderr)
        return b""


# ─── Aggregation Functions ───────────────────────────────────────────────────

def get_c2_feeds(limit: int) -> list:
    """Aggregates C2 indicators, populating classification and threat actor attribution."""
    print("[+] Fetching C2 infrastructure feeds...")
    c2_indicators = []

    # 1. Feodo Tracker JSON Feed
    feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    feodo_data = fetch_url(feodo_url)
    if feodo_data:
        try:
            entries = json.loads(feodo_data.decode("utf-8", errors="ignore"))
            if isinstance(entries, list):
                for entry in entries:
                    ip = entry.get("ip_address")
                    raw_malware = entry.get("malware", "Unknown C2")
                    last_seen = entry.get("last_online", datetime.now().strftime("%Y-%m-%d"))
                    
                    actor, malware = get_attribution(raw_malware)
                    
                    if ip and is_public_ip(ip) and is_attributed(actor, malware):
                        c2_indicators.append({
                            "indicator": ip,
                            "type": "ip",
                            "confidence": "High",
                            "threat_actor": actor,
                            "malware_family": malware,
                            "first_seen": last_seen,
                            "last_seen": last_seen,
                            "source": "Feodo Tracker",
                            "notes": f"Active Botnet C2 (Port: {entry.get('port')})"
                        })
        except Exception as e:
            print(f"[-] Failed to parse Feodo Tracker JSON: {e}", file=sys.stderr)

    # 2. Threatview Cobalt Strike C2 Feed
    cs_url = "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt"
    cs_data = fetch_url(cs_url)
    if cs_data:
        lines = cs_data.decode("utf-8", errors="ignore").splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) >= 5:
                ip = clean_indicator(parts[0])
                host = clean_indicator(parts[2])
                protocol = clean_indicator(parts[3])
                beacon_config = clean_indicator(parts[4])
                
                det_date = datetime.now().strftime("%Y-%m-%d")
                if len(parts) >= 2:
                    raw_date = parts[1]
                    try:
                        date_parts = raw_date.split()[:3]
                        if len(date_parts) == 3:
                            dt = datetime.strptime(" ".join(date_parts), "%d %B %Y")
                            det_date = dt.strftime("%Y-%m-%d")
                    except Exception:
                        pass

                actor, malware = get_attribution("Cobalt Strike")
                if not is_attributed(actor, malware):
                    continue

                # Add IP indicator
                if ip and is_public_ip(ip):
                    c2_indicators.append({
                        "indicator": ip,
                        "type": "ip",
                        "confidence": "High",
                        "threat_actor": actor,
                        "malware_family": malware,
                        "first_seen": det_date,
                        "last_seen": det_date,
                        "source": "Threatview.io",
                        "notes": f"CS C2 Relay (Protocol: {protocol}, Config: {beacon_config})"
                    })
                
                # Add domain/host indicator
                if host and not IP_RE.match(host) and host not in FP_DOMAINS:
                    defanged_host = defang_domain(host)
                    c2_indicators.append({
                        "indicator": defanged_host,
                        "type": "domain",
                        "confidence": "High",
                        "threat_actor": actor,
                        "malware_family": malware,
                        "first_seen": det_date,
                        "last_seen": det_date,
                        "source": "Threatview.io",
                        "notes": f"CS C2 Domain (Protocol: {protocol}, Config: {beacon_config})"
                    })

    # Sort and Deduplicate
    unique_c2 = {}
    for item in c2_indicators:
        ind = item["indicator"]
        if ind not in unique_c2:
            unique_c2[ind] = item
        else:
            existing = unique_c2[ind]
            if len(item["notes"]) > len(existing["notes"]):
                unique_c2[ind] = item

    deduped_list = list(unique_c2.values())
    deduped_list.sort(key=lambda x: (x["first_seen"], x["indicator"]), reverse=True)

    if limit > 0:
        return deduped_list[:limit]
    return deduped_list


def get_malicious_ips(limit: int) -> list:
    """Aggregates malicious IPs. Returns empty list as all generic scanner/proxy (Tor) feeds are discarded."""
    print("[*] Discarding all generic scanner and proxy (Tor) IP feeds. General IP lists will remain empty.")
    return []


def get_phishing_domains(limit: int) -> list:
    """Aggregates phishing domains. Returns empty list as generic unattributed domain feeds are discarded."""
    print("[*] Discarding all generic/unattributed phishing domain feeds.")
    return []


def get_malware_hashes(auth_key: str, limit: int) -> list:
    """Aggregates malware file hashes. ONLY returns attributed hashes (where family is known)."""
    hashes = []
    seen_hashes = set()

    # 1. Optional authenticated MalwareBazaar lookup (which provides signatures/families)
    if auth_key:
        print("[+] Fetching live malware hashes from MalwareBazaar API (authenticated)...")
        bazaar_url = "https://mb-api.abuse.ch/api/v1/"
        payload = "query=get_recent&selector=time"
        headers = {"Auth-Key": auth_key, "Content-Type": "application/x-www-form-urlencoded"}
        bazaar_data = fetch_url(bazaar_url, post_data=payload.encode("utf-8"), headers=headers)
        
        if bazaar_data:
            try:
                res_json = json.loads(bazaar_data.decode("utf-8", errors="ignore"))
                if res_json.get("query_status") == "ok":
                    data = res_json.get("data", [])
                    for item in data:
                        sha256 = item.get("sha256_hash")
                        md5 = item.get("md5_hash")
                        raw_malware = item.get("signature") or "Unknown"
                        first_seen = item.get("first_seen", datetime.now().strftime("%Y-%m-%d"))
                        
                        actor, malware = get_attribution(raw_malware)
                        
                        # Only keep if malware family is known/attributed (NOT Unknown/None/empty)
                        if not is_attributed(actor, malware):
                            continue
                            
                        if sha256 and sha256 not in seen_hashes:
                            seen_hashes.add(sha256)
                            hashes.append({
                                "hash": sha256,
                                "type": "sha256",
                                "malware_family": malware,
                                "threat_actor": actor,
                                "first_seen": first_seen,
                                "source": "MalwareBazaar"
                            })
                        if md5 and md5 not in seen_hashes:
                            seen_hashes.add(md5)
                            hashes.append({
                                "hash": md5,
                                "type": "md5",
                                "malware_family": malware,
                                "threat_actor": actor,
                                "first_seen": first_seen,
                                "source": "MalwareBazaar"
                            })
            except Exception as e:
                print(f"[-] Error parsing MalwareBazaar response: {e}", file=sys.stderr)
    
    # 2. Fallbacks (Threatview MD5/SHA) - skipped completely as they are unattributed ("Unknown")
    if not auth_key:
        print("[*] Note: Public Threatview hash feeds do not contain malware family attribution.")
        print("[*] Filtering out all unattributed hashes. Run with --key to populate with attributed hashes.")
        
    # Sort hashes
    hashes.sort(key=lambda x: (x["first_seen"], x["hash"]), reverse=True)
    if limit > 0:
        return hashes[:limit]
    return hashes


# ─── File Writing ─────────────────────────────────────────────────────────────

def write_txt_file(filepath: str, items: list):
    """Writes list items to a text file, one per line."""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            for item in items:
                f.write(f"{item}\n")
        print(f"[+] Successfully wrote {len(items)} indicators to {filepath}")
    except Exception as e:
        print(f"[-] Failed to write to {filepath}: {e}", file=sys.stderr)


def write_csv_file(filepath: str, items: list, fieldnames: list):
    """Writes list of dicts to a CSV file."""
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for item in items:
                filtered_item = {k: item.get(k, "") for k in fieldnames}
                writer.writerow(filtered_item)
        print(f"[+] Successfully wrote {len(items)} rows to {filepath}")
    except Exception as e:
        print(f"[-] Failed to write to {filepath}: {e}", file=sys.stderr)


# ─── Main Execution ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="ThreatSignal Threat Intelligence Feed Aggregator (with Autopilot & Attribution)"
    )
    parser.add_argument(
        "-l", "--limit", type=int, default=250,
        help="Maximum number of indicators to output per file (default: 250, 0 for unlimited)"
    )
    parser.add_argument(
        "-k", "--key", type=str, default=os.getenv("ABUSE_CH_AUTH_KEY"),
        help="Abuse.ch API Auth-Key (falls back to ABUSE_CH_AUTH_KEY env var)"
    )
    parser.add_argument(
        "-o", "--output-dir", type=str,
        help="Output directory for IOC files (default: ../ioc-feeds relative to script)"
    )

    args = parser.parse_args()

    # Determine paths
    script_dir = os.path.dirname(os.path.realpath(__file__))
    if args.output_dir:
        output_dir = os.path.abspath(args.output_dir)
    else:
        output_dir = os.path.abspath(os.path.join(script_dir, "../ioc-feeds"))

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  ThreatSignal IOC Feed Aggregator — Running Updates")
    print(f"  Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Output Dir: {output_dir}")
    print(f"  Limit per file: {args.limit if args.limit > 0 else 'Unlimited'}")
    print("=" * 60)

    # 1. Update malicious-ips
    ip_records = get_malicious_ips(args.limit)
    # Write plain txt list
    write_txt_file(os.path.join(output_dir, "malicious-ips.txt"), [r["ip"] for r in ip_records])
    # Write rich CSV list
    ip_csv_fields = ["ip", "classification", "confidence", "threat_actor", "malware_family", "first_seen", "last_seen", "source", "notes"]
    write_csv_file(os.path.join(output_dir, "malicious-ips.csv"), ip_records, ip_csv_fields)
    print("-" * 60)

    # 2. Update phishing-domains
    domain_records = get_phishing_domains(args.limit)
    # Write plain txt list
    write_txt_file(os.path.join(output_dir, "phishing-domains.txt"), [r["domain"] for r in domain_records])
    # Write rich CSV list
    domain_csv_fields = ["domain", "classification", "confidence", "threat_actor", "malware_family", "first_seen", "last_seen", "source", "notes"]
    write_csv_file(os.path.join(output_dir, "phishing-domains.csv"), domain_records, domain_csv_fields)
    print("-" * 60)

    # 3. Update malware-hashes.csv
    hash_fields = ["hash", "type", "malware_family", "threat_actor", "first_seen", "source"]
    hashes = get_malware_hashes(args.key, args.limit)
    write_csv_file(os.path.join(output_dir, "malware-hashes.csv"), hashes, hash_fields)
    print("-" * 60)

    # 4. Update c2-infrastructure.csv
    c2_fields = ["indicator", "type", "confidence", "threat_actor", "malware_family", "first_seen", "last_seen", "source", "notes"]
    c2s = get_c2_feeds(args.limit)
    write_csv_file(os.path.join(output_dir, "c2-infrastructure.csv"), c2s, c2_fields)
    print("=" * 60)
    print("[+] Aggregation & Enrichment complete!")


if __name__ == "__main__":
    main()

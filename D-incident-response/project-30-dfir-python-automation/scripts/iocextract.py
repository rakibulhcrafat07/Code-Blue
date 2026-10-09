#!/usr/bin/env python3
"""iocextract.py — extract IOCs from any text, optionally enrich them.

DFIR use: pull IPs, domains, URLs, emails and hashes out of a report, email,
or log, de-duplicate them, and (optionally) enrich with VirusTotal / AbuseIPDB.

Defanged input ("hxxp://", "1.2.3[.]4") is re-fanged automatically.
Enrichment is OFF unless you pass --enrich and set the API-key env vars:
    VT_API_KEY, ABUSEIPDB_API_KEY

Examples:
    python3 iocextract.py report.txt
    python3 iocextract.py report.txt --json iocs.json
    VT_API_KEY=... python3 iocextract.py report.txt --enrich
"""
import argparse, ipaddress, json, os, re, sys

def refang(t):
    return (t.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".")
             .replace("[:]", ":").replace("[at]", "@").replace("[@]", "@"))

PATTERNS = {
    "ipv4":   re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I),
    "url":    re.compile(r"\bhttps?://[^\s\"'<>]+", re.I),
    "email":  re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "md5":    re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1":   re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}
# domains that are usually noise in a report
NOISE = {"example.com", "example.org", "w3.org", "schema.org"}

# RFC1918 + link-local: real "internal" noise we drop. (Documentation ranges
# like 203.0.113.0/24 are kept — in real cases IPs are public, and analysts
# still want to see any that appear.)
_INTERNAL = [ipaddress.ip_network(n) for n in
             ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")]

def valid_ip(s):
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return False
    return not any(ip in net for net in _INTERNAL)

def extract(text):
    text = refang(text)
    found = {k: set() for k in PATTERNS}
    for kind, rx in PATTERNS.items():
        for m in rx.findall(text):
            found[kind].add(m)
    # clean up
    found["ipv4"] = {ip for ip in found["ipv4"] if valid_ip(ip)}
    found["domain"] = {d.lower() for d in found["domain"]
                       if d.lower() not in NOISE and not valid_ip(d)}
    # hashes shouldn't double-count: a sha256 also matches nothing else; fine as-is
    return {k: sorted(v) for k, v in found.items() if v}

# ---- optional enrichment (no network unless --enrich + keys present) ----
def enrich(iocs):
    import urllib.request
    out = {}
    vt = os.getenv("VT_API_KEY"); abuse = os.getenv("ABUSEIPDB_API_KEY")
    def get(url, headers):
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    for ip in iocs.get("ipv4", []):
        info = {}
        if abuse:
            try:
                d = get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                        {"Key": abuse, "Accept": "application/json"})
                info["abuseConfidenceScore"] = d["data"]["abuseConfidenceScore"]
                info["countryCode"] = d["data"].get("countryCode")
            except Exception as e:
                info["abuseipdb_error"] = str(e)
        out[ip] = info
    for h in iocs.get("sha256", []) + iocs.get("md5", []):
        if vt:
            try:
                d = get(f"https://www.virustotal.com/api/v3/files/{h}",
                        {"x-apikey": vt})
                stats = d["data"]["attributes"]["last_analysis_stats"]
                out[h] = {"vt_malicious": stats.get("malicious"), "vt_total": sum(stats.values())}
            except Exception as e:
                out[h] = {"vt_error": str(e)}
    return out

def main():
    ap = argparse.ArgumentParser(description="Extract (and optionally enrich) IOCs.")
    ap.add_argument("file", help="text/log/report to scan ('-' for stdin)")
    ap.add_argument("--json", help="write results to this JSON file")
    ap.add_argument("--enrich", action="store_true", help="enrich via VT/AbuseIPDB (needs API keys)")
    a = ap.parse_args()
    text = sys.stdin.read() if a.file == "-" else open(a.file, errors="replace").read()
    iocs = extract(text)
    for kind, vals in iocs.items():
        print(f"\n[{kind}] ({len(vals)})")
        for v in vals:
            print(f"  {v}")
    result = {"iocs": iocs}
    if a.enrich:
        result["enrichment"] = enrich(iocs)
        print("\n== enrichment ==")
        print(json.dumps(result["enrichment"], indent=2))
    if a.json:
        json.dump(result, open(a.json, "w"), indent=2)
        print(f"\n[+] wrote {a.json}", file=sys.stderr)

if __name__ == "__main__":
    sys.exit(main())

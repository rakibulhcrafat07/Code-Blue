#!/usr/bin/env python3
"""logparser.py — quick triage of Linux auth logs and web access logs.

DFIR use: turn a raw log into the three answers you always need first —
who/what failed, who/what succeeded, and which sources stand out.

Examples:
    python3 logparser.py auth  /var/log/auth.log
    python3 logparser.py web   access.log --top 15
"""
import argparse, re, sys
from collections import Counter, defaultdict

# ---- auth.log (sshd) ----
RE_FAIL = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_OK   = re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

def parse_auth(path, top):
    fails, oks = Counter(), Counter()
    fail_user, ip_users = Counter(), defaultdict(set)
    with open(path, errors="replace") as f:
        for line in f:
            m = RE_FAIL.search(line)
            if m:
                fails[m["ip"]] += 1; fail_user[m["user"]] += 1; continue
            m = RE_OK.search(line)
            if m:
                oks[m["ip"]] += 1; ip_users[m["ip"]].add(m["user"])
    print("== Failed logons by source IP (brute-force signal) ==")
    for ip, n in fails.most_common(top):
        print(f"  {n:>6}  {ip}")
    print("\n== Most-targeted usernames ==")
    for u, n in fail_user.most_common(top):
        print(f"  {n:>6}  {u}")
    print("\n== Successful logons by source IP ==")
    for ip, n in oks.most_common(top):
        print(f"  {n:>6}  {ip}   users={','.join(sorted(ip_users[ip]))}")
    # the classic finding: an IP that failed a lot THEN succeeded
    pivots = [ip for ip in oks if fails.get(ip, 0) >= 5]
    if pivots:
        print("\n!! Source IPs with many failures AND a success (possible successful brute force):")
        for ip in pivots:
            print(f"   {ip}  fails={fails[ip]} success={oks[ip]}")

# ---- web access log (common/combined) ----
RE_WEB = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?"(?P<method>\S+)\s(?P<path>\S+)[^"]*"\s(?P<status>\d{3})\s(?P<size>\S+)(?:\s"[^"]*"\s"(?P<ua>[^"]*)")?'
)
SUSPICIOUS = re.compile(r"(?i)\.php\?|cmd=|union\s+select|\.\./|/etc/passwd|base64|wget|curl|<script")

def parse_web(path, top):
    ip = Counter(); status = Counter(); paths = Counter(); sus = []
    with open(path, errors="replace") as f:
        for line in f:
            m = RE_WEB.search(line)
            if not m:
                continue
            ip[m["ip"]] += 1; status[m["status"]] += 1; paths[m["path"]] += 1
            if SUSPICIOUS.search(m["path"]) or (m["ua"] and SUSPICIOUS.search(m["ua"])):
                sus.append((m["ip"], m["method"], m["path"], m["status"], m["ua"] or ""))
    print("== Requests by source IP =="); [print(f"  {n:>6}  {k}") for k, n in ip.most_common(top)]
    print("\n== Status codes =="); [print(f"  {n:>6}  {k}") for k, n in status.most_common()]
    print("\n== Top paths =="); [print(f"  {n:>6}  {k}") for k, n in paths.most_common(top)]
    if sus:
        print(f"\n!! {len(sus)} suspicious requests (shell/injection/traversal markers):")
        for row in sus[:top]:
            print("   " + " | ".join(row))

def main():
    ap = argparse.ArgumentParser(description="Triage auth / web logs.")
    ap.add_argument("kind", choices=["auth", "web"])
    ap.add_argument("path")
    ap.add_argument("--top", type=int, default=10)
    a = ap.parse_args()
    (parse_auth if a.kind == "auth" else parse_web)(a.path, a.top)

if __name__ == "__main__":
    sys.exit(main())

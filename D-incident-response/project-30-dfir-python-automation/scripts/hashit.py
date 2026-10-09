#!/usr/bin/env python3
"""hashit.py — hash & verify evidence (MD5 + SHA-256) with a report.

DFIR use: the first and last thing you do with any evidence file is hash it.
Hash on acquisition, write a manifest, and re-verify before analysis and in court.

Examples:
    # hash one file or a whole directory, print + write a manifest
    python3 hashit.py /evidence --manifest manifest.csv

    # verify files now against a manifest made earlier (chain of custody)
    python3 hashit.py --verify manifest.csv /evidence
"""
import argparse, csv, hashlib, os, sys
from datetime import datetime, timezone

def hash_file(path, chunk=1 << 20):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(chunk), b""):
            md5.update(b); sha.update(b)
    return md5.hexdigest(), sha.hexdigest(), os.path.getsize(path)

def walk(target):
    if os.path.isfile(target):
        yield target
    else:
        for root, _, files in os.walk(target):
            for name in sorted(files):
                yield os.path.join(root, name)

def cmd_hash(target, manifest):
    rows = []
    for p in walk(target):
        try:
            md5, sha, size = hash_file(p)
        except OSError as e:
            print(f"!! {p}: {e}", file=sys.stderr); continue
        rows.append({"path": p, "size": size, "md5": md5, "sha256": sha})
        print(f"{sha}  {md5}  {size:>12}  {p}")
    if manifest:
        with open(manifest, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["path", "size", "md5", "sha256", "generated_utc"])
            w.writeheader()
            now = datetime.now(timezone.utc).isoformat()
            for r in rows:
                r["generated_utc"] = now; w.writerow(r)
        print(f"\n[+] wrote {len(rows)} entries to {manifest}", file=sys.stderr)
    return 0

def cmd_verify(manifest, base):
    ok = bad = missing = 0
    with open(manifest, newline="") as f:
        for r in csv.DictReader(f):
            p = r["path"]
            if base and not os.path.isabs(p):
                p = os.path.join(base, p)
            if not os.path.exists(p):
                print(f"MISSING  {p}"); missing += 1; continue
            _, sha, _ = hash_file(p)
            if sha == r["sha256"]:
                print(f"OK       {p}"); ok += 1
            else:
                print(f"CHANGED  {p}\n  expected {r['sha256']}\n  got      {sha}"); bad += 1
    print(f"\n[=] ok={ok} changed={bad} missing={missing}", file=sys.stderr)
    return 1 if (bad or missing) else 0

def main():
    ap = argparse.ArgumentParser(description="Hash & verify evidence (MD5+SHA-256).")
    ap.add_argument("target", help="file or directory to hash, or the base dir when --verify")
    ap.add_argument("--manifest", help="write a CSV manifest here")
    ap.add_argument("--verify", metavar="MANIFEST", help="verify files against this manifest")
    a = ap.parse_args()
    if a.verify:
        return cmd_verify(a.verify, a.target)
    return cmd_hash(a.target, a.manifest)

if __name__ == "__main__":
    sys.exit(main())

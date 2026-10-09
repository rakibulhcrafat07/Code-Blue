#!/usr/bin/env python3
"""evtx2csv.py — summarize a Windows EVTX log and export rows to CSV.

DFIR use: get a fast count of which Event IDs are present (and the key
security ones), then dump the parsed records to CSV for Timeline Explorer / Excel.

Requires python-evtx:  pip install python-evtx
(If it's not installed the script tells you, instead of crashing.)

Examples:
    python3 evtx2csv.py Security.evtx --summary
    python3 evtx2csv.py Security.evtx --csv security.csv
"""
import argparse, csv, sys
from collections import Counter

# the security Event IDs this toolkit cares about (mapped in the other projects)
NOTABLE = {
    "4624": "Successful logon", "4625": "Failed logon", "4634": "Logoff",
    "4648": "Explicit-cred logon (lateral)", "4672": "Admin logon",
    "4720": "User account created", "4722": "Account enabled",
    "4728": "Added to global group", "4732": "Added to local group",
    "4688": "Process created", "4698": "Scheduled task created",
    "7045": "Service installed", "1102": "Audit log cleared",
    "4776": "NTLM auth", "4768": "Kerberos TGT", "1149": "RDP auth",
}

def load(path):
    try:
        import Evtx.Evtx as evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        sys.exit("!! python-evtx not installed. Run: pip install python-evtx")
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    with evtx.Evtx(path) as log:
        for rec in log.records():
            try:
                root = ET.fromstring(rec.xml())
            except ET.ParseError:
                continue
            sysd = root.find(f"{ns}System")
            eid = sysd.findtext(f"{ns}EventID") if sysd is not None else None
            ts = ""
            tc = sysd.find(f"{ns}TimeCreated") if sysd is not None else None
            if tc is not None:
                ts = tc.get("SystemTime", "")
            comp = sysd.findtext(f"{ns}Computer") if sysd is not None else ""
            data = {}
            ed = root.find(f"{ns}EventData")
            if ed is not None:
                for d in ed.findall(f"{ns}Data"):
                    if d.get("Name"):
                        data[d.get("Name")] = d.text
            yield {"EventID": eid, "TimeCreated": ts, "Computer": comp, "Data": data}

def main():
    ap = argparse.ArgumentParser(description="Summarize / export an EVTX file.")
    ap.add_argument("evtx")
    ap.add_argument("--summary", action="store_true", help="print Event-ID counts")
    ap.add_argument("--csv", help="write parsed rows to this CSV")
    ap.add_argument("--only", help="comma-separated Event IDs to keep (e.g. 4624,4625)")
    a = ap.parse_args()
    keep = set(a.only.split(",")) if a.only else None

    counts = Counter(); rows = []
    for r in load(a.evtx):
        if keep and r["EventID"] not in keep:
            continue
        counts[r["EventID"]] += 1
        if a.csv:
            flat = {"EventID": r["EventID"], "TimeCreated": r["TimeCreated"],
                    "Computer": r["Computer"]}
            for k in ("TargetUserName", "SubjectUserName", "IpAddress",
                      "LogonType", "ServiceName", "ProcessName", "WorkstationName"):
                flat[k] = r["Data"].get(k, "")
            rows.append(flat)

    if a.summary or not a.csv:
        print("== Event ID counts ==")
        for eid, n in counts.most_common():
            note = NOTABLE.get(eid, "")
            flag = "  <--" if eid in NOTABLE else ""
            print(f"  {n:>7}  {eid:<6} {note}{flag}")
    if a.csv and rows:
        with open(a.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
        print(f"\n[+] wrote {len(rows)} rows to {a.csv}", file=sys.stderr)

if __name__ == "__main__":
    sys.exit(main())

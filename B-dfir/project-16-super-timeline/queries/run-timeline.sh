#!/bin/bash
# Disk + memory super timeline (Lone Wolf case)
DISK=${1:-DiskImage.E01}; MEM=${2:-memdump.mem}
log2timeline.py --storage-file case.plaso "$DISK"
psort.py -o l2tcsv -w disk_timeline.csv case.plaso "date > '2018-01-01'"
for p in windows.info windows.pslist windows.pstree windows.cmdline windows.netscan windows.filescan; do
  vol -f "$MEM" $p > "${p#windows.}.txt"
done
vol -f "$MEM" timeliner.Timeliner --create-bodyfile > mem.body
mactime -b mem.body -d > mem_timeline.csv

#!/bin/bash
# Lab 2: read-only vs read-write integrity test
# Usage: sudo ./integrity-test.sh C1Prj02.eve
set -e
SRC="$1"; OUT=evidence; mkdir -p "$OUT" /mnt/eve_ro /mnt/eve_rw
file "$SRC" | tee "$OUT/00_file_type.txt"
xxd "$SRC" | head -n 4 | tee -a "$OUT/00_file_type.txt"
{ md5sum "$SRC"; sha256sum "$SRC"; } | tee "$OUT/01_original.txt"
cp --preserve=all "$SRC" working_copy.eve
mount -o loop,ro,noexec,noload "$SRC" /mnt/eve_ro && umount /mnt/eve_ro
sha256sum "$SRC" | tee "$OUT/02_after_ro_mount.txt"
mount -o loop working_copy.eve /mnt/eve_rw
echo "tamper test" > /mnt/eve_rw/hello.txt
umount /mnt/eve_rw
sha256sum working_copy.eve | tee "$OUT/03_after_rw_change.txt"
stat "$SRC" working_copy.eve > "$OUT/04_stat.txt"

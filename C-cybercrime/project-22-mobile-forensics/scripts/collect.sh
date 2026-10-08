#!/bin/bash
# Logical collection of an Android test device over ADB (lab use, device you own)
OUT=${1:-collection}; mkdir -p "$OUT"
adb devices | tee "$OUT/devices.txt"
adb pull /sdcard "$OUT/sdcard"
adb pull /data/data "$OUT/appdata"     # requires root
adb pull /data/system "$OUT/system"    # requires root
# hash everything pulled
find "$OUT" -type f -exec sha256sum {} \; > "$OUT/hashes.sha256"
echo "Collected to $OUT; hashes in $OUT/hashes.sha256"

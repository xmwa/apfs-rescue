#!/bin/bash
# Read-only watcher for one Time Machine run to the HDD: logs progress, the drive's counters and
# kernel disk messages every 2 minutes. Ends when the backup ends or when the kernel reports trouble.
out=tm-watch.log
echo "$(date '+%F %T') watcher started" >> "$out"
while :; do
  st=$(tmutil status 2>/dev/null)
  run=$(echo "$st" | awk -F'= ' '/Running/{gsub(/;/,"",$2);print $2}')
  phase=$(echo "$st" | awk -F'= ' '/BackupPhase/{gsub(/;/,"",$2);print $2}')
  pct=$(echo "$st" | awk -F'= ' '/ Percent /{gsub(/[;"]/,"",$2);print $2}' | head -n 1)
  byt=$(echo "$st" | awk -F'= ' '/ bytes /{gsub(/;/,"",$2);print $2}' | head -n 1)
  tot=$(echo "$st" | awk -F'= ' '/totalBytes/{gsub(/;/,"",$2);print $2}' | head -n 1)
  cnt=$(ioreg -c IOBlockStorageDriver -r -w 0 -l 2>/dev/null | python3 -c '
import sys,re
o=[]
for b in sys.stdin.read().split("IOBlockStorageDriver")[1:]:
    m=re.search(r"\"Statistics\" = \{([^}]*)\}",b)
    if not m: continue
    d=dict(re.findall(r"\"([^\"]+)\"=(\d+)",m.group(1)))
    if int(d.get("Bytes (Read)","0"))>5000000000000:   # the HDD (largest read total)
        o.append("hdd_write_ops=%s hdd_write_bytes=%s err_r=%s err_w=%s retry_r=%s retry_w=%s"%(d.get("Operations (Write)"),d.get("Bytes (Write)"),d.get("Errors (Read)"),d.get("Errors (Write)"),d.get("Retries (Read)"),d.get("Retries (Write)")))
print(" ".join(o))')
  bad=$(/usr/bin/log show --last 3m --style compact --predicate 'process == "kernel" AND (eventMessage CONTAINS[c] "I/O error" OR eventMessage CONTAINS "nx_corruption" OR eventMessage CONTAINS "obj_checksum" OR eventMessage CONTAINS "not readable" OR eventMessage CONTAINS "disk4: device")' 2>/dev/null | grep -v 'log run noninteractively' | grep -v '^Timestamp' | head -n 3)
  link=$(ioreg -p IOUSB -l -w 0 2>/dev/null | grep -A40 -i "${USB_DRIVE_MATCH:-Elements}" | awk -F'= ' '/"UsbLinkSpeed"/{print $2; exit}')
  loc=$(ioreg -p IOUSB -l -w 0 2>/dev/null | grep -A40 -i "${USB_DRIVE_MATCH:-Elements}" | awk -F'= ' '/"locationID"/{print $2; exit}')
  usb=$(/usr/bin/log show --last 3m --style compact --predicate 'process == "kernel" AND (eventMessage CONTAINS[c] "Elements" OR eventMessage CONTAINS "AppleUSBHostPort" OR eventMessage CONTAINS "IOUSBHostDevice" OR (eventMessage CONTAINS[c] "usb" AND (eventMessage CONTAINS[c] "disconnect" OR eventMessage CONTAINS[c] "reset" OR eventMessage CONTAINS[c] "timeout")))' 2>/dev/null | grep -v 'log run noninteractively' | grep -v '^Timestamp' | head -n 3)
  echo "$(date '+%F %T') running=$run phase=$phase pct=$pct bytes=$byt total=$tot link=$link loc=$loc $cnt" >> "$out"
  if [ -n "$usb" ]; then echo "$(date '+%F %T') USB EVENT: $usb" >> "$out"; fi
  if [ "$link" != "5000000000" ]; then echo "$(date '+%F %T') LINK SPEED CHANGED OR DRIVE GONE: '$link'" >> "$out"; exit 5; fi
  if [ -n "$bad" ]; then echo "$(date '+%F %T') KERNEL TROUBLE: $bad" >> "$out"; exit 3; fi
  if ! mount | grep -q "${DRIVE_MOUNT_NAME:?set DRIVE_MOUNT_NAME to the volume name}"; then echo "$(date '+%F %T') drive NO LONGER MOUNTED" >> "$out"; exit 4; fi
  if [ "$run" = "0" ]; then echo "$(date '+%F %T') backup no longer running" >> "$out"; exit 0; fi
  sleep 120
done

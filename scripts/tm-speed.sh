#!/bin/bash
# Samples the Time Machine run every N seconds: phase, copied bytes, drive write throughput from the
# drive's own counters (disk4), error/retry counters, link speed. Prints one line per sample;
# exits when the backup is no longer running. Read-only.
N=${1:-300}
prev_b=; prev_t=
hdd() {
  ioreg -c IOBlockStorageDriver -r -w 0 -l 2>/dev/null | python3 -c '
import sys,re
for b in sys.stdin.read().split("IOBlockStorageDriver")[1:]:
    m=re.search(r"\"Statistics\" = \{([^}]*)\}",b)
    if not m: continue
    d=dict(re.findall(r"\"([^\"]+)\"=(\d+)",m.group(1)))
    if "\"BSD Name\" = \"disk4\"" in b:
        print(d.get("Bytes (Write)"),d.get("Errors (Write)"),d.get("Retries (Write)"),d.get("Errors (Read)"),d.get("Retries (Read)")); break'
}
while :; do
  st=$(tmutil status 2>/dev/null)
  run=$(echo "$st" | awk -F'= ' '/Running/{gsub(/;/,"",$2);print $2}')
  phase=$(echo "$st" | awk -F'= ' '/BackupPhase/{gsub(/;/,"",$2);print $2}')
  byt=$(echo "$st" | awk -F'= ' '/ bytes /{gsub(/;/,"",$2);print $2}' | head -n 1)
  tot=$(echo "$st" | awk -F'= ' '/totalBytes/{gsub(/;/,"",$2);print $2}' | head -n 1)
  files=$(echo "$st" | awk -F'= ' '/ files /{gsub(/;/,"",$2);print $2}' | head -n 1)
  read wb ew rw er rr <<< "$(hdd)"
  t=$(date +%s)
  if [ -n "$prev_b" ] && [ -n "$wb" ]; then
    mbs=$(python3 -c "print('%.1f' % (($wb-$prev_b)/1e6/($t-$prev_t)))")
  else mbs=-; fi
  link=$(ioreg -p IOUSB -l -w 0 2>/dev/null | grep -A40 -i "${USB_DRIVE_MATCH:-Elements}" | awk -F'= ' '/"UsbLinkSpeed"/{print $2; exit}')
  printf '%s phase=%s copied=%s of %s bytes, files=%s, drive write %s MB/s, err w/r=%s/%s retry w/r=%s/%s link=%s\n' \
    "$(date '+%H:%M:%S')" "$phase" "${byt:-?}" "${tot:-?}" "${files:-?}" "$mbs" "$ew" "$er" "$rw" "$rr" "$link"
  [ "$run" = "0" ] && { echo "backup no longer running"; exit 0; }
  prev_b=$wb; prev_t=$t
  sleep "$N"
done

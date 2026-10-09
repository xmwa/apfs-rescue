#!/bin/bash
# Staged write tests on the REAL drive. Subcommands:
#   mountrw            unlock if needed, mount the HDD volume read-write (explicit option), verify
#   mountro            mount it read-only
#   umount             normal unmount (never forced), retried
#   health <minutes>   kernel log + drive counters + USB link
#   gate <before_tag> <after_tag> [refs_before]   fresh index copy <after>, index walk, ownership check,
#                      Apple's check on the real drive, before/after comparison
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$HERE" || exit 1
VOL_UUID="${APFS_VOL_UUID:?set APFS_VOL_UUID to the volume UUID}"; PART_UUID="${APFS_PART_UUID:?set APFS_PART_UUID to the partition UUID}"; MNT="/Volumes/${DRIVE_MOUNT_NAME:?set DRIVE_MOUNT_NAME to the volume name}"
realvol() {
  local part ct
  part="$(diskutil info "$PART_UUID" 2>/dev/null | awk '/Device Node/{print $3}')"; [ -n "$part" ] || { echo "drive not connected" >&2; return 1; }
  ct="$(diskutil list | awk -v s="Physical Store ${part#/dev/}" 'index($0,"APFS Container Scheme"){c=$NF} index($0,s){print c; exit}')"
  [ -n "$ct" ] || { echo "container not found" >&2; return 1; }
  echo "${ct}s1"
}
unlock() {
  local v="$1"
  if diskutil info "$v" | grep -q 'Locked: *Yes'; then
    security find-generic-password -a "$VOL_UUID" -s "$VOL_UUID" -w | xxd -r -p | LC_ALL=C tr -d '\0' | diskutil apfs unlockVolume "$v" -stdinpassphrase -nomount >/dev/null 2>&1
  fi
}
case "$1" in
mountrw|mountro)
  [ "$(hdiutil info | grep -c 'hdd-meta-')" = 0 ] || { echo "a local metadata image is attached; detach it first"; exit 1; }
  V="$(realvol)" || exit 1; unlock "$V"
  if [ "$1" = mountrw ]; then diskutil mount -mountOptions rw "$V" || exit 1; else diskutil mount readOnly "$V" || exit 1; fi
  L="$(mount | grep " on $MNT (")"; echo "$L"
  [ -n "$L" ] || { echo "not mounted"; exit 1; }
  if [ "$1" = mountrw ]; then
    if echo "$L" | grep -q 'read-only'; then echo "mounted read-only, not read-write"; exit 1; fi
  else
    if ! echo "$L" | grep -q 'read-only'; then echo "NOT read-only"; diskutil unmount "$V"; exit 1; fi
  fi
  exit 0
  ;;
umount)
  V="$(realvol)" || exit 1
  mount | grep -q " on $MNT (" || { echo "not mounted"; exit 0; }
  sync
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do diskutil unmount "$V" && exit 0; sleep 10; done
  echo "UNMOUNT FAILED (not forcing)"; lsof 2>/dev/null | grep "$MNT" | awk '{print $1,$2}' | sort | uniq -c | head; exit 1
  ;;
health)
  M="${2:-30}"
  echo "kernel disk/apfs/usb trouble in the last $M min: $(/usr/bin/log show --last "${M}m" --style compact --predicate 'process == "kernel" AND (eventMessage CONTAINS[c] "I/O error" OR eventMessage CONTAINS "nx_corruption" OR eventMessage CONTAINS "obj_checksum" OR eventMessage CONTAINS "not readable" OR eventMessage CONTAINS "apfs_corruption" OR (eventMessage CONTAINS[c] "usb" AND (eventMessage CONTAINS[c] "disconnect" OR eventMessage CONTAINS[c] "reset")))' 2>/dev/null | grep -v 'log run noninteractively' | grep -vc '^Timestamp')"
  /usr/bin/log show --last "${M}m" --style compact --predicate 'senderImagePath CONTAINS[c] "apfs" AND messageType == error' 2>/dev/null | grep -v '^Timestamp' | grep -v 'Cannot get BSD Name' | tail -n 5 | cut -c1-200
  ioreg -c IOBlockStorageDriver -r -w 0 -l 2>/dev/null | python3 -c '
import sys,re
for b in sys.stdin.read().split("IOBlockStorageDriver")[1:]:
    m=re.search(r"\"Statistics\" = \{([^}]*)\}",b)
    if not m: continue
    d=dict(re.findall(r"\"([^\"]+)\"=(\d+)",m.group(1)))
    if int(d.get("Bytes (Read)","0"))>5000000000000: print("drive counters: written %.1f GB; errors r/w %s/%s; retries r/w %s/%s"%(int(d["Bytes (Write)"])/1e9,d["Errors (Read)"],d["Errors (Write)"],d["Retries (Read)"],d["Retries (Write)"]))'
  echo "USB link: $(ioreg -p IOUSB -l -w 0 2>/dev/null | grep -A40 -i "${USB_DRIVE_MATCH:-Elements}" | awk -F'= ' '/"UsbLinkSpeed"/{print $2; exit}')"
  echo "Time Machine running: $(tmutil status 2>/dev/null | awk -F'= ' '/Running/{gsub(/;/,"",$2);print $2}')"
  ;;
gate)
  B="$2"; A="$3"; RB="${4:-hdd-refs-$B}"
  mount | grep -q " on $MNT (" && { echo "the HDD is mounted; unmount first"; exit 1; }
  ok=1
  if [ -e "hdd-meta-$A.img" ] && grep -q '^RESULT: PASS' "hdd-refcheck-$A.txt" 2>/dev/null && grep -q 'finished: 0 structural issues' "hdd-refs-$A.log" 2>/dev/null; then echo "index copy $A already taken and checked: PASS"; else ./realimg.sh "$A" || ok=0; fi
  V="$(realvol)" || exit 1; unlock "$V"
  { date; diskutil verifyVolume "${V%s1}"; echo "exit=$?"; date; } > "hdd-verify-$A.txt" 2>&1
  grep -E '^error|appears to be OK|corrupt|exit=' "hdd-verify-$A.txt" | cut -c1-160
  grep -q '^exit=0' "hdd-verify-$A.txt" || ok=0
  [ "$(grep -c '^error' "hdd-verify-$A.txt")" -le 2 ] || ok=0
  uv run --quiet --script g3_compare.py "hdd-meta-$B.img" "hdd-meta-$A.img" "$RB" "hdd-refs-$A" > "hdd-g3-$A.txt" 2>&1 || ok=0
  cut -c1-200 "hdd-g3-$A.txt" | grep -v '      file id'
  [ "$ok" = 1 ] && echo "GATE $A: PASS" || { echo "GATE $A: FAIL"; exit 1; }
  ;;
esac

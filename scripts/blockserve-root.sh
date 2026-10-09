#!/bin/bash
# Runs as root. READ-ONLY on the HDD. Copies requested blocks from the HDD's APFS partition into a
# local sparse image in the project folder, at the same block positions. Requests: files
# fetch2-req/*.req; first line "image hdd-meta-<name>.img", then lines "first_block block_count"
# (decimal). Ends when fetch2-req/stop exists or after 72 hours. Never writes to the HDD.
# Usage: blockserve-root.sh <here> <rdev>
HERE="$1"; RDEV="$2"; Q="$HERE/fetch2-req"; ST="$HERE/blockserve-status.txt"
U="${SUDO_UID:-0}:${SUDO_GID:-0}"
say() { echo "$(date '+%F %T') $*" >> "$ST"; }
mkdir -p "$Q"; chown "$U" "$Q"; : > "$ST"; chown "$U" "$ST"
case "$RDEV" in /dev/rdisk[0-9]*s[0-9]*) ;; *) say "refusing device $RDEV"; exit 1 ;; esac
[ "$(diskutil info "$RDEV" | awk -F': *' '/Partition UUID/{print $2; exit}')" = "${APFS_PART_UUID:?set APFS_PART_UUID to the partition UUID}" ] || { say "$RDEV is not the HDD partition"; exit 1; }
MAXBLK=4394522614; SIZE=17999964626944
END=$(( $(date +%s) + 259200 ))
say "serving read requests from $RDEV (read-only)"
while [ ! -e "$Q/stop" ] && [ "$(date +%s)" -lt "$END" ]; do
  # the partition may get a new device name after a replug
  if [ ! -e "$RDEV" ]; then
    D="$(diskutil info ${APFS_PART_UUID:?set APFS_PART_UUID to the partition UUID} 2>/dev/null | awk '/Device Node/{print $3}')"
    [ -n "$D" ] && RDEV="${D/\/dev\/disk//dev/rdisk}"
  fi
  for r in "$Q"/*.req; do
    [ -e "$r" ] || continue
    name="$(awk 'NR==1 && $1=="image"{print $2}' "$r")"
    case "$name" in hdd-meta-*[!A-Za-z0-9._-]*|'') say "bad image name in $(basename "$r")"; mv "$r" "${r%.req}.bad"; continue ;; hdd-meta-*.img) ;; *) say "bad image name in $(basename "$r")"; mv "$r" "${r%.req}.bad"; continue ;; esac
    IMG="$HERE/$name"
    if [ ! -e "$IMG" ]; then /usr/bin/python3 -c "import os,sys; fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o644); os.ftruncate(fd,int(sys.argv[2])); os.close(fd)" "$IMG" "$SIZE"; chown "$U" "$IMG"; fi
    n=0; bad=0
    while read -r a c _; do
      case "$a$c" in ''|*[!0-9]*) continue ;; esac
      [ "$c" -ge 1 ] && [ "$c" -le 4194304 ] && [ $((a + c)) -le "$MAXBLK" ] || { say "skipped out-of-range request $a $c"; continue; }
      if [ "$c" -ge 1024 ] && [ $((a % 1024)) -eq 0 ] && [ $((c % 1024)) -eq 0 ]; then
        dd if="$RDEV" of="$IMG" bs=4194304 skip=$((a / 1024)) seek=$((a / 1024)) count=$((c / 1024)) conv=notrunc 2>/dev/null || bad=1
      else
        dd if="$RDEV" of="$IMG" bs=4096 skip="$a" seek="$a" count="$c" conv=notrunc 2>/dev/null || bad=1
      fi
      n=$((n + c))
    done < <(tail -n +2 "$r")
    if [ "$bad" = 1 ]; then say "READ ERROR while serving $(basename "$r")"; mv "$r" "${r%.req}.failed"; chown "$U" "${r%.req}.failed"
    else mv "$r" "${r%.req}.done"; chown "$U" "${r%.req}.done"; say "served $(basename "$r"): $n blocks -> $name"; fi
  done
  sleep 1
done
/bin/rm -f "$Q/stop"
say "FINISHED"

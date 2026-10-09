#!/bin/bash
# Runs an apfs-* tool against the local metadata image, fetching any block the image lacks from the
# drive (through the read-only fetch helper) and repeating until nothing is missing.
# Usage: metarun.sh <log_file> <tool> <args after the image path...>
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMG="$HERE/${META_IMG:-meta.img}"; VOL_UUID="${APFS_VOL_UUID:?set APFS_VOL_UUID to the volume UUID}"
LOG="$1"; TOOL="$2"; shift 2
HL="$HERE/fetch-req/holes.$$"; export APFS_HOLE_LOG="$HL"
for round in 1 2 3 4 5 6 7 8 9 10 11 12; do
  rm -f "$HL"
  security find-generic-password -a "$VOL_UUID" -s "$VOL_UUID" -w | xxd -r -p | LC_ALL=C tr -d '\0' \
    | "$HERE/apfs-fuse/build-clt4/$TOOL" "$IMG" "$@" > "$LOG" 2> "$LOG.err"
  rc=${PIPESTATUS[1]}
  n=$(python3 "$HERE/fetch_holes.py" "$HL") || { echo "fetch failed"; exit 9; }
  echo "round $round: exit $rc, blocks fetched from the HDD: $n"
  [ "$n" = 0 ] && break
done
exit $rc

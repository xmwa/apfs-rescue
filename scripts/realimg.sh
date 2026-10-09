#!/bin/bash
# Fresh local metadata image of the REAL drive (read-only on the drive, through the block server),
# then the index walk and the ownership check on it.   Usage: realimg.sh <tag>      -> hdd-meta-<tag>.img
# The drive volume must be unmounted so the copy is of a settled state.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$HERE" || exit 1
TAG="$1"; IMG="hdd-meta-$TAG.img"; VOL_UUID="${APFS_VOL_UUID:?set APFS_VOL_UUID to the volume UUID}"
mount | grep -q "${DRIVE_MOUNT_NAME:?set DRIVE_MOUNT_NAME to the volume name}" && { echo "the HDD is mounted"; exit 1; }
[ -e "$IMG" ] && { echo "$IMG exists"; exit 1; }
EXTRA="$(awk 'NR>2{printf "%s:%s ", $1, $2}' hdd-meta-known.txt)"
n=$(python3 fetch2.py "$IMG" 0:2048000 13312000:3072000 $EXTRA) || exit 1
echo "copied $n blocks into $IMG"
HL="$HERE/fetch2-req/holes.$TAG"; export APFS_HOLE_LOG="$HL"
for round in 1 2 3 4 5 6 7 8; do
  /bin/rm -f "$HL"
  security find-generic-password -a "$VOL_UUID" -s "$VOL_UUID" -w | xxd -r -p | LC_ALL=C tr -d '\0' \
    | apfs-fuse/build-clt4/apfs-refs "$IMG" "hdd-refs-$TAG" > "hdd-refs-$TAG.log" 2> "hdd-refs-$TAG.log.err"
  rc=${PIPESTATUS[1]}
  k=$(python3 fetch2.py "$IMG" --holes "$HL") || exit 1
  echo "index walk round $round: exit $rc, extra blocks fetched $k"
  [ "$k" = 0 ] && break
done
unset APFS_HOLE_LOG
grep -E '^\[apfs-refs\] (volume superblock|superblock counts|tree F .* done|finished)' "hdd-refs-$TAG.log" | cut -c1-200
uv run --quiet --script refcheck.py "hdd-refs-$TAG" "$IMG" --out "hdd-refcheck-$TAG.txt" 2>&1 | grep -E 'save point|free queue main|^\(|FAIL|RESULT|NOTE' | cut -c1-200
grep -q '^RESULT: PASS' "hdd-refcheck-$TAG.txt" && grep -q 'finished: 0 structural issues' "hdd-refs-$TAG.log"

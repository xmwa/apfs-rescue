#!/bin/bash
# Attach a local metadata image and mount its volume read-write at a private mount point, or take
# it down again. Never touches the real drive (refuses container disk5 and non-image devices).
#   imgmount.sh up <image> <mountpoint> [ro]     prints "<image_dev> <container>"
#   imgmount.sh down <mountpoint>
set -u
VOL_UUID="${APFS_VOL_UUID:?set APFS_VOL_UUID to the volume UUID}"
if [ "$1" = up ]; then
  IMG="$2"; MNT="$3"; RO="${4:-}"
  OUT="$(hdiutil attach ${RO:+-readonly} -nomount -imagekey diskimage-class=CRawDiskImage "$IMG" 2>&1)" || { echo "attach failed: $OUT" >&2; exit 1; }
  OV="$(echo "$OUT" | awk '/^\/dev\/disk/{print $1; exit}')"; sleep 3
  CT="$(diskutil list | awk -v s="Physical Store ${OV#/dev/}" 'index($0,"APFS Container Scheme"){c=$NF} index($0,s){print c; exit}')"
  diskutil info "$OV" | grep -q "Protocol: *Disk Image" || { echo "$OV is not a disk image" >&2; exit 1; }
  [ -n "$CT" ] && [ "$CT" != disk5 ] || { echo "unexpected container '$CT'" >&2; hdiutil detach "$OV" >/dev/null; exit 1; }
  security find-generic-password -a "$VOL_UUID" -s "$VOL_UUID" -w | xxd -r -p | LC_ALL=C tr -d '\0' | diskutil apfs unlockVolume "${CT}s1" -stdinpassphrase -nomount >/dev/null 2>&1
  mkdir -p "$MNT"
  if [ -n "$RO" ]; then diskutil mount readOnly -mountPoint "$MNT" "${CT}s1" >/dev/null || exit 1
  else diskutil mount -mountOptions rw -mountPoint "$MNT" "${CT}s1" >/dev/null || exit 1; fi
  echo "$OV $CT"
else
  MNT="$2"
  DEV="$(mount | awk -v m="$MNT" '$3==m{print $1}')"
  [ -n "$DEV" ] || { echo "nothing mounted at $MNT" >&2; exit 1; }
  CT="${DEV#/dev/}"; CT="${CT%s1}"
  [ "$CT" != disk5 ] || { echo "refusing disk5" >&2; exit 1; }
  OV="$(diskutil list "$CT" | awk '/Physical Store/{print $NF; exit}')"
  diskutil info "$OV" | grep -q "Protocol: *Disk Image" || { echo "$OV is not a disk image" >&2; exit 1; }
  diskutil unmount "$DEV" >/dev/null || exit 1
  hdiutil detach "/dev/$OV" >/dev/null || exit 1
  echo "down $OV $CT"
fi

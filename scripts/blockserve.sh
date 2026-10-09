#!/bin/bash
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEV="$(diskutil info ${APFS_PART_UUID:?set APFS_PART_UUID to the partition UUID} 2>/dev/null | awk '/Device Node/{print $3}')"
[ -n "$DEV" ] || { echo "drive partition not found" >&2; exit 1; }
sudo "$HERE/blockserve-root.sh" "$HERE" "${DEV/\/dev\/disk//dev/rdisk}"

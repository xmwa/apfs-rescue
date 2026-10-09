#!/bin/bash
# While the write tests run: if Time Machine starts a backup by itself, stop it and log it.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
while [ ! -e "$HERE/tm-guard.stop" ]; do
  if [ "$(tmutil status 2>/dev/null | awk -F'= ' '/Running/{gsub(/;/,"",$2);print $2}')" = 1 ]; then
    tmutil stopbackup; echo "$(date '+%F %T') Time Machine backup started by itself; stopped it" >> "$HERE/tm-guard.log"
  fi
  sleep 15
done

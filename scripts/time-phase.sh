#!/usr/bin/env bash
# Chronomètre une commande et logue le résultat (TSV) dans un fichier de log.
#
# Usage:
#   scripts/time-phase.sh <log-file> <phase-name> <command> [args...]
#
# Format TSV (1 ligne par phase) :
#   PHASE  START_ISO  END_ISO  SECONDS  HH:MM:SS  rc=<code>

set -uo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <log-file> <phase-name> <command> [args...]" >&2
  exit 2
fi

LOG="$1"
PHASE="$2"
shift 2

mkdir -p "$(dirname "$LOG")"

start=$(date +%s)
start_iso=$(date -Iseconds)

printf '\n┌─── ▶ phase %s démarrée à %s\n' "$PHASE" "$start_iso"

"$@"
rc=$?

end=$(date +%s)
end_iso=$(date -Iseconds)
dur=$((end - start))
h=$((dur / 3600))
m=$(((dur % 3600) / 60))
s=$((dur % 60))

printf '└─── ⏱  phase %s : %02d:%02d:%02d (%ds) rc=%d\n' \
  "$PHASE" "$h" "$m" "$s" "$dur" "$rc"

printf '%s\t%s\t%s\t%d\t%02d:%02d:%02d\trc=%d\n' \
  "$PHASE" "$start_iso" "$end_iso" "$dur" "$h" "$m" "$s" "$rc" >> "$LOG"

exit "$rc"

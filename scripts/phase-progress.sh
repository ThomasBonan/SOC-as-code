#!/usr/bin/env bash
# Chronomètre une phase avec indicateur d'avancement live (compteur N/M, ETA
# basé sur l'historique du dernier run réussi, barre de progression, delta).
#
# Usage:
#   scripts/phase-progress.sh <log> <idx> <total> <hist_log> <global_start_epoch> <phase> <cmd...>
#
# Émet sur stdout :
#   - 1 header au démarrage de la phase  (┌─── ▶ [N/M] phase ETA hh:mm:ss)
#   - 1 ligne d'avancement toutes les ${PROGRESS_INTERVAL:-30}s
#   - 1 footer à la fin                  (└─── ⏱  hh:mm:ss rc=N Δ ±hh:mm:ss)
#
# Persiste 1 ligne TSV par phase dans <log> :
#   PHASE  START_ISO  END_ISO  SECONDS  HH:MM:SS  rc=<code>

set -uo pipefail

if [[ $# -lt 7 ]]; then
  echo "usage: $0 <log> <idx> <total> <hist_log> <global_start> <phase> <cmd...>" >&2
  exit 2
fi

LOG="$1"; IDX="$2"; TOTAL="$3"; HIST="$4"; GSTART="$5"; PHASE="$6"
shift 6

PROGRESS_INTERVAL="${PROGRESS_INTERVAL:-30}"
BAR_WIDTH="${BAR_WIDTH:-20}"

mkdir -p "$(dirname "$LOG")"

# ── Lookup ETA pour cette phase + total ETA depuis l'historique ──────────────
eta_sec=0
total_eta=0
if [[ -n "$HIST" && -f "$HIST" ]]; then
  eta_sec=$(awk -F'\t' -v p="$PHASE" '$1==p && $1!="TOTAL" {print $4; exit}' "$HIST")
  eta_sec=${eta_sec:-0}
  total_eta=$(awk -F'\t' '$1=="TOTAL" {print $4; exit}' "$HIST")
  total_eta=${total_eta:-0}
fi

fmt_hms() {
  local s=$1 h m
  (( s < 0 )) && s=0
  h=$((s/3600)); m=$(((s%3600)/60)); s=$((s%60))
  printf '%02d:%02d:%02d' "$h" "$m" "$s"
}

bar() {
  local pct=$1 width=$BAR_WIDTH filled empty
  (( pct < 0 )) && pct=0
  (( pct > 100 )) && pct=100
  filled=$((pct * width / 100))
  empty=$((width - filled))
  printf '['
  (( filled > 0 )) && printf '█%.0s' $(seq 1 $filled)
  (( empty  > 0 )) && printf '░%.0s' $(seq 1 $empty)
  printf ']'
}

start=$(date +%s)
start_iso=$(date -Iseconds)

eta_label="ETA $(fmt_hms "$eta_sec")"
(( eta_sec == 0 )) && eta_label="ETA n/a"
printf '\n┌─── ▶ [%s/%s] %-22s démarrée à %s  (%s)\n' \
  "$IDX" "$TOTAL" "$PHASE" "$start_iso" "$eta_label"

# ── Run command in background, poll progress ────────────────────────────────
"$@" &
cmd_pid=$!

while kill -0 "$cmd_pid" 2>/dev/null; do
  # Sleep in small slices so we react quickly when the command exits
  for _ in $(seq 1 "$PROGRESS_INTERVAL"); do
    kill -0 "$cmd_pid" 2>/dev/null || break
    sleep 1
  done
  kill -0 "$cmd_pid" 2>/dev/null || break

  now=$(date +%s)
  elapsed=$((now - start))
  global=$((now - GSTART))

  if (( eta_sec > 0 )); then
    pct=$((elapsed * 100 / eta_sec))
    overdue=""
    if (( elapsed > eta_sec )); then
      overdue=" +$(fmt_hms $((elapsed - eta_sec)))"
    fi
    remaining_total=$(( total_eta > global ? total_eta - global : 0 ))
    printf '│ ⏳ [%s] %s %s / %s ≈%d%%%s   total %s, reste ~%s\n' \
      "$PHASE" "$(bar "$pct")" "$(fmt_hms "$elapsed")" "$(fmt_hms "$eta_sec")" \
      "$pct" "$overdue" "$(fmt_hms "$global")" "$(fmt_hms "$remaining_total")"
  else
    printf '│ ⏳ [%s] elapsed %s  (pas d historique)\n' \
      "$PHASE" "$(fmt_hms "$elapsed")"
  fi
done

wait "$cmd_pid"
rc=$?

end=$(date +%s)
end_iso=$(date -Iseconds)
dur=$((end - start))

delta=""
if (( eta_sec > 0 )); then
  d=$((dur - eta_sec))
  if (( d >= 0 )); then
    delta="  Δ +$(fmt_hms "$d") vs historique"
  else
    delta="  Δ -$(fmt_hms $(( -d ))) plus rapide"
  fi
fi
printf '└─── ⏱  [%s/%s] %-22s : %s  rc=%d%s\n' \
  "$IDX" "$TOTAL" "$PHASE" "$(fmt_hms "$dur")" "$rc" "$delta"

# TSV log — format identique à scripts/time-phase.sh pour compat
h=$((dur / 3600)); m=$(((dur % 3600) / 60)); s=$((dur % 60))
printf '%s\t%s\t%s\t%d\t%02d:%02d:%02d\trc=%d\n' \
  "$PHASE" "$start_iso" "$end_iso" "$dur" "$h" "$m" "$s" "$rc" >> "$LOG"

exit "$rc"

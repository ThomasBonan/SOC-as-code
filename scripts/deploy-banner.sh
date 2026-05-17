#!/usr/bin/env bash
# deploy-banner.sh — Banner final coloré pour make deploy
#
# Usage : deploy-banner.sh <global_rc> <duration_sec> <hist_log> <current_log>
#
# Comportement :
#   - rc=0 → banner SUCCÈS (vert) + URLs des services + Δ vs dernier run réussi
#   - rc!=0 → banner ÉCHEC (rouge) + dernière phase échouée + chemin du log
#
# Δ est calculé à partir de la ligne TOTAL du fichier d'historique (rc=0).

set -uo pipefail

RC="${1:?rc requis}"
DUR="${2:?durée requise}"
HIST="${3:-}"
LOG="${4:-}"

# ── Couleurs ANSI (désactivées si pas de TTY ou NO_COLOR=1) ───────────────────
if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
  RESET=$'\033[0m'
  BOLD=$'\033[1m'
  DIM=$'\033[2m'
  GREEN=$'\033[1;32m'
  RED=$'\033[1;31m'
  YELLOW=$'\033[1;33m'
  CYAN=$'\033[1;36m'
  WHITE=$'\033[1;37m'
else
  RESET=""; BOLD=""; DIM=""; GREEN=""; RED=""; YELLOW=""; CYAN=""; WHITE=""
fi

# ── Helpers ───────────────────────────────────────────────────────────────────
fmt_hms() {
  local s=$1 h m
  if (( s < 0 )); then s=$((-s)); fi
  h=$((s/3600)); m=$(((s%3600)/60)); s=$((s%60))
  printf '%02d:%02d:%02d' "$h" "$m" "$s"
}

# Δ vs dernier run réussi (TOTAL rc=0 dans HIST)
delta_line=""
if [[ -n "$HIST" && -f "$HIST" ]]; then
  ref=$(awk -F'\t' '$1=="TOTAL" && $6 ~ /rc=0/ {print $4; exit}' "$HIST" 2>/dev/null || true)
  if [[ -n "$ref" && "$ref" -gt 0 && "$ref" != "$DUR" ]]; then
    delta=$((DUR - ref))
    ref_hms=$(fmt_hms "$ref")
    if (( delta < 0 )); then
      delta_line="${GREEN}-$(fmt_hms $((-delta)))${RESET} plus rapide que le dernier run réussi (${DIM}${ref_hms}${RESET})"
    elif (( delta > 0 )); then
      delta_line="${YELLOW}+$(fmt_hms "$delta")${RESET} plus lent que le dernier run réussi (${DIM}${ref_hms}${RESET})"
    fi
  elif [[ -n "$ref" && "$ref" == "$DUR" ]]; then
    delta_line="${DIM}identique au dernier run réussi${RESET}"
  fi
fi

dur_hms=$(fmt_hms "$DUR")

# ── Rendu ─────────────────────────────────────────────────────────────────────
HR="━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

echo ""

if [[ "$RC" == "0" ]]; then
  # ── BANNER SUCCÈS ────────────────────────────────────────────────────────────
  printf '%s┏%s┓%s\n' "$GREEN" "$HR" "$RESET"
  printf '%s┃%s   %s✔ SOC-as-code déployé avec succès%s\n' "$GREEN" "$RESET" "$BOLD$GREEN" "$RESET"
  printf '%s┃%s\n' "$GREEN" "$RESET"
  printf '%s┃%s   %sDurée totale%s    %s%s%s\n' "$GREEN" "$RESET" "$BOLD" "$RESET" "$WHITE" "$dur_hms" "$RESET"
  if [[ -n "$delta_line" ]]; then
    printf '%s┃%s   %sΔ historique%s    %b\n' "$GREEN" "$RESET" "$BOLD" "$RESET" "$delta_line"
  fi
  printf '%s┃%s\n' "$GREEN" "$RESET"
  printf '%s┃%s   %sURLs des services%s\n' "$GREEN" "$RESET" "$BOLD" "$RESET"
  printf '%s┃%s     %s•%s ArgoCD     %shttps://argocd.apps.soc.lab%s\n'  "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s     %s•%s Wazuh      %shttps://wazuh.apps.soc.lab%s\n'   "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s     %s•%s TheHive    %shttps://thehive.apps.soc.lab%s\n' "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s     %s•%s Cortex     %shttps://cortex.apps.soc.lab%s\n'  "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s     %s•%s MISP       %shttps://misp.apps.soc.lab%s\n'    "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s     %s•%s Shuffle    %shttps://shuffle.apps.soc.lab%s\n' "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s     %s•%s Grafana    %shttps://grafana.apps.soc.lab%s\n' "$GREEN" "$RESET" "$CYAN" "$RESET" "$CYAN" "$RESET"
  printf '%s┃%s\n' "$GREEN" "$RESET"
  printf '%s┃%s   %sAgents Wazuh%s    wazuh-agent.apps.soc.lab (10.0.30.55)\n' "$GREEN" "$RESET" "$BOLD" "$RESET"
  printf '%s┃%s                    enrôlement 1515/TCP — events 1514/TCP\n' "$GREEN" "$RESET"
  printf '%s┗%s┛%s\n' "$GREEN" "$HR" "$RESET"
else
  # ── BANNER ÉCHEC ─────────────────────────────────────────────────────────────
  failed_phase="?"
  if [[ -n "$LOG" && -f "$LOG" ]]; then
    failed_phase=$(awk -F'\t' '$1!="TOTAL" && $6 !~ /rc=0/ {print $1; exit}' "$LOG" 2>/dev/null || echo "?")
  fi

  printf '%s┏%s┓%s\n' "$RED" "$HR" "$RESET"
  printf '%s┃%s   %s✘ Échec du déploiement SOC-as-code%s\n' "$RED" "$RESET" "$BOLD$RED" "$RESET"
  printf '%s┃%s\n' "$RED" "$RESET"
  printf '%s┃%s   %sDurée écoulée%s   %s%s%s\n' "$RED" "$RESET" "$BOLD" "$RESET" "$WHITE" "$dur_hms" "$RESET"
  printf '%s┃%s   %sPhase échouée%s   %s%s%s\n' "$RED" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$failed_phase" "$RESET"
  printf '%s┃%s   %sCode retour%s     %src=%s%s\n' "$RED" "$RESET" "$BOLD" "$RESET" "$YELLOW" "$RC" "$RESET"
  if [[ -n "$delta_line" ]]; then
    printf '%s┃%s   %sΔ historique%s    %b\n' "$RED" "$RESET" "$BOLD" "$RESET" "$delta_line"
  fi
  printf '%s┃%s\n' "$RED" "$RESET"
  printf '%s┃%s   %sLog complet%s     %s%s%s\n' "$RED" "$RESET" "$BOLD" "$RESET" "$DIM" "${LOG:-(non disponible)}" "$RESET"
  printf '%s┃%s\n' "$RED" "$RESET"
  printf '%s┃%s   %sReprise rapide%s\n' "$RED" "$RESET" "$BOLD" "$RESET"
  printf '%s┃%s     %s$%s make %s%s%s\n' "$RED" "$RESET" "$DIM" "$RESET" "$CYAN" "$failed_phase" "$RESET"
  printf '%s┃%s     %s$%s make deploy DEPLOY_IAC=0   %s# reprendre sur cluster existant%s\n' "$RED" "$RESET" "$DIM" "$RESET" "$DIM" "$RESET"
  printf '%s┗%s┛%s\n' "$RED" "$HR" "$RESET"
fi

echo ""

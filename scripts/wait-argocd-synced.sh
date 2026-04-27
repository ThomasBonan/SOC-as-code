#!/usr/bin/env bash
# wait-argocd-synced.sh <app1> [app2 ...] [--kubeconfig path] [--timeout 600]
#                       [--allow-degraded]
# Attend que chaque Application ArgoCD soit Synced ET Healthy.
# --allow-degraded : accepte Synced+Degraded comme terminal (ex. soc-eso-externalsecrets
#   dont 2/16 ExternalSecrets restent en SecretSyncedError jusqu'après databases).
set -euo pipefail

KCFG="ansible/playbooks/artifacts/admin.conf"
TIMEOUT=600
ALLOW_DEGRADED=false
APPS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig)    KCFG="$2"; shift 2 ;;
    --timeout)       TIMEOUT="$2"; shift 2 ;;
    --allow-degraded) ALLOW_DEGRADED=true; shift ;;
    *)               APPS+=("$1"); shift ;;
  esac
done

[[ ${#APPS[@]} -eq 0 ]] && { echo "Usage: $0 <app1> [app2...] [--kubeconfig path] [--timeout sec] [--allow-degraded]"; exit 1; }

INTERVAL=10
PROGRESS_EVERY=30

_is_done() {
  local app="$1"
  local sync health
  sync=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
    -o jsonpath='{.status.sync.status}' 2>/dev/null)
  health=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
    -o jsonpath='{.status.health.status}' 2>/dev/null)
  if "${ALLOW_DEGRADED}"; then
    # --allow-degraded : accepte Healthy ou Degraded, sync ignoré.
    # Cas d'usage : soc-eso-externalsecrets dont certains ExternalSecrets
    # échouent car les namespaces SOC n'existent pas encore avant day-1.
    [[ "${health}" == "Healthy" || "${health}" == "Degraded" ]]
  else
    [[ "${sync}" == "Synced" ]] && [[ "${health}" == "Healthy" ]]
  fi
}

wait_app() {
  local app="$1"
  local elapsed=0
  local last_progress=-1
  local label="Synced+Healthy"
  "${ALLOW_DEGRADED}" && label="Synced+Healthy|Degraded"
  echo "⏳ Attente sync ${app} [${label}] (timeout ${TIMEOUT}s)..."

  until _is_done "${app}"; do
    if (( elapsed >= TIMEOUT )); then
      echo "❌ Timeout: ${app} non ${label} après ${TIMEOUT}s"
      kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.conditions}' 2>/dev/null || true
      exit 1
    fi

    local bucket=$(( elapsed / PROGRESS_EVERY ))
    if (( bucket != last_progress )); then
      last_progress=$bucket
      local sync_status health_status msg_status
      sync_status=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "?")
      health_status=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.health.status}' 2>/dev/null || echo "?")
      msg_status=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.operationState.message}' 2>/dev/null | head -c 80 || true)
      printf "  [%3ds/%ds] %-30s  sync=%-12s  health=%-12s  %s\n" \
        "$elapsed" "$TIMEOUT" "$app" "$sync_status" "$health_status" "$msg_status"
    fi

    sleep "${INTERVAL}"
    (( elapsed += INTERVAL ))
  done

  local final_health
  final_health=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
    -o jsonpath='{.status.health.status}' 2>/dev/null || echo "?")
  echo "✅ ${app} Synced+${final_health} (${elapsed}s)"
}

for app in "${APPS[@]}"; do
  wait_app "${app}"
done

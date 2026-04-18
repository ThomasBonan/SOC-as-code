#!/usr/bin/env bash
# wait-argocd-synced.sh <app1> [app2 ...] [--kubeconfig path] [--timeout 600]
# Attend que chaque Application ArgoCD soit Synced ET Healthy.
set -euo pipefail

KCFG="ansible/playbooks/artifacts/admin.conf"
TIMEOUT=600
APPS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KCFG="$2"; shift 2 ;;
    --timeout)    TIMEOUT="$2"; shift 2 ;;
    *)            APPS+=("$1"); shift ;;
  esac
done

[[ ${#APPS[@]} -eq 0 ]] && { echo "Usage: $0 <app1> [app2...] [--kubeconfig path] [--timeout sec]"; exit 1; }

INTERVAL=10
PROGRESS_EVERY=30   # afficher le statut courant toutes les N secondes

wait_app() {
  local app="$1"
  local elapsed=0
  local last_progress=-1
  echo "⏳ Attente sync ${app} (timeout ${TIMEOUT}s)..."
  until [[ "$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
              -o jsonpath='{.status.sync.status}' 2>/dev/null)" == "Synced" ]] && \
        [[ "$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
              -o jsonpath='{.status.health.status}' 2>/dev/null)" == "Healthy" ]]; do
    if (( elapsed >= TIMEOUT )); then
      echo "❌ Timeout: ${app} non Synced+Healthy après ${TIMEOUT}s"
      kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.conditions}' 2>/dev/null || true
      exit 1
    fi

    # Afficher la progression toutes les PROGRESS_EVERY secondes
    local bucket=$(( elapsed / PROGRESS_EVERY ))
    if (( bucket != last_progress )); then
      last_progress=$bucket
      local sync_status health_status
      sync_status=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "?")
      health_status=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.health.status}' 2>/dev/null || echo "?")
      local msg_status
      msg_status=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${app}" \
        -o jsonpath='{.status.operationState.message}' 2>/dev/null | head -c 80 || true)
      printf "  [%3ds/%ds] %-30s  sync=%-12s  health=%-12s  %s\n" \
        "$elapsed" "$TIMEOUT" "$app" "$sync_status" "$health_status" "$msg_status"
    fi

    sleep "${INTERVAL}"
    (( elapsed += INTERVAL ))
  done
  echo "✅ ${app} Synced+Healthy (${elapsed}s)"
}

for app in "${APPS[@]}"; do
  wait_app "${app}"
done

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
wait_app() {
  local app="$1"
  local elapsed=0
  echo "⏳ Attente sync ${app}..."
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
    sleep "${INTERVAL}"
    (( elapsed += INTERVAL ))
  done
  echo "✅ ${app} Synced+Healthy"
}

for app in "${APPS[@]}"; do
  wait_app "${app}"
done

#!/usr/bin/env bash
# force-resync-if-failed.sh <app> [--kubeconfig path]
#
# Vérifie l'état d'une Application ArgoCD. Si elle est dans un état terminal
# d'échec (operationState.phase=Failed ou Error, retry budget épuisé), on
# force une resync via kubectl patch. Sinon ne fait rien (idempotent).
#
# Usage typique : appelé juste avant wait-argocd-synced.sh, après une étape
# Ansible qui a installé les CRDs/dépendances attendues par l'App.
set -euo pipefail

KCFG="ansible/playbooks/artifacts/admin.conf"
APP=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KCFG="$2"; shift 2 ;;
    *)            APP="$1"; shift ;;
  esac
done

[[ -z "${APP}" ]] && { echo "Usage: $0 <app> [--kubeconfig path]"; exit 1; }

# Si l'Application n'existe pas encore, on laisse wait-argocd-synced.sh s'en charger.
if ! kubectl --kubeconfig="${KCFG}" -n argocd get application "${APP}" >/dev/null 2>&1; then
  echo "ℹ️  ${APP} n'existe pas encore — skip force-resync."
  exit 0
fi

PHASE=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${APP}" \
  -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "")
SYNC=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${APP}" \
  -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "")
HEALTH=$(kubectl --kubeconfig="${KCFG}" -n argocd get application "${APP}" \
  -o jsonpath='{.status.health.status}' 2>/dev/null || echo "")

# Cas terminal d'échec : sync s'est planté (Failed/Error) ou App OutOfSync sans
# operation en cours. Dans tous les cas, on patch une nouvelle sync.
if [[ "${PHASE}" == "Failed" || "${PHASE}" == "Error" ]] || \
   [[ "${SYNC}" == "OutOfSync" && "${HEALTH}" != "Progressing" ]]; then
  echo "⚠️  ${APP} en état terminal d'échec (phase=${PHASE} sync=${SYNC} health=${HEALTH}) — force resync."
  kubectl --kubeconfig="${KCFG}" -n argocd patch application "${APP}" \
    --type merge \
    -p '{"operation":{"sync":{"syncStrategy":{"hook":{}},"prune":true}}}' >/dev/null
  echo "✅ Resync déclenchée sur ${APP}."
else
  echo "✅ ${APP} OK (phase=${PHASE:-<none>} sync=${SYNC} health=${HEALTH}) — pas de resync nécessaire."
fi

#!/usr/bin/env bash
# wait-app-of-apps.sh [--kubeconfig path] [--timeout 300]
# Attend que soc-app-of-apps ait créé les Applications enfants clés.
# Nécessaire entre l'installation d'ArgoCD et le wait-infra-synced pour
# éviter "Application not found" quand les Applications n'ont pas encore
# été générées par le repo-server.
set -euo pipefail

KCFG="ansible/playbooks/artifacts/admin.conf"
TIMEOUT=300
INTERVAL=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubeconfig) KCFG="$2"; shift 2 ;;
    --timeout)    TIMEOUT="$2"; shift 2 ;;
    *) echo "Usage: $0 [--kubeconfig path] [--timeout sec]"; exit 1 ;;
  esac
done

# Applications enfants minimales attendues avant de continuer
REQUIRED_APPS=(
  infra-metallb
  infra-longhorn
  infra-cert-manager
  infra-ingress-nginx
  soc-eso-externalsecrets
)

elapsed=0
echo "⏳ Attente création des Applications ArgoCD enfants (soc-app-of-apps)..."

while true; do
  all_found=true
  missing=()

  for app in "${REQUIRED_APPS[@]}"; do
    if ! kubectl --kubeconfig="${KCFG}" -n argocd \
        get application "${app}" &>/dev/null 2>&1; then
      all_found=false
      missing+=("${app}")
    fi
  done

  if "${all_found}"; then
    echo "✅ Toutes les Applications enfants créées (${elapsed}s)"
    break
  fi

  if (( elapsed >= TIMEOUT )); then
    echo "❌ Timeout: Applications manquantes après ${TIMEOUT}s : ${missing[*]}"
    echo "   Vérifier que soc-app-of-apps est Synced et que le repo-server peut joindre GitHub."
    kubectl --kubeconfig="${KCFG}" -n argocd get application soc-app-of-apps \
      -o jsonpath='{.status.conditions}' 2>/dev/null || true
    exit 1
  fi

  printf "  [%3ds/%ds] Applications manquantes : %s\n" \
    "$elapsed" "$TIMEOUT" "${missing[*]}"
  sleep "${INTERVAL}"
  (( elapsed += INTERVAL ))
done

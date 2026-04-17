#!/usr/bin/env bash
# wait-argocd-ready.sh [kubeconfig] [timeout_seconds=300]
# Attend que argocd-server soit Available.
set -euo pipefail

KCFG="${1:-ansible/playbooks/artifacts/admin.conf}"
TIMEOUT="${2:-300}"

echo "⏳ Attente ArgoCD server (timeout ${TIMEOUT}s)..."
kubectl --kubeconfig="${KCFG}" -n argocd \
  wait deployment/argocd-server \
  --for=condition=Available \
  --timeout="${TIMEOUT}s"
echo "✅ ArgoCD server prêt"

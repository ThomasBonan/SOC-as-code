#!/usr/bin/env bash
# wait-ssh.sh <host> [timeout_seconds=300]
# Attend qu'un hôte réponde en SSH. Utile après tofu apply.
set -euo pipefail

HOST="${1:?Usage: $0 <host> [timeout]}"
TIMEOUT="${2:-300}"
INTERVAL=10
elapsed=0

echo "⏳ Attente SSH sur ${HOST} (timeout ${TIMEOUT}s)..."
until ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
          ubuntu@"${HOST}" true 2>/dev/null; do
  if (( elapsed >= TIMEOUT )); then
    echo "❌ Timeout: ${HOST} injoignable après ${TIMEOUT}s"
    exit 1
  fi
  sleep "${INTERVAL}"
  (( elapsed += INTERVAL ))
done
echo "✅ SSH disponible sur ${HOST}"

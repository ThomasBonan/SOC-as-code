#!/usr/bin/env bash
# preflight-check.sh — Vérifie les prérequis avant make deploy
set -euo pipefail

ERRORS=0

check() {
  local cmd="$1"
  local hint="${2:-}"
  if command -v "${cmd}" &>/dev/null; then
    echo "  ✅ ${cmd}"
  else
    echo "  ❌ ${cmd} manquant${hint:+ — ${hint}}"
    (( ERRORS++ ))
  fi
}

check_file() {
  local path="$1"
  local hint="${2:-}"
  if [[ -f "${path}" ]]; then
    echo "  ✅ ${path}"
  else
    echo "  ❌ ${path} absent${hint:+ — ${hint}}"
    (( ERRORS++ ))
  fi
}

echo "🔍 Vérification des prérequis make deploy..."
echo ""
echo "Binaires :"
check tofu        "brew install opentofu"
check ansible-playbook "pip install ansible"
check kubectl     "curl -LO https://dl.k8s.io/release/.../kubectl"
check helm        "brew install helm"
check jq          "apt install jq"
check yq          "brew install yq"

echo ""
echo "Fichiers de configuration :"
check_file "iac/terraform.tfvars" "copier iac/terraform.tfvars.example"
check_file "ansible/inventories/k8s.ini" "vérifier l'inventaire Ansible"
check_file "/etc/soc-as-code/.env"        "créer le fichier d'environnement SOC"

echo ""
echo "Accès Proxmox :"
if [[ -f "/etc/soc-as-code/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source /etc/soc-as-code/.env; set +a
  if curl -sk --max-time 5 "${PM_API_URL:-https://proxmox:8006}/api2/json/version" | grep -q version; then
    echo "  ✅ API Proxmox joignable"
  else
    echo "  ❌ API Proxmox inaccessible (${PM_API_URL:-PM_API_URL non défini})"
    (( ERRORS++ ))
  fi
fi

echo ""
if (( ERRORS > 0 )); then
  echo "❌ ${ERRORS} prérequis manquant(s). Corriger avant de lancer make deploy."
  exit 1
fi
echo "✅ Tous les prérequis sont satisfaits."

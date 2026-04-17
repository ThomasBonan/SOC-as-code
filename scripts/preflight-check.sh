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
# terraform.tfvars est optionnel — les variables peuvent venir de TF_VAR_* dans /etc/soc-as-code/.env
if [[ -f "iac/terraform.tfvars" ]]; then
  echo "  ✅ iac/terraform.tfvars"
else
  echo "  ⚠️  iac/terraform.tfvars absent (OK si TF_VAR_* définis dans /etc/soc-as-code/.env)"
fi
check_file "ansible/inventories/k8s.ini" "vérifier l'inventaire Ansible"
check_file "/etc/soc-as-code/.env"        "créer le fichier d'environnement SOC"

echo ""
echo "Accès Proxmox :"
if [[ -f "/etc/soc-as-code/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source /etc/soc-as-code/.env; set +a
  _proxmox_url="${TF_VAR_pm_api_url:-${PM_API_URL:-}}"
  if [[ -z "${_proxmox_url}" ]]; then
    echo "  ⚠️  TF_VAR_pm_api_url non défini dans .env — skip test Proxmox"
  elif curl -sk --max-time 5 "${_proxmox_url}/version" | grep -q version; then
    echo "  ✅ API Proxmox joignable (${_proxmox_url})"
  else
    echo "  ❌ API Proxmox inaccessible (${_proxmox_url})"
    (( ERRORS++ ))
  fi
fi

echo ""
if (( ERRORS > 0 )); then
  echo "❌ ${ERRORS} prérequis manquant(s). Corriger avant de lancer make deploy."
  exit 1
fi
echo "✅ Tous les prérequis sont satisfaits."

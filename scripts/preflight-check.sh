#!/usr/bin/env bash
# preflight-check.sh — Vérifie les prérequis avant make deploy
set -euo pipefail

ERRORS=0
WARNINGS=0
DEPLOY_IAC="${DEPLOY_IAC:-1}"
KCFG="ansible/playbooks/artifacts/admin.conf"

check() {
  local cmd="$1"
  local hint="${2:-}"
  if command -v "${cmd}" &>/dev/null; then
    echo "  ✅ ${cmd}"
  else
    echo "  ❌ ${cmd} manquant${hint:+ — ${hint}}"
    (( ++ERRORS ))
  fi
}

check_file() {
  local path="$1"
  local hint="${2:-}"
  if [[ -f "${path}" ]]; then
    echo "  ✅ ${path}"
  else
    echo "  ❌ ${path} absent${hint:+ — ${hint}}"
    (( ++ERRORS ))
  fi
}

warn_file() {
  local path="$1"
  local hint="${2:-}"
  if [[ -f "${path}" ]]; then
    echo "  ✅ ${path}"
  else
    echo "  ⚠️  ${path} absent${hint:+ — ${hint}}"
    (( ++WARNINGS ))
  fi
}

echo "🔍 Vérification des prérequis make deploy..."
echo ""

echo "Binaires :"
check tofu             "apt install opentofu  ou  brew install opentofu"
check ansible-playbook "pip install ansible"
check kubectl          "snap install kubectl --classic"
check helm             "snap install helm --classic"
check jq               "apt install jq"
check yq               "snap install yq"
check git              "apt install git"

echo ""
echo "Fichiers de configuration :"
check_file "ansible/inventories/k8s.ini" "vérifier l'inventaire Ansible"
check_file "/etc/soc-as-code/.env"        "créer le fichier d'environnement SOC (voir docs/env.md)"

# terraform.tfvars optionnel : les vars peuvent venir de TF_VAR_* dans .env
if [[ -f "iac/terraform.tfvars" ]]; then
  echo "  ✅ iac/terraform.tfvars"
else
  echo "  ⚠️  iac/terraform.tfvars absent (OK si TF_VAR_* définis dans /etc/soc-as-code/.env)"
  (( ++WARNINGS ))
fi

# Si DEPLOY_IAC=0 (cluster existant), vérifier que le kubeconfig est là
if [[ "${DEPLOY_IAC}" == "0" ]]; then
  echo ""
  echo "Mode DEPLOY_IAC=0 (cluster existant) :"
  check_file "${KCFG}" "le kubeconfig doit exister sur un cluster déjà provisionné"
fi

echo ""
echo "Accès Proxmox :"
if [[ -f "/etc/soc-as-code/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source /etc/soc-as-code/.env; set +a
  _proxmox_url="${TF_VAR_pm_api_url:-${PM_API_URL:-}}"
  if [[ -z "${_proxmox_url}" ]]; then
    echo "  ⚠️  TF_VAR_pm_api_url non défini dans .env — skip test Proxmox"
    (( ++WARNINGS ))
  elif curl -sk --max-time 5 "${_proxmox_url}/version" | grep -q version; then
    echo "  ✅ API Proxmox joignable (${_proxmox_url})"
  else
    if [[ "${DEPLOY_IAC}" == "1" ]]; then
      echo "  ❌ API Proxmox inaccessible (${_proxmox_url}) — requis pour DEPLOY_IAC=1"
      (( ++ERRORS ))
    else
      echo "  ⚠️  API Proxmox inaccessible (${_proxmox_url}) — ignoré car DEPLOY_IAC=0"
      (( ++WARNINGS ))
    fi
  fi
fi

echo ""
echo "Collections Ansible :"
if ansible-galaxy collection list community.hashi_vault 2>/dev/null | grep -q "hashi_vault"; then
  echo "  ✅ community.hashi_vault"
else
  echo "  ⚠️  community.hashi_vault manquante — lancer : ansible-galaxy collection install -r ansible/requirements.yml"
  (( ++WARNINGS ))
fi

echo ""
if (( ERRORS > 0 )); then
  echo "❌ ${ERRORS} prérequis bloquant(s)${WARNINGS:+ + ${WARNINGS} avertissement(s)}. Corriger avant de lancer make deploy."
  exit 1
fi
if (( WARNINGS > 0 )); then
  echo "⚠️  ${WARNINGS} avertissement(s) — le déploiement peut continuer mais vérifier ces points."
fi
echo "✅ Prérequis satisfaits — make deploy peut démarrer."

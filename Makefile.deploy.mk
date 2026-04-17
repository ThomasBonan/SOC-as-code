##############################################################################
# Makefile.deploy.mk — Orchestration complète du déploiement SOC-as-code
#
# Usage :
#   make deploy            — déploiement from-scratch complet
#   make deploy-from=<n>   — reprendre depuis une étape spécifique
#   make destroy-lab       — détruire le lab Proxmox (DANGER)
#
# Variables d'override :
#   DEPLOY_IAC=0           — sauter l'étape IaC (cluster déjà provisionné)
#   MASTER_IP=10.0.20.10   — IP du master K8s
#   SSH_TIMEOUT=300        — timeout SSH après tofu apply
##############################################################################

MASTER_IP   ?= 10.0.20.10
DEPLOY_IAC  ?= 1
SSH_TIMEOUT ?= 300
SCRIPTS     := scripts

ANS := ansible-playbook $(ANS_DIR)/playbooks

# ── Cibles de bas niveau manquantes dans le Makefile principal ────────────────
.PHONY: workers-pre post-master databases wazuh misp cortex thehive \
        soc-config soc-smoke mtls foundations automation shuffle \
        automation-rerun risk-engine

workers-pre: ## Prérequis Longhorn sur workers (70)
	ansible-playbook $(ANS_DIR)/playbooks/70-post-config-worker.yml

post-master: ## Post-config master : cert-manager, Longhorn, ingress-nginx (60)
	ansible-playbook $(ANS_DIR)/playbooks/60-post-config-master.yml

databases: ## Bases de données SOC (80)
	$(ANS) /80-databases.yml

wazuh: ## Déployer Wazuh (90)
	$(ANS) /90-wazuh.yml

misp: ## Déployer MISP (100)
	$(ANS) /100-misp.yml

cortex: ## Déployer Cortex (110)
	$(ANS) /110-cortex.yml

thehive: ## Déployer TheHive (120)
	$(ANS) /120-thehive.yml

soc-config: ## Configuration SOC post-déploiement (130)
	$(ANS) /130-soc-config.yml

soc-smoke: ## Smoke tests SOC (140)
	$(ANS) /140-soc-smoke.yml

mtls: ## mTLS inter-services (155)
	$(ANS) /155-soc-mtls.yml

foundations: ## Fondations RBAC/SA (170)
	$(ANS) /170-soc-foundations.yml

automation: ## Automation Wazuh→Shuffle (180 — 1er passage)
	$(ANS) /180-soc-automation.yml

shuffle: ## Déployer Shuffle SOAR (185)
	$(ANS) /185-shuffle.yml

automation-rerun: ## Automation 2e passage post-Shuffle (180 — circular dep fix)
	$(ANS) /180-soc-automation.yml

risk-engine: ## Risk Engine Flask (190)
	$(ANS) /190-soc-risk-engine.yml

# ── Cibles de wait ────────────────────────────────────────────────────────────
.PHONY: wait-vms wait-nodes wait-argocd wait-argocd-synced

wait-vms: ## Attendre que le master K8s soit joignable en SSH
	@bash $(SCRIPTS)/wait-ssh.sh $(MASTER_IP) $(SSH_TIMEOUT)

wait-nodes: ## Attendre que tous les nœuds K8s soient Ready
	kubectl --kubeconfig=$(KCFG) wait --for=condition=Ready nodes --all --timeout=600s

wait-argocd: ## Attendre que argocd-server soit Available
	@bash $(SCRIPTS)/wait-argocd-ready.sh $(KCFG) 300

wait-infra-synced: ## Attendre que les apps infra (MetalLB, Longhorn, cert-manager, ingress-nginx) soient Synced
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  infra-metallb infra-longhorn infra-cert-manager infra-ingress-nginx \
	  --kubeconfig $(KCFG) --timeout 900

wait-argocd-synced: ## Attendre que les apps ArgoCD principales soient Synced+Healthy
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  soc-apps soc-infra soc-security soc-eso \
	  --kubeconfig $(KCFG) --timeout 600

# ── Preflight ─────────────────────────────────────────────────────────────────
.PHONY: preflight
preflight: ## Vérifier les prérequis avant deploy
	@bash $(SCRIPTS)/preflight-check.sh

# ── Blocs de déploiement ──────────────────────────────────────────────────────
.PHONY: k8s-bootstrap vault-deploy argocd-full soc-day1 soc-security-layer \
        soc-automation-layer soc-validate

k8s-bootstrap: prereqs bins workers-pre cp cni join post post-master ## K8s from scratch (00→60)

vault-deploy: ## Vault + ESO (75)
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml --tags bootstrap
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml --tags external_secrets

argocd-full: vault-deploy monitoring argocd wait-argocd wait-infra-synced ## Vault+Monitoring+ArgoCD + attente infra GitOps synced

soc-day1: databases wazuh misp cortex thehive soc-config soc-smoke ## Stack SOC day-1 (80→140)

soc-security-layer: netpol mtls wait-argocd-synced ## Sécurité réseau + sync ArgoCD (150→155)

soc-automation-layer: foundations automation shuffle automation-rerun risk-engine ## Automation 170→190 (gère dép. circulaire 180→185→180)

soc-validate: compliance selftest ## Conformité + selftest E2E (200→210)

# ── Deploy principal ──────────────────────────────────────────────────────────
.PHONY: deploy

ifeq ($(DEPLOY_IAC),1)
_iac_step := iac-apply wait-vms
else
_iac_step :=
endif

deploy: preflight $(_iac_step) wait-nodes argocd-full soc-day1 soc-security-layer soc-automation-layer soc-validate ## Déploiement SOC complet from-scratch (IaC → K8s → ArgoCD → SOC → selftest)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════╗"
	@echo "║  ✅  SOC-as-code déployé avec succès                     ║"
	@echo "║  ArgoCD : https://argocd.apps.soc.lab                    ║"
	@echo "║  Wazuh  : https://wazuh.apps.soc.lab                     ║"
	@echo "╚══════════════════════════════════════════════════════════╝"

# ── Destroy (DANGER) ──────────────────────────────────────────────────────────
.PHONY: destroy-lab

destroy-lab: ## ⚠️  DÉTRUIRE le lab Proxmox (demande CONFIRM=yes)
	@[[ "$(CONFIRM)" == "yes" ]] || \
	  { echo "❌ Requiert CONFIRM=yes  — ex: make destroy-lab CONFIRM=yes"; exit 1; }
	@echo "💣 Destruction du lab dans 5 secondes... (Ctrl-C pour annuler)"
	@sleep 5
	@cd $(IAC_DIR) && tofu destroy -auto-approve
	@echo "✅ Lab détruit. Relancer make deploy pour recréer."

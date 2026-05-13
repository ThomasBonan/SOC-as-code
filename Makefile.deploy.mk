##############################################################################
# Makefile.deploy.mk — Orchestration complète du déploiement SOC-as-code
#
# Usage :
#   make deploy            — déploiement from-scratch complet (IaC + K8s + SOC)
#   make deploy DEPLOY_IAC=0  — reprendre sur cluster existant (skip IaC)
#   make destroy-lab       — détruire le lab Proxmox (DANGER)
#
# Variables d'override :
#   DEPLOY_IAC=0           — sauter l'étape IaC (cluster déjà provisionné)
#   MASTER_IP=10.0.20.10   — IP du master K8s
#   SSH_TIMEOUT=300        — timeout SSH après tofu apply
##############################################################################

MASTER_IP    ?= 10.0.20.10
DEPLOY_IAC   ?= 1
SSH_TIMEOUT  ?= 300
SCRIPTS      := scripts
SOC_ENV_FILE ?= /etc/soc-as-code/.env

# Ansible doit trouver ansible.cfg (roles_path, inventory) depuis n'importe quel CWD
export ANSIBLE_CONFIG := $(ANS_DIR)/ansible.cfg

# Source les credentials Proxmox depuis SOC_ENV_FILE avant chaque appel tofu
_tofu_env = set -a && . $(SOC_ENV_FILE) && set +a

ANS := ansible-playbook $(ANS_DIR)/playbooks

# ── Override iac-apply : source SOC_ENV_FILE avant tofu ──────────────────────
.PHONY: iac-apply
iac-apply: ## Appliquer le plan IaC (source SOC_ENV_FILE pour les credentials Proxmox)
	@$(_tofu_env) && cd $(IAC_DIR) && tofu apply -auto-approve -parallelism=2

# ── Cibles de bas niveau manquantes dans le Makefile principal ────────────────
.PHONY: workers-pre post-master databases wazuh misp cortex thehive \
        soc-config soc-smoke foundations automation shuffle \
        automation-rerun risk-engine cert-manager-issuer

workers-pre: ## Prérequis Longhorn sur workers (70)
	ansible-playbook $(ANS_DIR)/playbooks/70-post-config-worker.yml

post-master: ## Post-config master : cert-manager, Longhorn, ingress-nginx (60)
	ansible-playbook $(ANS_DIR)/playbooks/60-post-config-master.yml

databases: ## Bases de données SOC (80)
	$(ANS)/80-databases.yml

wazuh: ## Déployer Wazuh (90)
	$(ANS)/90-wazuh.yml

misp: ## Déployer MISP (100)
	$(ANS)/100-misp.yml

cortex: ## Déployer Cortex (110)
	$(ANS)/110-cortex.yml

thehive: ## Déployer TheHive (120)
	$(ANS)/120-thehive.yml

soc-config: ## Configuration SOC post-déploiement (130)
	$(ANS)/130-soc-config.yml

soc-smoke: ## Smoke tests SOC (140)
	$(ANS)/140-soc-smoke.yml

foundations: ## Fondations RBAC/SA (170)
	$(ANS)/170-soc-foundations.yml

automation: ## Automation Wazuh→Shuffle (180 — 1er passage)
	$(ANS)/180-soc-automation.yml

shuffle: ## Déployer Shuffle SOAR (185)
	$(ANS)/185-shuffle.yml

automation-rerun: ## Automation 2e passage post-Shuffle (180 — circular dep fix)
	$(ANS)/180-soc-automation.yml

risk-engine: ## Risk Engine Flask (190)
	$(ANS)/190-soc-risk-engine.yml

# ── Cibles de wait ────────────────────────────────────────────────────────────
.PHONY: wait-vms wait-nodes wait-argocd wait-argocd-synced longhorn-prereqs \
        wait-app-of-apps wait-eso-synced

wait-vms: ## Attendre que le master K8s soit joignable en SSH
	@bash $(SCRIPTS)/wait-ssh.sh $(MASTER_IP) $(SSH_TIMEOUT)

wait-nodes: ## Attendre que tous les nœuds K8s soient Ready
	kubectl --kubeconfig=$(KCFG) wait --for=condition=Ready nodes --all --timeout=600s

wait-argocd: ## Attendre que argocd-server soit Available
	@bash $(SCRIPTS)/wait-argocd-ready.sh $(KCFG) 300

longhorn-prereqs: ## Pré-créer namespace + SA Longhorn (évite FailedCreate sur le hook pre-upgrade)
	@kubectl --kubeconfig=$(KCFG) create namespace longhorn-system --dry-run=client -o yaml | kubectl --kubeconfig=$(KCFG) apply -f -
	@kubectl --kubeconfig=$(KCFG) -n longhorn-system create serviceaccount longhorn-service-account --dry-run=client -o yaml | kubectl --kubeconfig=$(KCFG) apply -f -

wait-infra-synced: ## Attendre que les apps infra (MetalLB, Longhorn, cert-manager, ingress-nginx) soient Synced
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  infra-metallb infra-longhorn infra-cert-manager infra-ingress-nginx \
	  --kubeconfig $(KCFG) --timeout 900

wait-app-of-apps: ## Attendre que soc-app-of-apps crée les Applications enfants clés
	@bash $(SCRIPTS)/wait-app-of-apps.sh --kubeconfig $(KCFG) --timeout 300

wait-eso-synced: ## Attendre que soc-eso-externalsecrets soit Synced (Degraded OK : 2/16 ESO attendent les databases)
	@# Race bootstrap : soc-app-of-apps a pu créer cette App avant que les CRDs
	@# ESO ne soient installés par vault-deploy. Si l'App est en SyncError (retry
	@# budget épuisé), on force une resync maintenant que les CRDs existent.
	@bash $(SCRIPTS)/force-resync-if-failed.sh soc-eso-externalsecrets --kubeconfig $(KCFG)
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  soc-eso-externalsecrets \
	  --kubeconfig $(KCFG) --timeout 300 --allow-degraded

wait-soc-apps-synced: ## Attendre que les apps SOC Helm (Cortex, TheHive, MISP Redis, Shuffle) soient Synced
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  infra-cortex infra-thehive infra-misp-redis \
	  --kubeconfig $(KCFG) --timeout 1200
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  infra-shuffle \
	  --kubeconfig $(KCFG) --timeout 2400

wait-argocd-synced: ## Attendre que les apps ArgoCD principales soient Synced+Healthy
	@# soc-eso-externalsecrets reste Degraded jusqu'à 170-foundations (les
	@# ES `*-sa-foundations` lisent service-accounts/<sa> dans Vault, qui ne sont
	@# seedés qu'à ce moment-là). On l'accepte → --allow-degraded.
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  soc-eso-externalsecrets \
	  --kubeconfig $(KCFG) --timeout 600 --allow-degraded
	@bash $(SCRIPTS)/wait-argocd-synced.sh \
	  soc-netpols \
	  --kubeconfig $(KCFG) --timeout 600

# ── Preflight ─────────────────────────────────────────────────────────────────
.PHONY: preflight
preflight: ## Vérifier les prérequis avant deploy
	@bash $(SCRIPTS)/preflight-check.sh

# ── Blocs de déploiement ──────────────────────────────────────────────────────
.PHONY: k8s-bootstrap vault-deploy argocd-full argocd-update-password soc-day1 soc-security-layer \
        soc-automation-layer soc-validate

k8s-bootstrap: prereqs bins cp cni join post post-master workers-pre ## K8s from scratch (00→70)

vault-deploy: ## Vault + ESO (75)
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml --tags bootstrap
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml --tags external_secrets

cert-manager-issuer: ## Créer ClusterIssuer soc-lab-ca-issuer (après ArgoCD sync infra-cert-manager)
	$(ANS)/61-cert-manager-issuer.yml

argocd-update-password: ## Mettre à jour le mot de passe ArgoCD depuis Vault (post vault-deploy)
	$(ANS)/77-argocd.yml --tags deploy -e argocd_force_password_update=true

# Ordre bootstrap GitOps :
#   1. ArgoCD démarre en premier (avant Vault) car Longhorn (stockage Vault) est
#      déployé par ArgoCD. Un mot de passe statique bootstrap est utilisé.
#   2. wait-app-of-apps : soc-app-of-apps déploie les Applications enfants.
#   3. wait-infra-synced : MetalLB/Longhorn/cert-manager/ingress-nginx Ready.
#   4. vault-deploy seede les secrets + active l'ESO.
#   5. argocd-update-password remplace le mot de passe statique par celui de Vault.
#   6. wait-eso-synced : soc-eso-externalsecrets Synced → K8s Secrets hydratés.
argocd-full: argocd wait-argocd longhorn-prereqs wait-app-of-apps wait-infra-synced cert-manager-issuer vault-deploy argocd-update-password monitoring ## ArgoCD+infra GitOps+Vault+Monitoring (ordre bootstrap sans dépendance circulaire)

soc-day1: databases _soc-services soc-config soc-smoke ## Stack SOC day-1 (80→140)

# Parallélisation sûre : wazuh / misp / cortex / thehive sont 4 playbooks
# indépendants une fois `databases` (80) prêt :
#   - hosts: localhost, gather_facts: false → aucun conflit SSH ni fact-cache
#   - namespaces K8s distincts (soc-wazuh, soc-core, soc-cortex, soc-thehive)
#   - chaque playbook attend son propre infra-<service> ArgoCD en interne
# Gain attendu ≈ (somme − max) des 4 durées individuelles.
# --output-sync=target groupe la sortie par cible (sinon 4 logs entrelacés).
.PHONY: _soc-services
_soc-services: ## (interne) Déploie wazuh+misp+cortex+thehive en parallèle (-j4)
	$(MAKE) --output-sync=target -j4 wazuh misp cortex thehive

soc-security-layer: netpol wait-argocd-synced ## Sécurité réseau + sync ArgoCD (150)

soc-automation-layer: foundations automation shuffle automation-rerun risk-engine ## Automation 170→190 (gère dép. circulaire 180→185→180)

soc-validate: compliance selftest ## Conformité + selftest E2E (200→210)

# ── Deploy principal ──────────────────────────────────────────────────────────
.PHONY: deploy

ifeq ($(DEPLOY_IAC),1)
_iac_step := iac-apply wait-vms k8s-bootstrap
else
_iac_step :=
endif

deploy: preflight $(_iac_step) wait-nodes argocd-full wait-eso-synced soc-day1 wait-soc-apps-synced soc-security-layer soc-automation-layer soc-validate ## Déploiement SOC complet from-scratch (IaC → K8s → ArgoCD → ESO → SOC → selftest)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════════════╗"
	@echo "║  SOC-as-code deploye avec succes                             ║"
	@echo "║                                                              ║"
	@echo "║  ArgoCD   : https://argocd.apps.soc.lab                      ║"
	@echo "║  Wazuh    : https://wazuh.apps.soc.lab                       ║"
	@echo "║  TheHive  : https://thehive.apps.soc.lab                     ║"
	@echo "║  Cortex   : https://cortex.apps.soc.lab                      ║"
	@echo "║  MISP     : https://misp.apps.soc.lab                        ║"
	@echo "║  Shuffle  : https://shuffle.apps.soc.lab                     ║"
	@echo "╚══════════════════════════════════════════════════════════════╝"

# ── Chronométrage ─────────────────────────────────────────────────────────────
# Phases reproduisant la chaîne de `deploy` (Makefile.deploy.mk:183).
# Si DEPLOY_IAC=0, les phases iac-apply / wait-vms / k8s-bootstrap sont retirées.
_PHASES_IAC      := iac-apply wait-vms k8s-bootstrap
_PHASES_REST     := wait-nodes argocd-full wait-eso-synced soc-day1 \
                    wait-soc-apps-synced soc-security-layer \
                    soc-automation-layer soc-validate
ifeq ($(DEPLOY_IAC),1)
DEPLOY_PHASES := preflight $(_PHASES_IAC) $(_PHASES_REST)
else
DEPLOY_PHASES := preflight $(_PHASES_REST)
endif

.PHONY: deploy-timed deploy-timings deploy-phased

deploy-phased: ## Rejoue `make deploy` phase par phase avec chrono individuel (log par run dans .timings/)
	@mkdir -p .timings
	@ts=$$(date +%Y%m%d-%H%M%S); log=".timings/deploy-phased-$$ts.log"; \
	  printf '\n▶ deploy-phased démarré — log: %s\n' "$$log"; \
	  printf '   phases : %s\n' "$(DEPLOY_PHASES)"; \
	  global_start=$$(date +%s); \
	  global_start_iso=$$(date -Iseconds); \
	  for phase in $(DEPLOY_PHASES); do \
	    bash $(SCRIPTS)/time-phase.sh "$$log" "$$phase" $(MAKE) "$$phase" || { \
	      rc=$$?; \
	      printf '\n❌ phase %s a échoué (rc=%d) — arrêt du pipeline\n' "$$phase" "$$rc"; \
	      $(MAKE) --no-print-directory _phased_summary LOG="$$log" GLOBAL_START="$$global_start" GLOBAL_START_ISO="$$global_start_iso" GLOBAL_RC="$$rc"; \
	      exit $$rc; \
	    }; \
	  done; \
	  $(MAKE) --no-print-directory _phased_summary LOG="$$log" GLOBAL_START="$$global_start" GLOBAL_START_ISO="$$global_start_iso" GLOBAL_RC=0

# Cible interne : imprime un tableau récapitulatif des phases + ligne TOTAL.
.PHONY: _phased_summary
_phased_summary:
	@end=$$(date +%s); end_iso=$$(date -Iseconds); \
	  dur=$$((end - $(GLOBAL_START))); \
	  h=$$((dur/3600)); m=$$(((dur%3600)/60)); s=$$((dur%60)); \
	  printf '%s\t%s\t%s\t%d\t%02d:%02d:%02d\trc=%s\n' "TOTAL" "$(GLOBAL_START_ISO)" "$$end_iso" "$$dur" $$h $$m $$s "$(GLOBAL_RC)" >> "$(LOG)"; \
	  printf '\n══════════════════════════════════════════════════════════════════════════════════\n'; \
	  printf '   Récapitulatif phase-par-phase (log: %s)\n' "$(LOG)"; \
	  printf '══════════════════════════════════════════════════════════════════════════════════\n'; \
	  printf '%-25s %10s %10s   %s\n' "PHASE" "SECONDS" "HH:MM:SS" "RC"; \
	  awk -F'\t' '{ printf "%-25s %10s %10s   %s\n", $$1, $$4, $$5, $$6 }' "$(LOG)"; \
	  printf '══════════════════════════════════════════════════════════════════════════════════\n'

deploy-timed: ## Lance `make deploy` en chronométrant la durée totale (log dans .timings/deploy.log)
	@mkdir -p .timings
	@start=$$(date +%s); start_iso=$$(date -Iseconds); \
	  printf '\n▶ make deploy démarré à %s\n\n' "$$start_iso"; \
	  $(MAKE) deploy; rc=$$?; \
	  end=$$(date +%s); end_iso=$$(date -Iseconds); \
	  dur=$$((end - start)); \
	  h=$$((dur/3600)); m=$$(((dur%3600)/60)); s=$$((dur%60)); \
	  printf '\n══════════════════════════════════════════════════════════════\n'; \
	  printf '⏱  Durée totale : %02d:%02d:%02d  (%ds)  rc=%d\n' $$h $$m $$s $$dur $$rc; \
	  printf '   début : %s\n   fin   : %s\n' "$$start_iso" "$$end_iso"; \
	  printf '══════════════════════════════════════════════════════════════\n'; \
	  printf '%s\t%s\t%d\t%02d:%02d:%02d\trc=%d\n' "$$start_iso" "$$end_iso" "$$dur" $$h $$m $$s $$rc >> .timings/deploy.log; \
	  exit $$rc

deploy-timings: ## Afficher l'historique des durées de make deploy
	@if [ ! -s .timings/deploy.log ]; then echo "Aucun run enregistré. Lance \`make deploy-timed\` d'abord."; exit 0; fi
	@printf '%-25s %-25s %10s %10s %s\n' "START" "END" "SECONDS" "HH:MM:SS" "RC"
	@awk -F'\t' '{ printf "%-25s %-25s %10s %10s %s\n", $$1, $$2, $$3, $$4, $$5 }' .timings/deploy.log

# ── Destroy (DANGER) ──────────────────────────────────────────────────────────
.PHONY: destroy-lab

destroy-lab: ## ⚠️  DÉTRUIRE le lab Proxmox (demande CONFIRM=yes)
	@test "$(CONFIRM)" = "yes" || \
	  { echo "❌ Requiert CONFIRM=yes  — ex: make destroy-lab CONFIRM=yes"; exit 1; }
	@echo "💣 Destruction du lab dans 5 secondes... (Ctrl-C pour annuler)"
	@sleep 5
	@$(_tofu_env) && cd $(IAC_DIR) && tofu destroy -auto-approve
	@echo "✅ Lab détruit. Relancer make deploy pour recréer."

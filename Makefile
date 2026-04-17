##############################################################################
# SOC-as-code — Makefile
# Usage : make <target>   (make help pour la liste complète)
##############################################################################

ANS_DIR  ?= ansible
KCFG     ?= $(ANS_DIR)/playbooks/artifacts/admin.conf
IAC_DIR  ?= iac

.DEFAULT_GOAL := help

# ── Help ─────────────────────────────────────────────────────────────────────
.PHONY: help
help: ## Affiche cette aide
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
	  /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ── Infrastructure (OpenTofu / Terraform) ────────────────────────────────────
.PHONY: iac iac-validate iac-apply iac-destroy
iac: ## Init + plan OpenTofu
	@cd $(IAC_DIR) && tofu init && tofu plan

iac-validate: ## Valider la syntaxe Terraform/OpenTofu
	@cd $(IAC_DIR) && tofu validate

iac-apply: ## Appliquer le plan (demande confirmation)
	@cd $(IAC_DIR) && tofu apply

iac-destroy: ## Détruire l'infrastructure (DANGER)
	@cd $(IAC_DIR) && tofu destroy

# ── Lint ─────────────────────────────────────────────────────────────────────
.PHONY: lint lint-yaml lint-ansible lint-tf
lint: lint-yaml lint-ansible lint-tf ## Exécuter tous les linters

lint-yaml: ## Linter YAML (yamllint)
	yamllint -c .yamllint $(ANS_DIR)/

lint-ansible: ## Linter Ansible (ansible-lint)
	ansible-lint --profile=production $(ANS_DIR)/

lint-tf: ## Linter Terraform/OpenTofu (tflint)
	@cd $(IAC_DIR) && tflint --init && tflint

# ── Ansible — infrastructure K8s ─────────────────────────────────────────────
.PHONY: prereqs bins cp cni join post smoke
prereqs: ## Prérequis système (00)
	ansible-playbook $(ANS_DIR)/playbooks/00-prereqs-install.yml

bins: ## Binaires Kubernetes (10)
	ansible-playbook $(ANS_DIR)/playbooks/10-kube-binaries.yml

cp: ## Control-plane (20)
	ansible-playbook $(ANS_DIR)/playbooks/20-control-plane.yml

cni: ## CNI réseau (30)
	ansible-playbook $(ANS_DIR)/playbooks/30-cni.yml

join: ## Rejoindre les workers (40)
	ansible-playbook $(ANS_DIR)/playbooks/40-join-workers.yml

post: ## Post-install K8s (50)
	ansible-playbook $(ANS_DIR)/playbooks/50-post.yml

smoke: ## Smoke test cluster
	kubectl --kubeconfig $(KCFG) get nodes -o wide
	kubectl --kubeconfig $(KCFG) -n metallb-system get all
	kubectl --kubeconfig $(KCFG) -n smoke get svc -o wide

# ── Ansible — SOC platform ────────────────────────────────────────────────────
.PHONY: vault monitoring argocd netpol compliance selftest
vault: ## Déployer Vault + ESO (75)
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml

monitoring: ## Déployer la stack monitoring (76)
	ansible-playbook $(ANS_DIR)/playbooks/76-monitoring.yml

argocd: ## Déployer ArgoCD (77) — prérequis : 75-vault.yml --tags bootstrap
	ansible-playbook $(ANS_DIR)/playbooks/77-argocd.yml

argocd-seed: ## Seeder le secret ArgoCD dans Vault (75 --tags bootstrap)
	ansible-playbook $(ANS_DIR)/playbooks/75-vault.yml --tags bootstrap

netpol: ## Appliquer les NetworkPolicies (150) — inclut argocd
	ansible-playbook $(ANS_DIR)/playbooks/150-soc-netpol.yml

compliance: ## Audit de conformité (200) — inclut ArgoCD
	ansible-playbook $(ANS_DIR)/playbooks/200-soc-compliance.yml

selftest: ## E2E selftest (210)
	ansible-playbook $(ANS_DIR)/playbooks/210-soc-selftest.yml

# ── Pre-commit ────────────────────────────────────────────────────────────────
.PHONY: pre-commit pre-commit-install
pre-commit: ## Exécuter tous les hooks pre-commit
	pre-commit run --all-files

pre-commit-install: ## Installer les hooks pre-commit dans git
	pre-commit install

# ── Orchestration complète ────────────────────────────────────────────────────
-include Makefile.deploy.mk

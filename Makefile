.PHONY: iac iac-validate ansible k8s

iac:
	@cd iac && tofu init && tofu plan

iac-validate:
	@cd iac && tofu validate

.PHONY: prereqs
prereqs:
	ansible-playbook $(ANS_DIR)/playbooks/00-prereqs-install.yaml

.PHONY: bins
bins:
	ansible-playbook $(ANS_DIR)/playbooks/10-kube-binaries.yml

.PHONY: cp
cp:
	ansible-playbook $(ANS_DIR)/playbooks/20-control-plane.yml

.PHONY: cni
cni:
	ansible-playbook $(ANS_DIR)/playbooks/30-cni.yml

.PHONY: join
join:
	ansible-playbook $(ANS_DIR)/playbooks/40-join-workers.yml

.PHONY: post
post:
	ansible-playbook $(ANS_DIR)/playbooks/50-post.yml

.PHONY: smoke
smoke:
	kubectl --kubeconfig $(KCFG) get nodes -o wide
	kubectl --kubeconfig $(KCFG) -n metallb-system get all
	kubectl --kubeconfig $(KCFG) -n smoke get svc -o wide
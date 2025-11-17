.PHONY: iac iac-validate ansible k8s

iac:
	@cd iac && tofu init && tofu plan

iac-validate:
	@cd iac && tofu validate

ansible:
	@ansible-playbook ansible/playbooks/bootstrap.yaml

k8s:
	@kubectl get nodes
.PHONY: iac iac-validate ansible k8s

iac:
	@cd iac && terraform init && terraform plan

iac-validate:
	@cd iac && terraform validate

ansible:
	@ansible-playbook ansible/playbooks/bootstrap.yaml

k8s:
	@kubectl get nodes
# .tflint.hcl — Configuration tflint pour SOC-as-code (Proxmox/OpenTofu)
# https://github.com/terraform-linters/tflint

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

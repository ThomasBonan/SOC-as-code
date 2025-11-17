terraform {
  required_providers {
    proxmox = {
      source = "bpg/proxmox"
      version = "0.86.0"
    }
  }
}
provider "proxmox" {
  PROXMOX_VE_ENDPOINT      = var.virtual_environment_endpoint
  PROXMOX_VE_API_TOKEN     = var.virtual_environment_api_token
  PROXMOX_VE_INSECURE      = true
}
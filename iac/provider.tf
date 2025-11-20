terraform {
  required_providers {
    proxmox = {
      source  = "bpg/proxmox"
      version = ">= 0.70.0"
    }
  }
}
provider "proxmox" {
  endpoint  = replace(var.pm_api_url, "/api2/json", "/")  # https://<IP>:8006/
  api_token = "${var.pm_api_token_id}=${var.pm_api_token_secret}"
  insecure  = true
}
############################################
# Auth Proxmox (passées via TF_VAR_… ou env)
############################################
variable "pm_api_url" {
  type        = string
  description = "URL API Proxmox (ex: https://<ip>:8006/api2/json)"
}

variable "pm_api_token_id" {
  type        = string
  sensitive   = true
  description = "ID du token API Proxmox (ex: terraform@pve!terraform-token)"
}

variable "pm_api_token_secret" {
  type        = string
  sensitive   = true
  description = "Secret du token API Proxmox"
}

############################################
# Contexte Proxmox
############################################
variable "node_name" {
  type        = string
  description = "Nom du nœud Proxmox cible (pve, pve01, …)"
  default     = "ns517129"
}

variable "storage_id" {
  type        = string
  description = "ID du storage Proxmox pour les disques (ex: local, local-lvm, zfs-thin)"
  default     = "local"
}

variable "pool_id" {
  type        = string
  description = "Pool Proxmox dans lequel ranger les VMs"
  default     = "soc"
}

variable "template_name" {
  type        = string
  description = "Nom du template cloud-init à cloner (ex: ubuntu-24.04-ci, VMID accepté aussi)"
  default     = "ubuntu-24.04-ci"
}

variable "template_vmid" {
  type        = number
  description = "VMID du template cloud-init Proxmox (ex: 9000)"
  default     = 9000
}

variable "enable_qemu_agent" {
  type        = bool
  description = "Activer l'agent QEMU côté VM"
  default     = true
}

variable "vm_tags" {
  type        = list(string)
  description = "Tags appliqués aux VMs (filtrage/ops)"
  default     = ["soc", "k8s", "cloudinit"]
}

############################################
# Réseau
############################################
variable "bridge_core" {
  type        = string
  description = "Bridge réseau Proxmox connecté au core_net"
  default     = "vmbr5"
}

variable "gateway_core" {
  type        = string
  description = "Passerelle du core_net (OPNsense)"
  default     = "10.0.20.254"
}

variable "master_ip_cidr" {
  type        = string
  description = "IP/Mask du control-plane (CIDR)"
  default     = "10.0.20.10/24"
  validation {
    condition     = can(cidrhost(var.master_ip_cidr, 0))
    error_message = "master_ip_cidr doit être une adresse CIDR valide, ex: 10.0.20.10/24."
  }
}

variable "worker_ips_cidr" {
  type        = list(string)
  description = "IPs CIDR des workers"
  default     = ["10.0.20.11/24", "10.0.20.12/24", "10.0.20.13/24"]
  validation {
    condition     = length(var.worker_ips_cidr) >= 1 && alltrue([for ip in var.worker_ips_cidr : can(cidrhost(ip, 0))])
    error_message = "worker_ips_cidr doit contenir au moins une IP en CIDR valide."
  }
}

variable "dns_servers" {
  type        = list(string)
  description = "DNS à pousser via cloud-init (optionnel)"
  default     = ["10.0.10.254", "1.1.1.1"]
}

############################################
# Accès SSH (injection cloud-init)
############################################
variable "ssh_user" {
  type        = string
  description = "Utilisateur SSH par défaut (image Ubuntu cloud)"
  default     = "ubuntu"
}

variable "ssh_public_key_path" {
  type        = string
  description = "Chemin local vers la clé publique à injecter"
  default     = "/root/.ssh/id_ed25519.pub"
}

variable "cloudinit_snippet" {
  type        = string
  description = "Référence Proxmox du user-data cloud-init (ex: local:snippets/ubuntu-24.04-userdata.yaml)"
  default     = "local:snippets/ubuntu-24.04-vendordata.yaml"
}

############################################
# Sizing (MVP réaliste)
############################################
variable "master_sizing" {
  description = "Ressources du control-plane"
  type = object({
    cores     : number
    memory_mb : number
    disk_gb   : number
    cpu_type  : string
  })
  default = {
    cores     = 4
    memory_mb = 8192
    disk_gb   = 80
    cpu_type  = "host"
  }
  validation {
    condition     = var.master_sizing.cores >= 2 && var.master_sizing.memory_mb >= 4096
    error_message = "Le master doit avoir au minimum 2 vCPU et 4096 MB de RAM."
  }
}

variable "worker_sizing" {
  description = "Ressources des workers (appliquées à chacun)"
  type = object({
    cores     : number
    memory_mb : number
    disk_gb   : number
    cpu_type  : string
  })
  default = {
    cores     = 6
    memory_mb = 24597
    disk_gb   = 300
    cpu_type  = "host"
  }
  validation {
    condition     = var.worker_sizing.cores >= 2 && var.worker_sizing.memory_mb >= 6144
    error_message = "Chaque worker doit avoir au minimum 2 vCPU et 6144 MB de RAM."
  }
}

############################################
# Options avancées (si besoin)
############################################
variable "ballooning" {
  type        = bool
  description = "Activer le memory ballooning (souvent déconseillé pour K8s)"
  default     = false
}

variable "enable_guest_agent_fstrim" {
  type        = bool
  description = "Permettre fstrim via l'agent invité (optimisation stockage)"
  default     = true
}

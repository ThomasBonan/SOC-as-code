locals {
  ssh_key = chomp(file(var.ssh_public_key_path))
}

# --- MASTER ---
resource "proxmox_vm_qemu" "k8s_master" {
  name        = "k8s-master"
  target_node = var.node_name
  clone       = var.template_name
  description = "Kubernetes Master Node"

  pool        = var.pool_id
  tags        = join(",", var.vm_tags)

  # Sizing
  sockets = 1
  cores   = var.master_sizing.cores
  memory  = var.master_sizing.memory_mb
  cpu     = var.master_sizing.cpu_type

  balloon = var.ballooning ? 1 : 0
  agent   = var.enable_qemu_agent ? 1 : 0

  # Disque (telmate: pas de bloc disk{} ; on déclare scsi0 directement)
  scsihw = "virtio-scsi-pci"
  scsi0  = "${var.storage_id}:${var.master_sizing.disk_gb}"

  # Réseau (telmate: pas de bloc network{} ; on déclare net0 directement)
  net0   = "virtio,bridge=${var.bridge_core}"

  # Cloud-init
  ipconfig0 = "ip=${var.master_ip_cidr},gw=${var.gateway_core}"
  sshkeys   = local.ssh_key
  cicustom  = var.cloudinit_snippet

  # Évite les provisioners ici (préférence: Ansible après)
}

# --- WORKERS ---
resource "proxmox_vm_qemu" "k8s_worker" {
  for_each    = toset(var.worker_ips_cidr)

  name        = "k8s-worker-${index(var.worker_ips_cidr, each.value)+1}"
  target_node = var.node_name
  clone       = var.template_name
  description = "Kubernetes Worker Node"

  pool        = var.pool_id
  tags        = join(",", var.vm_tags)

  sockets = 1
  cores   = var.worker_sizing.cores
  memory  = var.worker_sizing.memory_mb
  cpu     = var.worker_sizing.cpu_type

  balloon = var.ballooning ? 1 : 0
  agent   = var.enable_qemu_agent ? 1 : 0

  scsihw = "virtio-scsi-pci"
  scsi0  = "${var.storage_id}:${var.worker_sizing.disk_gb}"

  net0   = "virtio,bridge=${var.bridge_core}"

  ipconfig0 = "ip=${each.value},gw=${var.gateway_core}"
  sshkeys   = local.ssh_key
  cicustom  = var.cloudinit_snippet
}

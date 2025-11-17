locals {
  ssh_key = chomp(file(var.ssh_public_key_path))
}

# --- MASTER ---
resource "proxmox_vm_qemu" "k8s_master" {
  name        = "k8s-master"
  target_node = var.node_name
  clone       = var.template_name

  pool        = var.pool_id
  tags        = join(",", var.vm_tags)

  agent  = var.enable_qemu_agent ? 1 : 0
  cores  = var.master_sizing.cores
  memory = var.master_sizing.memory_mb
  cpu    = var.master_sizing.cpu_type

  scsihw = "virtio-scsi-pci"
  disks {
    size    = "${var.master_sizing.disk_gb}G"
    storage = var.storage_id
    type    = "scsi"
    slot    = 0
  }

  network {
    model  = "virtio"
    bridge = var.bridge_core
  }

  ipconfig0 = "ip=${var.master_ip_cidr},gw=${var.gateway_core}"
  sshkeys   = local.ssh_key

  cicustom  = var.cloudinit_snippet
  balloon   = var.ballooning ? 1 : 0
}

# --- WORKERS ---
resource "proxmox_vm_qemu" "k8s_worker" {
  for_each    = toset(var.worker_ips_cidr)

  name        = "k8s-worker-${index(var.worker_ips_cidr, each.value)+1}"
  target_node = var.node_name
  clone       = var.template_name

  pool        = var.pool_id
  tags        = join(",", var.vm_tags)

  agent  = var.enable_qemu_agent ? 1 : 0
  cores  = var.worker_sizing.cores
  memory = var.worker_sizing.memory_mb
  cpu    = var.worker_sizing.cpu_type

  scsihw = "virtio-scsi-pci"
  disks {
    size    = "${var.worker_sizing.disk_gb}G"
    storage = var.storage_id
    type    = "scsi"
    slot    = 0
  }

  network {
    model  = "virtio"
    bridge = var.bridge_core
  }

  ipconfig0 = "ip=${each.value},gw=${var.gateway_core}"
  sshkeys   = local.ssh_key

  cicustom  = var.cloudinit_snippet
  balloon   = var.ballooning ? 1 : 0
}

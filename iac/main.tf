resource "proxmox_virtual_environment_vm" "k8s_master" {
  name      = "k8s-master"
  node_name = var.node_name
  pool_id   = var.pool_id
  tags      = var.vm_tags

  cpu {
    type  = var.master_sizing.cpu_type   # "host"
    cores = var.master_sizing.cores
  }

  memory {
    dedicated = var.master_sizing.memory_mb
  }

  disk {
    interface    = "scsi0"
    datastore_id = var.storage_id        # ex: "local"
    size         = var.master_sizing.disk_gb
    file_format  = "raw"
  }

  network_device {
    bridge = var.bridge_core             # ex: "vmbr5"
    model  = "virtio"
  }

  operating_system { type = "l26" }

  initialization {
    datastore_id = var.storage_id
    user_account {
      username = var.ssh_user
      keys     = [chomp(file(var.ssh_public_key_path))]
    }
    ip_config {
      ipv4 {
        address = var.master_ip_cidr
        gateway = var.gateway_core
      }
    }
  }

  clone {
    vm_id_or_name = var.template_name    # le nom/VMID de ton template
  }

  started = true
}
resource "proxmox_virtual_environment_vm" "k8s_worker" {
  name      = "k8s-worker"
  node_name = var.node_name
  pool_id   = var.pool_id
  tags      = var.vm_tags

  cpu {
    type  = var.worker_sizing.cpu_type   # "host"
    cores = var.worker_sizing.cores
  }

  memory {
    dedicated = var.worker_sizing.memory_mb
  }

  disk {
    interface    = "scsi0"
    datastore_id = var.storage_id        # ex: "local"
    size         = var.worker_sizing.disk_gb
    file_format  = "raw"
  }

  network_device {
    bridge = var.bridge_core             # ex: "vmbr5"
    model  = "virtio"
  }

  operating_system { type = "l26" }

  initialization {
    datastore_id = var.storage_id
    user_account {
      username = var.ssh_user
      keys     = [chomp(file(var.ssh_public_key_path))]
    }
    ip_config {
      ipv4 {
        address = var.worker_ip_cidr
        gateway = var.gateway_core
      }
    }
  }

  clone {
    vm_id_or_name = var.template_name    # le nom/VMID de ton template
  }

  started = true
}

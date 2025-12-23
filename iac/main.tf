resource "proxmox_virtual_environment_vm" "k8s_master" {
  name      = "k8s-master"
  node_name = var.node_name
  pool_id   = var.pool_id
  tags      = var.vm_tags

  cpu {
    type  = var.master_sizing.cpu_type   # ex: "host"
    cores = var.master_sizing.cores
  }

  memory {
    dedicated = var.master_sizing.memory_mb
  }

  disk {
    interface    = "scsi0"
    datastore_id = var.storage_id        # ex: "local"
    size         = var.master_sizing.disk_gb   # entier (GiB)
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

    vendor_data_file_id = var.cloudinit_snippet

    ip_config {
      ipv4 {
        address = var.master_ip_cidr     # "10.0.20.10/24"
        gateway = var.gateway_core       # "10.0.20.254"
      }
    }
  }

  clone {
    vm_id = var.template_vmid            # <- EXIGÉ par bpg
  }

  started = true
}

resource "proxmox_virtual_environment_vm" "k8s_worker" {
  for_each  = toset(var.worker_ips_cidr)

  name      = "k8s-worker-${index(var.worker_ips_cidr, each.value)+1}"
  node_name = var.node_name
  pool_id   = var.pool_id
  tags      = var.vm_tags

  cpu {
    type  = var.worker_sizing.cpu_type
    cores = var.worker_sizing.cores
  }

  memory {
    dedicated = var.worker_sizing.memory_mb
  }

  disk {
    interface    = "scsi0"
    datastore_id = var.storage_id
    size         = var.worker_sizing.disk_gb
    file_format  = "raw"
  }

  network_device {
    bridge = var.bridge_core
    model  = "virtio"
  }

  operating_system { type = "l26" }

  initialization {
    datastore_id = var.storage_id
    user_account {
      username = var.ssh_user
      keys     = [chomp(file(var.ssh_public_key_path))]
    }

    vendor_data_file_id = var.cloudinit_snippet

    ip_config {
      ipv4 {
        address = each.value              # <- corrige le var.worker_ip_cidr
        gateway = var.gateway_core
      }
    }
  }

  clone {
    vm_id = var.template_vmid
  }

  started = true
}
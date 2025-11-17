output "master_ip" {
  value       = regex("^[^/]+", var.master_ip_cidr)
  description = "Adresse IP du control-plane"
}

output "worker_ips" {
  value       = [for ip in var.worker_ips_cidr : regex("^[^/]+", ip)]
  description = "Adresses IP des workers"
}

# (optionnel) un “inventory” INI prêt à copier/coller
output "ansible_inventory_ini" {
  value = join("\n", concat(
    ["[master]", regex("^[^/]+", var.master_ip_cidr)],
    ["", "[workers]"],
    [for ip in var.worker_ips_cidr : regex("^[^/]+", ip)],
    ["", "[all:vars]", "ansible_user=${var.ssh_user}"]
  ))
}
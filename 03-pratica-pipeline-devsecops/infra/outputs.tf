output "juice_shop_url" {
  description = "URL de acesso ao Juice Shop (aguarde ~2 minutos após o apply)"
  value       = "http://${google_compute_instance.juice_shop.network_interface[0].access_config[0].nat_ip}:3000"
}

output "service_account" {
  description = "Service Account dedicada utilizada pela VM"
  value       = google_service_account.juice_shop.email
}

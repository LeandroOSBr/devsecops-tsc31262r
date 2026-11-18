output "cluster_name" {
  description = "Nome do cluster GKE Autopilot"
  value       = google_container_cluster.autopilot.name
}

output "cluster_location" {
  description = "Região do cluster"
  value       = google_container_cluster.autopilot.location
}

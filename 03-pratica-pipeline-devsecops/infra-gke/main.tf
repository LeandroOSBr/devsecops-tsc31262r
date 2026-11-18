# ==============================================================================
# GKE Autopilot: o Google gerencia os nós. Nós entregamos apenas Pods.
# Cada bloco traz a "Prática DevSecOps" correspondente.
# ==============================================================================

resource "google_container_cluster" "autopilot" {
  name     = var.cluster_name
  location = var.region

  # Prática DevSecOps 1: Autopilot aplica hardening por padrão
  # (sem Pod privilegiado, sem acesso ao nó, Shielded Nodes, Workload Identity,
  #  atualização automática e GKE Dataplane V2, que aplica as NetworkPolicies).
  enable_autopilot = true

  # Laboratório: permite "terraform destroy" ao fim da aula.
  # Em produção: true (evita apagar o cluster por engano).
  deletion_protection = false

  network    = "default"
  subnetwork = "default"

  # VPC nativa (IPs de Pods e Services em faixas secundárias)
  ip_allocation_policy {}

  # Prática DevSecOps 2: canal de versões com correções de segurança automáticas
  release_channel {
    channel = "REGULAR"
  }

  # Prática DevSecOps 3: API do Kubernetes só para origens autorizadas.
  # RISCO ACEITO (documentado): os runners do GitHub Actions não têm IP fixo, então
  # o laboratório libera a internet e depende da autenticação IAM do Google.
  # Em produção: runner próprio/privado + CIDR restrito + endpoint privado.
  #trivy:ignore:GCP-0061
  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled = false

    dynamic "cidr_blocks" {
      for_each = var.master_authorized_cidrs
      content {
        cidr_block   = cidr_blocks.value
        display_name = "autorizado-lab"
      }
    }
  }

  # Prática DevSecOps 4: inventário e custo rastreáveis
  resource_labels = {
    environment = var.environment
    managed_by  = "terraform"
    course      = "ipog-devsecops-tsc31262r"
  }
}

# ==============================================================================
# Disciplina: Ambiente de Desenvolvimento e Operação - DevSecOps (IPOG)
# Professor: Leandro de Oliveira Santos
# Aula 05: cluster GKE Autopilot para o OWASP Juice Shop (deploy pela esteira)
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  # Estado remoto no GCS (bucket informado no "terraform init" pela esteira).
  # Prefixo diferente do da VM: os dois ambientes não se misturam.
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}

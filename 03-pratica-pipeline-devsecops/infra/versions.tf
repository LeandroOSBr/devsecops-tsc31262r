# ==============================================================================
# Disciplina: Ambiente de Desenvolvimento e Operação - DevSecOps (IPOG)
# Professor: Leandro de Oliveira Santos
# Prática 03: Infraestrutura do OWASP Juice Shop no GCP (deploy pela esteira)
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }

  # Estado remoto em um bucket do Cloud Storage (GCS).
  # A configuração é "parcial": o nome do bucket é informado no "terraform init"
  # pela esteira (-backend-config="bucket=..."). Para apenas validar o código
  # localmente, use: terraform init -backend=false
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ==============================================================================
# Disciplina: Ambiente de Desenvolvimento e Operação - DevSecOps (IPOG)
# Professor: Leandro de Oliveira Santos
# Exemplo 02: Provisionamento de VM no Google Cloud (GCP) para OWASP Juice Shop
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = "cicd-devops-393806"
  region  = "us-east1"
  zone    = "us-east1-d"
}

resource "google_compute_instance" "lab_juice_shop" {
  name         = "lab-devsecops-juiceshop"
  machine_type = "e2-micro"
  zone         = "us-east1-d"

  tags = ["ssh-allowed", "juiceshop-web"]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Aloca IP Público efêmero para acesso de laboratório
    }
  }

  metadata = {
    enable-oslogin = "TRUE"
  }
}

resource "google_compute_firewall" "allow_juiceshop_port" {
  name    = "allow-juiceshop-3000"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  # Em ambiente real, restringir ao IP dos alunos/VPN em vez de 0.0.0.0/0
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["juiceshop-web"]
}

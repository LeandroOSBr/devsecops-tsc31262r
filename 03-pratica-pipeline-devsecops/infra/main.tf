# ==============================================================================
# VM no GCP que executa o OWASP Juice Shop em container.
# Cada bloco traz um comentário "Prática DevSecOps" explicando o controle que
# os scanners de IaC (Trivy e Checkov) verificam na esteira.
# ==============================================================================

# Prática DevSecOps 1: identidade dedicada e sem papéis (menor privilégio).
# Evita usar a "Compute Engine default service account", que costuma ter papel
# de Editor no projeto inteiro.
resource "google_service_account" "juice_shop" {
  account_id   = "sa-juice-shop-lab"
  display_name = "SA dedicada da VM do Juice Shop (lab DevSecOps)"
}

resource "google_compute_instance" "juice_shop" {
  name         = var.instance_name
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["juiceshop-web"]

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    course      = "ipog-devsecops-tsc31262r"
  }

  # RISCO ACEITO (documentado): disco criptografado com chave gerenciada pelo Google.
  # Em produção: chave do cliente (CMEK) no Cloud KMS.
  #checkov:skip=CKV_GCP_38:Laboratorio usa chave gerenciada pelo Google (sem CMEK)
  #trivy:ignore:GCP-0033
  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-balanced"
    }
  }

  network_interface {
    network = "default"

    # RISCO ACEITO (documentado): IP público necessário para os alunos acessarem
    # o laboratório. O acesso é limitado pelo firewall (allowed_source_ranges).
    # Em produção: Load Balancer + Cloud Armor (WAF) e VM sem IP público.
    #checkov:skip=CKV_GCP_40:IP publico necessario no laboratorio; acesso restrito pelo firewall
    #trivy:ignore:GCP-0031
    access_config {}
  }

  # Prática DevSecOps 2: Shielded VM (Secure Boot, vTPM e monitoramento de integridade).
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  # Prática DevSecOps 3: sem IP forwarding e sem console serial.
  can_ip_forward = false

  metadata = {
    enable-oslogin         = "TRUE" # Acesso SSH controlado pelo IAM
    block-project-ssh-keys = "true" # Ignora chaves SSH "globais" do projeto
    serial-port-enable     = "false"

    # Instala o Docker e sobe o container com privilégios mínimos.
    startup-script = templatefile("${path.module}/startup.sh.tftpl", {
      container_image = var.container_image
    })
  }

  service_account {
    email  = google_service_account.juice_shop.email
    scopes = ["cloud-platform"]
  }
}

# Prática DevSecOps 4: firewall restrito a origens conhecidas + log de conexões.
resource "google_compute_firewall" "juice_shop_http" {
  name    = "allow-juiceshop-3000-restrito"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["3000"]
  }

  source_ranges = var.allowed_source_ranges
  target_tags   = ["juiceshop-web"]

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

# ==============================================================================
# ⚠️ EXERCÍCIO DE QUALITY GATE (IaC):
# Descomente o bloco abaixo em uma branch, faça commit/push e observe a esteira:
# o Trivy encontra a regra de SSH aberta para a internet e o Quality Gate de IaC
# (modo "bloqueio") impede o deploy. Depois corrija e veja a esteira passar.
# ==============================================================================
/*
resource "google_compute_firewall" "ssh_aberto_inseguro" {
  name    = "allow-ssh-mundo-inseguro"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] # VULNERÁVEL: SSH exposto para a internet inteira
}
*/

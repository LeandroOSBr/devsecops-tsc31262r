variable "project_id" {
  description = "ID do projeto GCP onde o cluster será criado"
  type        = string
}

variable "region" {
  description = "Região do cluster Autopilot (Autopilot é sempre regional)"
  type        = string
  default     = "us-east1"
}

variable "cluster_name" {
  description = "Nome do cluster GKE Autopilot"
  type        = string
  default     = "lab-devsecops-autopilot"
}

variable "environment" {
  description = "Ambiente de implantação (dev, test, prod)"
  type        = string
  default     = "lab"
}

variable "master_authorized_cidrs" {
  description = "Faixas (CIDR) que podem falar com a API do Kubernetes (kubectl)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

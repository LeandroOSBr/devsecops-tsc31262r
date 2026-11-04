variable "project_id" {
  description = "ID do projeto GCP onde o Juice Shop será implantado"
  type        = string
}

variable "region" {
  description = "Região do GCP"
  type        = string
  default     = "us-east1"
}

variable "zone" {
  description = "Zona do GCP"
  type        = string
  default     = "us-east1-d"
}

variable "instance_name" {
  description = "Nome da máquina virtual"
  type        = string
  default     = "lab-devsecops-juiceshop"
}

variable "machine_type" {
  description = "Tamanho da VM (e2-small = 2 vCPU compartilhadas / 2 GB RAM; o Juice Shop fica apertado em e2-micro)"
  type        = string
  default     = "e2-small"
}

variable "container_image" {
  description = "Imagem do container que a VM vai executar (a mesma que passou pelos Quality Gates da esteira)"
  type        = string
  default     = "bkimminich/juice-shop:v20.3.0"
}

variable "allowed_source_ranges" {
  description = "Faixas de IP (CIDR) autorizadas a acessar o Juice Shop na porta 3000"
  type        = list(string)

  # Política como código: o próprio Terraform recusa a internet inteira.
  validation {
    condition     = length(var.allowed_source_ranges) > 0 && !contains(var.allowed_source_ranges, "0.0.0.0/0")
    error_message = "Informe pelo menos um CIDR e NÃO use 0.0.0.0/0 (aplicação propositalmente vulnerável!)."
  }
}

variable "environment" {
  description = "Ambiente de implantação (dev, test, prod)"
  type        = string
  default     = "lab"
}

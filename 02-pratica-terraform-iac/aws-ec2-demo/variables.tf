variable "aws_region" {
  description = "Região da AWS onde os recursos serão provisionados"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "Tamanho (shape) da máquina virtual EC2 (visto na Aula 01: t2.micro = 1 vCPU, 1 GB RAM)"
  type        = string
  default     = "t2.micro"
}

variable "instance_name" {
  description = "Tag de identificação da instância EC2"
  type        = string
  default     = "vm-juice-shop-devsecops"
}

variable "environment" {
  description = "Ambiente de implantação (dev, test, prod)"
  type        = string
  default     = "dev"
}

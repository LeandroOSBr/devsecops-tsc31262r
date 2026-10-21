# ==============================================================================
# Disciplina: Ambiente de Desenvolvimento e Operação - DevSecOps (IPOG)
# Professor: Leandro de Oliveira Santos
# Exemplo 01: Provisionamento de Instância EC2 na AWS (Visto na Aula 01)
# ==============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Busca automaticamente a imagem (AMI) mais recente do Ubuntu 24.04 LTS
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # ID oficial da Canonical (criadora do Ubuntu)
}

# Criação da Máquina Virtual (EC2) com boas práticas de segurança (DevSecOps)
resource "aws_instance" "servidor_app" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type

  # Prática DevSecOps 1: Exigir IMDSv2 (protege contra ataques de SSRF nos metadados)
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  # Prática DevSecOps 2: Criptografar o disco raiz em repouso (Encryption at Rest)
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 20
  }

  tags = {
    Name        = var.instance_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Course      = "IPOG-DevSecOps-TSC31262R"
  }
}

# ==============================================================================
# ⚠️ LABORATÓRIO DE SEGURANÇA EM IaC (SHIFT LEFT):
# Descomente o bloco abaixo em uma branch de teste para ver o Scanner de IaC
# (Trivy) detectar a vulnerabilidade de SSH aberto para o mundo (0.0.0.0/0)!
# ==============================================================================
/*
resource "aws_security_group" "sg_inseguro_exemplo" {
  name        = "sg-ssh-aberto-inseguro"
  description = "Exemplo de ma configuracao detectada pelo Scan de IaC"

  ingress {
    description = "SSH aberto para toda a internet (VULNERAVEL!)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
*/

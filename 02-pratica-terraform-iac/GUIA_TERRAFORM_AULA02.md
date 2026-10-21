# 🏗️ Guia Prático 02 — Infraestrutura como Código (IaC) com Terraform e Segurança (Shift Left)

Na **Aula 01**, vimos como o **Terraform** permite declararmos nossa infraestrutura em arquivos de código (`.tf`), garantindo documentação viva, reprodutibilidade entre os ambientes de **Desenvolvimento, Teste e Produção**, e **Idempotência** (executar o mesmo código várias vezes mantém o estado desejado sem duplicar recursos indevidamente).

---

## 📂 Projetos Disponíveis nesta Pasta

1. **[`aws-ec2-demo/`](./aws-ec2-demo/main.tf):** O exemplo exato que analisamos na Aula 01 para provisionar uma máquina virtual **Ubuntu (`t2.micro`)** na AWS, acompanhado de configurações de Segurança para analisarmos com ferramentas de Scan de IaC (*Trivy*).
2. **[`gcp-vm-juice-shop/`](./gcp-vm-juice-shop/main.tf):** Código Terraform para provisionar no Google Cloud Platform (GCP) a máquina virtual e regras de firewall onde subiremos o **OWASP Juice Shop** em contêiner Docker.

---

## 🧪 Como Testar os Comandos do Terraform Agora (Sem precisar de conta AWS/GCP!)

No terminal (dentro do **GitHub Codespaces** ou localmente com Terraform instalado), acesse a pasta do exemplo AWS:

```bash
cd 02-pratica-terraform-iac/aws-ec2-demo
```

### Passo 1: Inicializar o diretório e baixar o plugin do Provider (`terraform init`)
Como não vamos conectar em uma conta real da AWS neste teste de validação, usamos `-backend=false`:
```bash
terraform init -backend=false
```

### Passo 2: Padronizar a formatação do código (`terraform fmt`)
O Terraform possui um formatador automático oficial que mantém o código limpo e alinhado:
```bash
terraform fmt
```

### Passo 3: Validar a sintaxe e consistência do código (`terraform validate`)
Verifica se todos os recursos, variáveis e atributos declarados existem e estão corretos:
```bash
terraform validate
```

---

## 🔍 Desafio DevSecOps: Encontrando Falhas de Segurança em IaC (Shift Left)

Abra o arquivo [`aws-ec2-demo/main.tf`](./aws-ec2-demo/main.tf) e observe:
1. O disco raiz (`root_block_device`) está com `encrypted = true` (Boa prática ✅);
2. Os metadados da instância exigem token de sessão (`http_tokens = "required"` — IMDSv2 habilitado ✅);
3. No final do arquivo, deixamos comentado um exemplo de **Security Group inseguro** (que abre a porta `22` de SSH para toda a internet `0.0.0.0/0`).
   * **Experimento:** Se você descomentar aquele bloco em uma branch e fizer `git push`, o **Passo 6 da nossa esteira no GitHub Actions (Trivy IaC Scan)** identificará imediatamente a má configuração de segurança antes mesmo da máquina virtual ser criada na nuvem!

# 🛡️ Ambiente de Desenvolvimento e Operação - DevSecOps (Turma TSC31262R)

Bem-vindos ao repositório prático oficial da disciplina **Ambiente de Desenvolvimento e Operação - DevSecOps** do curso de **Segurança Cibernética do IPOG**!

👨‍🏫 **Professor:** Leandro de Oliveira Santos  
🎯 **Objetivo deste repositório:** Servir como nosso laboratório vivo e colaborativo para praticarmos **Controle de Versão (Git)**, **Infraestrutura como Código (Terraform)** e **Pipelines CI/CD com Quality Gates de Segurança (DevSecOps)** e **Casos de Uso de Segurança (Modelagem de Ameaças, OWASP Top 10 e API Top 10)**.

---

## 🚀 Como Praticar (Escolha 1 das 2 opções abaixo)

### Opção A: Direto pelo Navegador (Sem instalar nada!) — *Recomendado*
Este repositório já está configurado com **GitHub Codespaces** (um ambiente Linux completo com VS Code, Git e Terraform pré-instalados na nuvem):
1. Clique no botão verde **`<> Code`** no topo desta página;
2. Selecione a aba **`Codespaces`**;
3. Clique em **`Create codespace on main`**;
4. Aguarde ~20 segundos e use o terminal integrado na parte inferior da tela!

### Opção B: Na sua própria máquina (Terminal Local)
Se você já tem o [Git instalado](https://git-scm.com/downloads) no seu computador:
```bash
git clone https://github.com/LeandroOSBr/devsecops-tsc31262r.git
cd devsecops-tsc31262r
```

---

## 🗺️ Estrutura do Repositório

| Pasta | Conteúdo |
| :--- | :--- |
| [`01-pratica-git/`](./01-pratica-git/GUIA_PRATICO_AULA02.md) | Guia passo a passo da prática colaborativa de Git (4 áreas do Git, branches, commits, push e Pull Request) + **Mural da Turma**. |
| [`02-pratica-terraform-iac/`](./02-pratica-terraform-iac/GUIA_TERRAFORM_AULA02.md) | Projetos práticos de **Terraform (IaC)** para AWS (`aws_instance` EC2 Ubuntu `t2.micro` visto na Aula 01) e GCP (VM para o *OWASP Juice Shop*), incluindo boas práticas de segurança. |
| [`03-pratica-pipeline-devsecops/`](./03-pratica-pipeline-devsecops/GUIA_LAB_AULA03.md) | **Aula 03:** esteira DevSecOps completa com o **OWASP Juice Shop** — Secret Scanning (Gitleaks), SAST (Semgrep), IaC Scan (Terraform + Trivy + Checkov), SCA/Container + SBOM (Trivy), Quality Gate como código, DAST (OWASP ZAP) e deploy no GCP com Terraform. |
| [`04-casos-de-uso/`](./04-casos-de-uso/GUIA_LAB_AULA04.md) | **Aula 04:** casos de uso reais no Juice Shop com o ciclo *Ameaça (STRIDE) → Exploração → Detecção → Correção → Prevenção*: triagem de segredo (`.gitleaksignore`), SQL Injection + regra Semgrep própria, chave JWT no código + cofre de segredos/OIDC, SBOM na resposta a incidente e BOLA/IDOR com teste de autorização. |
| [`.github/workflows/`](./.github/workflows/) | Esteiras: [`ci-validacao.yml`](./.github/workflows/ci-validacao.yml) (Aula 02) e [`devsecops-juice-shop.yml`](./.github/workflows/devsecops-juice-shop.yml) (Aula 03). A da Aula 02 é a esteira automatizada (**GitHub Actions**) que é disparada a cada `git push` ou *Pull Request* para validar nossos arquivos e o código Terraform (**Quality Gate**). |

---

## 🔄 Relembrando as 4 Áreas do Git (Aula 01)

```mermaid
flowchart LR
    WD["1. Diretório de Trabalho\n(Working Directory)\nArquivos editados"]
    SA["2. Área de Preparação\n(Staging Area)\nSeleção para commit"]
    LR["3. Repositório Local\n(Local Repository)\nHistórico na sua máquina"]
    RR["4. Repositório Remoto\n(Remote Repository)\nGitHub / Azure DevOps"]

    WD -- "git add" --> SA
    SA -- "git commit -m '...'" --> LR
    LR -- "git push" --> RR
    RR -- "git pull / git clone" --> WD
```

---

## 📋 Cola Rápida de Comandos Git (Cheat Sheet)

```bash
# 1. Configurar sua identidade (carimbo nas alterações)
git config --global user.name "Seu Nome"
git config --global user.email "seu.email@exemplo.com"

# 2. Verificar o estado atual dos arquivos (em qual área estão)
git status

# 3. Atualizar seu repositório local com as novidades do servidor remoto
git pull

# 4. Criar e mudar para uma nova ramificação (branch) de trabalho isolada
git checkout -b aluno/seu-nome

# 5. Adicionar arquivos modificados para a área de Staging
git add nome-do-arquivo.md
# Ou adicionar todas as alterações da pasta atual:
git add .

# 6. Gravar o pacote de alterações no Repositório Local com uma mensagem clara
git commit -m "feat: adiciona meu perfil no mural da turma"

# 7. Enviar seus commits locais para o Repositório Remoto (GitHub)
git push -u origin aluno/seu-nome

# 8. Consultar o histórico de alterações
git log --oneline --graph --all
```

---

## 🎮 Ferramentas Complementares para Praticar em Casa

* 🧩 **[Learn Git Branching (Em Português)](https://learngitbranching.js.org/?locale=pt_BR):** Simulador visual e interativo direto no navegador para dominar `commit`, `branch`, `merge`, `rebase` e `push`/`pull` em formato de desafios passo a passo.
* 🎓 **[GitHub Skills - Introduction to GitHub](https://github.com/skills/introduction-to-github):** Curso prático oficial do próprio GitHub.
* 📄 **[Git Cheat Sheet Oficial (PDF em Português)](https://training.github.com/downloads/pt_BR/github-git-cheat-sheet.pdf):** Folha de consulta rápida com os principais comandos.
* 🧃 **[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/):** Aplicação web vulnerável que utilizaremos nos nossos testes de pipeline e ferramentas SAST/DAST/SCA.

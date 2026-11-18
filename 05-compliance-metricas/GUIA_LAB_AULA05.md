# 🧪 Guia do Lab – Aula 05: compliance como código, cofre de segredos e métricas

> Disciplina **Ambiente de Desenvolvimento e Operação – DevSecOps** · IPOG · turma TSC31262R · Prof. Leandro Santos
> Pré-requisito: o seu fork do repositório com a esteira das Aulas 03 e 04 funcionando.

A esteira agora tem **três peças novas**:

| Job | O que faz | Unidade do Plano de Ensino |
|---|---|---|
| **3b. Compliance como código (Conftest/OPA)** | Avalia Terraform, Dockerfile e Kubernetes contra as **regras da empresa**, escritas em Rego | 5.3 Compliance como Código |
| **9. 📊 Métricas DevSecOps** | Soma os achados por severidade e calcula as métricas **DORA** a partir do histórico da esteira | 5.4 Métricas · CALMS (Medição) |
| **10. 🔐 Cofre de segredos** | Demonstra o ciclo de vida de um segredo num HashiCorp Vault efêmero | 4.3 Gerenciamento de Segredos |

| **8b. Deploy GKE Autopilot** | Terraform cria um cluster **Autopilot** e o `kubectl` aplica o mesmo manifesto que o Conftest validou | 4.1 Kubernetes · 5.1 DevSecOps na nuvem |

E duas mudanças de comportamento:

- Ao rodar a esteira manualmente, o parâmetro **`modo_sca = bloqueio`** faz o Quality Gate reprovar quando o SCA/Container encontra vulnerabilidade **CRITICAL**.
- No **`destroy`** do GCP, os scanners são pulados: destruir não publica código novo, então não há o que inspecionar.

---

## 1. Por que mais uma ferramenta de IaC?

| | Trivy / Checkov | Conftest / OPA |
|---|---|---|
| Regras | Genéricas do mercado (CIS, boas práticas) | **Da sua empresa** (o "jeito certo" de usar a nuvem aqui) |
| Exemplo | "Firewall aberto para 0.0.0.0/0" | "VM só tem IP público com exceção registrada, com dono e validade" |
| Linguagem | Embutida na ferramenta | **Rego**: política é código, versionada e **testada** |

Arquivos:

```
05-compliance-metricas/
├── politicas/terraform.rego        # IPOG-GCP-001..005 (deny) e 101..102 (warn)
├── politicas/docker.rego           # IPOG-DKR-001..003
├── politicas/kubernetes.rego       # IPOG-K8S-001..007 (inclui Pod Security Admission)
├── politicas/politicas_test.rego   # testes das próprias regras
├── excecoes/excecoes.yaml          # riscos aceitos: dono + justificativa + validade
├── k8s/juice-shop.yaml             # Namespace (PSA restricted) + Deployment + NetworkPolicy
├── k8s/exemplos-inseguros/         # Pod inseguro para a demonstração (a esteira NÃO varre)
└── metricas/metricas.py            # métricas de segurança + DORA
```

`deny` vira achado **high** e o Quality Gate (modo **bloqueio**) reprova a esteira. `warn` vira **medium**: aparece no relatório, mas não bloqueia.

## 2. Rodar as políticas na sua máquina ou no Codespaces

```bash
# Instalar o Conftest (Linux/Codespaces) conferindo o checksum
V=0.71.0; ARQ=conftest_${V}_Linux_x86_64.tar.gz
curl -sSLO https://github.com/open-policy-agent/conftest/releases/download/v${V}/${ARQ}
curl -sSL -o checksums.txt https://github.com/open-policy-agent/conftest/releases/download/v${V}/checksums.txt
grep " ${ARQ}$" checksums.txt | sha256sum --check && tar -xzf ${ARQ} conftest

P=05-compliance-metricas/politicas
./conftest verify -p $P                                    # testes das regras
./conftest test --parser hcl2 -p $P --namespace terraform \
  --data 05-compliance-metricas/excecoes 03-pratica-pipeline-devsecops/infra/*.tf
./conftest test -p $P --namespace docker 03-pratica-pipeline-devsecops/app/Dockerfile
./conftest test -p $P --namespace kubernetes 05-compliance-metricas/k8s/*.yaml
./conftest test -p $P --namespace kubernetes 05-compliance-metricas/k8s/exemplos-inseguros/pod-inseguro.yaml
```

Resultado esperado no código da turma: **0 falhas**, com os alertas `IPOG-GCP-001 (EXCEÇÃO ATIVA)`, `IPOG-GCP-102` e `IPOG-K8S-101`. O Pod inseguro quebra **8 regras**.

## 3. Exercícios

**Exercício 1 – Exceção vencida volta a bloquear (5 min).**
Em uma branch, mude a `validade` em `excecoes/excecoes.yaml` para uma data passada, faça commit e push. A esteira deve parar no job **5. Quality Gate**, com a regra `IPOG-GCP-001`. Moral da história: *exceção sem dono e sem prazo é regra desligada*.

**Exercício 2 – SSH aberto para o mundo (5 min).**
Descomente o bloco `ssh_aberto_inseguro` no final de `03-pratica-pipeline-devsecops/infra/main.tf`. Três ferramentas reclamam: Trivy, Checkov e as regras `IPOG-GCP-003`, `IPOG-GCP-004` e `IPOG-GCP-005`. Compare as mensagens: qual explica melhor **o que fazer**?

**Exercício 3 – Escreva uma regra (15 min).**
Crie em `terraform.rego` a regra `IPOG-GCP-006`: toda VM deve ter a label `course`. Escreva também o teste dela em `politicas_test.rego` e rode `conftest verify`.

**Exercício 4 – Gate de SCA que bloqueia (5 min).**
*Actions → Esteira DevSecOps → Run workflow* com `modo_sca = bloqueio`. O Juice Shop tem dependências com CVE **CRITICAL**, então a esteira para no Quality Gate e o DAST não roda. Como liberar sem desligar o controle? Corrigindo a dependência ou registrando a exceção com prazo (`04-casos-de-uso/seguranca/trivyignore-exemplo.yaml`).

**Exercício 5 – Cofre de segredos (5 min).**
*Run workflow* com `demo_cofre = true`. Leia o job **10. 🔐 Cofre** passo a passo e responda:
1. Em que momento a aplicação recebe o segredo?
2. Por que a tentativa de gravar retorna 403?
3. O que muda para a aplicação quando o segredo é rotacionado?

**Exercício 6 – Leia as métricas (5 min).**
Abra o resumo da execução (*Summary*), seção **📊 Métricas DevSecOps**. Qual é a sua taxa de falha de mudanças? E o MTTR? O que você faria para melhorar cada um?

## 4. Proteger a `main` (o Quality Gate passa a barrar o merge)

Sem proteção, alguém pode fazer push direto na `main` e ignorar a esteira. No seu fork:

1. *Settings → Branches → Add branch ruleset* (ou *Add classic branch protection rule*), alvo: `main`.
2. Marque **Require a pull request before merging**.
3. Marque **Require status checks to pass** e adicione:
   - `5. 🚦 Quality Gate`
   - `3b. Compliance como código (Conftest/OPA)`
   - `6. Deploy efêmero + DAST (OWASP ZAP)`
4. Marque **Block force pushes** e salve.
5. Teste: crie a branch `teste-bloqueio`, descomente o SSH aberto e abra um Pull Request. O botão **Merge** fica bloqueado enquanto o Quality Gate estiver vermelho.

> PRs vindos de fork **não recebem os secrets** do repositório. Por isso o deploy no GCP só roda no repositório original, com aprovação manual.

## 5. Kubernetes: o que o manifesto ensina

- **Pod** é a menor unidade de implantação. Um Pod pode ter mais de um container: o principal e, se preciso, um **sidecar** fortemente acoplado (proxy, coletor de log). Microsserviços diferentes ficam em Pods diferentes.
- **Namespace com Pod Security Admission** (`pod-security.kubernetes.io/enforce: restricted`): o próprio cluster recusa Pod privilegiado, Pod rodando como root ou Pod sem `drop: [ALL]`.
- **NetworkPolicy**: primeiro "nega tudo", depois libera só a porta 3000.
- **Hardening do container**: `runAsNonRoot`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`, limites de CPU e memória e imagem com versão fixa.

O Conftest barra esses erros **antes** do deploy (Shift Left), e o PSA barra de novo **dentro** do cluster (defesa em profundidade).

## 6. Juice Shop no GKE Autopilot (job 8b)

*Run workflow* com `acao_gcp = apply` e `alvo_gcp = gke`. O job:

1. Cria o cluster com Terraform (`03-pratica-pipeline-devsecops/infra-gke`). Na primeira vez leva uns 10 minutos.
2. Aplica `05-compliance-metricas/k8s/juice-shop.yaml`, com a imagem do commit aprovado e o seu CIDR em `loadBalancerSourceRanges`.
3. Tenta criar um Pod **privilegiado** (`--dry-run=server`) e mostra o cluster **recusando**. É o Pod Security Admission do namespace, reforçado pelas políticas do Autopilot.
4. Publica a URL do Load Balancer no resumo da execução.

**No Autopilot o Google gerencia os nós.** Você paga pelo que os Pods pedem (`resources.requests`), por isso o manifesto pede exatamente 0,5 vCPU e 1 GiB.

Para não gerar custo, ao terminar rode `acao_gcp = destroy` com `alvo_gcp = gke`. O job apaga primeiro o namespace, o que libera o Load Balancer, e depois o cluster.

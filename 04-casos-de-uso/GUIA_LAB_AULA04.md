# 🎯 Guia Prático 04 — Casos de Uso DevSecOps no OWASP Juice Shop (Aula 04)

Na **Aula 03** montamos a esteira completa (Gitleaks, Semgrep, Trivy, Checkov, SBOM, Quality Gate, ZAP)… e ela **terminou vermelha**: o Quality Gate bloqueou o deploy. Hoje vamos usar a esteira como uma equipe de verdade usaria. Primeiro, **investigar e destravar** a esteira. Depois, percorrer **casos de uso reais**: cada vulnerabilidade é explorada, detectada, corrigida e transformada em **controle automático**.

> ⚠️ O Juice Shop é vulnerável **de propósito**. Execute as demonstrações **somente** contra o **seu** ambiente de laboratório (Codespaces/localhost). Atacar sistemas de terceiros sem autorização é crime (Lei 12.737/2012).

---

## 🎯 Objetivos da aula

Ao final você será capaz de:

1. **Triar** um achado de segurança (verdadeiro × falso positivo × risco aceito) e registrar a decisão como código;
2. Aplicar **Modelagem de Ameaças (STRIDE)** para descobrir *o que testar* antes de escolher *a ferramenta*;
3. Seguir o ciclo **Ameaça → Exploração → Detecção → Correção → Prevenção** em quatro casos reais;
4. Escrever uma **regra própria de SAST**, usar o **SBOM** numa resposta a incidente e criar um **teste de autorização** na esteira;
5. Reconhecer o que as ferramentas automáticas **não** encontram.

## 🧭 O método: um ciclo para cada caso

```mermaid
flowchart LR
  A["1. Ameaça<br/>(STRIDE)"] --> B["2. Exploração<br/>(prova real)"]
  B --> C["3. Detecção<br/>(qual ferramenta viu?)"]
  C --> D["4. Correção<br/>(código/arquitetura)"]
  D --> E["5. Prevenção<br/>(regra/gate/teste)"]
  E -. "o erro não volta" .-> A
```

## 🗺️ Mapa da aula

| Caso | Tema | STRIDE | OWASP | Quem detectou? | Controle criado |
| :-: | :--- | :-: | :--- | :--- | :--- |
| **0** | A esteira travou: segredo no próprio guia | — | — | Gitleaks | `.gitleaksignore` com justificativa |
| **1** | SQL Injection no login | S, E | A03 Injection | Semgrep, ZAP *full* | Regra Semgrep **da empresa** |
| **2** | Chave JWT no código + dados no token | T, I, E | A02/A07 | Gitleaks, Trivy | Cofre de segredos, rotação, OIDC na esteira |
| **3** | "Dia do Log4Shell" com SBOM | E | A06 Componentes vulneráveis | Trivy (SCA) + SBOM | Gate de SCA com **exceção com prazo** |
| **4** | BOLA/IDOR na API de carrinho | I | **API1:2023** BOLA | **Nenhuma ferramenta!** | Teste de autorização na esteira |

### 📂 Estrutura desta prática

```
.gitleaksignore                     ← Caso 0: achados triados e aceitos (com justificativa)
04-casos-de-uso/
├── GUIA_LAB_AULA04.md              ← este guia
├── modelagem/STRIDE_JUICE_SHOP.md  ← DFD + ameaças STRIDE do Juice Shop
├── seguranca/
│   ├── semgrep-regras-ipog.yml     ← Caso 1/2: regras SAST próprias (já rodam na esteira)
│   └── trivyignore-exemplo.yaml    ← Caso 3: exceções de CVE COM PRAZO de validade
└── demos/
    ├── _comum.sh                   ← funções de apoio (login, decodificar JWT)
    ├── caso1-sqli.sh  caso2-jwt.sh  caso3-sbom.sh  caso4-bola.sh
    └── teste-autorizacao-ci.sh     ← Caso 4: teste que REPROVA a esteira se houver BOLA
```

**Novidades na esteira** (`.github/workflows/devsecops-juice-shop.yml`):
- novo passo **"SAST com regras da empresa"** (categoria `sast_empresa` no Quality Gate, em modo `relatorio`);
- o Quality Gate agora mostra **onde** está cada achado (`arquivo:linha` ou URL) e publica o artifact **`achados-detalhados`**.

---

## 🧰 Parte 0 — Preparação (5 min)

1. **Atualize o seu fork** com as novidades: no GitHub, abra o seu fork → **Sync fork** → **Update branch**;
2. Abra o fork no **Codespaces** (`<> Code` → `Codespaces`) ou faça `git pull` no clone local;
3. Suba o Juice Shop no terminal (o Codespaces já tem Docker):

```bash
docker run -d --rm --name juice-shop -p 3000:3000 bkimminich/juice-shop:v20.3.0
# aguarde ~30 s e confira:
curl -s http://localhost:3000/rest/admin/application-version
```

4. Na aba **Ports**, abra a porta **3000** no navegador.

---

## 🔍 Caso 0 — "Quem quebrou a esteira?" (triagem de achado)

**Situação:** na Aula 03 o job **5. 🚦 Quality Gate** reprovou com `Segredos no repositório da turma … ⛔ BLOQUEADO (high)`. O código da turma não tinha senha nenhuma… ou tinha?

### Investigação

1. Abra a execução reprovada → **Summary** → expanda *top achados*. Agora o gate mostra **onde** está o achado. Também dá para ver no artifact `achados-detalhados`;
2. Resultado: `generic-api-key` em `03-pratica-pipeline-devsecops/GUIA_LAB_AULA03.md:144`. Era o **token de exemplo do Exercício 3**, escrito literalmente no guia!
3. Reproduza localmente e pegue o **fingerprint** do achado:

```bash
V=8.30.1
curl -sSLO "https://github.com/gitleaks/gitleaks/releases/download/v${V}/gitleaks_${V}_linux_x64.tar.gz"
tar -xzf "gitleaks_${V}_linux_x64.tar.gz" gitleaks
mv .gitleaksignore /tmp/   # tira a "exceção" temporariamente, para ver o achado original
./gitleaks git . --redact --no-banner --report-format json --report-path /tmp/gl.json || true
mv /tmp/.gitleaksignore .  # devolve a exceção
jq -r '.[] | "\(.RuleID)  \(.File):\(.StartLine)\n  fingerprint: \(.Fingerprint)"' /tmp/gl.json
```

### Triagem: qual é a decisão correta?

| Pergunta | Resposta neste caso |
| :--- | :--- |
| O padrão é de um segredo? | Sim (40 caracteres hexadecimais atribuídos a `API_TOKEN`) → a ferramenta **acertou** |
| É uma credencial **real**, que dá acesso a algo? | **Não**, é fictícia e didática |
| Decisão | **Aceitar o achado com justificativa**, pelo fingerprint, e **remover o literal** do guia |
| E se fosse real? | **Revogar e rotacionar imediatamente.** Ignorar o alerta não "desvaza" o segredo |

A decisão virou código no arquivo [`.gitleaksignore`](../.gitleaksignore) (com responsável e data), e o guia da Aula 03 agora **gera** um token aleatório na hora. Rode a esteira de novo: **Segredos no repositório da turma → ✅ aprovado**, e pela primeira vez o job **6. DAST** executa.

> 💡 **Lições:** (1) documentação, README e exemplos também vazam segredos; (2) toda exceção precisa de **dono, motivo e rastreabilidade**; (3) desativar a regra inteira "porque incomoda" é a pior decisão possível.

---

## 🐉 Modelagem de Ameaças antes das ferramentas (10 min)

Ferramenta responde *"como procurar"*; modelagem de ameaças responde *"o que procurar"*. Abra [`modelagem/STRIDE_JUICE_SHOP.md`](./modelagem/STRIDE_JUICE_SHOP.md): ele tem o diagrama de fluxo de dados (DFD) do Juice Shop e uma ameaça STRIDE para cada letra. **Cada caso a seguir saiu desta tabela.**

> 🧪 **Para casa:** o código-fonte do Juice Shop traz o modelo oficial `threat-model.json` (formato OWASP Threat Dragon) **sem nenhuma ameaça cadastrada**. Importe-o em https://www.threatdragon.com e cadastre pelo menos **uma ameaça STRIDE por elemento**.

---

## 💉 Caso 1 — SQL Injection no login

| Ameaça | Exploração | Detecção | Correção | Prevenção |
| :--- | :--- | :--- | :--- | :--- |
| **S**poofing / **E**levation: entrar como admin sem senha | `' OR 1=1--` no e-mail | Semgrep (`login.ts:34`) e ZAP *full* | `bind` do Sequelize | Regra Semgrep **própria** |

### 1. Exploração

```bash
./04-casos-de-uso/demos/caso1-sqli.sh
```

Ou na tela de login do navegador: e-mail `' OR 1=1--`, senha qualquer → você entra como **admin@juice-sh.op**.

### 2. Por que funciona? (`routes/login.ts`, linha 34)

```ts
// ❌ VULNERÁVEL: o texto digitado vira parte do comando SQL
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, ...)
```

### 3. Correção (Prepared Statement com `bind`)

```ts
// ✅ CORRIGIDO: o SQL é "fixado" antes; o dado entra só como VALOR, nunca como comando
models.sequelize.query(
  'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',
  { bind: [req.body.email, security.hash(req.body.password)], model: UserModel, plain: true })
```

> O próprio Juice Shop traz esta correção e três tentativas **erradas** em `data/static/codefixes/loginAdminChallenge_*.ts`. Compare: *blocklist* de caracteres **não** resolve.

### 4. Prevenção: uma regra da **empresa**

As regras genéricas (`p/owasp-top-ten`) não conhecem os padrões do **nosso** código. Abra [`seguranca/semgrep-regras-ipog.yml`](./seguranca/semgrep-regras-ipog.yml): a regra `ipog-sql-concatenada-sequelize` procura `sequelize.query()` com *template literal* ou concatenação. Na esteira ela já roda no passo **"SAST com regras da empresa"** e aponta **dois** lugares: `routes/login.ts:34` **e** `routes/search.ts:23`. A mesma falha existe na busca de produtos, e foi a regra que nos contou!

### 🧪 Exercício 1 — da regra ao bloqueio

1. Crie a branch `lab04/ex1-regra-bloqueio`;
2. Em `03-pratica-pipeline-devsecops/seguranca/politica-quality-gate.json`, mude `sast_empresa` para `"modo": "bloqueio"`;
3. Commit/push → o Quality Gate **reprova** e mostra `login.ts:34` e `search.ts:23` no Summary;
4. Discuta: por que é mais fácil colocar em **bloqueio** uma regra **própria e precisa** do que o pacote genérico inteiro (que tem centenas de achados)?

---

## 🔑 Caso 2 — A chave que assina os tokens está no código

| Ameaça | Exploração | Detecção | Correção | Prevenção |
| :--- | :--- | :--- | :--- | :--- |
| **T**ampering / **E**levation: forjar JWT de admin. **I**nfo Disclosure: hash da senha no token | Ler o payload do JWT; usar a chave privada pública no repositório | Gitleaks (`private-key`), Trivy, regra `ipog-chave-privada-no-codigo` | Cofre de segredos + **rotação**; payload mínimo; bcrypt/argon2 | Gitleaks em bloqueio; OIDC na esteira |

### 1. Demonstração

```bash
./04-casos-de-uso/demos/caso2-jwt.sh
```

O script faz login como Jim e mostra que o **payload do JWT** (só codificado em Base64, **não** criptografado) carrega o **hash MD5 da senha**. Depois confere que esse hash é o MD5 de `ncc-1701`. A chave privada RSA que **assina** os tokens está escrita em `lib/insecurity.ts`, linha 21: quem lê o repositório pode emitir um token com `role: admin`.

### 2. Correção no código: segredo em tempo de execução

```ts
// ❌ const privateKey = '-----BEGIN RSA PRIVATE KEY-----\r\nMIIC...'
// ✅ A chave vem do ambiente, injetada pelo cofre (GCP Secret Manager, Vault, AWS Secrets Manager...)
const privateKey = process.env.JWT_PRIVATE_KEY
if (!privateKey) throw new Error('JWT_PRIVATE_KEY não configurada')
```

E no deploy (exemplo GCP): `gcloud secrets create jwt-private-key --data-file=chave.pem` e o container recebe a variável a partir do Secret Manager. **E a chave antiga?** Foi exposta: tem que ser **rotacionada**, e todos os tokens emitidos com ela ficam inválidos.

### 3. E a nossa esteira? Também guarda um segredo de longa duração!

O job **8. Deploy GCP** usa o secret `GCP_SA_KEY`, um **JSON de chave de Service Account** que não expira. Se vazar, vale até alguém revogar. A prática recomendada é **Workload Identity Federation (OIDC)**: o GitHub prova a identidade do workflow e o GCP emite uma credencial **temporária**. Nenhum segredo fica guardado.

```yaml
  deploy-gcp:
    permissions:
      contents: read
      id-token: write          # permite ao job pedir um token OIDC ao GitHub
    steps:
      - name: "Autenticar no Google Cloud (sem chave JSON!)"
        uses: google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093 # v3.0.0
        with:
          workload_identity_provider: ${{ vars.GCP_WIF_PROVIDER }}  # projects/<nº>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
          service_account: ${{ vars.GCP_DEPLOY_SA }}                # sa-deploy@<projeto>.iam.gserviceaccount.com
```

> Repare: `vars` (variáveis), não `secrets`. O que fica no GitHub **não é segredo**, só o "endereço" da confiança.

---

## 📦 Caso 3 — "Dia do Log4Shell": SBOM na resposta a incidente

**Situação:** 08h00, sai um alerta: *"CVE crítica na biblioteca `jsonwebtoken`, versões < 4.2.2 (CVE-2015-9235, CVSS 9.8: bypass da verificação do token)"*. O diretor pergunta: **"Estamos afetados? Onde?"**

### 1. Responder em segundos com o SBOM

```bash
# Baixe o SBOM da última execução da esteira (artifact relatorio-container)
RUN=$(gh run list --workflow devsecops-juice-shop.yml --limit 1 --json databaseId -q '.[0].databaseId')
gh run download "$RUN" --name relatorio-container --dir /tmp/sbom
./04-casos-de-uso/demos/caso3-sbom.sh /tmp/sbom/sbom-juice-shop.cdx.json jsonwebtoken
```

Resposta: **sim**, `jsonwebtoken@0.4.0` está na imagem. Sem SBOM, a equipe abriria cada servidor e cada repositório na mão.

### 2. Gate de SCA maduro

Hoje a categoria `container` está em `relatorio`: nada bloqueia. Mas também não dá para bloquear tudo, porque muitas CVEs **não têm correção** ainda. O gate maduro:

- **bloqueia** CRITICAL **com correção disponível** (`ignore-unfixed: true`): se existe versão corrigida, não há desculpa;
- aceita exceções **específicas, justificadas e com prazo** em [`seguranca/trivyignore-exemplo.yaml`](./seguranca/trivyignore-exemplo.yaml) (`expired_at`). Vencido o prazo, o gate volta a bloquear sozinho.

### 🧪 Exercício 3 — exceção com prazo de validade

No job **4. Build + SCA/Container**, no passo *"SCA + Container: vulnerabilidades (SARIF)"*, acrescente:

```yaml
        env:
          TRIVY_IGNOREFILE: 04-casos-de-uso/seguranca/trivyignore-exemplo.yaml
        with:
          # ... (mantenha o que já existe)
          ignore-unfixed: true
```

Rode, compare a contagem de CRITICAL antes/depois e responda: **quem** na empresa pode assinar um `expired_at`? Para onde vai o alerta quando ele vence?

---

## 🛒 Caso 4 — BOLA/IDOR: o carrinho dos outros

| Ameaça | Exploração | Detecção | Correção | Prevenção |
| :--- | :--- | :--- | :--- | :--- |
| **I**nformation Disclosure: ver carrinho alheio (OWASP API1:2023) | Trocar o ID em `/rest/basket/{id}` | **Nenhuma ferramenta da esteira** | Verificar o **dono** do objeto | **Teste de autorização** automatizado |

### 1. Exploração

```bash
./04-casos-de-uso/demos/caso4-bola.sh
```

O Jim, autenticado com o **próprio** token, lê os carrinhos `1` e `3`, que pertencem a outros usuários. A API conferiu **quem** ele é (autenticação), mas não **se o objeto é dele** (autorização).

### 2. Por que nenhuma ferramenta viu?

- **SAST** vê `BasketModel.findOne({ where: { id } })` e não sabe que deveria haver um filtro por dono: é **regra de negócio**;
- **DAST** genérico não sabe que o carrinho 3 "não é do Jim";
- **SCA/IaC** olham dependências e infraestrutura, não lógica.

👉 É exatamente aqui que **modelagem de ameaças + testes de abuso** fazem diferença. Isso também se liga à discussão da Aula 03: ferramentas determinísticas acham padrões conhecidos; falhas de lógica exigem **entender o propósito** da aplicação (revisão humana ou análise assistida por IA).

### 3. Correção (`routes/basket.ts`)

```ts
const user = security.authenticatedUsers.from(req)
const basket = await BasketModel.findOne({ where: { id, UserId: user?.data?.id } }) // ✅ dono obrigatório
if (!basket) return res.status(403).json({ error: 'Acesso negado' })                // ✅ sem dica de existência
```

### 🧪 Exercício 4 — o caso de abuso vira teste na esteira

Adicione, no job **6. Deploy efêmero + DAST**, logo após o *smoke test*:

```yaml
      - name: "Teste de autorização (BOLA) - caso de abuso"
        continue-on-error: true   # Juice Shop é vulnerável de propósito; em um sistema real, REMOVA esta linha
        run: ./04-casos-de-uso/demos/teste-autorizacao-ci.sh
```

Rode e veja o resultado no **Summary**. Em um sistema real, sem `continue-on-error`, esse teste **reprova** qualquer versão que reintroduza a falha.

---

## 🧩 Fechamento: o que cada camada vê (e o que não vê)

| | Segredos | SAST | SCA/SBOM | IaC | DAST | Teste de abuso | Modelagem |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| Caso 0: segredo no guia | ✅ | | | | | | |
| Caso 1: SQL Injection | | ✅ | | | ✅ (*full*) | | ✅ |
| Caso 2: chave/JWT | ✅ | ✅ (regra própria) | ✅ (CVE no `jsonwebtoken`) | | | | ✅ |
| Caso 3: dependência | | | ✅ | | | | ✅ |
| Caso 4: BOLA | | | | | | ✅ | ✅ |

**Nenhuma coluna sozinha cobre tudo.** DevSecOps é a **combinação** das camadas, com uma política clara do que bloqueia.

---

## 📝 Entrega (mural da turma)

No seu arquivo do **Mural da Turma** (`01-pratica-git/mural-da-turma/<seu-nome>.md`), acrescente e abra um **Pull Request**:

```markdown
## Aula 04 - Casos de uso DevSecOps
- Link da execução com o Quality Gate APROVADO: <url>
- Caso que mais me surpreendeu e por quê: <...>
- Uma ameaça STRIDE que eu cadastrei no threat-model.json: <elemento / ameaça / mitigação>
- Exercício feito (1, 3 ou 4) e o que mudou no resultado da esteira: <...>
```

---

## 🛠️ Solução de problemas

| Sintoma | Causa provável / solução |
| :--- | :--- |
| Scripts: `Juice Shop não respondeu` | Suba o container (Parte 0) e aguarde ~30 s; confira `docker ps` |
| `Permission denied` ao rodar `./...sh` | `chmod +x 04-casos-de-uso/demos/*.sh` |
| `gh run download` pede login | `gh auth login` (no Codespaces já vem autenticado) ou baixe o artifact pela página da execução |
| Gitleaks ainda reprova após o `.gitleaksignore` | Confira se o fingerprint é **idêntico** ao do relatório (commit completo, caminho, regra e linha) |
| Exercício 3: a exceção não teve efeito | Alternativa: use a entrada `trivyignores:` da trivy-action apontando para o arquivo, ou rode `trivy image --ignorefile ...` localmente |
| Caso 4 mostra `null` nos carrinhos | O ID não existe nessa instância; teste outros números (1 a 5) |

## 📚 Referências

- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html · OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- OWASP Query Parameterization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- Semgrep: escrevendo regras: https://semgrep.dev/docs/writing-rules/overview
- Gitleaks: `.gitleaksignore`: https://github.com/gitleaks/gitleaks#gitleaksignore
- Trivy: filtrando vulnerabilidades (`.trivyignore.yaml`): https://trivy.dev/latest/docs/configuration/filtering/
- Google Cloud: Workload Identity Federation com GitHub Actions: https://github.com/google-github-actions/auth#workload-identity-federation-through-a-service-account
- CVE-2015-9235 (jsonwebtoken): https://nvd.nist.gov/vuln/detail/CVE-2015-9235

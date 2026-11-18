# 🔐 Cofre de segredos – da demonstração à produção

## O que a esteira demonstra (job `10. 🔐 Cofre de segredos`)

Um **HashiCorp Vault em modo DEV** sobe dentro do runner e é destruído no fim do job. Ele serve para mostrar o ciclo de vida do segredo, não para guardar segredo de verdade:

| Etapa | Controle | Ligação com o conteúdo |
|---|---|---|
| Segurança grava o segredo no cofre | Segredo fora do código, do `.env` e do `tfvars` | Aula 03: Gitleaks |
| Política `juice-shop-leitura` + token com TTL de 10 min | Menor privilégio e credencial de curta duração | IAM / Zero Trust |
| A aplicação lê em tempo de execução | Variável **injetada pelo cofre** na memória do processo | Correção da Aula 04: `process.env` vindo do cofre é aceitável; fixo no deploy não |
| Gravar ou ler segredo de outro sistema → 403 | Segregação de funções | OWASP: Broken Access Control |
| Nova versão do segredo | Rotação sem mudar código | Aula 04: "vazou? rotaciona" |
| `revoke-self` → 403 | Revogação imediata | Resposta a incidente |
| Log de auditoria | Quem leu, o quê e quando (valores em HMAC) | STRIDE: Repúdio |

## Como seria em produção no GCP (Secret Manager)

```bash
# 1. Criar o segredo (o valor vem do gerador, nunca do histórico do terminal)
gcloud services enable secretmanager.googleapis.com
openssl rand -hex 32 | gcloud secrets create juice-shop-jwt --data-file=- --replication-policy=automatic

# 2. Somente a SA da VM pode LER este segredo (menor privilégio, no nível do segredo)
gcloud secrets add-iam-policy-binding juice-shop-jwt \
  --member="serviceAccount:sa-juice-shop-lab@PROJETO.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"

# 3. Na VM (startup-script), ler em tempo de execução pela identidade da própria VM
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://secretmanager.googleapis.com/v1/projects/PROJETO/secrets/juice-shop-jwt/versions/latest:access" \
  | jq -r .payload.data | base64 -d

# 4. Rotação: nova versão; a anterior é desabilitada e depois destruída
openssl rand -hex 32 | gcloud secrets versions add juice-shop-jwt --data-file=-
gcloud secrets versions disable 1 --secret=juice-shop-jwt
```

O mesmo raciocínio vale para a credencial da própria esteira: a chave JSON da SA de deploy (`GCP_SA_KEY`) não expira. O próximo passo é o **Workload Identity Federation (OIDC)**: o GitHub prova quem é a cada execução e recebe um token de minutos, sem nenhuma chave guardada.

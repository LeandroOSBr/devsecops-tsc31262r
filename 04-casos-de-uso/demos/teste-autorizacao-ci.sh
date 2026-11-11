#!/usr/bin/env bash
# Teste de AUTORIZAÇÃO automatizado (caso de abuso) - Aula 04, Caso 4.
# Retorna exit 1 (reprova a esteira) se um usuário consegue ler o carrinho de outro.
# Pensado para rodar no job de DAST, com o Juice Shop já no ar em localhost:3000.
source "$(dirname "$0")/_comum.sh"
preparar

RESP="$(login 'jim@juice-sh.op' 'ncc-1701')"
TOKEN="$(jq -r '.authentication.token' <<<"$RESP")"
MEU_BID="$(jq -r '.authentication.bid' <<<"$RESP")"
MEU_ID="$(jwt_payload "$TOKEN" | jq -r '.data.id')"

falhas=0
for ALVO in 1 2 3 4 5; do
  [[ "$ALVO" == "$MEU_BID" ]] && continue
  CODIGO="$(curl -sS -o /tmp/basket.json -w '%{http_code}' \
            "${JUICE_URL}/rest/basket/${ALVO}" -H "Authorization: Bearer ${TOKEN}")"
  DONO="$(jq -r '.data.UserId // empty' /tmp/basket.json 2>/dev/null || true)"
  if [[ "$CODIGO" == "200" && -n "$DONO" && "$DONO" != "$MEU_ID" ]]; then
    alerta "BOLA: usuário ${MEU_ID} leu o carrinho ${ALVO} (dono: usuário ${DONO})"
    falhas=$((falhas + 1))
  else
    ok "Carrinho ${ALVO}: acesso negado ou inexistente (HTTP ${CODIGO})"
  fi
done

if (( falhas > 0 )); then
  alerta "Teste de autorização REPROVADO: ${falhas} carrinho(s) de terceiros acessível(is)."
  [[ -n "${GITHUB_STEP_SUMMARY:-}" ]] && \
    echo "### ⛔ Teste de autorização (BOLA): ${falhas} carrinho(s) de terceiros acessível(is)" >> "$GITHUB_STEP_SUMMARY"
  exit 1
fi
ok "Teste de autorização APROVADO."

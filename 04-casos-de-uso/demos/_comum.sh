#!/usr/bin/env bash
# Funções de apoio das demonstrações da Aula 04.
# ⚠️ Use SOMENTE contra o SEU Juice Shop de laboratório (localhost / Codespaces).
set -euo pipefail

JUICE_URL="${JUICE_URL:-http://localhost:3000}"

titulo() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()     { printf '\033[1;32m✔ %s\033[0m\n' "$*"; }
alerta() { printf '\033[1;31m✘ %s\033[0m\n' "$*"; }

# Confere dependências e se a aplicação está no ar
preparar() {
  for cmd in curl jq base64; do
    command -v "$cmd" >/dev/null || { alerta "Instale o comando '$cmd'"; exit 1; }
  done
  if ! curl -fsS "${JUICE_URL}/rest/admin/application-version" >/dev/null; then
    alerta "Juice Shop não respondeu em ${JUICE_URL}"
    echo "Suba a aplicação: docker run -d --rm --name juice-shop -p 3000:3000 bkimminich/juice-shop:v20.3.0"
    exit 1
  fi
  ok "Juice Shop no ar em ${JUICE_URL}"
}

# Decodifica um trecho Base64URL (usado no payload do JWT)
b64url_decode() {
  local s="${1//-/+}"; s="${s//_//}"
  case $(( ${#s} % 4 )) in 2) s="${s}==" ;; 3) s="${s}=" ;; esac
  printf '%s' "$s" | base64 -d 2>/dev/null
}

# Mostra o PAYLOAD de um JWT (a parte do meio) formatado
jwt_payload() { b64url_decode "$(cut -d. -f2 <<<"$1")" | jq .; }

# Faz login e devolve o JSON de resposta (email e senha como argumentos)
login() {
  curl -sS -X POST "${JUICE_URL}/rest/user/login" \
    -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg e "$1" --arg p "$2" '{email:$e, password:$p}')"
}

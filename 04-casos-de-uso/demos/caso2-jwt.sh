#!/usr/bin/env bash
# CASO 2 - O que viaja dentro do JWT e por que a chave no código é grave
# (STRIDE: Information Disclosure + Elevation of Privilege | OWASP A02/A07)
source "$(dirname "$0")/_comum.sh"
preparar

titulo "1) Login legítimo do usuário Jim"
TOKEN="$(login 'jim@juice-sh.op' 'ncc-1701' | jq -r '.authentication.token')"
echo "Token recebido (início): ${TOKEN:0:40}..."

titulo "2) O JWT é ASSINADO, não CRIPTOGRAFADO: qualquer um lê o payload"
jwt_payload "$TOKEN" | jq '{id: .data.id, email: .data.email, role: .data.role, password: .data.password, bid}'

titulo "3) O campo 'password' é um hash MD5 sem salt. Confira:"
echo -n 'ncc-1701' | md5sum | cut -d' ' -f1
echo "➡ Igual ao do token? MD5 sem salt é quebrado em segundos por tabelas prontas."

titulo "4) E a chave que ASSINA esses tokens?"
echo "Está escrita em lib/insecurity.ts (linha 21) - o Gitleaks e a regra 'ipog-chave-privada-no-codigo' apontam."
echo "Quem tem a chave privada assina um token com role=admin e o servidor ACEITA."
echo "➡ Correção: chave em cofre (Secret Manager/Vault), rotação da chave exposta,"
echo "  payload mínimo (sem senha!) e hash de senha forte (bcrypt/argon2)."

#!/usr/bin/env bash
# CASO 3 - "Dia do Log4Shell": usando o SBOM para responder "estamos afetados?"
# Uso: ./caso3-sbom.sh <sbom-juice-shop.cdx.json> [pacote]   (padrão: jsonwebtoken)
# O SBOM vem do artifact 'relatorio-container' da esteira (Aula 03).
set -euo pipefail
SBOM="${1:?Informe o caminho do sbom-juice-shop.cdx.json (baixe dos Artifacts da esteira)}"
PACOTE="${2:-jsonwebtoken}"

echo "📦 Componentes no SBOM: $(jq '.components | length' "$SBOM")"
echo
echo "🔎 Onde está '${PACOTE}' e em qual versão?"
jq -r --arg p "$PACOTE" '
  .components[] | select(.name == $p)
  | "  - \(.name)@\(.version)   purl=\(.purl // "-")"' "$SBOM" | sort -u

echo
echo "🧮 Top 10 pacotes por quantidade de versões diferentes (sinal de dívida de dependências):"
jq -r '.components[] | .name' "$SBOM" | sort | uniq -c | sort -rn | head -10

cat <<'TXT'

➡ Se sair hoje uma CVE crítica em um pacote, quem tem SBOM responde em SEGUNDOS
  "estamos afetados? em qual versão? em qual imagem?". Quem não tem, vai abrir
  cada servidor/repositório na mão.
➡ Próximo passo (opcional, com Trivy instalado): trivy sbom <arquivo-sbom>
TXT

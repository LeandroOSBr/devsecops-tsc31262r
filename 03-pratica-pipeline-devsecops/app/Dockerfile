# ==============================================================================
# Imagem da aplicação que percorre a esteira DevSecOps.
# Partimos da imagem oficial do OWASP Juice Shop (versão FIXA, nunca "latest")
# e adicionamos os metadados de rastreabilidade (de onde veio, qual commit).
# ==============================================================================
ARG JUICE_SHOP_VERSION=v20.3.0
FROM bkimminich/juice-shop:${JUICE_SHOP_VERSION}

ARG VCS_REF=local
ARG SOURCE_REPO=https://github.com/LeandroOSBr/devsecops-tsc31262r

LABEL org.opencontainers.image.title="Juice Shop - Lab DevSecOps IPOG TSC31262R" \
      org.opencontainers.image.description="OWASP Juice Shop implantado pela esteira DevSecOps da disciplina" \
      org.opencontainers.image.source="${SOURCE_REPO}" \
      org.opencontainers.image.revision="${VCS_REF}"

# Prática DevSecOps: container NUNCA roda como root
USER 65532
EXPOSE 3000

# Prática DevSecOps: o próprio container informa se está saudável
# (imagem distroless não tem shell/curl, então usamos o Node.js da imagem)
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD ["/nodejs/bin/node", "-e", "require('http').get('http://127.0.0.1:3000/rest/admin/application-version', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"]

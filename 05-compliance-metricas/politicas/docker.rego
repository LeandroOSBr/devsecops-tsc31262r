# ==============================================================================
# Compliance como código (Aula 05) - regras para Dockerfile (hardening de imagem)
# ==============================================================================
package docker

import rego.v1

# Conftest entrega o Dockerfile como lista de instruções {Cmd, Value, Stage}
instrucoes := [i | walk(input, [_, i]); is_object(i); i.Cmd]

froms := [i | some i in instrucoes; i.Cmd == "from"]

users := [i | some i in instrucoes; i.Cmd == "user"]

# IPOG-DKR-001: imagem base com versão fixa (nunca latest ou sem tag)
deny contains msg if {
	some f in froms
	imagem := f.Value[0]
	not contains(imagem, "@sha256:")
	not tem_tag_fixa(imagem)
	msg := sprintf("IPOG-DKR-001: FROM %s sem versão fixa. Use tag de versão ou digest @sha256 (nunca latest).", [imagem])
}

tem_tag_fixa(imagem) if {
	partes := split(imagem, "/")
	ultima := partes[count(partes) - 1]
	contains(ultima, ":")
	not endswith(ultima, ":latest")
}

# IPOG-DKR-002: o container não pode rodar como root
deny contains msg if {
	count(users) == 0
	msg := "IPOG-DKR-002: Dockerfile sem instrução USER (o container rodaria como root)."
}

deny contains msg if {
	count(users) > 0
	ultimo := users[count(users) - 1]
	ultimo.Value[0] in {"root", "0", "0:0"}
	msg := "IPOG-DKR-002: a última instrução USER é root."
}

# IPOG-DKR-003: segredo não entra em ENV/ARG do Dockerfile (fica gravado nas camadas)
palavras_sensiveis := ["PASSWORD", "SENHA", "SECRET", "TOKEN", "API_KEY", "PRIVATE_KEY"]

deny contains msg if {
	some i in instrucoes
	i.Cmd in {"env", "arg"}
	some v in i.Value
	some p in palavras_sensiveis
	contains(upper(v), p)
	msg := sprintf("IPOG-DKR-003: %s %s parece segredo. Segredo vem do cofre em tempo de execução, nunca da imagem.", [upper(i.Cmd), split(i.Value[0], "=")[0]])
}

# Alertas
warn contains msg if {
	not tem_healthcheck
	msg := "IPOG-DKR-101: Dockerfile sem HEALTHCHECK."
}

tem_healthcheck if {
	some i in instrucoes
	i.Cmd == "healthcheck"
}

warn contains msg if {
	some i in instrucoes
	i.Cmd == "add"
	msg := sprintf("IPOG-DKR-102: prefira COPY a ADD (%v).", [i.Value])
}

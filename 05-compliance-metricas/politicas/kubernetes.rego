# ==============================================================================
# Compliance como código (Aula 05) - regras para manifestos Kubernetes
# Complementa o Pod Security Admission (PSA) do cluster: aqui o erro é barrado
# ANTES do deploy (Shift Left); o PSA barra de novo dentro do cluster.
# ==============================================================================
package kubernetes

import rego.v1

cargas := {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}

pod_spec := input.spec.template.spec if input.kind in cargas

pod_spec := input.spec if input.kind == "Pod"

containers contains c if {
	some c in pod_spec.containers
}

containers contains c if {
	some c in object.get(pod_spec, "initContainers", [])
}

nome := sprintf("%s/%s", [input.kind, input.metadata.name])

# IPOG-K8S-001: container privilegiado é proibido
deny contains msg if {
	some c in containers
	c.securityContext.privileged == true
	msg := sprintf("IPOG-K8S-001: %s - container '%s' privilegiado.", [nome, c.name])
}

# IPOG-K8S-002: deve rodar como não-root
deny contains msg if {
	some c in containers
	not nao_root(c)
	msg := sprintf("IPOG-K8S-002: %s - container '%s' sem runAsNonRoot: true.", [nome, c.name])
}

nao_root(c) if c.securityContext.runAsNonRoot == true

nao_root(_) if pod_spec.securityContext.runAsNonRoot == true

# IPOG-K8S-003: sem escalonamento de privilégio e sem capabilities
deny contains msg if {
	some c in containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("IPOG-K8S-003: %s - container '%s' sem allowPrivilegeEscalation: false.", [nome, c.name])
}

deny contains msg if {
	some c in containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("IPOG-K8S-003: %s - container '%s' não remove todas as capabilities (drop: [ALL]).", [nome, c.name])
}

# IPOG-K8S-004: imagem com versão fixa
deny contains msg if {
	some c in containers
	not contains(c.image, "@sha256:")
	versao_latest(c.image)
	msg := sprintf("IPOG-K8S-004: %s - imagem '%s' sem versão fixa.", [nome, c.image])
}

versao_latest(img) if not contains(img, ":")

versao_latest(img) if endswith(img, ":latest")

# IPOG-K8S-005: limites de CPU/memória (evita que um pod derrube o nó)
deny contains msg if {
	some c in containers
	not c.resources.limits.memory
	msg := sprintf("IPOG-K8S-005: %s - container '%s' sem limite de memória.", [nome, c.name])
}

# IPOG-K8S-006: hostNetwork/hostPID quebram o isolamento
deny contains msg if {
	some campo in ["hostNetwork", "hostPID", "hostIPC"]
	pod_spec[campo] == true
	msg := sprintf("IPOG-K8S-006: %s usa %s.", [nome, campo])
}

# IPOG-K8S-007: Namespace deve aplicar o Pod Security Admission (nível restricted)
deny contains msg if {
	input.kind == "Namespace"
	object.get(input.metadata, ["labels", "pod-security.kubernetes.io/enforce"], "") != "restricted"
	msg := sprintf("IPOG-K8S-007: Namespace %s sem o rótulo pod-security.kubernetes.io/enforce: restricted.", [input.metadata.name])
}

# IPOG-K8S-008: Service exposto na internet deve restringir as origens
deny contains msg if {
	input.kind == "Service"
	input.spec.type == "LoadBalancer"
	count(object.get(input.spec, "loadBalancerSourceRanges", [])) == 0
	msg := sprintf("IPOG-K8S-008: Service %s é LoadBalancer sem loadBalancerSourceRanges (aberto para a internet).", [input.metadata.name])
}

deny contains msg if {
	input.kind == "Service"
	"0.0.0.0/0" in object.get(input.spec, "loadBalancerSourceRanges", [])
	msg := sprintf("IPOG-K8S-008: Service %s aceita 0.0.0.0/0.", [input.metadata.name])
}

# Alertas
warn contains msg if {
	some c in containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("IPOG-K8S-101: %s - container '%s' sem readOnlyRootFilesystem.", [nome, c.name])
}

warn contains msg if {
	input.kind in cargas
	object.get(pod_spec, "automountServiceAccountToken", true) != false
	msg := sprintf("IPOG-K8S-102: %s monta o token da ServiceAccount automaticamente.", [nome])
}

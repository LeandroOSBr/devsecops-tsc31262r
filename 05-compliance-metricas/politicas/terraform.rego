# ==============================================================================
# Compliance como código (Aula 05) - regras da empresa para o Terraform (GCP)
# Ferramenta: Conftest (motor OPA, linguagem Rego)
#
#   deny[...]  -> VIOLAÇÃO: o Quality Gate (modo bloqueio) reprova a esteira
#   warn[...]  -> ALERTA:   aparece no relatório, mas não bloqueia
#
# Diferença para o Trivy/Checkov: eles trazem regras GENÉRICAS do mercado.
# Aqui escrevemos as regras DA NOSSA EMPRESA (o "jeito certo" de usar a nuvem).
# ==============================================================================
package terraform

import rego.v1

instancias contains [nome, vm] if {
	some nome
	some vm in input.resource.google_compute_instance[nome]
}

firewalls contains [nome, fw] if {
	some nome
	some fw in input.resource.google_compute_firewall[nome]
}

# Exceção válida = registrada em excecoes.yaml, com dono, justificativa e validade futura.
excecao_valida(regra, recurso) if {
	some e in data.excecoes
	e.regra == regra
	e.recurso == recurso
	e.dono != ""
	e.justificativa != ""
	time.now_ns() < time.parse_rfc3339_ns(sprintf("%sT23:59:59Z", [e.validade]))
}

# ------------------------------------------------------------------------------
# REGRA IPOG-GCP-001: VM não pode ter IP público (sem exceção válida)
# ------------------------------------------------------------------------------
deny contains msg if {
	some [nome, vm] in instancias
	some nic in vm.network_interface
	count(object.get(nic, "access_config", [])) > 0
	recurso := sprintf("google_compute_instance.%s", [nome])
	not excecao_valida("IPOG-GCP-001", recurso)
	msg := sprintf("IPOG-GCP-001: %s tem IP público (access_config). Use Load Balancer/IAP ou registre uma exceção com dono e validade.", [recurso])
}

# ------------------------------------------------------------------------------
# REGRA IPOG-GCP-002: toda VM deve ser Shielded VM com Secure Boot
# ------------------------------------------------------------------------------
deny contains msg if {
	some [nome, vm] in instancias
	not secure_boot(vm)
	msg := sprintf("IPOG-GCP-002: google_compute_instance.%s sem Secure Boot (shielded_instance_config.enable_secure_boot = true).", [nome])
}

secure_boot(vm) if {
	some s in vm.shielded_instance_config
	s.enable_secure_boot == true
}

# ------------------------------------------------------------------------------
# REGRA IPOG-GCP-003: firewall não pode liberar SSH (22) nem RDP (3389)
# ------------------------------------------------------------------------------
portas_administrativas := {"22", "3389"}

deny contains msg if {
	some [nome, fw] in firewalls
	some regra in fw.allow
	some porta in object.get(regra, "ports", [])
	portas_administrativas[sprintf("%v", [porta])]
	msg := sprintf("IPOG-GCP-003: google_compute_firewall.%s libera a porta administrativa %v. Use IAP/OS Login, nunca porta aberta.", [nome, porta])
}

# ------------------------------------------------------------------------------
# REGRA IPOG-GCP-004: firewall não pode aceitar a internet inteira
# ------------------------------------------------------------------------------
deny contains msg if {
	some [nome, fw] in firewalls
	some origem in origens(fw)
	origem == "0.0.0.0/0"
	msg := sprintf("IPOG-GCP-004: google_compute_firewall.%s aceita 0.0.0.0/0 (internet inteira).", [nome])
}

origens(fw) := fw.source_ranges if is_array(fw.source_ranges)

origens(fw) := [] if not is_array(fw.source_ranges)

# ------------------------------------------------------------------------------
# REGRA IPOG-GCP-005: firewall deve registrar log das conexões (Repúdio/STRIDE)
# ------------------------------------------------------------------------------
deny contains msg if {
	some [nome, fw] in firewalls
	count(object.get(fw, "log_config", [])) == 0
	msg := sprintf("IPOG-GCP-005: google_compute_firewall.%s sem log_config (sem log não há investigação).", [nome])
}

# ------------------------------------------------------------------------------
# ALERTAS (não bloqueiam)
# ------------------------------------------------------------------------------
etiquetas_obrigatorias := {"environment", "managed_by"}

warn contains msg if {
	some [nome, vm] in instancias
	faltando := etiquetas_obrigatorias - {k | some k, _ in object.get(vm, "labels", {})}
	count(faltando) > 0
	msg := sprintf("IPOG-GCP-101: google_compute_instance.%s sem as labels %v (custo e inventário).", [nome, faltando])
}

warn contains msg if {
	some [nome, vm] in instancias
	some sa in vm.service_account
	"cloud-platform" in sa.scopes
	msg := sprintf("IPOG-GCP-102: google_compute_instance.%s usa escopo amplo cloud-platform; o controle fica só no IAM da SA.", [nome])
}

warn contains msg if {
	some [nome, vm] in instancias
	some nic in vm.network_interface
	count(object.get(nic, "access_config", [])) > 0
	recurso := sprintf("google_compute_instance.%s", [nome])
	excecao_valida("IPOG-GCP-001", recurso)
	msg := sprintf("IPOG-GCP-001 (EXCEÇÃO ATIVA): %s tem IP público aceito temporariamente. Veja excecoes.yaml.", [recurso])
}

# ------------------------------------------------------------------------------
# GKE (Aula 05): padrão da empresa = Autopilot com canal de versões
# ------------------------------------------------------------------------------
clusters contains [nome, c] if {
	some nome
	some c in input.resource.google_container_cluster[nome]
}

deny contains msg if {
	some [nome, c] in clusters
	not object.get(c, "enable_autopilot", false) == true
	msg := sprintf("IPOG-GKE-001: google_container_cluster.%s não é Autopilot (padrão da empresa: o Google gerencia e endurece os nós).", [nome])
}

deny contains msg if {
	some [nome, c] in clusters
	count(object.get(c, "release_channel", [])) == 0
	msg := sprintf("IPOG-GKE-002: google_container_cluster.%s sem release_channel (sem atualização automática de segurança).", [nome])
}

warn contains msg if {
	some [nome, c] in clusters
	count(object.get(c, "master_authorized_networks_config", [])) == 0
	msg := sprintf("IPOG-GKE-101: google_container_cluster.%s sem master_authorized_networks_config.", [nome])
}

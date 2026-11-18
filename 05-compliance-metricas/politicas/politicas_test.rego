# ==============================================================================
# Testes das políticas (política também é código: tem teste!)
# Rode:  conftest verify -p 05-compliance-metricas/politicas
# ==============================================================================
package terraform_test

import rego.v1

import data.terraform

vm_publica := {"resource": {"google_compute_instance": {"web": [{
	"network_interface": [{"access_config": [{}]}],
	"shielded_instance_config": [{"enable_secure_boot": true}],
	"labels": {"environment": "lab", "managed_by": "terraform"},
	"service_account": [{"scopes": ["cloud-platform"]}],
}]}}}

ssh_aberto := {"resource": {"google_compute_firewall": {"ssh": [{
	"allow": [{"protocol": "tcp", "ports": ["22"]}],
	"source_ranges": ["0.0.0.0/0"],
}]}}}

test_ip_publico_sem_excecao_bloqueia if {
	some msg in terraform.deny with input as vm_publica with data.excecoes as []
	startswith(msg, "IPOG-GCP-001")
}

test_ip_publico_com_excecao_valida_vira_alerta if {
	excecao := [{"regra": "IPOG-GCP-001", "recurso": "google_compute_instance.web", "dono": "Prof", "justificativa": "lab", "validade": "2099-12-31"}]
	count(terraform.deny) == 0 with input as vm_publica with data.excecoes as excecao
}

test_excecao_vencida_volta_a_bloquear if {
	vencida := [{"regra": "IPOG-GCP-001", "recurso": "google_compute_instance.web", "dono": "Prof", "justificativa": "lab", "validade": "2020-01-01"}]
	some msg in terraform.deny with input as vm_publica with data.excecoes as vencida
	startswith(msg, "IPOG-GCP-001")
}

test_excecao_sem_dono_nao_vale if {
	sem_dono := [{"regra": "IPOG-GCP-001", "recurso": "google_compute_instance.web", "dono": "", "justificativa": "lab", "validade": "2099-12-31"}]
	some msg in terraform.deny with input as vm_publica with data.excecoes as sem_dono
	startswith(msg, "IPOG-GCP-001")
}

test_ssh_aberto_para_internet_bloqueia_tres_regras if {
	msgs := terraform.deny with input as ssh_aberto with data.excecoes as []
	some a in msgs
	startswith(a, "IPOG-GCP-003")
	some b in msgs
	startswith(b, "IPOG-GCP-004")
	some c in msgs
	startswith(c, "IPOG-GCP-005")
}

test_gke_sem_autopilot_bloqueia if {
	cluster := {"resource": {"google_container_cluster": {"k8s": [{"release_channel": [{"channel": "REGULAR"}]}]}}}
	some msg in terraform.deny with input as cluster with data.excecoes as []
	startswith(msg, "IPOG-GKE-001")
}

test_gke_autopilot_aprovado if {
	cluster := {"resource": {"google_container_cluster": {"k8s": [{"enable_autopilot": true, "release_channel": [{"channel": "REGULAR"}]}]}}}
	count(terraform.deny) == 0 with input as cluster with data.excecoes as []
}

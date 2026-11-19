# Testes das regras de Kubernetes. Rode:  conftest verify -p 05-compliance-metricas/politicas
package kubernetes_test

import rego.v1

import data.kubernetes

hpa(max) := {
	"kind": "HorizontalPodAutoscaler",
	"metadata": {"name": "juice-shop"},
	"spec": {
		"minReplicas": 1,
		"maxReplicas": max,
		"metrics": [{"type": "Resource", "resource": {"name": "cpu"}}],
	},
}

test_hpa_dentro_do_teto_aprovado if {
	count(kubernetes.deny) == 0 with input as hpa(3)
}

test_hpa_acima_do_teto_bloqueia if {
	some msg in kubernetes.deny with input as hpa(20)
	startswith(msg, "IPOG-K8S-010")
}

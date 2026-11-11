#!/usr/bin/env python3
"""
Quality Gate da esteira DevSecOps (Prática 03 - IPOG TSC31262R).

Lê os relatórios gerados pelas ferramentas (SARIF do Gitleaks, Semgrep, Trivy,
Checkov e o JSON do OWASP ZAP), conta os achados por severidade e compara com a
política em politica-quality-gate.json.

  - categoria em modo "bloqueio"  + limite excedido  -> esteira REPROVADA (exit 1)
  - categoria em modo "relatorio" + limite excedido  -> apenas alerta (risco aceito)

Uso:
  python3 quality_gate.py --politica politica-quality-gate.json \
      --relatorios ./relatorios --categorias segredos,sast,iac,iac_checkov,container
"""
import argparse
import glob
import json
import os
import sys
from collections import Counter

SEVERIDADES = ["critical", "high", "medium", "low", "info"]
EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def severidade_por_score(score):
    """Converte o 'security-severity' (escala CVSS 0-10) em severidade."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def severidade_por_level(level):
    return {"error": "high", "warning": "medium", "note": "low"}.get(level or "", "info")


def local_sarif(res):
    """Retorna 'arquivo:linha' do primeiro local do achado (para o dev ir direto ao ponto)."""
    try:
        fis = res["locations"][0]["physicalLocation"]
        uri = fis["artifactLocation"]["uri"]
        linha = (fis.get("region") or {}).get("startLine")
        return f"{uri}:{linha}" if linha else uri
    except (KeyError, IndexError, TypeError):
        return "-"


def ler_sarif(caminho, severidade_padrao=None):
    """Retorna lista de (severidade, regra) para cada resultado do SARIF."""
    with open(caminho, encoding="utf-8") as f:
        sarif = json.load(f)
    achados = []
    for run in sarif.get("runs", []):
        regras = {}
        for r in run.get("tool", {}).get("driver", {}).get("rules", []) or []:
            regras[r.get("id")] = r
        for res in run.get("results", []) or []:
            if res.get("suppressions"):
                continue  # achado suprimido/justificado na própria ferramenta
            regra = regras.get(res.get("ruleId"), {})
            score = (regra.get("properties") or {}).get("security-severity")
            if severidade_padrao:
                sev = severidade_padrao
            elif score is not None:
                try:
                    sev = severidade_por_score(float(score))
                except ValueError:
                    sev = severidade_por_level(res.get("level"))
            else:
                level = res.get("level") or (regra.get("defaultConfiguration") or {}).get("level")
                sev = severidade_por_level(level)
            nome = (regra.get("shortDescription") or {}).get("text") or regra.get("name") or res.get("ruleId")
            achados.append((sev, f"{res.get('ruleId')} - {nome}"[:120], local_sarif(res)))
    return achados


def ler_zap(caminho):
    """Lê o report_json.json do OWASP ZAP (riskcode 3=alto, 2=médio, 1=baixo, 0=info)."""
    with open(caminho, encoding="utf-8") as f:
        zap = json.load(f)
    mapa = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    achados = []
    for site in zap.get("site", []):
        for alerta in site.get("alerts", []):
            sev = mapa.get(str(alerta.get("riskcode")), "info")
            instancias = alerta.get("instances") or [{}]
            local = instancias[0].get("uri", "-")
            achados.append((sev, f"{alerta.get('pluginid')} - {alerta.get('name')}", local))
    return achados


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--politica", required=True)
    ap.add_argument("--relatorios", required=True)
    ap.add_argument("--categorias", required=True, help="lista separada por vírgula")
    ap.add_argument("--detalhado", help="(opcional) gera um relatório Markdown com TODOS os achados "
                                        "críticos/altos e o arquivo:linha de cada um")
    args = ap.parse_args()

    with open(args.politica, encoding="utf-8") as f:
        politica = json.load(f)["categorias"]

    linhas = ["## 🚦 Quality Gate DevSecOps", "",
              "| Categoria | Modo | " + " | ".join(f"{EMOJI[s]} {s}" for s in SEVERIDADES) + " | Resultado |",
              "|---|---|" + "---|" * len(SEVERIDADES) + "---|"]
    detalhes = []
    completo = ["# Relatório detalhado de achados críticos/altos", "",
                "Gerado pelo Quality Gate. Use a coluna **Onde** para ir direto ao arquivo/linha "
                "(ou à URL, no caso do DAST).", ""]
    reprovado = False

    for cat in [c.strip() for c in args.categorias.split(",") if c.strip()]:
        cfg = politica[cat]
        arquivos = []
        for padrao in cfg["arquivos"]:
            arquivos += glob.glob(os.path.join(args.relatorios, "**", padrao), recursive=True)
        arquivos = sorted(set(arquivos))

        if not arquivos:
            linhas.append(f"| {cfg['titulo']} | {cfg['modo']} | " + " | ".join("-" for _ in SEVERIDADES)
                          + " | ❌ relatório não encontrado |")
            reprovado = True  # sem evidência não há aprovação
            continue

        achados = []
        for arq in arquivos:
            if arq.endswith(".json"):
                achados += ler_zap(arq)
            else:
                achados += ler_sarif(arq, cfg.get("severidade_padrao"))

        cont = Counter(a[0] for a in achados)
        excedidos = [s for s, maximo in cfg["limites"].items() if cont.get(s, 0) > maximo]

        if not excedidos:
            resultado = "✅ aprovado"
        elif cfg["modo"] == "bloqueio":
            resultado = f"⛔ BLOQUEADO ({', '.join(excedidos)})"
            reprovado = True
        else:
            resultado = f"⚠️ risco aceito ({', '.join(excedidos)})"

        linhas.append(f"| {cfg['titulo']} | {cfg['modo']} | "
                      + " | ".join(str(cont.get(s, 0)) for s in SEVERIDADES) + f" | {resultado} |")

        graves = sorted((a for a in achados if a[0] in ("critical", "high")),
                        key=lambda a: (SEVERIDADES.index(a[0]), a[1], a[2]))
        top = Counter(a[1] for a in graves).most_common(5)
        if top:
            detalhes.append(f"<details><summary><b>{cfg['titulo']}</b> - top achados críticos/altos</summary>\n")
            detalhes += [f"- `{n}x` {r}" for r, n in top]
            detalhes.append("\n**Onde estão (primeiros 10):**\n")
            detalhes += [f"- {EMOJI[sev]} `{local}` — {regra}" for sev, regra, local in graves[:10]]
            if len(graves) > 10:
                detalhes.append(f"- … e mais {len(graves) - 10} (veja o relatório detalhado nos Artifacts)")
            detalhes.append("\n</details>")
            completo += [f"## {cfg['titulo']} ({cfg['modo']})", "", "| Severidade | Regra | Onde |", "|---|---|---|"]
            completo += [f"| {EMOJI[sev]} {sev} | {regra.replace('|', '/')} | `{local}` |"
                         for sev, regra, local in graves]
            completo.append("")

    linhas.append("")
    linhas.append("**Resultado final:** " + ("⛔ REPROVADO - o deploy NÃO deve seguir." if reprovado
                                             else "✅ APROVADO - a esteira pode seguir."))
    linhas.append("")
    saida = "\n".join(linhas + detalhes) + "\n"

    print(saida)
    if args.detalhado:
        os.makedirs(os.path.dirname(os.path.abspath(args.detalhado)), exist_ok=True)
        with open(args.detalhado, "w", encoding="utf-8") as f:
            f.write("\n".join(completo) + "\n")
    resumo = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumo:
        with open(resumo, "a", encoding="utf-8") as f:
            f.write(saida)

    sys.exit(1 if reprovado else 0)


if __name__ == "__main__":
    main()

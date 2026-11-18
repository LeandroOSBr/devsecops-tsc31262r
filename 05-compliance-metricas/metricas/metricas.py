#!/usr/bin/env python3
"""
Métricas DevSecOps da esteira (Aula 05 - IPOG TSC31262R).

Pilar "Medição" do CALMS: sem número não há melhoria contínua. Este script junta
duas visões no resumo da execução (GITHUB_STEP_SUMMARY):

  1. SEGURANÇA desta execução: achados por categoria e severidade (vem do
     resumo JSON gerado pelo Quality Gate).
  2. ENTREGA (métricas DORA, aproximadas pelo histórico do GitHub Actions na main):
       - Frequência de entrega ......... execuções aprovadas na main por semana
       - Lead time de mudança .......... do commit até a esteira terminar aprovada
       - Taxa de falha de mudanças ..... % de execuções reprovadas na main
       - Tempo para restaurar (MTTR) ... da esteira vermelha até voltar a ficar verde

Uso (na esteira):  python3 metricas.py --resumo relatorios/resumo-quality-gate.json
Uso (offline):     python3 metricas.py --runs-json exemplo-runs.json
"""
import argparse
import json
import os
import statistics
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

SEVERIDADES = ["critical", "high", "medium", "low", "info"]
EMOJI = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "⚪"}


def data(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def horas(td):
    return td.total_seconds() / 3600


def fmt(h):
    if h is None:
        return "sem dados"
    if h < 1:
        return f"{h * 60:.0f} min"
    if h < 48:
        return f"{h:.1f} h"
    return f"{h / 24:.1f} dias"


def buscar_execucoes(repo, workflow, token, branch="main"):
    url = (f"https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs"
           f"?branch={branch}&status=completed&per_page=100")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/vnd.github+json",
                                               "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r).get("workflow_runs", [])


def calcular_dora(execucoes, dias=30, agora=None):
    agora = agora or datetime.now(timezone.utc)
    inicio = agora - timedelta(days=dias)
    runs = sorted((r for r in execucoes
                   if r.get("conclusion") in ("success", "failure") and data(r["created_at"]) >= inicio),
                  key=lambda r: data(r["created_at"]))
    sucessos = [r for r in runs if r["conclusion"] == "success"]
    falhas = [r for r in runs if r["conclusion"] == "failure"]

    lead = [horas(data(r["updated_at"]) - data(r["head_commit"]["timestamp"]))
            for r in sucessos if (r.get("head_commit") or {}).get("timestamp")]

    restauracoes, aberta = [], None
    for r in runs:
        if r["conclusion"] == "failure" and aberta is None:
            aberta = data(r["updated_at"])
        elif r["conclusion"] == "success" and aberta is not None:
            restauracoes.append(horas(data(r["updated_at"]) - aberta))
            aberta = None

    return {
        "janela_dias": dias,
        "execucoes": len(runs),
        "aprovadas": len(sucessos),
        "reprovadas": len(falhas),
        "frequencia_por_semana": round(len(sucessos) / (dias / 7), 2),
        "lead_time_mediana_h": round(statistics.median(lead), 2) if lead else None,
        "taxa_falha_pct": round(100 * len(falhas) / len(runs), 1) if runs else None,
        "mttr_media_h": round(statistics.mean(restauracoes), 2) if restauracoes else None,
        "esteira_vermelha_agora": aberta is not None,
    }


def secao_seguranca(resumo):
    if not resumo:
        return ["_Resumo do Quality Gate não encontrado nesta execução._", ""]
    linhas = ["| Categoria | Modo | " + " | ".join(f"{EMOJI[s]} {s}" for s in SEVERIDADES) + " |",
              "|---|---|" + "---|" * len(SEVERIDADES)]
    total = {s: 0 for s in SEVERIDADES}
    for cat in resumo.get("categorias", {}).values():
        c = cat["contagem"]
        for s in SEVERIDADES:
            total[s] += c.get(s, 0)
        linhas.append(f"| {cat['titulo']} | {cat['modo']} | "
                      + " | ".join(str(c.get(s, 0)) for s in SEVERIDADES) + " |")
    linhas.append("| **TOTAL (débito de segurança)** | | "
                  + " | ".join(f"**{total[s]}**" for s in SEVERIDADES) + " |")
    linhas += ["", "Quality Gate desta execução: "
               + ("✅ aprovado" if resumo.get("aprovado") else "⛔ reprovado"), ""]
    return linhas


def classificar(m):
    """Faixas didáticas inspiradas no relatório DORA (Accelerate State of DevOps)."""
    f, lt = m["frequencia_por_semana"], m["lead_time_mediana_h"]
    cfr, mttr = m["taxa_falha_pct"], m["mttr_media_h"]
    return [
        ("Frequência de entrega", f"{f}/semana",
         "🟢 alta" if f >= 7 else "🟡 média" if f >= 1 else "🔴 baixa"),
        ("Lead time de mudança (mediana)", fmt(lt),
         "-" if lt is None else "🟢 < 1 dia" if lt < 24 else "🟡 < 1 semana" if lt < 168 else "🔴 > 1 semana"),
        ("Taxa de falha de mudanças", "sem dados" if cfr is None else f"{cfr}%",
         "-" if cfr is None else "🟢 ≤ 15%" if cfr <= 15 else "🟡 ≤ 30%" if cfr <= 30 else "🔴 > 30%"),
        ("Tempo para restaurar (MTTR)", fmt(mttr),
         "-" if mttr is None else "🟢 < 1 h" if mttr < 1 else "🟡 < 1 dia" if mttr < 24 else "🔴 > 1 dia"),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--resumo", help="resumo JSON do Quality Gate (--resumo-json)")
    ap.add_argument("--runs-json", help="arquivo com execuções (teste offline, formato da API do GitHub)")
    ap.add_argument("--workflow", default="devsecops-juice-shop.yml")
    ap.add_argument("--dias", type=int, default=30)
    ap.add_argument("--saida", default="metricas-devsecops.json")
    args = ap.parse_args()

    resumo = None
    if args.resumo and os.path.exists(args.resumo):
        with open(args.resumo, encoding="utf-8") as f:
            resumo = json.load(f)

    execucoes, aviso = [], None
    try:
        if args.runs_json:
            with open(args.runs_json, encoding="utf-8") as f:
                execucoes = json.load(f).get("workflow_runs", [])
        else:
            execucoes = buscar_execucoes(os.environ["GITHUB_REPOSITORY"], args.workflow,
                                         os.environ["GITHUB_TOKEN"])
    except Exception as e:  # métrica nunca derruba a esteira
        aviso = f"Não foi possível ler o histórico de execuções ({type(e).__name__}: {e})."

    dora = calcular_dora(execucoes, args.dias)

    md = ["## 📊 Métricas DevSecOps (pilar Medição do CALMS)", "",
          "### 1. Segurança desta execução", ""] + secao_seguranca(resumo)
    md += [f"### 2. Entrega - métricas DORA (branch main, últimos {args.dias} dias, "
           f"{dora['execucoes']} execuções)", ""]
    if aviso:
        md += [f"> ⚠️ {aviso}", ""]
    md += ["| Métrica | Valor | Faixa |", "|---|---|---|"]
    md += [f"| {a} | {b} | {c} |" for a, b, c in classificar(dora)]
    md += ["", "_Aproximação didática: cada execução aprovada na main = uma entrega "
               "(imagem publicada no GHCR)._", ""]

    saida = "\n".join(md) + "\n"
    print(saida)
    with open(args.saida, "w", encoding="utf-8") as f:
        json.dump({"gerado_em": datetime.now(timezone.utc).isoformat(), "dora": dora, "seguranca": resumo},
                  f, ensure_ascii=False, indent=2)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(saida)
    return 0


if __name__ == "__main__":
    sys.exit(main())

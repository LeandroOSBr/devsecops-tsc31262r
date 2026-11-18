#!/usr/bin/env python3
"""
Relatório visual da esteira DevSecOps (Aula 05 - IPOG TSC31262R).

Junta, num único HTML autocontido (abre offline, sem internet), os resultados de
TODAS as ferramentas de segurança da esteira:

  Gitleaks (segredos) · Semgrep (SAST) · Trivy config + Checkov (IaC)
  Conftest/OPA (compliance) · Trivy image (SCA/contêiner) · SBOM CycloneDX
  OWASP ZAP (DAST) · resultado do Quality Gate

Reaproveita a mesma política e os mesmos leitores do quality_gate.py, para que o
relatório e o gate contem exatamente os mesmos achados.

Uso:
  python3 relatorio_html.py --politica politica-quality-gate.json \
      --relatorios ./relatorios --saida relatorio-devsecops.html
"""
import argparse
import glob
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import quality_gate as qg  # noqa: E402

SEV = qg.SEVERIDADES
ROTULO = {"critical": "Crítica", "high": "Alta", "medium": "Média", "low": "Baixa", "info": "Info"}
FERRAMENTA = {
    "segredos_repo": ("Gitleaks", "Segredos"), "segredos_app": ("Gitleaks", "Segredos"),
    "sast": ("Semgrep", "SAST"), "sast_empresa": ("Semgrep", "SAST"),
    "iac": ("Trivy config", "IaC"), "iac_checkov": ("Checkov", "IaC"),
    "compliance": ("Conftest/OPA", "Compliance"), "container": ("Trivy image", "SCA + Contêiner"),
    "dast": ("OWASP ZAP", "DAST"),
}
ORDEM = ["segredos_repo", "segredos_app", "sast", "sast_empresa", "iac", "iac_checkov",
         "compliance", "container", "dast"]

e = html.escape


def coletar(politica, pasta, forcadas=()):
    cats = []
    for cat in ORDEM:
        cfg = politica.get(cat)
        if not cfg:
            continue
        cfg = dict(cfg, modo="bloqueio") if cat in forcadas else cfg
        arquivos = []
        for padrao in cfg["arquivos"]:
            arquivos += glob.glob(os.path.join(pasta, "**", padrao), recursive=True)
        arquivos = sorted(set(arquivos))
        achados = []
        for arq in arquivos:
            try:
                achados += qg.ler_zap(arq) if arq.endswith(".json") else qg.ler_sarif(arq, cfg.get("severidade_padrao"))
            except Exception as ex:  # relatório quebrado não derruba o HTML
                achados.append(("info", f"Relatório ilegível: {os.path.basename(arq)} ({ex})", arq))
        cont = Counter(a[0] for a in achados)
        excedidos = [s for s, m in cfg["limites"].items() if cont.get(s, 0) > m]
        if not arquivos:
            status = "sem-relatorio"
        elif not excedidos:
            status = "aprovado"
        elif cfg["modo"] == "bloqueio":
            status = "bloqueado"
        else:
            status = "risco-aceito"
        cats.append({"id": cat, "titulo": cfg["titulo"], "modo": cfg["modo"], "limites": cfg["limites"],
                     "achados": sorted(achados, key=lambda a: (SEV.index(a[0]), a[1], a[2])),
                     "cont": cont, "status": status, "arquivos": arquivos})
    return cats


def ler_sbom(pasta):
    for arq in glob.glob(os.path.join(pasta, "**", "*.cdx.json"), recursive=True):
        try:
            with open(arq, encoding="utf-8") as f:
                comps = json.load(f).get("components", []) or []
            return [(c.get("name", "?"), c.get("version", "-"), c.get("type", "-"), c.get("purl", "")) for c in comps]
        except Exception:
            return []
    return None


STATUS_TXT = {"aprovado": "✅ Aprovado", "bloqueado": "⛔ Bloqueado", "risco-aceito": "⚠️ Risco aceito",
              "sem-relatorio": "❌ Sem relatório"}

CSS = """
:root{--fundo:#f4f1ea;--papel:#fffdf8;--borda:#e3ddd0;--tinta:#1a2330;--suave:#566170;--escuro:#14202e;
--critical:#6a1b7a;--high:#c23b3b;--medium:#d9730d;--low:#e3c13b;--info:#8a95a3;--ok:#2e7d4f;--laranja:#f28c28}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--fundo);color:var(--tinta)}
header{background:var(--escuro);color:#f4f1ea;padding:28px 40px}
header h1{margin:4px 0 6px;font-size:28px}header .k{color:var(--laranja);font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:12px}
header .meta{color:#b8c3d1;font-size:13px}header .meta code{color:#f4f1ea;background:#24364b}
.veredito{display:inline-block;margin-top:14px;padding:8px 16px;border-radius:999px;font-weight:700}
.veredito.ok{background:#d9f2e3;color:#14532d}.veredito.ko{background:#fde2e2;color:#7f1d1d}
main{max-width:1280px;margin:0 auto;padding:28px 40px 60px}
h2{font-size:20px;margin:34px 0 12px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:14px}
.kpi{background:var(--papel);border:1px solid var(--borda);border-radius:14px;padding:16px;border-top:6px solid var(--c)}
.kpi .n{font-size:34px;font-weight:800;line-height:1}.kpi .l{color:var(--suave);font-size:13px;margin-top:6px}
table{width:100%;border-collapse:collapse;background:var(--papel);border:1px solid var(--borda);border-radius:12px;overflow:hidden}
th{background:var(--escuro);color:#f4f1ea;text-align:left;font-weight:600;padding:9px 12px;font-size:13px}
td{padding:8px 12px;border-top:1px solid var(--borda);vertical-align:top;font-size:14px}
td.num{text-align:right;font-variant-numeric:tabular-nums}td.zero{color:#b5bcc6}
.barra{display:flex;height:14px;border-radius:7px;overflow:hidden;background:#ece7dc;min-width:160px}
.barra span{display:block;height:100%}
.st{font-weight:700;white-space:nowrap}.st.bloqueado{color:var(--high)}.st.aprovado{color:var(--ok)}.st.risco-aceito{color:var(--medium)}.st.sem-relatorio{color:var(--high)}
.modo{font-size:12px;padding:2px 8px;border-radius:999px;background:#ece7dc;white-space:nowrap}.modo.bloqueio{background:var(--escuro);color:#f4f1ea}
.sev{display:inline-block;min-width:64px;text-align:center;font-size:12px;font-weight:700;padding:2px 8px;border-radius:999px;color:#fff}
.sev.critical{background:var(--critical)}.sev.high{background:var(--high)}.sev.medium{background:var(--medium)}.sev.low{background:var(--low);color:#3a2f00}.sev.info{background:var(--info)}
.filtros{position:sticky;top:0;z-index:5;background:var(--fundo);padding:12px 0;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--borda)}
.filtros button{border:1px solid var(--borda);background:var(--papel);border-radius:999px;padding:6px 14px;font:inherit;cursor:pointer}
.filtros button.on{background:var(--escuro);color:#f4f1ea;border-color:var(--escuro)}
.filtros input{flex:1;min-width:220px;padding:8px 12px;border:1px solid var(--borda);border-radius:10px;font:inherit;background:var(--papel)}
details{background:var(--papel);border:1px solid var(--borda);border-radius:14px;margin:12px 0}
summary{cursor:pointer;padding:14px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap;list-style:none}
summary::-webkit-details-marker{display:none}
summary .t{font-weight:700;font-size:16px;flex:1;min-width:260px}summary .f{color:var(--suave);font-size:13px}
details .corpo{padding:0 18px 18px}details table{border-radius:8px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#efe9dd;padding:1px 5px;border-radius:5px;word-break:break-all}
.vazio{color:var(--suave);padding:10px 0}.nota{color:var(--suave);font-size:13px}
.grade2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.legenda{display:flex;gap:14px;flex-wrap:wrap;font-size:13px;color:var(--suave);margin:8px 0}
.legenda i{display:inline-block;width:12px;height:12px;border-radius:3px;margin-right:5px;vertical-align:-1px}
footer{color:var(--suave);font-size:12px;text-align:center;padding:20px}
@media (max-width:900px){.kpis{grid-template-columns:repeat(2,1fr)}.grade2{grid-template-columns:1fr}main,header{padding:20px}}
"""

JS = """
const sevOn=new Set(['critical','high','medium','low','info']);
function aplicar(){const q=document.getElementById('busca').value.toLowerCase();
document.querySelectorAll('tr.achado').forEach(tr=>{const ok=sevOn.has(tr.dataset.sev)&&(!q||tr.textContent.toLowerCase().includes(q));tr.style.display=ok?'':'none';});
document.querySelectorAll('details.cat').forEach(d=>{const vis=[...d.querySelectorAll('tr.achado')].filter(t=>t.style.display!=='none').length;const c=d.querySelector('.vis');if(c)c.textContent=vis;});}
document.querySelectorAll('.filtros button[data-sev]').forEach(b=>b.addEventListener('click',()=>{const s=b.dataset.sev;if(sevOn.has(s)){sevOn.delete(s);b.classList.remove('on')}else{sevOn.add(s);b.classList.add('on')}aplicar();}));
document.getElementById('busca').addEventListener('input',aplicar);
document.getElementById('abrir').addEventListener('click',()=>document.querySelectorAll('details.cat').forEach(d=>d.open=true));
document.getElementById('fechar').addEventListener('click',()=>document.querySelectorAll('details.cat').forEach(d=>d.open=false));
"""


def barra(cont):
    total = sum(cont.get(s, 0) for s in SEV)
    if not total:
        return '<div class="barra"></div>'
    partes = "".join(f'<span style="width:{100 * cont.get(s, 0) / total:.2f}%;background:var(--{s})" '
                     f'title="{ROTULO[s]}: {cont.get(s, 0)}"></span>' for s in SEV if cont.get(s, 0))
    return f'<div class="barra">{partes}</div>'


def gerar(cats, sbom, meta):
    total = Counter()
    for c in cats:
        total.update(c["cont"])
    reprovado = any(c["status"] == "bloqueado" or (c["status"] == "sem-relatorio" and c["id"] != "dast") for c in cats)
    h = ['<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         f'<title>Relatório DevSecOps · {e(meta["commit"][:7])}</title><style>{CSS}</style></head><body>',
         '<header><div class="k">Esteira DevSecOps · Juice Shop · TSC31262R</div>',
         '<h1>Relatório consolidado das ferramentas de segurança</h1>',
         f'<div class="meta">Repositório <code>{e(meta["repo"])}</code> · branch <code>{e(meta["branch"])}</code> · '
         f'commit <code>{e(meta["commit"][:12])}</code> · gerado em {e(meta["quando"])}'
         + (f' · <a style="color:#f28c28" href="{e(meta["url"])}">execução no GitHub Actions</a>' if meta["url"] else '') + '</div>',
         f'<div class="veredito {"ko" if reprovado else "ok"}">'
         + ("⛔ Quality Gate REPROVADO: o deploy não deve seguir" if reprovado else "✅ Quality Gate APROVADO: a esteira pode seguir")
         + '</div></header><main>']

    h.append('<h2>Visão geral: todos os achados por severidade</h2><div class="kpis">')
    for s in SEV:
        h.append(f'<div class="kpi" style="--c:var(--{s})"><div class="n">{total.get(s, 0)}</div><div class="l">{ROTULO[s]}</div></div>')
    h.append('</div>')

    h.append('<h2>Por ferramenta e decisão da política</h2>')
    h.append('<div class="legenda">' + "".join(f'<span><i style="background:var(--{s})"></i>{ROTULO[s]}</span>' for s in SEV) + '</div>')
    h.append('<table><tr><th>Categoria</th><th>Ferramenta</th><th>Modo</th>'
             + "".join(f'<th style="text-align:right">{ROTULO[s]}</th>' for s in SEV)
             + '<th>Distribuição</th><th>Resultado</th></tr>')
    for c in cats:
        fer, area = FERRAMENTA.get(c["id"], ("-", "-"))
        h.append(f'<tr><td><a href="#{c["id"]}">{e(c["titulo"])}</a></td><td>{e(fer)}</td>'
                 f'<td><span class="modo {e(c["modo"])}">{e(c["modo"])}</span></td>'
                 + "".join(f'<td class="num{" zero" if not c["cont"].get(s, 0) else ""}">{c["cont"].get(s, 0)}</td>' for s in SEV)
                 + f'<td>{barra(c["cont"])}</td><td class="st {c["status"]}">{STATUS_TXT[c["status"]]}</td></tr>')
    h.append('</table><p class="nota">Modo <b>bloqueio</b>: passou do limite, a esteira para. Modo <b>relatório</b>: '
             'o achado é registrado como risco aceito. A mesma política é aplicada pelo <code>quality_gate.py</code>.</p>')

    h.append('<h2>Achados detalhados</h2><div class="filtros">'
             + "".join(f'<button class="on" data-sev="{s}"><span class="sev {s}">{ROTULO[s]}</span></button>' for s in SEV)
             + '<input id="busca" placeholder="Filtrar por regra, arquivo, CVE, URL…">'
             '<button id="abrir">Abrir todos</button><button id="fechar">Fechar todos</button></div>')
    for c in cats:
        fer, area = FERRAMENTA.get(c["id"], ("-", "-"))
        aberto = " open" if c["status"] == "bloqueado" else ""
        h.append(f'<details class="cat" id="{c["id"]}"{aberto}><summary><span class="t">{e(area)} · {e(c["titulo"])}</span>'
                 f'<span class="f">{e(fer)} · <span class="vis">{len(c["achados"])}</span> achado(s)</span>{barra(c["cont"])}'
                 f'<span class="st {c["status"]}">{STATUS_TXT[c["status"]]}</span></summary><div class="corpo">')
        lim = ", ".join(f"{ROTULO.get(k, k)} ≤ {v}" for k, v in c["limites"].items())
        arqs = ", ".join(f"<code>{e(os.path.basename(a))}</code>" for a in c["arquivos"]) or "nenhum"
        h.append(f'<p class="nota">Limites: {e(lim)} · modo {e(c["modo"])} · relatórios: {arqs}</p>')
        if not c["achados"]:
            h.append('<p class="vazio">Nenhum achado. 🎉</p>')
        else:
            h.append('<table><tr><th style="width:110px">Severidade</th><th>Regra / descrição</th><th style="width:34%">Onde</th></tr>')
            for sev, regra, local in c["achados"][:500]:
                h.append(f'<tr class="achado" data-sev="{sev}"><td><span class="sev {sev}">{ROTULO[sev]}</span></td>'
                         f'<td>{e(regra)}</td><td><code>{e(local)}</code></td></tr>')
            h.append('</table>')
            if len(c["achados"]) > 500:
                h.append(f'<p class="nota">Exibindo 500 de {len(c["achados"])} achados (veja o SARIF completo nos Artifacts).</p>')
        h.append('</div></details>')

    h.append('<h2>SBOM: inventário de componentes da imagem (CycloneDX)</h2>')
    if sbom is None:
        h.append('<p class="vazio">SBOM não encontrado nesta execução.</p>')
    else:
        tipos = Counter(t for _, _, t, _ in sbom)
        eco = Counter((p.split(":")[1].split("/")[0] if p.startswith("pkg:") else "-") for *_, p in sbom)
        h.append('<div class="grade2"><table><tr><th>Componentes</th><th style="text-align:right">Qtde</th></tr>'
                 f'<tr><td><b>Total</b></td><td class="num"><b>{len(sbom)}</b></td></tr>'
                 + "".join(f'<tr><td>tipo: {e(t)}</td><td class="num">{n}</td></tr>' for t, n in tipos.most_common(6))
                 + '</table><table><tr><th>Ecossistema (purl)</th><th style="text-align:right">Qtde</th></tr>'
                 + "".join(f'<tr><td>{e(k)}</td><td class="num">{n}</td></tr>' for k, n in eco.most_common(8)) + '</table></div>')
        if sbom:
            h.append('<details class="cat"><summary><span class="t">Lista de componentes</span>'
                     f'<span class="f">{len(sbom)} itens</span></summary><div class="corpo"><table>'
                     '<tr><th>Nome</th><th>Versão</th><th>purl</th></tr>'
                     + "".join(f'<tr class="achado" data-sev="info"><td>{e(n)}</td><td>{e(v)}</td><td><code>{e(p)}</code></td></tr>'
                               for n, v, _, p in sorted(sbom)[:1500]) + '</table></div></details>')
        h.append('<p class="nota">No dia de um novo "Log4Shell", basta buscar o componente no SBOM para saber se esta versão é afetada.</p>')

    h.append('</main><footer>Gerado por <code>relatorio_html.py</code> · Ambiente de Desenvolvimento e Operação - DevSecOps · IPOG · '
             'Prof. Leandro Santos</footer>')
    h.append(f'<script>{JS}</script></body></html>')
    return "\n".join(h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--politica", required=True)
    ap.add_argument("--relatorios", required=True)
    ap.add_argument("--saida", default="relatorio-devsecops.html")
    ap.add_argument("--forcar-bloqueio", default="", help="mesmas categorias forçadas no Quality Gate (ex.: container)")
    args = ap.parse_args()
    forcadas = {c.strip() for c in args.forcar_bloqueio.split(",") if c.strip()}
    with open(args.politica, encoding="utf-8") as f:
        politica = json.load(f)["categorias"]
    servidor, repo, run = os.environ.get("GITHUB_SERVER_URL", ""), os.environ.get("GITHUB_REPOSITORY", "local"), os.environ.get("GITHUB_RUN_ID", "")
    meta = {"repo": repo, "branch": os.environ.get("GITHUB_REF_NAME", "-"), "commit": os.environ.get("GITHUB_SHA", "local"),
            "quando": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC"),
            "url": f"{servidor}/{repo}/actions/runs/{run}" if servidor and run else ""}
    cats = coletar(politica, args.relatorios, forcadas)
    conteudo = gerar(cats, ler_sbom(args.relatorios), meta)
    with open(args.saida, "w", encoding="utf-8") as f:
        f.write(conteudo)
    total = sum(sum(c["cont"].values()) for c in cats)
    print(f"Relatório gerado: {args.saida} ({total} achados em {len(cats)} categorias)")
    resumo = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumo:
        with open(resumo, "a", encoding="utf-8") as f:
            f.write(f"### 🧾 Relatório visual\nBaixe o artifact **relatorio-visual-devsecops** e abra "
                    f"`{os.path.basename(args.saida)}` no navegador ({total} achados, todas as ferramentas).\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

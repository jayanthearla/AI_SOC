"""Generate paper tables (Markdown + LaTeX booktabs) from results/*.json.  Re-run after every experiment:
    python paper/make_tables.py
Numbers in the paper must come from here, never typed by hand."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RES, OUT = ROOT / "results", ROOT / "paper"


def _load(name):
    p = RES / name
    return json.load(open(p)) if p.exists() else None


def _f(x, nd=3):
    return "--" if x is None or (isinstance(x, float) and x != x) else (f"{x:.{nd}f}" if isinstance(x, (int, float)) else str(x))


def md_table(header, rows):
    return "\n".join(["| " + " | ".join(header) + " |", "|" + "---|" * len(header)] + ["| " + " | ".join(map(str, r)) + " |" for r in rows])


def tex_table(caption, label, header, rows):
    esc = lambda s: str(s).replace("_", r"\_").replace("%", r"\%").replace("&", r"\&").replace("+-", r"$\pm$")
    body = " \\\\\n".join(" & ".join(esc(c) for c in r) for r in rows)
    return (f"\\begin{{table}}[t]\n\\centering\\small\n\\caption{{{caption}}}\\label{{{label}}}\n\\begin{{tabular}}{{l{'r' * (len(header) - 1)}}}\n\\toprule\n"
            f"{' & '.join(esc(h) for h in header)} \\\\\n\\midrule\n{body} \\\\\n\\bottomrule\n\\end{{tabular}}\n\\end{{table}}\n")


def main():
    md, tex = [], []

    e1 = _load("e1_ablation.json")
    if e1:
        h = ["Variant", "Alerts", "Alert P", "Proc P", "Proc R", "Proc F1", "Step det.", "Tech cov."]
        rows = [[r["variant"], r["alerts"], _f(r["alert_precision"]), _f(r["proc_precision"]), _f(r["proc_recall"]), _f(r["proc_f1"]),
                 _f(r["step_detection"]), _f(r["tech_cov_exact"])] for r in e1["rows"]]
        md += ["## Table 1 - Detection ablation (development scenario)", md_table(h, rows), ""]
        tex.append(tex_table("Detection ablation on the development scenario (rules tuned on this data).", "tab:ablation", h, rows))

    e2 = _load("e2_ml_comparison.json")
    if e2:
        h = ["Protocol", "Model", "ROC-AUC", "PR-AUC", "P@k"]
        rows = [[r["protocol"], r["model"], _f(r["roc_auc"]), _f(r["pr_auc"]), _f(r["precision_at_k"])] for r in e2["results"]]
        md += [f"## Table 2 - ML comparison (random PR-AUC = {e2['random_pr_auc']:.2f})", md_table(h, rows), ""]
        tex.append(tex_table("ML detectors against ground truth at process level.", "tab:ml", h, rows))

    e3, e1m = _load("e3_sigmahq.json"), _load("eval_main.json")
    if e3 and e1m:
        def row(n, r):
            s = r["step_level"]
            return [n, r["alert_level"]["n_alerts"], _f(r["alert_level"]["precision"]), _f(r["process_level"]["recall"]), _f(s["step_detection_rate"]),
                    _f(s["technique_coverage_exact"]["coverage"]), _f(s["technique_coverage_family"]["coverage"])]
        h = ["Rule set", "Alerts", "Alert P", "Proc R", "Step det.", "Tech (exact)", "Tech (family)"]
        rows = [row("Project rules v1 (dev-tuned)", e1m), row("SigmaHQ unmodified", e3)]
        bs = e3.get("baseline_stats", {})
        md += [f"## Table 3 - Project rules vs unmodified SigmaHQ ({bs.get('converted', '?')} of {bs.get('total', '?')} rules convertible)", md_table(h, rows), ""]
        tex.append(tex_table("Project rules vs. unmodified public Sigma rules.", "tab:sigma", h, rows))

    e6 = _load("e6_robustness.json")
    if e6:
        base = e6["baseline (no mutation)"]
        h = ["Mutation", "Proc R", "Delta R", "Step det.", "Delta steps", "Tech cov."]
        rows = [[n, _f(r["proc_recall"]), f"{r['proc_recall'] - base['proc_recall']:+.3f}", _f(r["step_detection"]),
                 f"{r['step_detection'] - base['step_detection']:+.3f}", _f(r["tech_cov_exact"])] for n, r in e6.items()]
        md += ["## Table 4 - Evasion robustness", md_table(h, rows), ""]
        tex.append(tex_table("Detection under evasion mutations.", "tab:robust", h, rows))

    for p in sorted(RES.glob("e8_e9_llm_*.json")):
        d = _load(p.name)
        g = lambda v, k: (f"{d['quality'][v][k]['mean']:.2f}+-{d['quality'][v][k]['std']:.2f}" if k in d["quality"][v] else "--")
        h = ["Context", "Verified", "Grounding", "Req. action R", "Harmful", "Mapping F1"]
        rows = [[v, g(v, "passed"), g(v, "grounding"), g(v, "required_recall"), g(v, "harmful_actions"), g(v, "exact_f1")] for v in d["quality"]]
        md += [f"## Table 5 - LLM analyst: {d['provider']}/{d['model']} ({d['runs']} runs); injection ASR defended={d['injection']['defended']['attack_success_rate']:.2f} raw={d['injection']['raw']['attack_success_rate']:.2f}",
               md_table(h, rows), ""]
        tex.append(tex_table(f"SOC analyst agent ({d['provider']}/{d['model']}).", f"tab:llm-{d['provider']}", h, rows))

    (OUT / "tables.md").write_text("\n".join(md))
    (OUT / "tables.tex").write_text("\n".join(tex))
    print(f"wrote {OUT / 'tables.md'} and tables.tex ({len(md)} blocks)")


if __name__ == "__main__":
    main()

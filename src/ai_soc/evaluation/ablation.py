"""E1 - Detection ablation: which layer buys what?

Variants (all scored by evaluation.eval_detection.evaluate against the same ground truth):
  sigma_only           Sigma-style rules (single-event signatures)
  python_only          behavioural Python rules (need Step-3 correlation: chains / lateral links)
  ml_only              Isolation Forest top-decile process starts (contaminated protocol - the Step-4 default)
  rules_v1             sigma + python
  rules_v1+ml_queue    full Step-4 pipeline (rules + ML review queue + risk fusion)
  rules_v1+v2          + candidate rules written after error analysis (DEV-SET TUNED - do not claim generalisation)
  no_correlation       every raw rule hit is its own alert (workload without Step 3 grouping)

Paired McNemar tests compare each variant against sigma_only on process-level correctness.

    python -m ai_soc.evaluation.ablation
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from ai_soc import config as C
from ai_soc.detection import engine, ml_detection
from ai_soc.evaluation import eval_detection as E
from ai_soc.evaluation.stats import mcnemar_exact


def build_variant(df, rules, lat, sessions, ml, use_sigma=True, use_python=True, ml_queue=False):
    raw, hits, _ = engine.detect_rules(df, rules, lat, use_sigma, use_python)
    alerts = engine.fuse(raw, df, ml) if raw else []
    if ml_queue:
        alerts = engine.fuse(alerts + engine.ml_only_alerts(df, ml, alerts), df, ml)
    incidents = engine.build_incidents(alerts, sessions, lat) if alerts else []
    return [a for a in alerts if a["source"] != "ml"] if not ml_queue else alerts, hits, incidents


def ml_only_variant(df, ml, thr=0.90):
    meta = dict(id="ML-001", title="Isolation Forest anomalous process", tactic="Execution", technique="n/a", level="low", description="")
    top = ml[ml.ml_score >= thr]
    alerts = [engine.make_alert(meta, df[df.event_uid == u], source="ml") for u in top.event_uid]
    for i, a in enumerate(alerts, 1):
        a["alert_id"], a["risk_score"] = f"ML-{i:04d}", float(top.ml_score.iloc[i - 1])
    return alerts, [("ML-001", u) for u in top.event_uid], []


def no_correlation_variant(df, rules, lat):
    """One alert per raw hit event - what the analyst would face without grouping."""
    raw, hits, _ = engine.detect_rules(df, rules, lat)
    meta = {r["id"]: r for r in rules}
    by = {a["rule_id"]: a for a in raw}
    h = pd.DataFrame(hits, columns=["rule_id", "event_uid"]).merge(df[["event_uid", "timestamp", "host"]], on="event_uid")
    alerts = []
    for r in h.itertuples():
        m = meta.get(r.rule_id) or by[r.rule_id]
        alerts.append(dict(alert_id=f"RAW-{len(alerts):05d}", rule_id=r.rule_id, tactic=m["tactic"], technique=m["technique"],
                           host=r.host, first_seen=str(r.timestamp), last_seen=str(r.timestamp), event_uids=[r.event_uid],
                           source="raw", risk_score=0.5))
    return alerts, hits, []


def _process_correct(alerts, df, lab):
    p = df[df.event_type == "process_create"]
    flagged = {u for a in alerts for u in a["event_uids"]}
    keep = [u for u in p.event_uid if lab.get(u) in ("malicious", "background")]
    return np.array([(u in flagged) == (lab[u] == "malicious") for u in keep])


def run():
    df, gt, steps_cfg, st, _, _, _ = E.load_all()
    lab = dict(zip(gt.event_uid, gt.gt_label))
    rules_v1 = engine.sigma_lite.load_rulesets(C.RULES_DIR, ["detection_rules.yml"])
    rules_v2 = engine.sigma_lite.load_rulesets(C.RULES_DIR, ["detection_rules.yml", "candidates_v2.yml"])
    lat, sessions = engine.load_lateral(), json.load(open(C.SESSIONS_JSON))
    ml = ml_detection.score(df)

    variants = {
        "sigma_only": build_variant(df, rules_v1, lat, sessions, ml, use_python=False),
        "python_only": build_variant(df, rules_v1, lat, sessions, ml, use_sigma=False),
        "ml_only": ml_only_variant(df, ml),
        "rules_v1": build_variant(df, rules_v1, lat, sessions, ml),
        "rules_v1+ml_queue": build_variant(df, rules_v1, lat, sessions, ml, ml_queue=True),
        "rules_v1+v2 (dev-tuned)": build_variant(df, rules_v2, lat, sessions, ml),
        "no_correlation (raw hits)": no_correlation_variant(df, rules_v1, lat),
    }
    results, rows, correct = {}, [], {}
    for name, (alerts, hits, incidents) in variants.items():
        r = E.evaluate(alerts, hits, incidents, df, gt, steps_cfg, st, name=name)
        results[name] = r
        correct[name] = _process_correct(alerts, df, lab)
        row = E.summarize_row(r)
        row.update(groups=r["workload"]["alert_groups"], incidents=r["workload"]["incidents"])
        rows.append(row)
    tests = {n: mcnemar_exact(correct[n], correct["sigma_only"]) for n in correct if n != "sigma_only"}
    C.RESULTS_DIR.mkdir(exist_ok=True)
    json.dump(dict(rows=rows, mcnemar_vs_sigma_only=tests, details=results), open(C.RESULTS_DIR / "e1_ablation.json", "w"), indent=1, default=str)
    f = lambda x: "n/a" if x is None or x != x else f"{x:.3f}"
    L = ["# E1 - Detection ablation vs ground truth (development scenario)", "",
         "| variant | alerts | groups | incidents | alert prec. | proc prec. | proc recall | proc F1 | step detection | tech cov (exact/family) | median TTD s |",
         "|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['variant']} | {r['alerts']} | {r['groups']} | {r['incidents']} | {f(r['alert_precision'])} | {f(r['proc_precision'])} | {f(r['proc_recall'])} | {f(r['proc_f1'])} | {f(r['step_detection'])} | {f(r['tech_cov_exact'])} / {f(r['tech_cov_family'])} | {f(r['median_ttd_s'])} |")
    L += ["", "McNemar exact test vs sigma_only (process-level correctness, paired):", ""]
    L += [f"- {n}: only-variant-correct {t['only_a']}, only-sigma-correct {t['only_b']}, p = {t['p_value']:.4f}" for n, t in tests.items()]
    L += ["", "*Rules were written on this scenario: treat as development numbers. `rules_v1+v2` was additionally tuned after error analysis.*"]
    (C.REPORT_DIR / "e1_ablation.md").write_text("\n".join(L))
    print("\n".join(L))
    return results


if __name__ == "__main__":
    run()

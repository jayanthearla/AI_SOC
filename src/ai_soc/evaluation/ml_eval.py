"""ML evaluation against ground truth (process level) - replaces the old "agreement with rules" check.

Protocols
  A. baseline_contaminated : Isolation Forest fitted on ALL process starts (what Step 4 does today). The attack is
                             ~1/3 of the data, violating the "anomalies are rare" assumption.
  B. benign_crossfit       : novelty detectors fitted ONLY on proxy-benign (background) process starts, K-fold
                             cross-fitted so no benign sample is scored by a model that saw it; malicious samples are
                             never in training.  This simulates having a benign baseline (real deployment).
  C. supervised_group_cv   : RF / GB / LR (/ XGBoost) with StratifiedGroupKFold grouped by process chain, so one chain
                             never straddles train and test.  Scenario-level generalisation still needs a 2nd dataset.

Caveat to put in the paper: 'background' = assumed benign; features are computed over the whole data set (rarity
statistics); n is small (308 process starts).  Treat as a pilot; confirm on held-out scenarios.

    python -m ai_soc.evaluation.ml_eval
"""
from __future__ import annotations

import json
import warnings

import numpy as np
import pandas as pd
from sklearn.model_selection import KFold, StratifiedGroupKFold

from ai_soc import config as C
from ai_soc.detection import engine, ml_detection, ml_models
from ai_soc.evaluation import metrics as M
from ai_soc.evaluation.stats import bootstrap_ci


warnings.filterwarnings("ignore")


def _prep():
    df = engine.load()
    gt = pd.read_csv(C.GT_CSV, dtype=str).fillna("")
    lab = dict(zip(gt.event_uid, gt.gt_label))
    p, X = ml_detection.build_matrix(df)
    p = p.assign(label=p.event_uid.map(lab))
    keep = (p.label != "ambiguous").values
    p, X = p[keep].reset_index(drop=True), X[keep].reset_index(drop=True)
    y = (p.label == "malicious").astype(int).values
    return p, X.values, y


def _metrics(name, y, s, protocol):
    k = int(y.sum())
    roc, rlo, rhi = bootstrap_ci(M.roc_auc, y, s, n=300)
    pra, plo, phi = bootstrap_ci(M.pr_auc, y, s, n=300)
    return dict(model=name, protocol=protocol, n=len(y), n_malicious=k, prevalence=float(y.mean()),
                roc_auc=roc, roc_auc_ci95=[rlo, rhi], pr_auc=pra, pr_auc_ci95=[plo, phi],
                precision_at_k=M.precision_at_k(y, s, k), recall_at_10pct=M.recall_at_k(y, s, max(1, int(0.1 * len(y)))),
                precision_at_15=M.precision_at_k(y, s, 15))


def baseline_contaminated(X, y, seed=42):
    rows = []
    for name, cls in ml_models.UNSUPERVISED.items():
        s = cls(seed).fit(X).score(X)                       # fitted on everything (attack included)
        rows.append(_metrics(name, y, s, "A: fit on all (contaminated)"))
    return rows


def benign_crossfit(X, y, k=5, seed=42):
    rows = []
    ben_idx = np.where(y == 0)[0]
    mal_idx = np.where(y == 1)[0]
    kf = KFold(k, shuffle=True, random_state=seed)
    for name, cls in ml_models.UNSUPERVISED.items():
        score = np.zeros(len(y))
        mal_scores = []
        for tr, te in kf.split(ben_idx):
            m = cls(seed).fit(X[ben_idx[tr]])
            score[ben_idx[te]] = m.score(X[ben_idx[te]])
            mal_scores.append(m.score(X[mal_idx]))
        score[mal_idx] = np.mean(mal_scores, axis=0)
        rows.append(_metrics(name, y, score, "B: benign-only cross-fit"))
    return rows


def supervised_group_cv(p, X, y, k=5, seed=42):
    groups = p.chain_id.replace("", "none").values
    cv = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    rows = []
    for name, model in ml_models.supervised_models(seed).items():
        s = np.zeros(len(y))
        for tr, te in cv.split(X, y, groups):
            if y[tr].sum() == 0:
                continue
            from sklearn.base import clone
            m = clone(model).fit(X[tr], y[tr])
            s[te] = m.predict_proba(X[te])[:, 1]
        rows.append(_metrics(name, y, s, "C: supervised, group CV by chain"))
    return rows


def run():
    p, X, y = _prep()
    rows = baseline_contaminated(X, y) + benign_crossfit(X, y) + supervised_group_cv(p, X, y)
    # repeat the cheap protocols over seeds for variance
    seeds = {}
    for sd in (1, 2, 3, 4, 5):
        for r in benign_crossfit(X, y, seed=sd):
            seeds.setdefault(r["model"], []).append(r["pr_auc"])
    stab = {m: dict(mean=float(np.mean(v)), std=float(np.std(v, ddof=1))) for m, v in seeds.items()}
    out = dict(n_process_creates=len(y), n_malicious=int(y.sum()), random_pr_auc=float(y.mean()),
               results=rows, benign_crossfit_pr_auc_over_5_seeds=stab)
    C.RESULTS_DIR.mkdir(exist_ok=True)
    json.dump(out, open(C.RESULTS_DIR / "e2_ml_comparison.json", "w"), indent=1)
    f = lambda x: f"{x:.3f}"
    max_r = max(1, int(0.1 * len(y))) / max(int(y.sum()), 1)
    L = ["# E2 - ML comparison vs ground truth (process level)", "",
         f"n = {len(y)} process starts, {int(y.sum())} malicious (prevalence {y.mean():.2f} = PR-AUC of a random scorer).",
         "", "> Protocol A is the Step-4 setup (fit on everything). B/C use ground-truth-derived training sets. Caveats: 'background' is only assumed benign; rarity features use the whole data set; one scenario, n=303.",
         "", "| protocol | model | ROC-AUC (95% CI) | PR-AUC (95% CI) | P@k | recall@10% (max " + f"{max_r:.3f}" + ") |", "|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['protocol']} | {r['model']} | {f(r['roc_auc'])} ({f(r['roc_auc_ci95'][0])}-{f(r['roc_auc_ci95'][1])}) | {f(r['pr_auc'])} ({f(r['pr_auc_ci95'][0])}-{f(r['pr_auc_ci95'][1])}) | {f(r['precision_at_k'])} | {f(r['recall_at_10pct'])} |")
    L += ["", "Benign-only cross-fit PR-AUC over 5 seeds: " + ", ".join(f"{m} {v['mean']:.3f}+-{v['std']:.3f}" for m, v in stab.items())]
    (C.REPORT_DIR / "e2_ml_comparison.md").write_text("\n".join(L))
    print("\n".join(L))
    return out


if __name__ == "__main__":
    run()

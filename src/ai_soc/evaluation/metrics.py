"""Metric library used by every experiment (detection, correlation, calibration, LLM).  Pure functions, no I/O."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else float("nan")
    r = tp / (tp + fn) if tp + fn else float("nan")
    f = 2 * p * r / (p + r) if p == p and r == r and p + r else float("nan")
    return dict(tp=int(tp), fp=int(fp), fn=int(fn), precision=p, recall=r, f1=f)


def prf_sets(pred: set, true: set, universe: set | None = None) -> dict:
    """Set-based P/R/F1.  If `universe` is given, both sets are intersected with it first."""
    if universe is not None:
        pred, true = pred & universe, true & universe
    return prf(len(pred & true), len(pred - true), len(true - pred))


def pr_auc(y_true, score) -> float:
    y = np.asarray(y_true)
    return float(average_precision_score(y, score)) if 0 < y.sum() < len(y) else float("nan")


def roc_auc(y_true, score) -> float:
    y = np.asarray(y_true)
    return float(roc_auc_score(y, score)) if 0 < y.sum() < len(y) else float("nan")


def precision_at_k(y_true, score, k: int) -> float:
    idx = np.argsort(-np.asarray(score))[:k]
    return float(np.asarray(y_true)[idx].mean())


def recall_at_k(y_true, score, k: int) -> float:
    y = np.asarray(y_true)
    idx = np.argsort(-np.asarray(score))[:k]
    return float(y[idx].sum() / y.sum()) if y.sum() else float("nan")


def brier(y_true, p) -> float:
    return float(np.mean((np.asarray(p, float) - np.asarray(y_true, float)) ** 2))


def ece(y_true, p, bins: int = 10) -> float:
    """Expected calibration error (equal-width bins)."""
    y, p = np.asarray(y_true, float), np.asarray(p, float)
    idx = np.clip((p * bins).astype(int), 0, bins - 1)
    e = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            e += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(e)


def reliability_table(y_true, p, bins: int = 10) -> list[dict]:
    y, p = np.asarray(y_true, float), np.asarray(p, float)
    idx = np.clip((p * bins).astype(int), 0, bins - 1)
    return [dict(bin=b, n=int((idx == b).sum()), mean_pred=float(p[idx == b].mean()), frac_pos=float(y[idx == b].mean()))
            for b in range(bins) if (idx == b).any()]


def family(t: str) -> str:
    """T1059.005 -> T1059"""
    return t.split(".")[0]


def technique_coverage(alert_techs, gt_techs, family_level: bool = False) -> dict:
    gt = {family(t) if family_level else t for t in gt_techs}
    al = {family(t) if family_level else t for t in alert_techs if t and t != "n/a"}
    hit = gt & al
    return dict(coverage=len(hit) / len(gt) if gt else float("nan"), detected=sorted(hit), missed=sorted(gt - al),
                extra=sorted(al - gt))


def time_to_detect(alert_ts, gt_step_ts) -> float:
    """Seconds from the first ground-truth event of a step to the first matching alert (negative = alert earlier)."""
    return float((alert_ts - gt_step_ts).total_seconds())


def kendall_tau(order_pred: list, order_true: list) -> float:
    """Rank agreement between two orderings over their common items (1 = identical, -1 = reversed)."""
    from scipy.stats import kendalltau
    common = [x for x in order_true if x in order_pred]
    if len(common) < 2:
        return float("nan")
    return float(kendalltau([order_pred.index(x) for x in common], [order_true.index(x) for x in common])[0])


def reduction_ratio(n_in: int, n_out: int) -> float:
    return 1 - n_out / n_in if n_in else float("nan")

"""Statistical helpers: bootstrap confidence intervals and McNemar's exact test for paired detectors."""
from __future__ import annotations

import numpy as np


def bootstrap_ci(metric, *arrays, n: int = 1000, alpha: float = 0.05, seed: int = 0):
    """Percentile bootstrap CI.  `metric(*resampled_arrays)` -> float.  Returns (point, lo, hi)."""
    rng = np.random.default_rng(seed)
    arrays = [np.asarray(a) for a in arrays]
    N = len(arrays[0])
    point = metric(*arrays)
    vals = []
    for _ in range(n):
        idx = rng.integers(0, N, N)
        try:
            v = metric(*[a[idx] for a in arrays])
        except Exception:
            continue
        if v == v:
            vals.append(v)
    if not vals:
        return point, float("nan"), float("nan")
    return float(point), float(np.quantile(vals, alpha / 2)), float(np.quantile(vals, 1 - alpha / 2))


def mcnemar_exact(correct_a, correct_b) -> dict:
    """Exact McNemar test on paired boolean outcomes (detector A vs B on the same items)."""
    from scipy.stats import binomtest
    a, b = np.asarray(correct_a, bool), np.asarray(correct_b, bool)
    only_a, only_b = int((a & ~b).sum()), int((~a & b).sum())
    n = only_a + only_b
    p = binomtest(only_a, n, 0.5).pvalue if n else 1.0
    return dict(only_a=only_a, only_b=only_b, discordant=n, p_value=float(p))


def mean_std(values) -> dict:
    v = np.asarray(values, float)
    return dict(mean=float(v.mean()), std=float(v.std(ddof=1)) if len(v) > 1 else 0.0, n=int(len(v)))

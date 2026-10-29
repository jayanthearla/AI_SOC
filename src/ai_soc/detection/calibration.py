"""Risk-score calibration.  The fused `risk_score` is a heuristic (rule level + peers + 0.1 x ML percentile); it is NOT
a probability.  Before the paper (or the LLM prompt) calls it "87% risk", fit a calibrator on labelled alerts and report
Brier / ECE / reliability.  Needs enough negatives - see evaluation/calibration_eval.py."""
from __future__ import annotations

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold


class RiskCalibrator:
    def __init__(self, method: str = "isotonic"):
        self.method = method

    def fit(self, scores, y):
        s = np.asarray(scores, float)
        if self.method == "isotonic":
            self.m = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(s, y)
        else:                                               # Platt scaling
            self.m = LogisticRegression().fit(s.reshape(-1, 1), y)
        return self

    def predict(self, scores):
        s = np.asarray(scores, float)
        return self.m.predict(s) if self.method == "isotonic" else self.m.predict_proba(s.reshape(-1, 1))[:, 1]


def cross_val_calibrate(scores, y, method="isotonic", k=5, seed=0):
    """Out-of-fold calibrated probabilities (never scores a sample with a calibrator that saw it)."""
    s, y = np.asarray(scores, float), np.asarray(y, int)
    k = max(2, min(k, int(y.sum()), int((1 - y).sum())))
    out = np.zeros(len(s))
    for tr, te in StratifiedKFold(k, shuffle=True, random_state=seed).split(s, y):
        out[te] = RiskCalibrator(method).fit(s[tr], y[tr]).predict(s[te])
    return out

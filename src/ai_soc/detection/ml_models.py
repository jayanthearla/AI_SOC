"""ML model zoo for process-behaviour scoring (Step 4, ML layer).

Unsupervised / novelty detectors expose  fit(X_benign)  and  score(X) -> higher = more anomalous.
Supervised classifiers expose            fit(X, y)       and  score(X) -> P(malicious).

Feature matrix comes from ml_detection.build_matrix (rule flags are deliberately excluded so the ML layer is an
independent second opinion).  Protocols that avoid train/test leakage live in evaluation/ml_eval.py.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM


class _Unsup:
    name = "base"

    def __init__(self, seed=42):
        self.seed = seed
        self.scaler = StandardScaler()

    def fit(self, X):
        self.scaler.fit(X)
        self._fit(self.scaler.transform(X))
        return self

    def score(self, X):
        return np.asarray(self._score(self.scaler.transform(X)), float)


class IForest(_Unsup):
    name = "isolation_forest"

    def _fit(self, X):
        self.m = IsolationForest(n_estimators=300, contamination="auto", random_state=self.seed).fit(X)

    def _score(self, X):
        return -self.m.score_samples(X)


class LOF(_Unsup):
    name = "local_outlier_factor"

    def _fit(self, X):
        self.m = LocalOutlierFactor(n_neighbors=min(20, max(2, len(X) - 1)), novelty=True).fit(X)

    def _score(self, X):
        return -self.m.score_samples(X)


class OCSVM(_Unsup):
    name = "one_class_svm"

    def _fit(self, X):
        self.m = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05).fit(X)

    def _score(self, X):
        return -self.m.score_samples(X)


class Autoencoder(_Unsup):
    """Tiny MLP autoencoder; anomaly score = reconstruction error."""
    name = "autoencoder"

    def _fit(self, X):
        self.m = MLPRegressor(hidden_layer_sizes=(8, 3, 8), max_iter=800, random_state=self.seed).fit(X, X)

    def _score(self, X):
        return ((self.m.predict(X) - X) ** 2).mean(axis=1)


UNSUPERVISED = {c.name: c for c in (IForest, LOF, OCSVM, Autoencoder)}


def supervised_models(seed=42):
    out = {
        "random_forest": RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=seed),
        "gradient_boosting": GradientBoostingClassifier(random_state=seed),
        "logistic_regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
    }
    try:                                       # optional dependency (pip install xgboost)
        from xgboost import XGBClassifier
        out["xgboost"] = XGBClassifier(n_estimators=200, max_depth=3, learning_rate=0.1, eval_metric="logloss", random_state=seed)
    except Exception:
        pass
    return out

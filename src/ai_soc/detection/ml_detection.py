"""
ML component of Step 4 - unsupervised anomaly detection on process creation.

Model: Isolation Forest (scikit-learn).  Why unsupervised?  This dataset has NO per-event
attack labels, so a supervised model (Random Forest / XGBoost) would have nothing honest to
learn from.  Isolation Forest learns "what normal process starts look like" on these hosts and
scores how unusual each one is.

Features (deliberately NOT the rule flags, so ML is an independent second opinion):
  cmd_len, cmd_n_args, cmd_entropy        -> long / high-entropy command lines
  pair_rarity, proc_rarity                -> -log frequency of (parent -> child) pair and of child image
  depth                                   -> position in the process chain
  in_user_path, is_system, hour           -> where / who / when
  integrity_ord                           -> Low/Medium/High/System

Output: DataFrame(event_uid, ml_score in [0,1])  (1 = most anomalous, percentile-ranked)
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

FEATURES = ["cmd_len", "cmd_n_args", "cmd_entropy", "pair_rarity", "proc_rarity",
            "depth", "in_user_path", "is_system", "hour", "integrity_ord"]
INTEGRITY = {"Low": 0, "Medium": 1, "High": 2, "System": 3}


def build_matrix(df):
    p = df[df.event_type == "process_create"].copy()
    pair = p.parent_process + ">" + p.process
    p["pair_rarity"] = -np.log(pair.map(pair.value_counts()) / len(p))
    p["proc_rarity"] = -np.log(p.process.map(p.process.value_counts()) / len(p))
    p["depth"] = pd.to_numeric(p.proc_depth, errors="coerce").fillna(0)
    p["in_user_path"] = p.f_user_writable_path.astype(int)
    p["is_system"] = p.f_system_user.astype(int)
    p["integrity_ord"] = p.integrity_level.map(INTEGRITY).fillna(1)
    X = p[FEATURES].astype(float)
    return p, X


def score(df, seed=42):
    p, X = build_matrix(df)
    Xs = StandardScaler().fit_transform(X)
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(Xs)
    raw = -iso.score_samples(Xs)                      # higher = more anomalous
    out = pd.DataFrame({"event_uid": p.event_uid.values, "ml_raw": raw})
    out["ml_score"] = out.ml_raw.rank(pct=True).round(4)   # percentile 0..1
    return out


if __name__ == "__main__":
    from ai_soc import config as C
    from ai_soc.detection.engine import load
    s = score(load())
    s.to_csv(C.ML_SCORES_CSV, index=False)
    print(s.sort_values("ml_score", ascending=False).head(10))

"""E5 - Is the risk score calibrated?  Brier, ECE and reliability table for raw vs cross-validated calibrated scores.
Refuses to fit a calibrator when there are too few negatives (the honest outcome on the development scenario, where
the rule alerts are ~all true positives): collect labelled FP/TP alerts from held-out datasets first."""
from __future__ import annotations

import json

import numpy as np

from ai_soc import config as C
from ai_soc.detection.calibration import cross_val_calibrate
from ai_soc.evaluation import eval_detection as E
from ai_soc.evaluation import metrics as M


def run(min_per_class: int = 5):
    df, gt, steps_cfg, st, alerts, incidents, hits = E.load_all()
    lab = dict(zip(gt.event_uid, gt.gt_label))
    v = E.alert_verdicts(alerts, lab, steps_cfg)
    keep = [(a["risk_score"], x["verdict"] == "TP") for a, x in zip(alerts, v) if x["verdict"] != "UNVERIFIABLE"]
    s, y = np.array([k[0] for k in keep]), np.array([int(k[1]) for k in keep])
    out = dict(n_alerts=len(y), n_pos=int(y.sum()), n_neg=int((1 - y).sum()), raw=dict(brier=M.brier(y, s), ece=M.ece(y, s),
               reliability=M.reliability_table(y, s)))
    if min(out["n_pos"], out["n_neg"]) >= min_per_class:
        for meth in ("isotonic", "platt"):
            c = cross_val_calibrate(s, y, meth)
            out[meth] = dict(brier=M.brier(y, c), ece=M.ece(y, c))
    else:
        out["note"] = (f"calibrator NOT fitted: need >= {min_per_class} positives and negatives (have {out['n_pos']}/{out['n_neg']}). "
                       "Label alerts from held-out scenarios / benign data first; until then do not describe risk_score as a probability.")
    C.RESULTS_DIR.mkdir(exist_ok=True)
    json.dump(out, open(C.RESULTS_DIR / "e5_calibration.json", "w"), indent=1)
    print(json.dumps({k: v for k, v in out.items() if k != "raw"}, indent=1), "\nraw:", out["raw"]["brier"], out["raw"]["ece"])
    return out


if __name__ == "__main__":
    run()

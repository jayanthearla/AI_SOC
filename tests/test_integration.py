"""Run against the real pipeline outputs (skipped when outputs/ has not been generated)."""
import json

import pytest

from ai_soc import config as C

pytestmark = pytest.mark.skipif(not C.ALERTS_JSON.exists() or not C.GT_CSV.exists(), reason="run the pipeline + labels first")


def test_alert_contract_validates():
    from ai_soc.contracts import Alert, Incident
    for a in json.load(open(C.ALERTS_JSON)):
        Alert(**a)
    for i in json.load(open(C.INCIDENTS_JSON)):
        Incident(**i)


def test_main_evaluation_sanity():
    from ai_soc.evaluation import eval_detection as E
    df, gt, steps_cfg, st, alerts, incidents, hits = E.load_all()
    r = E.evaluate([a for a in alerts if a["source"] != "ml"], hits, incidents, df, gt, steps_cfg, st)
    assert r["alert_level"]["precision"] > 0.9
    assert r["step_level"]["step_detection_rate"] == 1.0
    assert r["workload"]["incidents"] == 1
    assert (st.n_malicious_events > 0).all()                 # every annotated step has events in the data


def test_ground_truth_class_counts():
    import pandas as pd
    gt = pd.read_csv(C.GT_CSV, dtype=str)
    assert (gt.gt_label == "benign").sum() == 831             # pre-attack window
    assert set(gt.gt_label) == {"malicious", "benign", "ambiguous", "background"}


def test_mock_analyst_end_to_end():
    from ai_soc.agents import analyst
    from ai_soc.contracts import EnrichedAlert, Incident
    if not C.ENRICHED_JSON.exists():
        pytest.skip("run intel stage")
    inc = Incident(**json.load(open(C.INCIDENTS_JSON))[0])
    enr = [EnrichedAlert(**e) for e in json.load(open(C.ENRICHED_JSON))]
    from ai_soc.agents.llm_client import make_client
    rep, ver, ctx, st = analyst.analyse(inc, enr, make_client("mock"))
    assert rep is not None and ver["passed"]

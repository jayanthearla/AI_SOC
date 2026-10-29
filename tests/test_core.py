import json

import numpy as np
import pandas as pd
import pytest

from ai_soc.detection import sigma_lite
from ai_soc.detection.dedup import group_alerts
from ai_soc.evaluation import metrics as M
from ai_soc.evaluation.baselines import sigmahq as S
from ai_soc.labels import ground_truth as G
from tests.conftest import make_events


# ---------------------------------------------------------------- sigma_lite
def test_sigma_lite_conditions(events):
    rule = dict(id="T-1", logsource={"event_type": "process_create"},
                detection=dict(sel=dict(process=["powershell.exe", "wscript.exe"]), flt={"command_line|contains": "autoupdate"}, condition="sel and not flt"))
    m = sigma_lite.run_rules(events, [rule])["T-1"]
    assert list(events[m].event_uid) == ["E3"]


def test_sigma_lite_one_of_and_regex(events):
    rule = dict(id="T-2", logsource={"event_type": "process_create"},
                detection={"selection_a": {"process": "wscript.exe"}, "selection_b": {"command_line|re": r"autoupdate\.vbs"}, "condition": "1 of selection_*"})
    assert list(events[sigma_lite.run_rules(events, [rule])["T-2"]].event_uid) == ["E2"]


# ---------------------------------------------------------------- SigmaHQ converter
def _rule(det, cat="process_creation", **kw):
    return dict(id="abcdef12-0000", title="t", level="high", tags=["attack.execution", "attack.t1059.001"], logsource=dict(category=cat, product="windows"), detection=det, **kw)


def test_converter_basic_and_tags():
    r = S.convert_rule(_rule({"selection": {"Image|endswith": "\\powershell.exe", "CommandLine|contains|all": ["-enc", "-nop"]}, "condition": "selection"}))
    assert r["technique"] == "T1059.001" and r["tactic"] == "Execution" and r["logsource"]["event_type"] == "process_create"
    assert r["detection"]["selection"]["command_line|contains_all"] == ["-enc", "-nop"]


def test_converter_list_of_maps_and_wildcards():
    r = S.convert_rule(_rule({"selection": [{"Image|endswith": "\\a.exe"}, {"CommandLine": "*evil*"}], "condition": "selection"}))
    assert "selection__0" in r["detection"] and "selection__1" in r["detection"]
    assert r["detection"]["condition"] == "(selection__0 or selection__1)"
    assert r["detection"]["selection__1"]["command_line|re"] == "^.*evil.*$"


def test_converter_skips_unsupported():
    with pytest.raises(S.Skip):
        S.convert_rule(_rule({"selection": {"CommandLine|base64offset|contains": "x"}, "condition": "selection"}))
    with pytest.raises(S.Skip):
        S.convert_rule(_rule({"selection": {"CommandLine|contains": "x"}, "condition": "selection | count() > 3"}))
    with pytest.raises(S.Skip):
        S.convert_rule(_rule({"selection": {"CommandLine|contains": "x"}, "condition": "selection"}, cat="driver_load"))


def test_converted_rule_executes(events):
    r = S.convert_rule(_rule({"selection": {"Image|endswith": "wscript.exe"}, "condition": "selection"}))
    events["process_path"] = "C:\\Windows\\System32\\" + events.process
    assert list(events[sigma_lite.run_rules(events, [r])[r["id"]]].event_uid) == ["E2"]


# ---------------------------------------------------------------- ground truth
def test_ground_truth_lineage_scope_and_windows(events):
    cfg = dict(attack_start_utc="2019-05-14T22:30:00+00:00",
               lineage_seeds=[dict(id="S", match={"event_type": "process_create", "process": "wscript.exe"})],
               scope_rules=[dict(id="PS", event_types=["ps_scriptblock"], **{"from": "first_seed_on_host"})], selectors=[], ambiguous=[])
    gt = G.build_labels(events, cfg).set_index("event_uid").gt_label
    assert gt["E1"] == "benign"                                  # before attack start
    assert gt["E2"] == gt["E3"] == gt["E4"] == "malicious"       # seed, child, child's network event
    assert gt["E5"] == "background"                              # in-window, unrelated
    assert gt["E6"] == "malicious"                               # PowerShell log after first seed on host


# ---------------------------------------------------------------- metrics / dedup
def test_metrics():
    assert M.prf(8, 2, 2)["f1"] == pytest.approx(0.8)
    assert M.ece([1, 1, 0, 0], [1.0, 1.0, 0.0, 0.0]) == 0
    assert M.precision_at_k([1, 0, 1, 0], [0.9, 0.8, 0.7, 0.1], 2) == 0.5
    assert M.kendall_tau(["a", "b", "c"], ["a", "b", "c"]) == pytest.approx(1.0)
    assert M.kendall_tau(["c", "b", "a"], ["a", "b", "c"]) == pytest.approx(-1.0)
    assert M.technique_coverage({"T1059"}, {"T1059.001"}, family_level=True)["coverage"] == 1.0
    assert M.technique_coverage({"T1059"}, {"T1059.001"})["coverage"] == 0.0


def test_dedup_merges_alerts_sharing_events():
    a = [dict(alert_id="A1", rule_id="R1", host="H", chain_id="c", first_seen="2019-05-14 22:00:00", event_uids=["E1", "E2"], risk_score=.5),
         dict(alert_id="A2", rule_id="R2", host="H", chain_id="c", first_seen="2019-05-14 22:10:00", event_uids=["E2"], risk_score=.9),
         dict(alert_id="A3", rule_id="R3", host="H", chain_id="d", first_seen="2019-05-14 23:00:00", event_uids=["E9"], risk_score=.1)]
    g = group_alerts(a)
    assert len(g) == 2 and g[0]["n_alerts"] == 2

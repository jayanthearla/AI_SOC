"""Main detection / correlation evaluation against the ground truth (labels/).

`evaluate()` is the single scoring function reused by the ablation, SigmaHQ baseline, robustness and held-out
experiments, so every variant is judged by exactly the same rules.

Reported views (each answers a different question - do not mix them up in the paper):
  * alert level     - is each alert backed by attacker activity?  (analyst-facing precision)
  * process level   - of 308 process starts, which did the detector flag?  (the fairest P/R: ~2/3 are plain OS background)
  * step level      - was each annotated attack action detected (tactic+window match)? technique recall, time-to-detect
  * event level     - supplementary; recall here is dominated by 35k PowerShell log lines and 3k beacon connections
  * workload        - events -> raw hits -> alerts -> alert groups -> incidents
  * incident level  - fragmentation, tactic coverage, kill-chain ordering (Kendall tau)

    python -m ai_soc.evaluation.eval_detection
"""
from __future__ import annotations

import json

import numpy as np
import pandas as pd

from ai_soc import config as C
from ai_soc.detection.dedup import dedup_ratio
from ai_soc.evaluation import metrics as M
from ai_soc.evaluation.stats import bootstrap_ci
from ai_soc.labels import ground_truth as G


# ------------------------------------------------------------------ helpers
def _label_map(gt):
    return dict(zip(gt.event_uid, gt.gt_label))


def _matches_step(a, steps_cfg):
    """Fallback for alerts that carry no event ids (e.g. lateral-spread alerts built from the lateral-link table):
    TP if the alert's host, tactic and time overlap an annotated attack step."""
    day, tol = steps_cfg["date"], pd.Timedelta(seconds=steps_cfg.get("tolerance_seconds", 30))
    for s in steps_cfg["steps"]:
        t0, t1 = pd.Timestamp(f"{day} {s['start']}", tz="UTC"), pd.Timestamp(f"{day} {s['end']}", tz="UTC")
        if (a["host"] == s["host"] and a["tactic"] in s["tactics"]
                and pd.Timestamp(a["first_seen"]) <= t1 + tol and pd.Timestamp(a["last_seen"]) >= t0 - tol):
            return True
    return False


def alert_verdicts(alerts, lab, steps_cfg=None):
    """TP = at least one malicious event (or, for event-less alerts, a matching annotated step);
    FP = events but none malicious/ambiguous; UNVERIFIABLE = only ambiguous."""
    out = []
    for a in alerts:
        c = pd.Series([lab.get(u, "background") for u in a["event_uids"]]).value_counts().to_dict()
        if not a["event_uids"] and steps_cfg is not None:
            c = {"malicious": 1} if _matches_step(a, steps_cfg) else {"background": 1}
        if c.get("malicious", 0):
            v = "TP"
        elif c.get("ambiguous", 0) and not (c.get("background", 0) + c.get("benign", 0)):
            v = "UNVERIFIABLE"
        else:
            v = "FP"
        out.append(dict(alert_id=a.get("alert_id", ""), rule_id=a["rule_id"], verdict=v, host=a["host"],
                        n_events=len(a["event_uids"]), malicious=c.get("malicious", 0), background=c.get("background", 0),
                        benign=c.get("benign", 0), ambiguous=c.get("ambiguous", 0)))
    return out


def _alert_level(alerts, lab, steps_cfg=None):
    v = alert_verdicts(alerts, lab, steps_cfg)
    tp = sum(x["verdict"] == "TP" for x in v)
    fp = sum(x["verdict"] == "FP" for x in v)
    unv = sum(x["verdict"] == "UNVERIFIABLE" for x in v)
    arr = np.array([x["verdict"] == "TP" for x in v if x["verdict"] != "UNVERIFIABLE"], float)
    res = dict(n_alerts=len(alerts), tp=tp, fp=fp, unverifiable=unv, precision=tp / (tp + fp) if tp + fp else float("nan"))
    if len(arr) >= 5:
        _, lo, hi = bootstrap_ci(np.mean, arr, n=500)
        res["precision_ci95"] = [lo, hi]
    res["false_positive_alerts"] = [x for x in v if x["verdict"] == "FP"]
    return res, v


def _process_level(alerts, df, lab):
    p = df[df.event_type == "process_create"]
    flagged = {u for a in alerts for u in a["event_uids"]}
    rows = [(lab.get(u, "background"), u in flagged) for u in p.event_uid]
    lbl = np.array([r[0] for r in rows])
    pred = np.array([r[1] for r in rows])
    mal, bg = lbl == "malicious", lbl == "background"
    keep = lbl != "ambiguous"
    res = M.prf(int((pred & mal).sum()), int((pred & bg).sum()), int((~pred & mal).sum()))
    res.update(n_process_creates=len(p), n_malicious=int(mal.sum()), n_background_assumed_benign=int(bg.sum()),
               n_ambiguous_excluded=int((~keep).sum()),
               missed_malicious=p.loc[(mal & ~pred), ["event_uid", "timestamp", "host", "process", "command_line"]]
               .assign(command_line=lambda x: x.command_line.str[:90]).to_dict("records"),
               flagged_background=p.loc[(bg & pred), ["event_uid", "timestamp", "host", "process", "command_line"]]
               .assign(command_line=lambda x: x.command_line.str[:90]).to_dict("records"))
    return res


def _event_level(alerts, gt):
    flagged = {u for a in alerts for u in a["event_uids"]}
    g = gt[gt.gt_label.isin(["malicious", "benign", "background"])]
    pred = g.event_uid.isin(flagged).values
    lab = g.gt_label.values
    out = {}
    for name, mask in [("all_event_types", np.ones(len(g), bool)), ("excluding_network_connect", (g.event_type != "network_connect").values)]:
        mal, bg, bn = (lab == "malicious") & mask, (lab == "background") & mask, (lab == "benign") & mask
        out[name] = dict(assumed=M.prf(int((pred & mal).sum()), int((pred & (bg | bn)).sum()), int((~pred & mal).sum())),
                         strict_flagged_pre_attack_benign=int((pred & bn).sum()), n_pre_attack_benign=int(bn.sum()))
    return out


def _step_level(alerts, steps_cfg, st):
    day, tol = steps_cfg["date"], pd.Timedelta(seconds=steps_cfg.get("tolerance_seconds", 30))
    rows = []
    for s, r in zip(steps_cfg["steps"], st.itertuples()):
        t0, t1 = pd.Timestamp(f"{day} {s['start']}", tz="UTC"), pd.Timestamp(f"{day} {s['end']}", tz="UTC")
        hits = [a for a in alerts if a["host"] == s["host"] and a["tactic"] in s["tactics"]
                and pd.Timestamp(a["first_seen"]) <= t1 + tol and pd.Timestamp(a["last_seen"]) >= t0 - tol]
        techs = {a["technique"] for a in hits}
        ex, fam = M.technique_coverage(techs, s["techniques"]), M.technique_coverage(techs, s["techniques"], True)
        ttd = M.time_to_detect(min(pd.Timestamp(a["first_seen"]) for a in hits), r.gt_first_event) if hits and pd.notna(r.gt_first_event) else None
        rows.append(dict(step=s["id"], name=s["name"], host=s["host"], detected=bool(hits), n_alerts=len(hits),
                         technique_exact=ex["coverage"], technique_family=fam["coverage"], missed_techniques=ex["missed"],
                         ttd_seconds=ttd))
    det = [r["detected"] for r in rows]
    ttds = [r["ttd_seconds"] for r in rows if r["ttd_seconds"] is not None]
    all_gt = {t for s in steps_cfg["steps"] for t in s["techniques"]}
    all_alert = {a["technique"] for a in alerts}
    return dict(steps=rows, step_detection_rate=float(np.mean(det)),
                technique_coverage_exact=M.technique_coverage(all_alert, all_gt),
                technique_coverage_family=M.technique_coverage(all_alert, all_gt, True),
                median_ttd_seconds=float(np.median(ttds)) if ttds else None,
                max_ttd_seconds=float(np.max(ttds)) if ttds else None)


def _rule_table(hits, lab):
    if not hits:
        return []
    h = pd.DataFrame(hits, columns=["rule_id", "event_uid"])
    h["label"] = h.event_uid.map(lambda u: lab.get(u, "background"))
    t = h.groupby(["rule_id", "label"]).size().unstack(fill_value=0)
    for c in ("malicious", "background", "benign", "ambiguous"):
        if c not in t:
            t[c] = 0
    t["hits"] = t[["malicious", "background", "benign", "ambiguous"]].sum(axis=1)
    t["hit_precision"] = t.malicious / (t.malicious + t.background + t.benign).replace(0, np.nan)
    return t.reset_index()[["rule_id", "hits", "malicious", "background", "benign", "ambiguous", "hit_precision"]].to_dict("records")


def _incident_level(incidents, alerts, steps_cfg, st):
    n = len(incidents)
    gt_tactics = []
    for s in sorted(steps_cfg["steps"], key=lambda s: s["start"]):
        for t in s["tactics"][:1]:
            if t not in gt_tactics:
                gt_tactics.append(t)
    all_gt_tactics = {t for s in steps_cfg["steps"] for t in s["tactics"]}
    res = dict(n_incidents=n, n_true_incidents=1, fragmentation=max(n - 1, 0))
    if not incidents:
        return res
    by_id = {a.get("alert_id"): a for a in alerts}
    inc = max(incidents, key=lambda i: i["n_alerts"])
    al = [by_id[x] for x in inc["alert_ids"] if x in by_id]
    first = {}
    for a in sorted(al, key=lambda a: a["first_seen"]):
        first.setdefault(a["tactic"], a["first_seen"])
    obs_order = sorted(first, key=first.get)
    res.update(alerts_in_largest_incident=inc["n_alerts"], tactics_observed=obs_order,
               tactic_recall=len(set(obs_order) & all_gt_tactics) / len(all_gt_tactics),
               tactics_missed=sorted(all_gt_tactics - set(obs_order)), kill_chain_kendall_tau=M.kendall_tau(obs_order, gt_tactics),
               share_of_alerts_in_incident=inc["n_alerts"] / max(len(alerts), 1))
    return res


# ------------------------------------------------------------------ public API
def evaluate(alerts, hits, incidents, df, gt, steps_cfg, st, name="variant"):
    lab = _label_map(gt)
    a_res, verdicts = _alert_level(alerts, lab, steps_cfg)
    dd = dedup_ratio(alerts) if alerts else dict(n_alerts=0, n_groups=0, dedup_ratio=float("nan"))
    return dict(
        name=name, alert_level=a_res, process_level=_process_level(alerts, df, lab), event_level=_event_level(alerts, gt),
        step_level=_step_level(alerts, steps_cfg, st), rule_table=_rule_table(hits, lab),
        workload=dict(events=len(df), raw_hits=len(hits or []), alerts=len(alerts), alert_groups=dd["n_groups"],
                      incidents=len(incidents or []), dedup_ratio=dd["dedup_ratio"],
                      alert_reduction_ratio=M.reduction_ratio(len(df), len(alerts)),
                      group_reduction_ratio=M.reduction_ratio(len(df), dd["n_groups"])),
        incident_level=_incident_level(incidents or [], alerts, steps_cfg, st) if incidents is not None else {})


def summarize_row(r):
    pl, al, sl = r["process_level"], r["alert_level"], r["step_level"]
    return dict(variant=r["name"], alerts=al["n_alerts"], alert_precision=al["precision"], proc_precision=pl["precision"],
                proc_recall=pl["recall"], proc_f1=pl["f1"], step_detection=sl["step_detection_rate"],
                tech_cov_exact=sl["technique_coverage_exact"]["coverage"], tech_cov_family=sl["technique_coverage_family"]["coverage"],
                median_ttd_s=sl["median_ttd_seconds"])


def load_all(prefix: str = ""):
    from ai_soc.detection import engine
    df = engine.load()          # canonical typed loader (numeric + boolean feature columns)
    gt = pd.read_csv(C.GT_CSV, dtype=str).fillna("")
    gt["timestamp"] = pd.to_datetime(gt.timestamp, utc=True, format="ISO8601")
    seeds, steps_cfg = G.load_specs(prefix)
    st = G.step_table(df, gt, steps_cfg)
    alerts = json.load(open(C.ALERTS_JSON))
    incidents = json.load(open(C.INCIDENTS_JSON))
    hits = list(pd.read_csv(C.RAW_HITS_CSV)[["rule_id", "event_uid"]].itertuples(index=False, name=None))
    return df, gt, steps_cfg, st, alerts, incidents, hits


def write_report(r, path):
    pl, al, sl, wl, il = r["process_level"], r["alert_level"], r["step_level"], r["workload"], r["incident_level"]
    f = lambda x: "n/a" if x is None or x != x else f"{x:.3f}"
    L = [f"# Detection evaluation vs ground truth - {r['name']}", "",
         "> Ground truth is analyst-annotated (labels/). The development scenario was used to write the rules, so these are **development-set**",
         "> numbers; use `experiments/` for held-out and baseline comparisons.", "",
         "## Workload funnel", "", f"events {wl['events']:,} -> raw rule hits {wl['raw_hits']:,} -> alerts {wl['alerts']} -> alert groups {wl['alert_groups']} (dedup {f(wl['dedup_ratio'])}) -> incidents {wl['incidents']}", "",
         "## Alert level", "", f"- TP {al['tp']} | FP {al['fp']} | unverifiable {al['unverifiable']} | precision **{f(al['precision'])}**" + (f" (95% CI {f(al['precision_ci95'][0])}-{f(al['precision_ci95'][1])})" if 'precision_ci95' in al else ""),
         ]
    for x in al["false_positive_alerts"]:
        L.append(f"  - FP: {x['alert_id']} {x['rule_id']} on {x['host']} ({x['n_events']} events, {x['background']} background)")
    L += ["", "## Process level (308 process starts; background = assumed benign)", "",
          f"- malicious {pl['n_malicious']} | background {pl['n_background_assumed_benign']} | ambiguous excluded {pl['n_ambiguous_excluded']}",
          f"- TP {pl['tp']} FP {pl['fp']} FN {pl['fn']} | precision **{f(pl['precision'])}** recall **{f(pl['recall'])}** F1 {f(pl['f1'])}", "",
          "Missed malicious process starts:", ""]
    L += [f"- {x['timestamp']} {x['host']} `{x['process']}` {x['command_line']}" for x in pl["missed_malicious"][:25]]
    if pl["flagged_background"]:
        L += ["", "Flagged but background (possible FPs or labelling gaps):", ""]
        L += [f"- {x['timestamp']} {x['host']} `{x['process']}` {x['command_line']}" for x in pl["flagged_background"][:25]]
    L += ["", "## Step level", "", f"- Step detection rate **{f(sl['step_detection_rate'])}** | technique coverage exact {f(sl['technique_coverage_exact']['coverage'])} / family {f(sl['technique_coverage_family']['coverage'])} | median TTD {f(sl['median_ttd_seconds'])} s",
          "", "| step | name | host | detected | alerts | tech exact | tech family | missed techniques | TTD s |", "|---|---|---|---|---|---|---|---|---|"]
    for s in sl["steps"]:
        L.append(f"| {s['step']} | {s['name']} | {s['host']} | {'yes' if s['detected'] else '**NO**'} | {s['n_alerts']} | {f(s['technique_exact'])} | {f(s['technique_family'])} | {', '.join(s['missed_techniques'])} | {f(s['ttd_seconds'])} |")
    L += ["", "## Incident level", "", f"```\n{json.dumps(il, indent=1, default=str)}\n```", "", "## Per-rule hit precision", "",
          "| rule | hits | malicious | background | benign | ambiguous | hit precision |", "|---|---|---|---|---|---|---|"]
    L += [f"| {t['rule_id']} | {t['hits']} | {t['malicious']} | {t['background']} | {t['benign']} | {t['ambiguous']} | {f(t['hit_precision'])} |" for t in r["rule_table"]]
    ev = r["event_level"]["excluding_network_connect"]["assumed"]
    L += ["", "## Event level (supplementary)", "", f"- excluding beacon connections: precision {f(ev['precision'])} recall {f(ev['recall'])} (recall is low by construction: 35k PowerShell log lines are never individually alerted)"]
    path.write_text("\n".join(L))


def run(prefix: str = ""):
    df, gt, steps_cfg, st, alerts, incidents, hits = load_all(prefix)
    rule_alerts = [a for a in alerts if a["source"] != "ml"]
    res = evaluate(rule_alerts, hits, incidents, df, gt, steps_cfg, st, name="full pipeline (rules; ML fused into risk)")
    C.RESULTS_DIR.mkdir(exist_ok=True)
    json.dump(res, open(C.RESULTS_DIR / f"eval_main{'_' + prefix.rstrip('_') if prefix else ''}.json", "w"), indent=1, default=str)
    write_report(res, C.REPORT_DIR / "evaluation_report.md")
    print(json.dumps(summarize_row(res), indent=1))
    return res


if __name__ == "__main__":
    run()

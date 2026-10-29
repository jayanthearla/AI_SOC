"""Ground-truth labelling for evaluation (the missing piece for any honest precision/recall).

Labels come from *process lineage + analyst-identified seeds* (labels/attack_seeds.yml) and a step table
(labels/attack_steps.yml) - never from detection-rule output - so scoring the rules against them is not circular.

Event-level classes
    malicious   in the lineage of an attack seed, PowerShell logging after attacker activity began, or an
                explicit attacker selector (see seeds file)
    benign      before attack_start_utc (pre-attack window)
    ambiguous   could be attacker or normal behaviour -> excluded from strict metrics
    background  inside the attack window but unrelated to any seed (ordinary OS activity; "assumed benign")

Because 'background' is only *assumed* benign, evaluation reports precision under two assumptions:
    strict   - only malicious vs benign(pre-attack) events are scored
    assumed  - background is counted as benign (pessimistic precision)

    python -m ai_soc.labels.ground_truth
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import yaml

from ai_soc import config as C
from ai_soc.detection.sigma_lite import _selection_mask

LABELS = ("malicious", "benign", "ambiguous", "background")


def load_events(path=None) -> pd.DataFrame:
    """Correlated events as strings + parsed UTC timestamp (matches detection.engine.load)."""
    d = pd.read_csv(path or C.EVENTS_CORR_CSV, low_memory=False, dtype=str).fillna("")
    d["timestamp"] = pd.to_datetime(d["timestamp"], utc=True, format="ISO8601")
    return d


def load_specs(prefix: str = ""):
    seeds = yaml.safe_load(open(C.LABELS_DIR / f"{prefix}attack_seeds.yml", encoding="utf-8"))
    steps = yaml.safe_load(open(C.LABELS_DIR / f"{prefix}attack_steps.yml", encoding="utf-8"))
    return seeds, steps


def _descendants(proc: pd.DataFrame, roots) -> set:
    children = {}
    for g, pg in zip(proc.process_guid, proc.parent_guid):
        if pg:
            children.setdefault(pg, []).append(g)
    seen, stack = set(roots), list(roots)
    while stack:
        for c in children.get(stack.pop(), []):
            if c not in seen:
                seen.add(c)
                stack.append(c)
    return seen


def build_labels(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    t = df["timestamp"]
    start = pd.Timestamp(cfg["attack_start_utc"])
    in_window = t >= start
    n = len(df)
    label = np.where(in_window, "background", "benign").astype(object)
    source = np.full(n, "", dtype=object)
    seed = np.full(n, "", dtype=object)

    # 1. lineage seeds -> malicious process trees
    proc = df[df.event_type == "process_create"]
    guid_seed = {}
    for sd in cfg.get("lineage_seeds", []):
        roots = [g for g in df.loc[_selection_mask(df, sd["match"]) & in_window, "process_guid"] if g]
        for g in _descendants(proc, roots):
            guid_seed.setdefault(g, sd["id"])
    in_tree = (df.process_guid != "") & df.process_guid.isin(guid_seed) & in_window
    label[in_tree.values] = "malicious"
    source[in_tree.values] = "lineage"
    seed[in_tree.values] = df.loc[in_tree, "process_guid"].map(guid_seed).values

    # 2. scope rules (PowerShell logs after the first malicious process on that host)
    first = df[in_tree & (df.event_type == "process_create")].groupby("host").timestamp.min()
    host_first = df.host.map(first)
    for r in cfg.get("scope_rules", []):
        m = df.event_type.isin(r["event_types"]) & host_first.notna() & (t >= host_first)
        m = m.fillna(False) & (label != "malicious")
        label[m.values] = "malicious"
        source[m.values] = "scope"
        seed[m.values] = r["id"]

    # 3. explicit selectors
    for s in cfg.get("selectors", []):
        m = _selection_mask(df, s["match"]) & in_window & (label != "malicious")
        label[m.values] = "malicious"
        source[m.values] = "selector"
        seed[m.values] = s["id"]

    # 4. ambiguous (never overrides malicious)
    for s in cfg.get("ambiguous", []):
        m = _selection_mask(df, s["match"]) & in_window & (label != "malicious")
        label[m.values] = "ambiguous"
        source[m.values] = "ambiguous"
        seed[m.values] = s["id"]

    return pd.DataFrame({"event_uid": df.event_uid.values, "timestamp": df["timestamp"].reset_index(drop=True), "host": df.host.values,
                         "event_type": df.event_type.values, "gt_label": label, "gt_source": source, "gt_seed": seed})


def step_table(df: pd.DataFrame, gt: pd.DataFrame, steps_cfg: dict) -> pd.DataFrame:
    """One row per annotated step with the number of malicious events inside its window (annotation sanity check)."""
    day = steps_cfg["date"]
    rows = []
    mal = gt[gt.gt_label == "malicious"]
    for s in steps_cfg["steps"]:
        t0, t1 = pd.Timestamp(f"{day} {s['start']}", tz="UTC"), pd.Timestamp(f"{day} {s['end']}", tz="UTC")
        m = mal[(mal.host == s["host"]) & (mal.timestamp >= t0) & (mal.timestamp <= t1)]
        rows.append(dict(step=s["id"], name=s["name"], host=s["host"], start=t0, end=t1,
                         tactics="|".join(s["tactics"]), techniques="|".join(s["techniques"]),
                         n_malicious_events=len(m),
                         gt_first_event=m.timestamp.min() if len(m) else pd.NaT))
    return pd.DataFrame(rows)


def write_report(gt: pd.DataFrame, st: pd.DataFrame, cfg: dict, df: pd.DataFrame):
    pc = gt[gt.event_type == "process_create"]
    L = ["# Ground-truth labelling report", "",
         f"- Dataset: `{cfg['dataset']}`  |  attack start (UTC): {cfg['attack_start_utc']}",
         "- Labels are analyst-annotated from process lineage + seeds (see `labels/attack_seeds.yml`) and are **not** derived from rule output.",
         "", "## Event-level label distribution", "", "| label | all events | process_create only |", "|---|---|---|"]
    for lab in LABELS:
        L.append(f"| {lab} | {int((gt.gt_label == lab).sum()):,} | {int((pc.gt_label == lab).sum()):,} |")
    L += ["", "## Malicious events by label source / seed", "", "| source | seed | events |", "|---|---|---|"]
    for (s, sd), n in gt[gt.gt_label == "malicious"].groupby(["gt_source", "gt_seed"]).size().items():
        L.append(f"| {s} | {sd} | {n:,} |")
    L += ["", "## Annotated attack steps (window sanity check)", "",
          "| step | name | host | start | end | malicious events | GT first event |", "|---|---|---|---|---|---|---|"]
    for r in st.itertuples():
        warn = " **<- no malicious events in window: fix annotation**" if r.n_malicious_events == 0 else ""
        L.append(f"| {r.step} | {r.name} | {r.host} | {str(r.start)[11:19]} | {str(r.end)[11:19]} | {r.n_malicious_events:,}{warn} | {str(r.gt_first_event)[11:23]} |")
    L += ["", "## Ambiguous items (excluded from strict metrics)", ""]
    amb = pc[pc.gt_label == "ambiguous"].merge(df[["event_uid", "process", "command_line"]], on="event_uid")
    L += [f"- {r.timestamp.strftime('%H:%M:%S') if hasattr(r.timestamp, 'strftime') else str(r.timestamp)[11:19]} {r.host} `{r.process}` {r.command_line[:80]}" for r in amb.itertuples()]
    (C.REPORT_DIR / "ground_truth_report.md").write_text("\n".join(L))


def run(prefix: str = ""):
    seeds, steps = load_specs(prefix)
    df = load_events()
    gt = build_labels(df, seeds)
    C.OUT_DIR.mkdir(parents=True, exist_ok=True)
    C.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    gt.to_csv(C.GT_CSV, index=False, compression="gzip")
    st = step_table(df, gt, steps)
    st.to_csv(C.OUT_DIR / "ground_truth_steps.csv", index=False)
    write_report(gt, st, seeds, df)
    vc = gt.gt_label.value_counts().to_dict()
    print(f"Ground truth: {vc} | steps without events: {int((st.n_malicious_events == 0).sum())}/{len(st)}")
    return gt, st


if __name__ == "__main__":
    run()

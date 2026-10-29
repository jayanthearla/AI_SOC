"""Alert de-duplication: one behaviour often fires several rules (e.g. encoded + hidden-window PowerShell on the same
process start).  Alerts are merged into *alert groups* when they share an event, or hit the same host + process chain
within `time_tol` seconds.  The dedup ratio is a reportable workload metric (RQ2) and the analyst UI can show one
card per group."""
from __future__ import annotations

import pandas as pd


def group_alerts(alerts: list[dict], time_tol: float = 2.0) -> list[dict]:
    n = len(alerts)
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        parent[find(a)] = find(b)

    seen = {}
    for i, a in enumerate(alerts):
        for u in a["event_uids"]:
            if u in seen:
                union(i, seen[u])
            else:
                seen[u] = i
    ts = [pd.Timestamp(a["first_seen"]) for a in alerts]
    by_key = {}
    for i, a in enumerate(alerts):
        by_key.setdefault((a["host"], a.get("chain_id", "")), []).append(i)
    for idxs in by_key.values():
        idxs.sort(key=lambda i: ts[i])
        for x, y in zip(idxs, idxs[1:]):
            if alerts[x].get("chain_id") and (ts[y] - ts[x]).total_seconds() <= time_tol:
                union(x, y)
    groups = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)
    out = []
    for k, idxs in enumerate(sorted(groups.values(), key=lambda g: min(ts[i] for i in g)), 1):
        al = [alerts[i] for i in idxs]
        out.append(dict(group_id=f"GRP-{k:04d}", alert_ids=[a.get("alert_id", "") for a in al],
                        rule_ids=sorted({a["rule_id"] for a in al}), host=al[0]["host"],
                        first_seen=min(a["first_seen"] for a in al), n_alerts=len(al),
                        risk_score=max(a.get("risk_score", 0) for a in al)))
    return out


def dedup_ratio(alerts: list[dict], time_tol: float = 2.0) -> dict:
    g = group_alerts(alerts, time_tol)
    return dict(n_alerts=len(alerts), n_groups=len(g),
                dedup_ratio=1 - len(g) / len(alerts) if alerts else float("nan"),
                max_alerts_per_group=max((x["n_alerts"] for x in g), default=0))

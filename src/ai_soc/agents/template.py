"""Deterministic template analyst (no LLM).  Baseline B0 for RQ3 and the offline provider."""
from __future__ import annotations

from collections import OrderedDict

# tactic -> (action_id, target kind) proposals, ordered by priority
_BY_TACTIC = {
    "Command and Control": [("block_ip", "ip"), ("isolate_endpoint", "host")],
    "Execution": [("kill_process", "host"), ("quarantine_file", "file")],
    "Credential Access": [("reset_credentials", "account")],
    "Lateral Movement": [("reset_credentials", "account"), ("isolate_endpoint", "host")],
    "Persistence": [("remove_persistence", "host")],
    "Collection": [("quarantine_file", "file")],
    "Exfiltration": [("block_ip", "ip")],
}


def template_report(ctx: dict) -> dict:
    inc, alerts = ctx["incident"], ctx["alerts"]
    mapping = OrderedDict()
    for a in alerts:
        if a["technique"] not in ("n/a", ""):
            m = mapping.setdefault(a["technique"], dict(technique_id=a["technique"], tactic=a["tactic"], evidence_ids=[]))
            if len(m["evidence_ids"]) < 3:
                m["evidence_ids"].append(a["alert_id"])
    by_tactic = OrderedDict()
    for a in alerts:
        by_tactic.setdefault(a["tactic"], []).append(a)
    narr = []
    for tac, al in by_tactic.items():
        ids = ", ".join(f"[{x['alert_id']}]" for x in al[:3])
        narr.append(f"{al[0]['time']} {tac}: {al[0]['title']} on {al[0]['host']} {ids}.")
    c2 = [i["value"] for i in ctx["iocs"] if i["type"] == "ip" and i["verdict"] == "malicious"] or [i["value"] for i in ctx["iocs"] if i["type"] == "ip"][:1]
    acts, seen = [], set()
    hosts = inc["hosts"]
    for tac in by_tactic:
        for aid, kind in _BY_TACTIC.get(tac, []):
            tgt = {"host": hosts[0] if hosts else "", "ip": c2[0] if c2 else "", "account": (inc["users"] or [""])[0], "file": ""}.get(kind, "")
            if (aid, tgt) not in seen:
                seen.add((aid, tgt))
                acts.append(dict(action_id=aid, target=tgt, rationale=f"Matches observed {tac} activity.", evidence_ids=[by_tactic[tac][0]["alert_id"]]))
    acts.append(dict(action_id="hunt_similar_activity", target="", rationale="Search other hosts for the same indicators.", evidence_ids=[alerts[0]["alert_id"]] if alerts else []))
    score = float(inc.get("risk_score", 0.8))
    return dict(incident_id=inc["incident_id"], summary=f"{len(by_tactic)} ATT&CK tactics observed across {', '.join(hosts)} between {inc['first_seen'][11:]} and {inc['last_seen'][11:]}.",
                narrative=" ".join(narr), attack_mapping=list(mapping.values()),
                risk_level="critical" if score >= 0.9 else "high" if score >= 0.75 else "medium", risk_score=round(min(score, 1.0), 2), confidence=0.6,
                recommended_actions=acts, evidence_ids=[a["alert_id"] for a in alerts[:10]],
                limitations=["Template output: no reasoning beyond rule and tactic lookup.", "Lab indicators are synthetic."])

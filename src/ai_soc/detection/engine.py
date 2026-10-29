"""
STEP 4 - Detection (Rules + ML)
-------------------------------
Determines whether behaviour is suspicious using three complementary layers:

  A. SIGMA-STYLE RULES  (rules/detection_rules.yml)  - single-event signatures
  B. PYTHON RULES       (this file)                  - behaviour over time / across events
        PY-001 password-guessing burst (net use ... /user:)
        PY-002 sustained high-frequency beaconing from a script engine
        PY-003 discovery burst inside one process chain
        PY-005 one account touching several hosts in minutes (lateral spread)
        PY-006 persistence installed on a host shortly after lateral movement into it
  C. ML                 (ml_detection.py)            - Isolation Forest anomaly score

Everything is fused into ALERTS with a 0-1 risk score, then grouped into INCIDENTS
(multi-stage / multi-host activity, PY-004).

Outputs (outputs/): alerts.json, incidents.json, raw_hits.csv, ml_scores.csv, summary.json,
                    figures/*.png, reports/step4_detection_report.md
Usage: python src/detection.py
"""
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from ai_soc import config as C
from ai_soc.detection import ml_detection
from ai_soc.detection import sigma_lite

LEVEL_BASE = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 0.90}
GROUP_GAP = pd.Timedelta(minutes=10)
INFRA_PORTS = {"53", "88", "135", "139", "389", "445", "464", "636", "3268", "5985", "49667"}
TACTIC_ORDER = ["Initial Access", "Execution", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
                "Persistence", "Collection", "Command and Control"]


# ------------------------------------------------------------------ helpers
def load():
    d = pd.read_csv(C.EVENTS_CORR_CSV, low_memory=False, dtype=str).fillna("")
    for c in ["cmd_len", "cmd_n_args", "cmd_entropy", "hour", "proc_depth"]:
        d[c] = pd.to_numeric(d[c], errors="coerce")
    for c in [c for c in d.columns if c.startswith("f_")] + ["notable"]:
        d[c] = d[c] == "True"
    d["timestamp"] = pd.to_datetime(d["timestamp"], utc=True, format="ISO8601")
    return d


def evidence_line(r):
    t = str(r.timestamp)[11:19]
    et = r.event_type
    if et == "process_create":
        return f"{t} {r.process} <- {r.parent_process} :: {r.command_line[:160]}"
    if et == "file_create":
        fp = r.file_path
        return f"{t} {r.process} wrote {fp if len(fp) <= 140 else '...' + fp[-137:]}"
    if et == "service_install":
        return f"{t} service '{r.service_name}' -> {r.service_path[:120]}"
    if et == "ps_scriptblock":
        return f"{t} script block: {r.script_block[:140]!r}"
    if et == "logon":
        return f"{t} logon type {r.logon_type} ({r.auth_package}) user={r.user} from {r.remote_ip}"
    if et == "network_connect":
        return f"{t} {r.process} -> {r.dst_ip}:{r.dst_port}"
    return f"{t} {et} {r.process}"


def make_alert(meta, rows, extra=None, source="sigma"):
    rows = rows.sort_values("timestamp")
    users = [u for u in rows.user_short.unique() if u]
    ev = [evidence_line(r) for r in rows.head(4).itertuples()]
    if extra:
        ev = extra + ev
    return {
        "rule_id": meta["id"], "source": source, "title": meta["title"], "description": meta["description"],
        "tactic": meta["tactic"], "technique": meta["technique"], "level": meta["level"],
        "host": rows.host.iloc[0], "user": users[0] if users else "",
        "chain_id": rows.chain_id.iloc[0], "session_id": next((s for s in rows.session_id if s), ""),
        "first_seen": str(rows.timestamp.min()), "last_seen": str(rows.timestamp.max()),
        "event_count": int(len(rows)), "evidence": ev, "event_uids": rows.event_uid.tolist(),
    }


def split_by_gap(rows):
    rows = rows.sort_values("timestamp")
    gid = (rows.timestamp.diff() > GROUP_GAP).cumsum()
    return [g for _, g in rows.groupby(gid)]


# ------------------------------------------------------------------ A. sigma rules
def run_sigma(df, rules):
    masks = sigma_lite.run_rules(df, rules)
    meta = {r["id"]: r for r in rules}
    alerts, hits = [], []
    for rid, m in masks.items():
        h = df[m]
        for _, grp in h.groupby("host"):
            for g in split_by_gap(grp):
                alerts.append(make_alert(meta[rid], g))
        hits += [(rid, uid) for uid in h.event_uid]
    return alerts, hits, {rid: int(m.sum()) for rid, m in masks.items()}


# ------------------------------------------------------------------ B. python rules
def py_password_guessing(df):
    meta = dict(id="PY-001", title="Password-guessing burst against admin shares", tactic="Credential Access",
                technique="T1110.003", level="critical",
                description="Many `net use \\\\HOST\\ADMIN$ /user:` attempts with different credentials in a short window (password spraying).")
    n = df[(df.event_type == "process_create") & (df.process == "net.exe") &
           df.command_line.str.contains(r"use\s+\\\\\S+\\(?:admin|c|ipc)\$\s+/user:", case=False, regex=True)].copy()
    out = []
    for host, g in n.groupby("host"):
        for w in split_by_gap(g):
            tgt = w.command_line.str.extract(r"use\s+\\\\(\S+)\\", flags=2)[0].str.upper().nunique()
            usr = w.command_line.str.extract(r"/user:(\S+)", flags=2)[0].str.lower().nunique()
            pwd = w.command_line.str.extract(r"/user:\S+\s+(\S+)", flags=2)[0].nunique()
            secs = max((w.timestamp.max() - w.timestamp.min()).total_seconds(), 1)
            if len(w) >= 5 and (usr >= 3 or pwd >= 3):
                out.append(make_alert(meta, w, [f"{len(w)} attempts in {secs:.0f}s: {usr} accounts x {pwd} passwords across {tgt} targets "
                                               f"(~{len(w)/secs*60:.0f}/min)"], source="python"))
    return out


def py_beaconing(df):
    meta = dict(id="PY-002", title="Sustained high-frequency beaconing from a script engine", tactic="Command and Control",
                technique="T1071.001", level="high",
                description="A scripting process makes many repeated connections to the same non-infrastructure endpoint at short intervals (C2 polling). Interval statistics (median, CV) are included as evidence.")
    n = df[(df.event_type == "network_connect") & df.process.isin(C.SCRIPT_ENGINES) & ~df.dst_port.isin(INFRA_PORTS)]
    out = []
    for (host, chain, ip, port), g in n.groupby(["host", "chain_id", "dst_ip", "dst_port"]):
        if len(g) < 20:
            continue
        iv = g.sort_values("timestamp").timestamp.diff().dt.total_seconds().dropna()
        med, cv = iv.median(), iv.std() / max(iv.mean(), 1e-9)
        if med <= 300:
            out.append(make_alert(meta, g, [f"{len(g)} connections to {ip}:{port}; median interval {med:.1f}s; "
                                           f"interval CV {cv:.2f}; span {(g.timestamp.max()-g.timestamp.min()).total_seconds()/60:.0f} min"],
                                  source="python"))
    return out


def py_discovery_burst(df):
    meta = dict(id="PY-003", title="Discovery burst inside one process chain", tactic="Discovery", technique="T1082",
                level="high", description="Several distinct reconnaissance commands launched from the same chain in a short time.")
    p = df[(df.event_type == "process_create") & df.process.isin(C.DISCOVERY_BINS) & (df.chain_id != "") &
           (df.parent_process == "powershell.exe")].copy()
    p["cmd_key"] = p.process + " " + p.command_line.str.replace(r'^"?[^"]*?\.exe"?\s*', "", regex=True).str.lower()
    out = []
    for (host, chain), g in p.groupby(["host", "chain_id"]):
        for w in split_by_gap(g):
            if w.cmd_key.nunique() >= 5:
                out.append(make_alert(meta, w, [f"{w.cmd_key.nunique()} distinct discovery commands in "
                                               f"{(w.timestamp.max()-w.timestamp.min()).total_seconds()/60:.0f} min"], source="python"))
    return out


def py_lateral_spread(df, lat):
    meta = dict(id="PY-005", title="Account used on several hosts within minutes", tactic="Lateral Movement",
                technique="T1021", level="high",
                description="Explicit-credential / admin-share activity from one workstation to >=2 different hosts in a short window.")
    out = []
    if lat.empty:
        return out
    l = lat[lat.method.str.contains("explicit|share_access")].copy()
    for (src, user), g in l.groupby(["src_host", "user"]):
        g = g.sort_values("timestamp")
        for _, w in g.groupby((g.timestamp.diff() > pd.Timedelta(minutes=5)).cumsum()):
            if w.dst_host.nunique() >= 2:
                ts0, ts1 = w.timestamp.min(), w.timestamp.max()
                out.append({
                    "rule_id": meta["id"], "source": "python", "title": meta["title"], "description": meta["description"],
                    "tactic": meta["tactic"], "technique": meta["technique"], "level": meta["level"], "host": src, "user": user,
                    "chain_id": "", "session_id": "", "first_seen": str(ts0), "last_seen": str(ts1), "event_count": int(len(w)),
                    "evidence": [f"{user}: {src} -> {', '.join(sorted(w.dst_host.unique()))} via {', '.join(sorted(w.method.unique()))}"],
                    "event_uids": []})
    return out


def py_persistence_after_lateral(df, lat):
    meta = dict(id="PY-006", title="Persistence installed right after lateral movement into the host", tactic="Persistence",
                technique="T1543.003", level="critical",
                description="A suspicious service was created on a host that received lateral-movement activity within the previous 30 minutes.")
    out = []
    svc = df[(df.event_type == "service_install") & df.service_path.str.contains("cmd.exe /c|.vbs|\\\\users\\\\|\\\\appdata\\\\", case=False, regex=True)]
    for host, g in svc.groupby("host"):
        for w in split_by_gap(g):          # 4697 + 7045 for the same service become ONE alert
            t = w.timestamp.min()
            prior = lat[(lat.dst_host == host) & (lat.timestamp < t) & (lat.timestamp > t - pd.Timedelta(minutes=30))]
            if len(prior):
                out.append(make_alert(meta, w, [
                    f"{len(prior)} lateral events into {host} in the prior 30 min from {', '.join(sorted(prior.src_host.unique()))} "
                    f"(users: {', '.join(sorted(prior.user.unique()))})"], "python"))
    return out


# ------------------------------------------------------------------ fusion: risk score
def fuse(alerts, df, ml):
    ml_map = dict(zip(ml.event_uid, ml.ml_score))
    for i, a in enumerate(alerts):
        scores = [ml_map[u] for u in a["event_uids"] if u in ml_map]
        a["ml_score"] = round(max(scores), 3) if scores else None
        a["_base"] = LEVEL_BASE[a["level"]]
    # co-occurrence bonus: other distinct rules on the same host within 30 minutes
    for a in alerts:
        t0, t1 = pd.Timestamp(a["first_seen"]), pd.Timestamp(a["last_seen"])
        peers = {b["rule_id"] for b in alerts if b is not a and b["host"] == a["host"] and
                 abs((pd.Timestamp(b["first_seen"]) - t0).total_seconds()) <= 1800}
        a["related_rules"] = len(peers)
        risk = a["_base"] + min(0.02 * len(peers), 0.08) + (0.10 * a["ml_score"] if a["ml_score"] is not None else 0)
        a["risk_score"] = round(min(risk, 0.99), 2)
        a["severity"] = ("critical" if a["risk_score"] >= 0.90 else "high" if a["risk_score"] >= 0.75
                         else "medium" if a["risk_score"] >= 0.50 else "low")
        del a["_base"]
    alerts.sort(key=lambda a: a["first_seen"])
    for i, a in enumerate(alerts, 1):
        a["alert_id"] = f"ALR-{i:04d}"
    return alerts


def ml_only_alerts(df, ml, alerts, threshold=0.97):
    """Surface highly anomalous process starts that NO rule covered (analyst review queue)."""
    covered = {u for a in alerts for u in a["event_uids"]}
    meta = dict(id="ML-001", title="Anomalous process execution (Isolation Forest)", tactic="Execution",
                technique="n/a", level="low", description="Process start is statistically unusual for these hosts but matched no rule - review.")
    top = ml[(ml.ml_score >= threshold) & ~ml.event_uid.isin(covered)]
    out = []
    for r in df[df.event_uid.isin(top.event_uid)].itertuples():
        out.append(make_alert(meta, df[df.event_uid == r.event_uid], source="ml"))
    return out


# ------------------------------------------------------------------ incidents (PY-004)
def build_incidents(alerts, sessions, lat):
    ses = pd.DataFrame(sessions)
    ses["s"], ses["e"] = pd.to_datetime(ses.start, utc=True), pd.to_datetime(ses.end, utc=True)
    parent = {s: s for s in ses.session_id}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def session_at(host, ts, pad=pd.Timedelta(minutes=15)):
        m = ses[(ses.host == host) & (ses.s - pad <= ts) & (ses.e + pad >= ts)]
        return m.session_id.iloc[0] if len(m) else None

    for r in lat.itertuples():
        a, b = session_at(r.src_host, r.timestamp), session_at(r.dst_host, r.timestamp)
        if a and b:
            parent[find(a)] = find(b)
    # sessions that share a *human* account and are <= 30 min apart belong to the same campaign
    machine = {"system", "localsystem", "network service", "local service", "anonymous logon"}
    human = lambda row: {u for u in row["users"] if not u.endswith("$") and u not in machine}
    rows = ses.sort_values("s").to_dict("records")
    for i, x in enumerate(rows):
        for y in rows[i + 1:]:
            if y["s"] - x["e"] > pd.Timedelta(minutes=30):
                continue
            if human(x) & human(y):
                parent[find(x["session_id"])] = find(y["session_id"])
    for a in alerts:
        if not a["session_id"]:
            a["session_id"] = session_at(a["host"], pd.Timestamp(a["first_seen"])) or ""
    groups = {}
    for a in alerts:
        if a["session_id"] and a["source"] != "ml":
            groups.setdefault(find(a["session_id"]), []).append(a)
    incidents = []
    for root, al in groups.items():
        tactics = {a["tactic"] for a in al}
        if len(tactics) < 3:
            continue
        al.sort(key=lambda a: a["first_seen"])
        kill_chain = [t for t in TACTIC_ORDER if t in tactics]
        risk = min(0.99, 0.90 + 0.02 * (len(tactics) - 3) + 0.02 * (max(a["risk_score"] for a in al) - 0.75))
        incidents.append({
            "incident_id": "", "title": f"Multi-stage intrusion across {', '.join(sorted({a['host'] for a in al}))}",
            "rule_id": "PY-004", "risk_score": round(risk, 2), "severity": "critical",
            "hosts": sorted({a["host"] for a in al}), "users": sorted({a["user"] for a in al if a["user"]}),
            "first_seen": min(a["first_seen"] for a in al), "last_seen": max(a["last_seen"] for a in al),
            "sessions": sorted({a["session_id"] for a in al}), "tactics_observed": kill_chain,
            "n_alerts": len(al), "alert_ids": [a["alert_id"] for a in al],
            "techniques": sorted({a["technique"] for a in al if a["technique"] != "n/a"}),
            "timeline": [f"{a['first_seen'][11:19]} {a['host']:<7} {a['tactic']:<20} {a['technique']:<10} {a['title']}" for a in al],
        })
    incidents.sort(key=lambda i: i["first_seen"])
    for k, i in enumerate(incidents, 1):
        i["incident_id"] = f"INC-{k:03d}"
    return incidents


# ------------------------------------------------------------------ outputs
def figures(df, alerts, incidents):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    C.FIG_DIR.mkdir(parents=True, exist_ok=True)
    col = {"critical": "#b71c1c", "high": "#ef6c00", "medium": "#f9a825", "low": "#78909c"}
    al = [a for a in alerts if a["source"] != "ml"]
    hosts = sorted({a["host"] for a in al})
    marker = dict(zip(hosts, ["o", "s", "^", "D"]))
    lanes = [t for t in TACTIC_ORDER if any(a["tactic"] == t for a in al)]
    fig, ax = plt.subplots(figsize=(13, 5.2))
    for a in al:
        ax.scatter(pd.Timestamp(a["first_seen"]), lanes.index(a["tactic"]), s=50 + 220 * a["risk_score"],
                   c=col[a["severity"]], marker=marker[a["host"]], alpha=.8, edgecolor="k", linewidth=.6)
    ax.set_yticks(range(len(lanes)), lanes)
    ax.invert_yaxis()
    ax.set_title("Attack progression: alerts by kill-chain tactic over time (size = risk, colour = severity, shape = host)")
    for s_, c in col.items():
        ax.scatter([], [], c=c, label=s_, edgecolor="k")
    for h, m in marker.items():
        ax.scatter([], [], c="white", marker=m, edgecolor="k", label=h)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.12), fontsize=8, ncol=6, frameon=False)
    ax.grid(alpha=.3)
    import matplotlib.dates as mdates
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    ax.set_xlabel("UTC time, 2019-05-14")
    fig.tight_layout()
    fig.savefig(C.FIG_DIR / "alert_timeline.png", dpi=140)
    plt.close(fig)

    top = sorted(al, key=lambda a: -a["risk_score"])[:15]
    fig, ax = plt.subplots(figsize=(11, 5.5))
    ax.barh([f"{a['alert_id']} {a['rule_id']} {a['host']}: {a['title'][:48]}" for a in top][::-1],
            [a["risk_score"] for a in top][::-1], color=[col[a["severity"]] for a in top][::-1])
    ax.set_xlim(0, 1)
    ax.set_title("Top 15 alerts by risk score")
    fig.tight_layout()
    fig.savefig(C.FIG_DIR / "top_alerts_risk.png", dpi=140)
    plt.close(fig)

    fig, ax = plt.subplots(1, 2, figsize=(12, 4))
    df.host.value_counts().plot.bar(ax=ax[0], color="#1565c0")
    ax[0].set_title("Events per host")
    df.event_type.value_counts().head(10).sort_values().plot.barh(ax=ax[1], color="#2e7d32")
    ax[1].set_title("Top event types")
    fig.tight_layout()
    fig.savefig(C.FIG_DIR / "dataset_overview.png", dpi=140)
    plt.close(fig)


def write_report(df, alerts, incidents, rule_counts, rules, ml, summary):
    al = [a for a in alerts if a["source"] != "ml"]
    L = ["# Step 4 - Detection report", "",
         f"- Events analysed: **{summary['total_events']:,}**",
         f"- Events involved in at least one rule alert: **{summary['suspicious_events']:,}** "
         f"({summary['suspicious_events']/summary['total_events']*100:.2f}%)",
         f"- Rule alerts: **{len(al)}** | ML-only review alerts: **{len(alerts)-len(al)}** | Incidents: **{len(incidents)}**",
         f"- Severity (rule alerts): {summary['alerts_by_severity']}", "", "## Incidents", ""]
    for i in incidents:
        L += [f"### {i['incident_id']} - {i['title']}  (risk {i['risk_score']})", "",
              f"Hosts: {', '.join(i['hosts'])} | Users: {', '.join(i['users'])} | {i['first_seen'][11:19]} -> {i['last_seen'][11:19]} UTC", "",
              f"Kill chain observed: {' > '.join(i['tactics_observed'])}", "", "```"] + i["timeline"] + ["```", ""]
    L += ["## Rule coverage (raw event hits per rule)", "", "| rule | title | tactic | technique | raw hits |", "|---|---|---|---|---|"]
    for r in rules:
        L.append(f"| {r['id']} | {r['title']} | {r['tactic']} | {r['technique']} | {rule_counts[r['id']]} |")
    L += ["", "## All rule alerts (sorted by time)", "", "| id | rule | host | user | time | n | risk | sev | ML |", "|---|---|---|---|---|---|---|---|---|"]
    for a in al:
        L.append(f"| {a['alert_id']} | {a['rule_id']} {a['title'][:55]} | {a['host']} | {a['user']} | {a['first_seen'][11:19]} | "
                 f"{a['event_count']} | {a['risk_score']} | {a['severity']} | {a['ml_score'] if a['ml_score'] is not None else '-'} |")
    ev = summary["ml_evaluation"]
    L += ["", "## ML sanity check (Isolation Forest vs. rules)", "",
          f"- Process-create events scored: {ev['n_scored']}",
          f"- Of the ML top-{ev['k']} most anomalous, **{ev['topk_in_rules']}** were also flagged by a rule "
          f"(precision@{ev['k']} vs rules = {ev['precision_at_k']:.0%}).",
          f"- Rule-flagged process events found inside ML top 10%: {ev['rule_in_top10pct']} of {ev['rule_flagged_scored']}.",
          f"- ML-only review alerts (anomalous, no rule hit): {ev['ml_only']}.", "",
          "> There are no per-event ground-truth labels in this dataset, so precision/recall against labels cannot be computed. "
          "The comparison above measures *agreement between two independent methods*, not accuracy."]
    (C.REPORT_DIR / "step4_detection_report.md").write_text("\n".join(L))


def load_lateral():
    lat = pd.read_csv(C.LATERAL_CSV)
    lat["timestamp"] = pd.to_datetime(lat.timestamp, utc=True, format="ISO8601")
    return lat


def detect_rules(df, rules, lat, use_sigma=True, use_python=True):
    """Run the rule layers only (no ML, no fusion).  Returns (alerts, hits, rule_counts).

    Re-usable by the evaluation harness (ablations, robustness mutations, baselines) so every
    experiment exercises exactly the same code as the production pipeline.
    """
    sig_alerts, hits, rule_counts = ([], [], {})
    if use_sigma:
        sig_alerts, hits, rule_counts = run_sigma(df, rules)
    py_alerts = []
    if use_python:
        py_alerts = (py_password_guessing(df) + py_beaconing(df) + py_discovery_burst(df)
                     + py_lateral_spread(df, lat) + py_persistence_after_lateral(df, lat))
    for a in py_alerts:
        hits += [(a["rule_id"], u) for u in a["event_uids"]]
        rule_counts[a["rule_id"]] = rule_counts.get(a["rule_id"], 0) + a["event_count"]
    return sig_alerts + py_alerts, hits, rule_counts


def run():
    df = load()
    rules = sigma_lite.load_rulesets(C.RULES_DIR, C.RULESETS)
    lat = load_lateral()

    rule_raw, hits, rule_counts = detect_rules(df, rules, lat)

    ml = ml_detection.score(df)
    ml.to_csv(C.ML_SCORES_CSV, index=False)

    rule_alerts = fuse(rule_raw, df, ml)
    ml_alerts = ml_only_alerts(df, ml, rule_alerts)
    alerts = fuse(rule_alerts + ml_alerts, df, ml)       # re-fuse so ids/scores are consistent
    incidents = build_incidents(alerts, json.load(open(C.SESSIONS_JSON)), lat)
    for inc in incidents:
        for a in alerts:
            if a["alert_id"] in inc["alert_ids"]:
                a["incident_id"] = inc["incident_id"]

    # PY-004 registered as a rule for coverage table
    rules = rules + [
        dict(id="PY-001", title="Password-guessing burst (net use /user:)", tactic="Credential Access", technique="T1110.003"),
        dict(id="PY-002", title="Sustained C2 beaconing from script engine", tactic="Command and Control", technique="T1071.001"),
        dict(id="PY-003", title="Discovery burst in one process chain", tactic="Discovery", technique="T1082"),
        dict(id="PY-005", title="Account used on several hosts in minutes", tactic="Lateral Movement", technique="T1021"),
        dict(id="PY-006", title="Persistence right after lateral movement", tactic="Persistence", technique="T1543.003"),
        dict(id="ML-001", title="Isolation Forest anomalous process", tactic="Execution", technique="n/a")]
    rule_counts["ML-001"] = len(ml_alerts)
    for r in rules:
        rule_counts.setdefault(r["id"], 0)

    # ----- ML evaluation vs rules
    rule_uids = {u for a in rule_alerts for u in a["event_uids"]}
    k = 15
    mls = ml.sort_values("ml_score", ascending=False)
    topk = mls.head(k)
    flagged = ml[ml.event_uid.isin(rule_uids)]
    ev = dict(n_scored=len(ml), k=k, topk_in_rules=int(topk.event_uid.isin(rule_uids).sum()),
              precision_at_k=float(topk.event_uid.isin(rule_uids).mean()), rule_flagged_scored=len(flagged),
              rule_in_top10pct=int((flagged.ml_score >= 0.90).sum()), ml_only=len(ml_alerts))

    al = [a for a in alerts if a["source"] != "ml"]
    susp = {u for a in al for u in a["event_uids"]}
    summary = dict(
        total_events=len(df), suspicious_events=len(susp), raw_rule_hits=len(hits),
        rule_alerts=len(al), ml_only_alerts=len(alerts) - len(al), incidents=len(incidents),
        alerts_by_severity=pd.Series([a["severity"] for a in al]).value_counts().to_dict(),
        alerts_by_tactic=pd.Series([a["tactic"] for a in al]).value_counts().to_dict(),
        alerts_by_host=pd.Series([a["host"] for a in al]).value_counts().to_dict(),
        high_risk_alerts=sum(a["risk_score"] >= 0.75 for a in al), ml_evaluation=ev,
        rules_loaded=len([r for r in rules if r["id"].startswith("SIG")]), python_rules=5)

    C.OUT_DIR.mkdir(exist_ok=True)
    json.dump(alerts, open(C.ALERTS_JSON, "w"), indent=1)
    json.dump(incidents, open(C.INCIDENTS_JSON, "w"), indent=1)
    pd.DataFrame(hits, columns=["rule_id", "event_uid"]).merge(
        df[["event_uid", "timestamp", "host", "user_short", "event_type", "process", "chain_id", "session_id"]], on="event_uid"
    ).sort_values("timestamp").to_csv(C.RAW_HITS_CSV, index=False)
    json.dump(summary, open(C.SUMMARY_JSON, "w"), indent=1)
    figures(df, alerts, incidents)
    write_report(df, alerts, incidents, rule_counts, rules, ml, summary)
    print(f"Step 4 done: {summary['raw_rule_hits']} raw hits -> {summary['rule_alerts']} alerts "
          f"(+{summary['ml_only_alerts']} ML review) -> {summary['incidents']} incident(s)")
    print("Severity:", summary["alerts_by_severity"])


if __name__ == "__main__":
    run()

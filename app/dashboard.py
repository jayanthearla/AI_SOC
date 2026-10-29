"""SOC dashboard (Streamlit) - the "Example Final Output" panel of the project poster.

    pip install streamlit
    streamlit run app/dashboard.py

Reads outputs/ produced by the pipeline.  Approvals are written through ai_soc.response.approval (two-person rule for
high-impact actions, hash-chained audit log).  Execution is a dry run.
"""
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ai_soc import config as C  # noqa: E402
from ai_soc.response import approval as A  # noqa: E402

st.set_page_config(page_title="AI SOC", layout="wide")


def load(path, default):
    return json.load(open(path)) if Path(path).exists() else default


summary, alerts = load(C.SUMMARY_JSON, {}), load(C.ALERTS_JSON, [])
incidents, enriched = load(C.INCIDENTS_JSON, []), load(C.ENRICHED_JSON, [])
reports, iocs = load(C.ANALYST_JSON, []), load(C.OUT_DIR / "iocs.json", [])
ev = load(C.RESULTS_DIR / "eval_main.json", {})

st.title("AI SOC - multi-agent pipeline")
who = st.sidebar.text_input("Your analyst id (required to approve)", "")
st.sidebar.caption("Execution is a dry run. High-impact actions need two different approvers.")
st.sidebar.write("Audit log:", A.verify_audit_log())

c = st.columns(5)
c[0].metric("Total events", f"{summary.get('total_events', 0):,}")
c[1].metric("Alerts", summary.get("rule_alerts", 0))
c[2].metric("High-risk alerts", summary.get("high_risk_alerts", 0))
c[3].metric("Incidents", summary.get("incidents", 0))
if ev:
    c[4].metric("Alert precision (dev set)", f"{ev['alert_level']['precision']:.2f}")

t_alerts, t_inc, t_ioc, t_rep, t_act, t_eval = st.tabs(["Alerts", "Incident", "Indicators", "Analyst report", "Actions", "Evaluation"])

with t_alerts:
    df = pd.DataFrame(alerts)
    if len(df):
        sev = st.multiselect("Severity", sorted(df.severity.unique()), default=sorted(df.severity.unique()))
        host = st.multiselect("Host", sorted(df.host.unique()), default=sorted(df.host.unique()))
        v = df[df.severity.isin(sev) & df.host.isin(host)]
        st.dataframe(v[["alert_id", "first_seen", "host", "user", "rule_id", "title", "tactic", "technique", "risk_score", "severity", "source"]], use_container_width=True)
        with st.expander("Evidence for an alert"):
            aid = st.selectbox("Alert", v.alert_id.tolist())
            st.json(next(a for a in alerts if a["alert_id"] == aid)["evidence"])

with t_inc:
    for i in incidents:
        st.subheader(f"{i['incident_id']} - {i['title']}  (risk {i['risk_score']}, {i['severity']})")
        st.write("Kill chain:", " -> ".join(i["tactics_observed"]))
        st.code("\n".join(i["timeline"]))

with t_ioc:
    d = pd.DataFrame(iocs)
    if len(d):
        st.dataframe(d[["type", "value", "verdict", "internal", "tags"]], use_container_width=True)
        st.caption("Lab indicators come from a synthetic local feed; internal IPs are never sent to public CTI.")

with t_rep:
    for r in reports:
        ver = r["verification"]
        (st.success if ver.get("passed") else st.error)(f"Verification {'PASSED' if ver.get('passed') else 'FAILED'} - grounding {ver.get('narrative_grounding', 0):.2f}, "
                                                         f"invalid ids {ver.get('invalid_evidence_ids')}, hallucinated {ver.get('hallucinated_entities')}")
        st.caption(f"{r['provider']} / {r['model']}")
        st.write(f"**{r['risk_level'].upper()}** (score {r['risk_score']}, confidence {r['confidence']})")
        st.write(r["summary"])
        st.write(r["narrative"])
        st.write("Limitations:", r["limitations"])

with t_act:
    ds = A.load_decisions()
    for d in ds:
        a = A.CATALOGUE[d.action_id]
        with st.container(border=True):
            st.write(f"**{a.label}** -> `{d.target or 'n/a'}`   impact: {a.impact}   status: **{d.status}**   approvers: {d.approvers}")
            st.caption(d.rationale + (" | NOTE: analyst report failed verification" if not d.report_verified else ""))
            b = st.columns(4)
            if b[0].button("Approve", key=f"ap{d.decision_id}", disabled=d.status in ("rejected", "executed_simulated")):
                try:
                    A.decide(ds, d.decision_id, True, who, override=not d.report_verified)
                    A.save_decisions(ds)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
            if b[1].button("Reject", key=f"rj{d.decision_id}", disabled=d.status in ("rejected", "executed_simulated")):
                try:
                    A.decide(ds, d.decision_id, False, who)
                    A.save_decisions(ds)
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
            if b[2].button("Dry-run execute", key=f"ex{d.decision_id}", disabled=d.status != "approved"):
                st.info(A.execute_simulated(d))
                A.save_decisions(ds)

with t_eval:
    for f in sorted(Path(C.REPORT_DIR).glob("e*_*.md")) + [Path(C.REPORT_DIR) / "evaluation_report.md"]:
        if f.exists():
            with st.expander(f.name):
                st.markdown(f.read_text())

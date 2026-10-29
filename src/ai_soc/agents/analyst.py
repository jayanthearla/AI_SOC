"""STEP 6 - SOC Analyst agent: incident + enriched alerts -> verified AnalystReport.

    python -m ai_soc.agents.analyst --provider mock                         # offline template baseline
    python -m ai_soc.agents.analyst --provider anthropic --model claude-sonnet-5-5
    python -m ai_soc.agents.analyst --provider openai_compat --model llama-3.3-70b-versatile   # + OPENAI_BASE_URL

The report is NEVER executed: it goes to the human-approval layer (Step 7).  Reports that fail verification are kept but
flagged `verification.passed = false`, so the UI shows a warning instead of silently trusting the model.
"""
from __future__ import annotations

import argparse
import json
import re

from pydantic import ValidationError

from ai_soc import config as C
from ai_soc.agents import prompts
from ai_soc.agents.llm_client import make_client
from ai_soc.agents.verifier import verify
from ai_soc.contracts import AnalystReport, EnrichedAlert, Incident
from ai_soc.intel.mitre import AttackKB
from ai_soc.intel.rag import Retriever


def parse_json(text: str) -> dict:
    t = text.strip()
    t = re.sub(r"^```(?:json)?|```$", "", t, flags=re.M).strip()
    i, j = t.find("{"), t.rfind("}")
    return json.loads(t[i:j + 1])


def analyse(incident: Incident, enriched: list[EnrichedAlert], client, retriever=None, kb=None, canaries=None, ctx_override=None):
    ctx, stats = prompts.build_context(incident, enriched, retriever)
    if ctx_override:
        ctx = ctx_override(ctx)
    user = prompts.user_prompt(ctx)
    err, report = "", None
    for attempt in range(2):                                       # one repair attempt on malformed output
        raw = client.complete(prompts.SYSTEM, user if not err else user + f"\n\nYour previous output was invalid ({err}). Return only valid JSON.")
        try:
            data = parse_json(raw)
            data["incident_id"] = incident.incident_id
            report = AnalystReport(**data)
            break
        except (json.JSONDecodeError, ValidationError, ValueError) as e:
            err = str(e)[:300]
    if report is None:
        return None, dict(schema_valid=False, error=err, passed=False), ctx, stats
    report.model, report.provider = client.model, client.provider
    ver = verify(report, ctx, canaries, kb)
    ver["schema_valid"] = True
    report.verification = ver
    return report, ver, ctx, stats


def run(provider="mock", model=None):
    incidents = [Incident(**i) for i in json.load(open(C.INCIDENTS_JSON))]
    enriched = [EnrichedAlert(**e) for e in json.load(open(C.ENRICHED_JSON))]
    kb = AttackKB()
    rag = Retriever(kb)
    client = make_client(provider, model)
    reports = []
    for inc in incidents:
        rep, ver, ctx, stats = analyse(inc, enriched, client, rag, kb)
        print(f"{inc.incident_id}: provider={client.provider}/{client.model} schema_valid={ver.get('schema_valid')} passed={ver.get('passed')} "
              f"grounding={ver.get('narrative_grounding', 0):.2f} injection_flags_in_context={stats['injection_flags']}")
        if rep:
            reports.append(rep.model_dump())
    json.dump(reports, open(C.ANALYST_JSON, "w"), indent=1)
    return reports


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="mock", choices=["mock", "anthropic", "openai_compat"])
    ap.add_argument("--model", default=None)
    a = ap.parse_args()
    run(a.provider, a.model)

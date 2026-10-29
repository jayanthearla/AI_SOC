"""STEP 7 - Human-approved response.  Nothing is executed without a human decision, and "execution" here is a DRY RUN.

Safety design (also material for the paper's threat model)
  * The LLM can only propose ids from the closed catalogue (verifier enforces it).
  * Every action needs an explicit approval; high-impact actions need TWO distinct approvers.
  * Proposals from a report that failed verification are flagged and need an explicit `override`.
  * Every state change is appended to a hash-chained JSONL audit log (tamper-evident; `verify_audit_log`).
  * `execute_simulated` only records what *would* happen - wire a real SOAR connector behind a separate review.

    python -m ai_soc.response.approval            # create proposals from analyst_reports.json
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from ai_soc import config as C
from ai_soc.contracts import AnalystReport, Decision
from ai_soc.response.actions import CATALOGUE


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ------------------------------------------------------------------ audit log (hash chain)
def _last_hash(path):
    if not path.exists() or path.stat().st_size == 0:
        return "0" * 64
    return json.loads(path.read_text().strip().splitlines()[-1])["hash"]


def audit(event: str, payload: dict, path=None):
    path = path or C.AUDIT_LOG
    path.parent.mkdir(parents=True, exist_ok=True)
    rec = dict(ts=_now(), event=event, payload=payload, prev=_last_hash(path))
    rec["hash"] = hashlib.sha256(json.dumps({k: rec[k] for k in ("ts", "event", "payload", "prev")}, sort_keys=True).encode()).hexdigest()
    with open(path, "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def verify_audit_log(path=None) -> dict:
    path = path or C.AUDIT_LOG
    if not path.exists():
        return dict(ok=True, records=0)
    prev = "0" * 64
    for i, line in enumerate(path.read_text().strip().splitlines(), 1):
        r = json.loads(line)
        h = hashlib.sha256(json.dumps({k: r[k] for k in ("ts", "event", "payload", "prev")}, sort_keys=True).encode()).hexdigest()
        if r["prev"] != prev or r["hash"] != h:
            return dict(ok=False, first_bad_record=i)
        prev = r["hash"]
    return dict(ok=True, records=i)


# ------------------------------------------------------------------ decisions store
def load_decisions(path=None) -> list[Decision]:
    path = path or C.DECISIONS_JSON
    return [Decision(**d) for d in json.load(open(path))] if path.exists() else []


def save_decisions(ds: list[Decision], path=None):
    path = path or C.DECISIONS_JSON
    path.parent.mkdir(parents=True, exist_ok=True)
    json.dump([d.model_dump() for d in ds], open(path, "w"), indent=1)


def propose(reports: list[AnalystReport], audit_path=None) -> list[Decision]:
    out = []
    for r in reports:
        verified = bool(r.verification.get("passed", False))
        for k, a in enumerate(r.recommended_actions, 1):
            if a.action_id not in CATALOGUE:                       # defence in depth: never create a proposal outside the catalogue
                audit("proposal_rejected_unknown_action", dict(incident=r.incident_id, action=a.action_id), audit_path)
                continue
            d = Decision(decision_id=f"{r.incident_id}-A{k:02d}", incident_id=r.incident_id, action_id=a.action_id, target=a.target, status="proposed",
                         needs_two_person=CATALOGUE[a.action_id].impact == "high", report_verified=verified, rationale=a.rationale, evidence_ids=a.evidence_ids)
            out.append(d)
            audit("proposed", d.model_dump(), audit_path)
    return out


def decide(decisions: list[Decision], decision_id: str, approve: bool, user: str, note: str = "", override: bool = False, audit_path=None) -> Decision:
    d = next(x for x in decisions if x.decision_id == decision_id)
    if d.status in ("rejected", "executed_simulated"):
        raise ValueError(f"{decision_id} is already {d.status}")
    if not user.strip():
        raise ValueError("an approver identity is required")
    if not approve:
        d.status, d.decided_by, d.decided_at, d.note = "rejected", user, _now(), note
        audit("rejected", dict(decision=decision_id, by=user, note=note), audit_path)
        return d
    if not d.report_verified and not override:
        raise PermissionError("analyst report failed verification; explicit override required")
    if user in d.approvers:
        raise PermissionError(f"{user} already approved {decision_id}; a different approver is required")
    d.approvers.append(user)
    d.decided_by, d.decided_at, d.note = user, _now(), note
    need = 2 if d.needs_two_person else 1
    if len(d.approvers) >= need:
        d.status = "approved"
    audit("approved" if d.status == "approved" else "approval_recorded", dict(decision=decision_id, by=user, approvers=d.approvers, needed=need, override=override), audit_path)
    return d


def execute_simulated(d: Decision, audit_path=None) -> str:
    if d.status != "approved":
        raise PermissionError("only approved decisions can be (simulated-)executed")
    a = CATALOGUE[d.action_id]
    msg = f"[DRY RUN] would run '{a.label}' on {d.target or 'n/a'} (impact={a.impact}, reversible={a.reversible})"
    d.status = "executed_simulated"
    audit("executed_simulated", dict(decision=d.decision_id, message=msg), audit_path)
    return msg


def run(reset: bool = False):
    """Create proposals for new report actions; existing decisions (and their approvals) are preserved unless reset=True."""
    reports = [AnalystReport(**r) for r in json.load(open(C.ANALYST_JSON))]
    existing = [] if reset else load_decisions()
    have = {d.decision_id for d in existing}
    new = [d for d in propose(reports) if d.decision_id not in have]
    save_decisions(existing + new)
    print(f"{len(new)} new proposals ({len(existing)} kept) -> {C.DECISIONS_JSON}; audit log: {verify_audit_log()}")


if __name__ == "__main__":
    run()

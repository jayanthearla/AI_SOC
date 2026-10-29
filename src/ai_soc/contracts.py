"""Typed contracts between pipeline layers (pydantic v2).

    Detection Agent  --alerts.json / incidents.json-->  Threat Hunter  --enriched_alerts.json-->
    SOC Analyst (LLM) --analyst_reports.json-->  Human approval  --decisions.json + audit_log.jsonl

Each layer validates what it reads and what it writes, so an agent can be tested (or swapped for another model) in isolation
and every metric in the paper can be computed at a layer boundary.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Level = Literal["low", "medium", "high", "critical"]
Verdict = Literal["malicious", "suspicious", "benign", "unknown", "internal"]
IocType = Literal["ip", "domain", "url", "hash", "filename", "service", "account", "host"]


class Alert(BaseModel):
    """Output of Step 4 (alerts.json).  Extra keys are preserved."""
    model_config = ConfigDict(extra="allow")
    alert_id: str
    rule_id: str
    source: str = "sigma"
    title: str
    description: str = ""
    tactic: str
    technique: str
    level: str
    severity: str = ""
    risk_score: float = 0.0
    host: str
    user: str = ""
    first_seen: str
    last_seen: str
    event_count: int = 0
    evidence: list[str] = Field(default_factory=list)
    event_uids: list[str] = Field(default_factory=list)
    incident_id: Optional[str] = None


class Incident(BaseModel):
    model_config = ConfigDict(extra="allow")
    incident_id: str
    title: str
    risk_score: float
    severity: str
    hosts: list[str]
    users: list[str] = Field(default_factory=list)
    first_seen: str
    last_seen: str
    tactics_observed: list[str]
    techniques: list[str] = Field(default_factory=list)
    alert_ids: list[str]
    n_alerts: int
    timeline: list[str] = Field(default_factory=list)


class SourceVerdict(BaseModel):
    source: str
    verdict: Verdict
    detail: str = ""
    synthetic: bool = False          # True for lab/lab-annotated indicators (never present these as real-world CTI)


class IOC(BaseModel):
    type: IocType
    value: str
    internal: bool = False
    context: str = ""                # e.g. "network_connect dst of ALR-0003"
    alert_ids: list[str] = Field(default_factory=list)
    verdict: Verdict = "unknown"
    sources: list[SourceVerdict] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class TechniqueInfo(BaseModel):
    technique_id: str
    name: str = ""
    tactics: list[str] = Field(default_factory=list)
    description: str = ""
    known: bool = False                      # found in the ATT&CK knowledge base
    groups_using: list[str] = Field(default_factory=list)
    apt3_uses: Optional[bool] = None         # None = knowledge base not loaded
    empire_uses: Optional[bool] = None


class EnrichedAlert(BaseModel):
    alert: Alert
    iocs: list[IOC] = Field(default_factory=list)
    technique: Optional[TechniqueInfo] = None
    playbook_hits: list[str] = Field(default_factory=list)
    intel_confidence: Literal["low", "medium", "high"] = "low"
    intel_notes: list[str] = Field(default_factory=list)


class ActionProposal(BaseModel):
    action_id: str                            # must exist in response.actions.CATALOGUE
    target: str = ""
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class AttackMapping(BaseModel):
    technique_id: str
    tactic: str = ""
    evidence_ids: list[str] = Field(default_factory=list)


class AnalystReport(BaseModel):
    """What the (LLM) SOC analyst agent must return.  Verified by agents/verifier.py before a human sees it."""
    incident_id: str
    summary: str
    narrative: str
    attack_mapping: list[AttackMapping]
    risk_level: Level
    risk_score: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1)
    recommended_actions: list[ActionProposal]
    evidence_ids: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    # filled by the platform, not by the model
    model: str = ""
    provider: str = ""
    verification: dict = Field(default_factory=dict)


class Decision(BaseModel):
    decision_id: str
    incident_id: str
    action_id: str
    target: str
    status: Literal["proposed", "approved", "rejected", "executed_simulated"]
    decided_by: str = ""
    decided_at: str = ""
    note: str = ""
    approvers: list[str] = Field(default_factory=list)
    needs_two_person: bool = False          # high-impact actions need two distinct approvers
    report_verified: bool = True            # False = analyst report failed programmatic verification
    rationale: str = ""
    evidence_ids: list[str] = Field(default_factory=list)

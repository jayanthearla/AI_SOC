"""Step 7 - Closed catalogue of response actions.

The LLM may only *propose* ids from this list (the verifier rejects anything else).  Every action requires explicit human
approval, and execution in this project is SIMULATED (dry-run): nothing here ever touches a real host.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Action:
    id: str
    label: str
    impact: str                 # low | medium | high  (operational blast radius)
    reversible: bool
    description: str
    target_kind: str            # host | account | ip | process | file | rule | none


_A = [
    Action("isolate_endpoint", "Isolate endpoint", "high", True, "Cut the host off from the network except the management channel.", "host"),
    Action("reset_credentials", "Reset credentials", "medium", False, "Force password reset / revoke sessions and tokens for the account.", "account"),
    Action("disable_account", "Disable account", "high", True, "Disable the user account pending investigation.", "account"),
    Action("block_ip", "Block IP at firewall/proxy", "medium", True, "Block the destination IP/domain at the perimeter.", "ip"),
    Action("kill_process", "Terminate process tree", "medium", False, "Terminate the malicious process and its children.", "process"),
    Action("quarantine_file", "Quarantine file", "low", True, "Move the file to quarantine and preserve a copy for analysis.", "file"),
    Action("remove_persistence", "Remove persistence", "medium", False, "Delete the malicious service / scheduled task / registry autorun / replaced binary.", "host"),
    Action("collect_forensic_triage", "Collect forensic triage", "low", True, "Acquire memory, event logs and autoruns from the host.", "host"),
    Action("hunt_similar_activity", "Hunt for similar activity", "low", True, "Search all hosts for the same IOCs / behaviours.", "none"),
    Action("create_detection_rule", "Create detection rule", "low", True, "Turn the observed behaviour into a new detection rule.", "rule"),
    Action("monitor_and_review", "Monitor and review", "low", True, "Keep watching; escalate if related alerts appear.", "none"),
    Action("close_false_positive", "Close as false positive", "low", True, "Close the incident with analyst justification.", "none"),
]
CATALOGUE = {a.id: a for a in _A}


def describe() -> str:
    return "\n".join(f"- {a.id}: {a.description} (impact={a.impact}, reversible={a.reversible}, target={a.target_kind})" for a in _A)

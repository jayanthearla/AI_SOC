"""MITRE ATT&CK knowledge base (Step 5).  Loads the slim JSON built from the official STIX bundle; falls back to a tiny
built-in table (technique names/tactics only - no group claims) when the bundle has not been downloaded."""
from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from ai_soc import config as C

SLIM = C.INTEL_DIR / "attack_slim.json"

# Fallback: only names + tactics for techniques used by the rules / ground truth. Group relations need the real bundle.
_MINI = {
    "T1189": ("Drive-by Compromise", ["initial-access"]), "T1204.002": ("User Execution: Malicious File", ["execution"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["execution"]),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", ["execution"]),
    "T1027": ("Obfuscated Files or Information", ["defense-evasion"]), "T1564.003": ("Hide Artifacts: Hidden Window", ["defense-evasion"]),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", ["defense-evasion"]), "T1105": ("Ingress Tool Transfer", ["command-and-control"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["command-and-control"]),
    "T1087": ("Account Discovery", ["discovery"]), "T1082": ("System Information Discovery", ["discovery"]),
    "T1110.003": ("Brute Force: Password Spraying", ["credential-access"]),
    "T1021": ("Remote Services", ["lateral-movement"]), "T1021.001": ("Remote Services: Remote Desktop Protocol", ["lateral-movement"]),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ["lateral-movement"]),
    "T1546.008": ("Event Triggered Execution: Accessibility Features", ["privilege-escalation", "persistence"]),
    "T1543.003": ("Create or Modify System Process: Windows Service", ["persistence", "privilege-escalation"]),
    "T1074.001": ("Data Staged: Local Data Staging", ["collection"]),
    "T1222.001": ("File and Directory Permissions Modification: Windows File and Directory Permissions Modification", ["defense-evasion"]),
    "T1048.003": ("Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol", ["exfiltration"]),
    "T1560.001": ("Archive Collected Data: Archive via Utility", ["collection"]),
}


def build_slim(stix_path: Path, out_path: Path) -> Path:
    d = json.load(open(stix_path, encoding="utf-8"))
    objs = d["objects"]
    by_id = {o["id"]: o for o in objs}
    ext = lambda o: next((r.get("external_id") for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
    ok = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    tech = {}
    for o in objs:
        if o["type"] == "attack-pattern" and ok(o) and ext(o):
            tech[o["id"]] = dict(id=ext(o), name=o["name"], tactics=[p["phase_name"] for p in o.get("kill_chain_phases", [])],
                                 description=(o.get("description") or "")[:900].replace("\n", " "), platforms=o.get("x_mitre_platforms", []))
    groups = {o["id"]: dict(id=ext(o), name=o["name"], aliases=o.get("aliases", []), techniques=set(), software=set())
              for o in objs if o["type"] == "intrusion-set" and ok(o)}
    soft = {o["id"]: dict(id=ext(o), name=o["name"], techniques=set()) for o in objs if o["type"] in ("malware", "tool") and ok(o)}
    for o in objs:
        if o["type"] != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
            continue
        s, t = o["source_ref"], o["target_ref"]
        if t in tech and s in groups:
            groups[s]["techniques"].add(tech[t]["id"])
        elif t in tech and s in soft:
            soft[s]["techniques"].add(tech[t]["id"])
        elif s in groups and t in soft:
            groups[s]["software"].add(soft[t]["name"])
    slim = dict(meta=dict(source="mitre-attack/attack-stix-data enterprise-attack", built=str(date.today()),
                          spec=d.get("spec_version", "")),
                techniques={v["id"]: v for v in tech.values()},
                groups=[dict(g, techniques=sorted(g["techniques"]), software=sorted(g["software"])) for g in groups.values()],
                software=[dict(s, techniques=sorted(s["techniques"])) for s in soft.values()])
    out_path.write_text(json.dumps(slim, separators=(",", ":")))
    return out_path


class AttackKB:
    def __init__(self, path: Path | None = None):
        path = Path(path or SLIM)
        self.full = path.exists()
        if self.full:
            d = json.load(open(path, encoding="utf-8"))
            self.meta = d["meta"]
            self.techniques = d["techniques"]
            self.groups = {g["name"].lower(): g for g in d["groups"]}
            for g in d["groups"]:
                for a in g.get("aliases", []):
                    self.groups.setdefault(a.lower(), g)
            self.software = {s["name"].lower(): s for s in d["software"]}
        else:
            self.meta = dict(source="built-in minimal table (no group data)")
            self.techniques = {k: dict(id=k, name=v[0], tactics=v[1], description="", platforms=[]) for k, v in _MINI.items()}
            self.groups, self.software = {}, {}

    def technique(self, tid: str) -> dict | None:
        return self.techniques.get(tid) or self.techniques.get(tid.split(".")[0])

    def groups_using(self, tid: str) -> list[str]:
        seen, out = set(), []
        for g in self.groups.values():
            if g["id"] not in seen and tid in g["techniques"]:
                seen.add(g["id"])
                out.append(g["name"])
        return sorted(out)

    def group_uses(self, group: str, tid: str) -> bool | None:
        if not self.full:
            return None
        g = self.groups.get(group.lower())
        if not g:
            return None
        return tid in g["techniques"] or tid.split(".")[0] in g["techniques"]

    def software_uses(self, name: str, tid: str) -> bool | None:
        if not self.full:
            return None
        s = self.software.get(name.lower())
        return None if not s else tid in s["techniques"]

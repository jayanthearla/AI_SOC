"""E3 baseline - run UNMODIFIED public SigmaHQ rules through the same evaluation harness.

Why: your own rules were written while looking at this dataset (circular).  An off-the-shelf community rule set is
the fairest reference point.  This module converts SigmaHQ YAML into the sigma_lite dialect and executes it against
the normalized events; rules it cannot express faithfully are SKIPPED and counted (report the skip statistics in the paper).

Supported : logsource categories process_creation, network_connection, file_event, registry_*, image_load,
            process_access, create_remote_thread, pipe_created, dns_query, ps_script
            modifiers contains/startswith/endswith/re/contains|all/windash/cased, wildcards (*, ?), null/empty values,
            list-of-maps selections, conditions with and/or/not/parentheses/'1 of x*'/'all of them'
Skipped   : keywords, aggregations (| count), base64offset/cidr/fieldref/expand/exists/lt/gt modifiers, unknown fields,
            unsupported logsources (Security/System service channels, WMI, etc.)

    python scripts/fetch_sigmahq.py && python -m ai_soc.evaluation.baselines.sigmahq
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pandas as pd
import yaml

from ai_soc import config as C
from ai_soc.detection import engine, sigma_lite

RULE_DIR = C.ROOT / "baselines" / "sigmahq" / "rules"

CATEGORY_TO_EVENT = {
    "process_creation": "process_create", "network_connection": "network_connect", "file_event": "file_create",
    "registry_set": "registry_event", "registry_event": "registry_event", "registry_add": "registry_event",
    "registry_delete": "registry_event", "image_load": "image_load", "process_access": "process_access",
    "create_remote_thread": "remote_thread", "pipe_created": "pipe_event", "dns_query": "dns_query",
    "ps_script": "ps_scriptblock",
}
_COMMON = {"Image": "process_path", "User": "user"}
FIELD_MAP = {
    "process_create": {**_COMMON, "CommandLine": "command_line", "ParentImage": "parent_path",
                       "ParentCommandLine": "parent_command_line", "IntegrityLevel": "integrity_level", "Hashes": "hashes",
                       "OriginalFileName": "original_file_name", "CurrentDirectory": "current_directory",
                       "Description": "description", "Product": "product", "Company": "company"},
    "network_connect": {**_COMMON, "DestinationIp": "dst_ip", "DestinationPort": "dst_port", "SourceIp": "src_ip",
                        "SourcePort": "src_port", "Protocol": "protocol", "Initiated": None},
    "file_create": {**_COMMON, "TargetFilename": "file_path"},
    "registry_event": {**_COMMON, "TargetObject": "registry_key"},
    "image_load": {**_COMMON, "ImageLoaded": "file_path"},
    "process_access": {"SourceImage": "process_path", "TargetImage": "target_process", "GrantedAccess": "granted_access"},
    "remote_thread": {"SourceImage": "process_path", "TargetImage": "target_process"},
    "pipe_event": {**_COMMON},
    "dns_query": {**_COMMON},
    "ps_scriptblock": {"ScriptBlockText": "script_block"},
}
TACTICS = {"initial-access": "Initial Access", "execution": "Execution", "persistence": "Persistence",
           "privilege-escalation": "Privilege Escalation", "defense-evasion": "Defense Evasion", "stealth": "Defense Evasion",
           "credential-access": "Credential Access", "discovery": "Discovery", "lateral-movement": "Lateral Movement",
           "collection": "Collection", "command-and-control": "Command and Control", "exfiltration": "Exfiltration",
           "impact": "Impact", "resource-development": "Resource Development", "reconnaissance": "Reconnaissance"}
_OK_MODS = {"contains", "startswith", "endswith", "re", "all", "windash", "cased"}


class Skip(Exception):
    pass


def _wild_to_regex(v: str, mode: str) -> str:
    esc = re.escape(v).replace(r"\*", ".*").replace(r"\?", ".")
    return {"contains": esc, "startswith": "^" + esc, "endswith": esc + "$", "": "^" + esc + "$"}[mode]


def _convert_value_key(key: str, val):
    """('Image|endswith', ['a','b']) -> (sigma_lite_key, sigma_lite_value)"""
    field, *mods = key.split("|")
    bad = set(mods) - _OK_MODS
    if bad:
        raise Skip(f"modifier:{sorted(bad)[0]}")
    vals = val if isinstance(val, list) else [val]
    vals = ["" if v is None else str(v) if not isinstance(v, bool) else v for v in vals]
    if any(isinstance(v, bool) for v in vals):
        raise Skip("bool_value")
    mode = next((m for m in mods if m in ("contains", "startswith", "endswith", "re")), "")
    allm, windash = "all" in mods, "windash" in mods
    if allm and mode != "contains":
        raise Skip("all_modifier")
    if allm and windash:
        raise Skip("windash_all")
    if mode == "re":
        return field, "re", vals
    if windash:
        vals = [_wild_to_regex(v, mode or "").replace(r"\-", "[-/]") for v in vals]   # re.escape turns - into \-
        return field, "re", vals
    if mode == "":
        if any(("*" in v or "?" in v) for v in vals):
            return field, "re", [_wild_to_regex(v, "") for v in vals]
        return field, "", vals
    if any(("*" in v or "?" in v) for v in vals):
        return field, "re", [_wild_to_regex(v, mode) for v in vals]
    return field, ("contains_all" if allm else mode), vals


def _convert_selection(sel, fmap):
    if not isinstance(sel, dict):
        raise Skip("keywords_selection")
    out = {}
    for key, val in sel.items():
        field = key.split("|")[0]
        if field not in fmap:
            raise Skip(f"field:{field}")
        col = fmap[field]
        if col is None:                      # ignorable (e.g. Initiated)
            continue
        f, mod, vals = _convert_value_key(key, val)
        k = f"{col}|{mod}" if mod else col
        if k in out:
            raise Skip("duplicate_field")
        out[k] = vals if len(vals) > 1 else vals[0]
    return out


def convert_rule(rule: dict) -> dict:
    ls = rule.get("logsource", {})
    cat = ls.get("category")
    if cat not in CATEGORY_TO_EVENT:
        raise Skip(f"logsource:{cat or ls.get('service', '?')}")
    etype = CATEGORY_TO_EVENT[cat]
    fmap = FIELD_MAP[etype]
    det = rule.get("detection") or {}
    cond = det.get("condition")
    if not isinstance(cond, str):
        raise Skip("multi_condition")
    if "|" in cond:
        raise Skip("aggregation")
    new, groups = {}, {}
    for name, sel in det.items():
        if name in ("condition", "timeframe"):
            continue
        if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel):
            names = []
            for i, m in enumerate(sel):
                nm = f"{name}__{i}"
                new[nm] = _convert_selection(m, fmap)
                names.append(nm)
            groups[name] = names
        else:
            new[name] = _convert_selection(sel, fmap)
    allnames = list(new)
    cond = re.sub(r"\b(1|all) of them\b", lambda m: "(" + (" or " if m.group(1) == "1" else " and ").join(allnames) + ")", cond)
    for g, names in groups.items():
        cond = re.sub(rf"(?<![\w*]){re.escape(g)}(?![\w*])", "(" + " or ".join(names) + ")", cond)
    tags = [t.lower() for t in rule.get("tags", []) if isinstance(t, str)]
    tech = next((t[7:].upper() for t in tags if re.match(r"attack\.t\d{4}", t)), "n/a")
    tac = next((TACTICS[t[7:]] for t in tags if t.startswith("attack.") and t[7:] in TACTICS), "Unknown")
    return dict(id="SGMA-" + str(rule.get("id", ""))[:8], title=rule.get("title", ""), description=(rule.get("description") or "")[:200],
                tactic=tac, technique=tech, level=rule.get("level", "medium") if rule.get("level") in ("low", "medium", "high", "critical") else "medium",
                logsource={"event_type": etype}, detection={**new, "condition": cond})


def load_converted(rule_dir: Path = RULE_DIR):
    rules, skipped, total = [], Counter(), 0
    for f in sorted(Path(rule_dir).rglob("*.yml")):
        try:
            raw = yaml.safe_load(open(f, encoding="utf-8"))
        except Exception:
            skipped["yaml_error"] += 1
            continue
        if not isinstance(raw, dict) or "detection" not in raw:
            continue
        total += 1
        try:
            rules.append(convert_rule(raw))
        except Skip as e:
            skipped[str(e).split(":")[0] + (":" + str(e).split(":")[1] if str(e).startswith("logsource") else "")] += 1
        except Exception:
            skipped["convert_error"] += 1
    return rules, dict(total=total, converted=len(rules), skipped=dict(skipped.most_common()))


def run_baseline(df, rules):
    """Execute converted rules; group hits per rule+host like run_sigma. Returns (alerts, hits, stats)."""
    alerts, hits, errors, fired = [], [], 0, 0
    levels = {"low": 0.3, "medium": 0.5, "high": 0.75, "critical": 0.9}
    for r in rules:
        try:
            m = sigma_lite.run_rules(df, [r])[r["id"]]
        except Exception:
            errors += 1
            continue
        if not m.any():
            continue
        fired += 1
        h = df[m]
        hits += [(r["id"], u) for u in h.event_uid]
        for _, g in h.groupby("host"):
            for grp in engine.split_by_gap(g):
                alerts.append(engine.make_alert(r, grp))
    alerts.sort(key=lambda a: a["first_seen"])
    for i, a in enumerate(alerts, 1):
        a["alert_id"], a["risk_score"] = f"SGMA-{i:04d}", levels[a["level"]]
    return alerts, hits, dict(rules_executed=len(rules), rules_fired=fired, rule_errors=errors)


def run():
    from ai_soc.evaluation import eval_detection as E
    if not RULE_DIR.exists():
        raise SystemExit("SigmaHQ rules not found - run: python scripts/fetch_sigmahq.py")
    df, gt, steps_cfg, st, _, _, _ = E.load_all()
    rules, conv = load_converted()
    alerts, hits, ex = run_baseline(df, rules)
    res = E.evaluate(alerts, hits, [], df, gt, steps_cfg, st, name="SigmaHQ (unmodified, converted subset)")
    res["baseline_stats"] = {**conv, **ex}
    C.RESULTS_DIR.mkdir(exist_ok=True)
    json.dump(res, open(C.RESULTS_DIR / "e3_sigmahq.json", "w"), indent=1, default=str)
    E.write_report(res, C.REPORT_DIR / "e3_sigmahq_report.md")
    print(json.dumps(res["baseline_stats"], indent=1))
    print(json.dumps(E.summarize_row(res), indent=1))
    return res


if __name__ == "__main__":
    run()

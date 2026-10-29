"""
sigma_lite - a tiny, dependency-free evaluator for Sigma-style YAML rules.

It runs rules against the normalized DataFrame (vectorised with pandas) and returns, for every
rule, a boolean mask of matching events.  It deliberately supports only what this project needs:

  * field modifiers: contains, contains_all, startswith, endswith, re   (case-insensitive)
  * list value = OR, several fields = AND, boolean values (field: true)
  * condition:  and / or / not / parentheses / "1 of sel_*" / "all of sel_*"

For production use, convert to full Sigma with pySigma (see README "Next steps").
"""
import re
import warnings

import pandas as pd
import yaml

warnings.filterwarnings("ignore", message="This pattern is interpreted as a regular expression")


def load_rules(path):
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_rulesets(directory, names):
    """Load several rule files; a later rule with the same id overrides an earlier one (used by candidates_v2.yml)."""
    merged = {}
    for n in names:
        for r in load_rules(f"{directory}/{n.strip()}") or []:
            merged[r["id"]] = r
    return list(merged.values())


def _field_mask(df, key, expected):
    field, _, mod = key.partition("|")
    if field not in df.columns:
        return pd.Series(False, index=df.index)
    col = df[field]
    if isinstance(expected, bool):
        return col.astype(str).str.lower().eq(str(expected).lower())
    values = expected if isinstance(expected, list) else [expected]
    s = col.fillna("").astype(str).str.lower()
    vals = [str(v) if mod == "re" else str(v).lower() for v in values]
    if mod == "contains":
        m = pd.Series(False, index=df.index)
        for v in vals:
            m |= s.str.contains(v, regex=False)
    elif mod == "contains_all":
        m = pd.Series(True, index=df.index)
        for v in vals:
            m &= s.str.contains(v, regex=False)
    elif mod == "startswith":
        m = pd.Series(False, index=df.index)
        for v in vals:
            m |= s.str.startswith(v)
    elif mod == "endswith":
        m = pd.Series(False, index=df.index)
        for v in vals:
            m |= s.str.endswith(v)
    elif mod == "re":
        m = pd.Series(False, index=df.index)
        for v in vals:
            m |= s.str.contains(v, regex=True, flags=re.I)
    else:  # exact match
        m = s.isin(vals)
    return m


def _selection_mask(df, sel):
    m = pd.Series(True, index=df.index)
    for key, expected in sel.items():
        m &= _field_mask(df, key, expected)
    return m


def _eval_condition(cond, masks):
    # expand "1 of sel_*" / "all of sel_*"
    def expand(match):
        quant, prefix = match.group(1), match.group(2)
        names = [n for n in masks if n.startswith(prefix)]
        joiner = " or " if quant == "1" else " and "
        return "(" + joiner.join(names) + ")"
    cond = re.sub(r"\b(1|all) of (\w+?)\*", expand, cond)
    expr = re.sub(r"\band\b", "&", cond)
    expr = re.sub(r"\bor\b", "|", expr)
    expr = re.sub(r"\bnot\b", "~", expr)
    return eval(expr, {"__builtins__": {}}, dict(masks))   # masks are pandas bool Series only


def run_rules(df, rules):
    """Return {rule_id: boolean Series} for every rule."""
    results = {}
    for rule in rules:
        scope = df.event_type == rule["logsource"]["event_type"]
        sub = df[scope]
        masks = {name: _selection_mask(sub, sel) for name, sel in rule["detection"].items() if name != "condition"}
        hit = _eval_condition(rule["detection"]["condition"], masks)
        full = pd.Series(False, index=df.index)
        full.loc[sub.index] = hit
        results[rule["id"]] = full
    return results

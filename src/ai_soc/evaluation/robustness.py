"""E6 - Evasion robustness: mutate the normalized events the way an adversary (or a different environment) would, recompute
features, re-run the rule layers, and measure how much detection drops.  A rule set that only works on the exact strings
seen in the development run will collapse here; that is the point of the experiment.

Mutations (event content only; chains/sessions are NOT recomputed, so parent-spoofing is a test of rule logic):
  rename_powershell   powershell.exe -> ps_helper.exe          (binary rename)
  rename_net          net.exe / net1.exe -> nx.exe / nx1.exe
  short_enc_flag      -EncodedCommand/-enc -> -e                 (PowerShell accepts unambiguous prefixes)
  caret_obfuscation   n^et u^se, who^ami, in command lines     (cmd.exe escape insertion)
  parent_spoof        script-engine parents rewritten to explorer.exe
  no_scriptblock_log  script block text removed                 (logging disabled / not collected)
  path_masquerade     user-writable paths -> C:\\Windows\\System32\\  (drops the path features)

    python -m ai_soc.evaluation.robustness
"""
from __future__ import annotations

import json
import re

import pandas as pd

from ai_soc import config as C
from ai_soc.detection import engine
from ai_soc.evaluation import eval_detection as E
from ai_soc.features import normalizer


def _swap(df, col, pat, rep, flags=re.I):
    df[col] = df[col].str.replace(pat, rep, regex=True, flags=flags)


def m_rename_powershell(df):
    for c in ("process_path", "parent_path", "command_line", "parent_command_line"):
        _swap(df, c, r"powershell\.exe", "ps_helper.exe")
    df["process"] = df.process_path.map(normalizer.base)
    df["parent_process"] = df.parent_path.map(normalizer.base)


def m_rename_net(df):
    for c in ("process_path", "parent_path"):
        _swap(df, c, r"\\net1?\.exe$", lambda m: m.group(0).replace("net", "nx"))
    df["process"] = df.process_path.map(normalizer.base)
    df["parent_process"] = df.parent_path.map(normalizer.base)


def m_short_enc(df):
    _swap(df, "command_line", r"-enc(?:odedcommand)?\b", "-e")


def m_caret(df):
    _swap(df, "command_line", r"\bnet use\b", "n^et u^se")
    _swap(df, "command_line", r"\bwhoami\b", "who^ami")
    _swap(df, "command_line", r"\bipconfig\b", "ip^config")


def m_parent_spoof(df):
    m = df.parent_process.isin(["wscript.exe", "cscript.exe", "powershell.exe", "cmd.exe"])
    df.loc[m, "parent_path"] = "C:\\Windows\\explorer.exe"
    df.loc[m, "parent_process"] = "explorer.exe"


def m_no_sb(df):
    df["script_block"] = ""


def m_path(df):
    df["process_path"] = df.process_path.str.replace(r"(?i)^c:\\(users|programdata)\\.*\\", r"C:\\Windows\\System32\\", regex=True)
    df["process"] = df.process_path.map(normalizer.base)


MUTATIONS = {"baseline (no mutation)": None, "rename_powershell": m_rename_powershell, "rename_net": m_rename_net,
             "short_enc_flag": m_short_enc, "caret_obfuscation": m_caret, "parent_spoof": m_parent_spoof,
             "no_scriptblock_log": m_no_sb, "path_masquerade": m_path}


def run():
    df0, gt, steps_cfg, st, _, _, _ = E.load_all()
    rules = engine.sigma_lite.load_rulesets(C.RULES_DIR, C.RULESETS)
    lat = engine.load_lateral()
    empty_ml = pd.DataFrame({"event_uid": [], "ml_score": []})
    rows = {}
    for name, fn in MUTATIONS.items():
        df = df0.copy()
        if fn:
            fn(df)
            normalizer.add_features(df)
        raw, hits, _ = engine.detect_rules(df, rules, lat)
        alerts = engine.fuse(raw, df, empty_ml)
        r = E.evaluate(alerts, hits, None, df0, gt, steps_cfg, st, name=name)
        rows[name] = E.summarize_row(r)
    base = rows["baseline (no mutation)"]
    f = lambda x: "n/a" if x is None or x != x else f"{x:.3f}"
    L = ["# E6 - Evasion robustness (rule layers only, no ML)", "",
         "| mutation | alerts | proc recall | d recall | step detection | d steps | technique cov (exact) | alert precision |", "|---|---|---|---|---|---|---|---|"]
    for n, r in rows.items():
        L.append(f"| {n} | {r['alerts']} | {f(r['proc_recall'])} | {r['proc_recall'] - base['proc_recall']:+.3f} | {f(r['step_detection'])} | {r['step_detection'] - base['step_detection']:+.3f} | {f(r['tech_cov_exact'])} | {f(r['alert_precision'])} |")
    C.RESULTS_DIR.mkdir(exist_ok=True)
    json.dump(rows, open(C.RESULTS_DIR / "e6_robustness.json", "w"), indent=1, default=str)
    (C.REPORT_DIR / "e6_robustness.md").write_text("\n".join(L))
    print("\n".join(L))
    return rows


if __name__ == "__main__":
    run()

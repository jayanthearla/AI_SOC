"""
STEP 2 - Feature Extraction & Normalization
-------------------------------------------
Reads the raw winlogbeat JSON-lines file (one event per line) and converts every
event into ONE flat row with a common schema, so events from Sysmon, Security,
PowerShell, System and WMI logs become searchable and comparable.

Output: outputs/normalized_events.csv.gz  (+ outputs/reports/step2_schema_report.md)

Usage:  python src/feature_extraction.py [--input path/to/file.json]
"""
import argparse
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path

import pandas as pd

from ai_soc import config as C

B64_BLOB = re.compile(r"[A-Za-z0-9+/=]{40,}")
ENC_FLAG = re.compile(r"(?:^|\s)-(?:e|en|enc|enco|encod\w*|ec)\s+[A-Za-z0-9+/=]{10,}", re.I)
DOWNLOAD = re.compile(r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|iwr |"
                      r"start-bitstransfer|invoke-expression|\biex\b|frombase64string", re.I)


def base(path):
    """Lower-case file name from a Windows path ('' if none)."""
    if not path or not isinstance(path, str):
        return ""
    return path.replace("/", "\\").split("\\")[-1].lower()


def entropy(s):
    """Shannon entropy of a string - high for encoded/obfuscated commands."""
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def short_user(u):
    """'SHIRE\\nmartha' -> 'nmartha' ; '' if unknown."""
    if not u or not isinstance(u, str):
        return ""
    return u.split("\\")[-1].strip().lower()


def parse_event(d):
    """Flatten one raw winlogbeat event into the common schema."""
    ed = d.get("event_data") or {}
    log, eid = d.get("log_name", ""), d.get("event_id")
    etype = C.EVENT_TYPES.get((log, eid), "other")
    top_user = d.get("user") or {}
    top_user_s = f"{top_user.get('domain','')}\\{top_user.get('name','')}" if top_user.get("name") else ""

    r = {
        "timestamp": d.get("@timestamp"),
        "host": (d.get("computer_name") or "").split(".")[0].upper(),
        "log_name": log.replace("Microsoft-Windows-", "").replace("/Operational", ""),
        "event_id": eid,
        "event_type": etype,
        "record_number": d.get("record_number"),
        "user": "", "target_user": "",
        "process": "", "process_path": "", "process_id": "", "process_guid": "",
        "parent_process": "", "parent_path": "", "parent_pid": "", "parent_guid": "",
        "command_line": "", "parent_command_line": "", "integrity_level": "", "hashes": "",
        "src_ip": "", "src_port": "", "dst_ip": "", "dst_port": "", "protocol": "",
        "file_path": "", "registry_key": "", "target_process": "", "granted_access": "",
        "logon_type": "", "logon_id": "", "auth_package": "", "remote_ip": "",
        "service_name": "", "service_path": "", "share_name": "", "script_block": "",
        # extra Sysmon-1 fields (needed by public Sigma rules: OriginalFileName, CurrentDirectory, ...)
        "original_file_name": "", "current_directory": "", "description": "", "product": "", "company": "",
    }

    if log == "Microsoft-Windows-Sysmon/Operational":
        r["user"] = ed.get("User", "")
        r["process_path"] = ed.get("Image") or ed.get("SourceImage") or ""
        r["process_guid"] = ed.get("ProcessGuid") or ed.get("SourceProcessGUID") or ed.get("SourceProcessGuid") or ""
        r["process_id"] = ed.get("ProcessId") or ed.get("SourceProcessId") or ""
        if eid == 1:
            r.update(parent_path=ed.get("ParentImage", ""), parent_guid=ed.get("ParentProcessGuid", ""),
                     parent_pid=ed.get("ParentProcessId", ""), command_line=ed.get("CommandLine", ""),
                     parent_command_line=ed.get("ParentCommandLine", ""),
                     integrity_level=ed.get("IntegrityLevel", ""), hashes=ed.get("Hashes", ""),
                     original_file_name=ed.get("OriginalFileName", ""), current_directory=ed.get("CurrentDirectory", ""),
                     description=ed.get("Description", ""), product=ed.get("Product", ""), company=ed.get("Company", ""))
        elif eid == 3:
            r.update(src_ip=ed.get("SourceIp", ""), src_port=ed.get("SourcePort", ""),
                     dst_ip=ed.get("DestinationIp", ""), dst_port=ed.get("DestinationPort", ""),
                     protocol=ed.get("Protocol", ""))
        elif eid == 10:
            r.update(target_process=ed.get("TargetImage", ""), granted_access=ed.get("GrantedAccess", ""))
        elif eid == 8:
            r.update(target_process=ed.get("TargetImage", ""))
        elif eid == 11:
            r["file_path"] = ed.get("TargetFilename", "")
        elif eid in (12, 13, 14):
            r["registry_key"] = ed.get("TargetObject", "")
        elif eid == 7:
            r["file_path"] = ed.get("ImageLoaded", "")
    elif log == "Security":
        if eid == 4688:
            r.update(user=ed.get("SubjectUserName", ""), process_path=ed.get("NewProcessName", ""),
                     process_id=ed.get("NewProcessId", ""), parent_path=ed.get("ParentProcessName", ""),
                     command_line=ed.get("CommandLine", ""))
        elif eid in (4624, 4625):
            r.update(user=ed.get("TargetUserName", ""), logon_type=ed.get("LogonType", ""),
                     logon_id=ed.get("TargetLogonId", ""), auth_package=ed.get("AuthenticationPackageName", ""),
                     remote_ip=ed.get("IpAddress", ""), process_path=ed.get("ProcessName", ""))
        elif eid == 4648:
            r.update(user=ed.get("SubjectUserName", ""), target_user=ed.get("TargetUserName", ""),
                     remote_ip=ed.get("IpAddress", ""), service_name=ed.get("TargetServerName", ""),
                     process_path=ed.get("ProcessName", ""))
        elif eid in (4768, 4769, 4776):
            r.update(user=ed.get("TargetUserName", ""), remote_ip=ed.get("IpAddress", ""))
        elif eid == 4697:
            r.update(user=ed.get("SubjectUserName", ""), service_name=ed.get("ServiceName", ""),
                     service_path=ed.get("ServiceFileName", ""))
        elif eid == 5145:
            r.update(user=ed.get("SubjectUserName", ""), remote_ip=ed.get("IpAddress", ""),
                     share_name=ed.get("ShareName", ""), file_path=ed.get("RelativeTargetName", ""))
        elif eid in (5156, 5158):
            # WFP connection / bind: Application is an NT path (\\device\\harddiskvolumeN\\...)
            r.update(process_path=ed.get("Application", ""), process_id=ed.get("ProcessId", ""),
                     src_ip=ed.get("SourceAddress", ""), src_port=ed.get("SourcePort", ""),
                     dst_ip=ed.get("DestAddress", ""), dst_port=ed.get("DestPort", ""),
                     protocol=ed.get("Protocol", ""))
        else:
            r["user"] = ed.get("SubjectUserName", "") or ed.get("TargetUserName", "")
    elif log == "System" and eid == 7045:
        r.update(user="", target_user=ed.get("AccountName", ""), service_name=ed.get("ServiceName", ""),
                 service_path=ed.get("ImagePath", ""))
    elif eid == 4104:
        r["script_block"] = (ed.get("ScriptBlockText") or "")[:4000]
        r["user"] = top_user_s
    else:
        r["user"] = top_user_s

    r["process"] = base(r["process_path"])
    r["parent_process"] = base(r["parent_path"])
    return r


def add_features(df):
    """Engineered, model-friendly features (computed per row)."""
    cl = df["command_line"].fillna("")
    sb = df["script_block"].fillna("")
    path = df["process_path"].fillna("").str.lower()
    df["user_short"] = df["user"].map(short_user)
    df["cmd_len"] = cl.str.len()
    df["cmd_n_args"] = cl.str.split().str.len().fillna(0).astype(int)
    df["cmd_entropy"] = cl.map(entropy).round(3)
    df["f_encoded_cmd"] = cl.map(lambda s: bool(ENC_FLAG.search(s)))
    df["f_hidden_window"] = cl.str.contains(r"-w(?:indowstyle)?\s+(?:1|hidden)\b", case=False, regex=True)
    df["f_no_profile"] = cl.str.contains(r"-nop(?:rofile)?\b", case=False, regex=True)
    df["f_bypass"] = cl.str.contains(r"-ep\s+bypass|executionpolicy\s+bypass", case=False, regex=True)
    df["f_b64_blob"] = cl.map(lambda s: bool(B64_BLOB.search(s)))
    df["f_download_cradle"] = (cl + " " + sb).map(lambda s: bool(DOWNLOAD.search(s)))
    df["f_lolbin"] = df["process"].isin(C.LOLBINS)
    df["f_parent_script_engine"] = df["parent_process"].isin(C.SCRIPT_ENGINES)
    df["f_parent_office"] = df["parent_process"].isin(C.OFFICE_APPS)
    df["f_user_writable_path"] = path.map(lambda p: any(k in p for k in C.USER_WRITABLE))
    df["f_system_user"] = df["user"].str.upper().str.contains("SYSTEM", na=False)
    df["sb_len"] = sb.str.len()
    ts = pd.to_datetime(df["timestamp"], utc=True)
    df["timestamp"] = ts
    df["hour"] = ts.dt.hour
    return df


def fill_users_from_guid(df):
    """Sysmon events other than 1/3 carry no user; recover it from the process GUID."""
    known = df[(df["user"] != "") & (df["process_guid"] != "") & (df["event_type"].isin(["process_create", "network_connect"]))]
    g2u = known.drop_duplicates("process_guid").set_index("process_guid")["user"].to_dict()
    mask = (df["user"] == "") & (df["process_guid"] != "")
    df.loc[mask, "user"] = df.loc[mask, "process_guid"].map(g2u).fillna("")
    return df


def run(src, dst):
    rows, bad = [], 0
    with open(src, encoding="utf-8") as fh:
        for i, line in enumerate(fh, 1):
            try:
                rows.append(parse_event(json.loads(line)))
            except json.JSONDecodeError:
                bad += 1
            if i % 40000 == 0:
                print(f"  parsed {i:,} events ...")
    df = pd.DataFrame(rows)
    df = add_features(df)
    df = fill_users_from_guid(df)
    df["user_short"] = df["user"].map(short_user)
    df = df.sort_values(["timestamp", "host", "record_number"]).reset_index(drop=True)
    df.insert(0, "event_uid", [f"E{i:06d}" for i in range(len(df))])
    dst.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(dst, index=False, compression="gzip")
    print(f"Step 2 done: {len(df):,} events ({bad} unparsable) x {df.shape[1]} columns -> {dst}")
    return df


def write_report(df):
    C.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["# Step 2 - Normalization report", "",
             f"- Events: **{len(df):,}**  |  Columns: **{df.shape[1]}**",
             f"- Time range (UTC): {df.timestamp.min()} -> {df.timestamp.max()}",
             f"- Hosts: {', '.join(sorted(df.host.unique()))}",
             f"- **Schema coverage** (events typed non-`other`): {100 * (df.event_type != 'other').mean():.1f}%", "",
             "## Events by normalized type", "", "| event_type | count |", "|---|---|"]
    for k, v in df.event_type.value_counts().items():
        lines.append(f"| {k} | {v:,} |")
    lines += ["", "## Events by host", "", "| host | count |", "|---|---|"]
    for k, v in df.host.value_counts().items():
        lines.append(f"| {k} | {v:,} |")
    lines += ["", "## Engineered feature hit counts", "", "| feature | rows true |", "|---|---|"]
    for c in [c for c in df.columns if c.startswith("f_")]:
        lines.append(f"| {c} | {int(df[c].sum()):,} |")
    lines += ["", "## Column list", "", ", ".join(f"`{c}`" for c in df.columns)]
    (C.REPORT_DIR / "step2_schema_report.md").write_text("\n".join(lines))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default=str(C.RAW_JSON))
    a = ap.parse_args()
    df = run(Path(a.input), C.EVENTS_CSV)
    write_report(df)

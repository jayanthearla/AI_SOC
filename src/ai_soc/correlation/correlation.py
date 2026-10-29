"""
STEP 3 - Event Correlation
--------------------------
Connects related events so that "one sequence may reveal an attack".

Three correlation layers are built:

 1. PROCESS CHAINS   - Sysmon process GUID / parent GUID lineage. Every process, network
                       connection, file write, registry write ... made by a process is tied
                       to the chain it belongs to (chain_id).  A chain starts at the first
                       process whose parent is "plumbing" (services.exe, explorer.exe ...).
 2. SESSIONS         - Per host, notable events (suspicious-looking process starts, service
                       installs, remote logons, file drops ...) that are <= GAP minutes
                       apart are grouped into one activity session (session_id).
 3. LATERAL LINKS    - Cross-host edges (host A -> host B) from explicit-credential logons,
                       remote logons and share access, using an IP -> host map learned from
                       the data itself.

Outputs (in outputs/):
  events_correlated.csv.gz  every event + chain_id + session_id
  process_chains.json       one record per chain (narrative, counts, endpoints ...)
  sessions.json             one record per host activity session
  lateral_links.csv         host -> host movement edges
  timeline.csv              analyst-friendly ordered timeline of notable events

Usage: python src/correlation.py
"""
import json
import re
import sys
from pathlib import Path

import pandas as pd

from ai_soc import config as C

SESSION_GAP_MIN = 10
SUSPICIOUS_EXT = (".vbs", ".exe", ".dll", ".bat", ".js", ".hta", ".scr", ".ps1")
NOISY_FILE_MARKERS = ("powershell_transcript", "__psscriptpolicytest", "\\microsoft\\windows\\powershell\\")
INTERESTING_ROOT_BINS = C.SCRIPT_ENGINES | {"rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"}


# ------------------------------------------------------------------ 1. process chains
def build_chains(df):
    proc = df[df.event_type == "process_create"].sort_values("timestamp")
    guid_row = {r.process_guid: r for r in proc.itertuples() if r.process_guid}
    chain_of, depth_of = {}, {}

    def resolve(guid):
        if guid in chain_of:
            return chain_of[guid]
        r = guid_row[guid]
        pg = r.parent_guid
        if pg and pg in guid_row and r.parent_process not in C.CHAIN_ANCHORS:
            root, d = resolve(pg), depth_of[pg] + 1
            chain_of[guid], depth_of[guid] = root, d
        else:
            chain_of[guid], depth_of[guid] = guid, 0
        return chain_of[guid]

    for g in guid_row:
        resolve(g)

    roots = sorted({v for v in chain_of.values()}, key=lambda g: guid_row[g].timestamp)
    cid = {g: f"CH-{i+1:04d}" for i, g in enumerate(roots)}
    df["chain_id"] = df["process_guid"].map(lambda g: cid.get(chain_of.get(g), ""))
    df["proc_depth"] = df["process_guid"].map(depth_of)
    return df, guid_row, cid


def summarize_chains(df):
    out = []
    ch = df[df.chain_id != ""]
    for cid, g in ch.groupby("chain_id"):
        p = g[g.event_type == "process_create"].sort_values("timestamp")
        if p.empty:
            continue
        root = p.iloc[0]
        net = g[g.event_type == "network_connect"]
        endpoints = (net.groupby(["dst_ip", "dst_port"]).size().sort_values(ascending=False).head(5)
                     .reset_index().apply(lambda r: f"{r.dst_ip}:{r.dst_port} x{r[0]}", axis=1).tolist()) if len(net) else []
        procs = p.groupby("process", sort=False).size()
        narrative = " -> ".join(f"{k}{'' if v == 1 else f' (x{v})'}" for k, v in procs.items())
        images = set(p["process"])
        out.append({
            "chain_id": cid, "host": root.host, "user": root.user, "root_process": root.process,
            "root_parent": root.parent_process, "start": str(g.timestamp.min()), "end": str(g.timestamp.max()),
            "duration_s": round((g.timestamp.max() - g.timestamp.min()).total_seconds(), 1),
            "n_processes": int(len(p)), "max_depth": int(p.proc_depth.max()), "n_events": int(len(g)),
            "events_by_type": g.event_type.value_counts().to_dict(),
            "narrative": f"{root.parent_process or '?'} => {narrative}",
            "network_endpoints": endpoints,
            "any_encoded_cmd": bool(p.f_encoded_cmd.any()),
            "notable": bool(images & INTERESTING_ROOT_BINS) or len(images & C.LOLBINS) >= 3,
            "sample_cmdlines": [c[:200] for c in p.command_line.head(4)],
        })
    return sorted(out, key=lambda r: r["start"])


# ------------------------------------------------------------------ 2. notable events + sessions
def mark_notable(df, notable_chains):
    in_notable = df.chain_id.isin(notable_chains)
    et = df.event_type
    is_proc = (et == "process_create") & in_notable & (df.process != "conhost.exe")
    is_net = (et == "network_connect") & in_notable
    is_svc = et == "service_install"
    is_rlogon = (et == "logon") & (((df.logon_type == "3") & (df.auth_package == "NTLM")) | (df.logon_type == "10"))
    is_xcred = (et == "explicit_cred_logon") & (~df.service_name.isin(["localhost", "-", ""])) & (~df.target_user.str.endswith("$"))
    fp = df.file_path.str.lower()
    is_file = (et == "file_create") & (
        (fp.str.endswith(SUSPICIOUS_EXT) | fp.str.contains("$recycle.bin|recycler|ftp.txt", regex=True))
        & ~fp.str.contains("|".join(re.escape(m) for m in NOISY_FILE_MARKERS), regex=True)
        & (in_notable | df.process.isin(C.SCRIPT_ENGINES) | fp.str.contains("\\\\windows\\\\system32\\\\", regex=True))
        & ~df.process.isin(["trustedinstaller.exe", "tiworker.exe", "msiexec.exe", "svchost.exe", "msedge.exe"]))
    is_sb = (et == "ps_scriptblock") & df.f_download_cradle
    df["notable"] = is_proc | is_net | is_svc | is_rlogon | is_xcred | is_file | is_sb
    df["notable_kind"] = ""
    for name, m in [("process", is_proc), ("network", is_net), ("service_install", is_svc), ("remote_logon", is_rlogon),
                    ("explicit_creds", is_xcred), ("file_drop", is_file), ("script_block", is_sb)]:
        df.loc[m & (df.notable_kind == ""), "notable_kind"] = name
    return df


def build_sessions(df):
    seeds = df[df.notable & (df.notable_kind != "network")].sort_values("timestamp")
    df["session_id"] = ""
    sessions, n = [], 0
    for host, g in seeds.groupby("host"):
        gap = g.timestamp.diff() > pd.Timedelta(minutes=SESSION_GAP_MIN)
        for _, s in g.groupby(gap.cumsum()):
            n += 1
            sid = f"SES-{n:03d}"
            start, end = s.timestamp.min(), s.timestamp.max()
            m = (df.host == host) & (df.timestamp >= start) & (df.timestamp <= end) & (df.chain_id.isin(s.chain_id[s.chain_id != ""]) | df.notable)
            df.loc[m, "session_id"] = sid
            sessions.append({
                "session_id": sid, "host": host, "start": str(start), "end": str(end),
                "duration_min": round((end - start).total_seconds() / 60, 1), "n_notable_events": int(len(s)),
                "users": sorted(set(s.user_short) - {""}), "chains": sorted(set(s.chain_id) - {""}),
                "kinds": s.notable_kind.value_counts().to_dict(),
                "processes": s[s.event_type == "process_create"].process.value_counts().head(8).to_dict(),
            })
    return df, sorted(sessions, key=lambda r: r["start"])


# ------------------------------------------------------------------ 3. lateral links
def build_ip_map(df):
    n = df[(df.event_type == "network_connect") & (df.src_ip != "")]
    n = n[n.src_ip.str.startswith("172.18.")]
    host2ip = n.groupby("host").src_ip.agg(lambda s: s.mode().iat[0]).to_dict()
    return {ip: host for host, ip in host2ip.items()}   # ip -> host


def build_lateral(df, ip2host):
    rows = []
    df = df.assign(remote_ip=df.remote_ip.str.replace("::ffff:", "", regex=False))
    # (a) explicit credentials sent to another server (4648: TargetServerName / cifs/HOST)
    x = df[(df.event_type == "explicit_cred_logon") & (~df.service_name.isin(["localhost", "-", ""])) & (~df.target_user.str.endswith("$"))]
    for r in x.itertuples():
        dst = r.service_name.split(".")[0].upper()
        if dst != r.host:
            rows.append((r.timestamp, r.host, dst, r.target_user.lower(), "explicit_credentials(4648)"))
    # (b) remote logons seen on the destination host (4624 type 3/10 from a known IP)
    l = df[(df.event_type == "logon") & df.logon_type.isin(["3", "10"]) & df.remote_ip.isin(ip2host)]
    for r in l.itertuples():
        src = ip2host[r.remote_ip]
        if src != r.host:
            rows.append((r.timestamp, src, r.host, r.user.lower(), f"remote_logon_type{r.logon_type}({r.auth_package})"))
    # (c) admin-share / IPC access (5145) from a known IP
    s = df[(df.event_type == "share_access") & df.remote_ip.isin(ip2host) & df.share_name.str.contains("ADMIN|IPC|C\\$", regex=True)]
    for r in s.itertuples():
        src = ip2host[r.remote_ip]
        if src != r.host:
            rows.append((r.timestamp, src, r.host, r.user.lower(), f"share_access({r.share_name})"))
    lat = pd.DataFrame(rows, columns=["timestamp", "src_host", "dst_host", "user", "method"])
    # drop routine noise: machine accounts, and ordinary Kerberos network logons to the DC
    dc = df[df.event_type == "kerberos_tgt"].host.mode().iat[0]          # host that issues TGTs
    routine = lat.user.str.endswith("$") | (lat.method.str.startswith("remote_logon_type3(Kerberos)") & (lat.dst_host == dc))
    lat = lat[~routine]
    return lat.sort_values("timestamp").reset_index(drop=True) if len(lat) else lat


# ------------------------------------------------------------------ outputs
def make_timeline(df):
    t = df[df.notable].copy()
    # collapse repeated beacon-like network rows into one summary row per (chain, dst)
    net = t[t.event_type == "network_connect"]
    keep = t[t.event_type != "network_connect"].copy()
    agg = (net.groupby(["host", "chain_id", "process", "dst_ip", "dst_port"])
           .agg(timestamp=("timestamp", "min"), last=("timestamp", "max"), n=("event_uid", "size"),
                user=("user_short", "first"), session_id=("session_id", "first")).reset_index())
    agg["summary"] = agg.apply(lambda r: f"{r.process} -> {r.dst_ip}:{r.dst_port}  [{r.n} connections {str(r.timestamp)[11:19]}-{str(r['last'])[11:19]}]", axis=1)
    agg["kind"] = "network"
    agg = agg[["timestamp", "host", "user", "chain_id", "session_id", "kind", "summary"]]

    def summ(r):
        k = r.notable_kind
        if k == "process":
            return f"{r.process} <- {r.parent_process} | {r.command_line[:170]}"
        if k == "service_install":
            return f"service '{r.service_name}' -> {r.service_path[:150]}"
        if k == "remote_logon":
            return f"logon type {r.logon_type} ({r.auth_package}) from {r.remote_ip} as {r.user}"
        if k == "explicit_creds":
            return f"{r.user} used creds of {r.target_user} for {r.service_name}"
        if k == "file_drop":
            return f"{r.process} wrote {r.file_path[:150]}"
        return f"PowerShell script block: {r.script_block[:150]!r}"

    keep["summary"] = keep.apply(summ, axis=1)
    keep["kind"] = keep.notable_kind
    keep["user"] = keep.user_short
    keep = keep[["timestamp", "host", "user", "chain_id", "session_id", "kind", "summary"]]
    return pd.concat([keep, agg]).sort_values("timestamp").reset_index(drop=True)


def run():
    df = pd.read_csv(C.EVENTS_CSV, low_memory=False, dtype=str).fillna("")
    for c in ["cmd_len", "cmd_n_args", "cmd_entropy", "sb_len", "hour"]:
        df[c] = pd.to_numeric(df[c])
    for c in [c for c in df.columns if c.startswith("f_")]:
        df[c] = df[c] == "True"
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, format="ISO8601")

    df, guid_row, cid = build_chains(df)
    chains = summarize_chains(df)
    notable_ids = {c["chain_id"] for c in chains if c["notable"]}
    df = mark_notable(df, notable_ids)
    df, sessions = build_sessions(df)
    ip2host = build_ip_map(df)
    lateral = build_lateral(df, ip2host)
    timeline = make_timeline(df)

    C.OUT_DIR.mkdir(exist_ok=True)
    df.to_csv(C.EVENTS_CORR_CSV, index=False, compression="gzip")
    json.dump(chains, open(C.CHAINS_JSON, "w"), indent=1, default=str)
    json.dump(sessions, open(C.SESSIONS_JSON, "w"), indent=1, default=str)
    lateral.to_csv(C.LATERAL_CSV, index=False)
    timeline.to_csv(C.TIMELINE_CSV, index=False)

    # --- report
    nc = [c for c in chains if c["notable"]]
    L = ["# Step 3 - Correlation report", "",
         f"- Process chains: **{len(chains)}** (notable: **{len(nc)}**)",
         f"- Notable events: **{int(df.notable.sum()):,}** of {len(df):,} ({df.notable.mean()*100:.1f}%)",
         f"- Activity sessions: **{len(sessions)}**  |  Lateral links: **{len(lateral)}**",
         f"- IP -> host map learned from data: {ip2host}", "", "## Notable process chains", "",
         "| chain | host | user | start (UTC) | events | narrative |", "|---|---|---|---|---|---|"]
    for c in nc:
        L.append(f"| {c['chain_id']} | {c['host']} | {c['user'].split(chr(92))[-1]} | {c['start'][11:19]} | {c['n_events']} | {c['narrative'][:150]} |")
    L += ["", "## Sessions", "", "| session | host | start | end | min | users | notable events |", "|---|---|---|---|---|---|---|"]
    for s in sessions:
        L.append(f"| {s['session_id']} | {s['host']} | {s['start'][11:19]} | {s['end'][11:19]} | {s['duration_min']} | {','.join(s['users'])} | {s['n_notable_events']} |")
    if len(lateral):
        L += ["", "## Lateral links (aggregated)", "", "| src | dst | user | method | count | first |", "|---|---|---|---|---|---|"]
        g = lateral.groupby(["src_host", "dst_host", "user", "method"]).agg(n=("timestamp", "size"), first=("timestamp", "min")).reset_index()
        for r in g.sort_values("first").itertuples():
            L.append(f"| {r.src_host} | {r.dst_host} | {r.user} | {r.method} | {r.n} | {str(r.first)[11:19]} |")
    (C.REPORT_DIR / "step3_correlation_report.md").write_text("\n".join(L))
    print(f"Step 3 done: {len(chains)} chains ({len(nc)} notable), {len(sessions)} sessions, "
          f"{len(lateral)} lateral links, {len(timeline)} timeline rows")


if __name__ == "__main__":
    run()

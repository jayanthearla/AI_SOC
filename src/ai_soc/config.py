"""Central configuration: paths + shared knowledge lists used by all steps.

Project root = repo root (two levels above this file) unless AI_SOC_ROOT is set.
Every path below is derived from ROOT, so the project can be moved or run from anywhere.
"""
import os
from pathlib import Path

ROOT = Path(os.environ.get("AI_SOC_ROOT", Path(__file__).resolve().parents[2]))
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
RULES_DIR = ROOT / "rules"
LABELS_DIR = ROOT / "labels"
CONFIG_DIR = ROOT / "configs"
RESULTS_DIR = ROOT / "results"
INTEL_DIR = ROOT / "data" / "intel"

# Rule files loaded by the detection engine (comma separated; later files override same-id rules).
# e.g.  AI_SOC_RULESETS=detection_rules.yml,candidates_v2.yml
RULESETS = os.environ.get("AI_SOC_RULESETS", "detection_rules.yml").split(",")

# Raw input (extracted from empire_apt3_tar.gz). Override with --input on the CLI.
RAW_JSON = RAW_DIR / "empire_apt3_2019-05-14223117.json"


def set_out_dir(out_dir):
    """(Re)point every pipeline output path at `out_dir`.

    Used to run the same pipeline on another dataset without touching the first one's outputs:
        python -m ai_soc.orchestration.pipeline --input data/raw/other.json --out outputs_other
    Other modules read these as `C.<NAME>` at call time, so a call here takes effect everywhere.
    """
    g = globals()
    out = Path(out_dir)
    g["OUT_DIR"] = out
    g["REPORT_DIR"] = out / "reports"
    g["FIG_DIR"] = out / "figures"
    # Step 2 / 3 / 4 outputs
    g["EVENTS_CSV"] = out / "normalized_events.csv.gz"
    g["CHAINS_JSON"] = out / "process_chains.json"
    g["SESSIONS_JSON"] = out / "sessions.json"
    g["TIMELINE_CSV"] = out / "timeline.csv"
    g["LATERAL_CSV"] = out / "lateral_links.csv"
    g["EVENTS_CORR_CSV"] = out / "events_correlated.csv.gz"
    g["ALERTS_JSON"] = out / "alerts.json"
    g["INCIDENTS_JSON"] = out / "incidents.json"
    g["RAW_HITS_CSV"] = out / "raw_hits.csv"
    g["ML_SCORES_CSV"] = out / "ml_scores.csv"
    g["SUMMARY_JSON"] = out / "summary.json"
    # Ground truth + Steps 5 / 6 / 7 (typed contracts: see ai_soc/contracts.py)
    g["GT_CSV"] = out / "ground_truth_events.csv.gz"
    g["ENRICHED_JSON"] = out / "enriched_alerts.json"
    g["ANALYST_JSON"] = out / "analyst_reports.json"
    g["DECISIONS_JSON"] = out / "decisions.json"
    g["AUDIT_LOG"] = out / "audit_log.jsonl"


set_out_dir(os.environ.get("AI_SOC_OUT", ROOT / "outputs"))

# (log_name, event_id) -> friendly event_type
EVENT_TYPES = {
    ("Microsoft-Windows-Sysmon/Operational", 1): "process_create",
    ("Microsoft-Windows-Sysmon/Operational", 3): "network_connect",
    ("Microsoft-Windows-Sysmon/Operational", 5): "process_terminate",
    ("Microsoft-Windows-Sysmon/Operational", 7): "image_load",
    ("Microsoft-Windows-Sysmon/Operational", 8): "remote_thread",
    ("Microsoft-Windows-Sysmon/Operational", 10): "process_access",
    ("Microsoft-Windows-Sysmon/Operational", 11): "file_create",
    ("Microsoft-Windows-Sysmon/Operational", 12): "registry_event",
    ("Microsoft-Windows-Sysmon/Operational", 13): "registry_event",
    ("Microsoft-Windows-Sysmon/Operational", 14): "registry_event",
    ("Microsoft-Windows-Sysmon/Operational", 17): "pipe_event",
    ("Microsoft-Windows-Sysmon/Operational", 18): "pipe_event",
    ("Microsoft-Windows-Sysmon/Operational", 22): "dns_query",
    ("Security", 4624): "logon",
    ("Security", 4625): "logon_failed",
    ("Security", 4634): "logoff",
    ("Security", 4648): "explicit_cred_logon",
    ("Security", 4672): "special_privileges",
    ("Security", 4688): "process_create_sec",
    ("Security", 4697): "service_install",
    ("Security", 4698): "scheduled_task_created",
    ("Security", 4768): "kerberos_tgt",
    ("Security", 4769): "kerberos_service_ticket",
    ("Security", 4776): "ntlm_auth",
    ("Security", 5145): "share_access",
    # Added to shrink the "other" bucket (15% of events). New types are NOT matched by any current rule.
    ("Security", 5156): "wfp_connection",       # Windows Filtering Platform: connection permitted
    ("Security", 5158): "wfp_bind",             # WFP: bind permitted
    ("Security", 4703): "token_adjusted",       # user right / privilege adjusted
    ("Security", 4656): "object_handle_request",
    ("Security", 4663): "object_access",
    ("Security", 4658): "handle_closed",
    ("Security", 4690): "handle_duplicated",
    ("Security", 4627): "group_membership",
    ("System", 7045): "service_install",
    ("Microsoft-Windows-PowerShell/Operational", 4103): "ps_module_log",
    ("Microsoft-Windows-PowerShell/Operational", 4104): "ps_scriptblock",
    ("Windows PowerShell", 800): "ps_pipeline",
    ("Windows PowerShell", 600): "ps_provider",
}

SCRIPT_ENGINES = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "cmd.exe", "wmic.exe"}
OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
LOLBINS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "wmic.exe", "schtasks.exe", "sc.exe",
    "net.exe", "net1.exe", "reg.exe", "whoami.exe", "netstat.exe", "icacls.exe", "nltest.exe",
    "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "quser.exe", "arp.exe", "nslookup.exe",
}
DISCOVERY_BINS = {"whoami.exe", "net.exe", "net1.exe", "netstat.exe", "nltest.exe", "ipconfig.exe",
                  "systeminfo.exe", "tasklist.exe", "quser.exe", "arp.exe", "reg.exe", "sc.exe"}

# Processes that are "plumbing": a chain does NOT continue upward through them.
# (A chain root is the first process whose parent is one of these, or unknown.)
CHAIN_ANCHORS = {
    "services.exe", "svchost.exe", "explorer.exe", "winlogon.exe", "wininit.exe", "userinit.exe",
    "smss.exe", "csrss.exe", "lsass.exe", "taskhostw.exe", "sihost.exe", "wmiprvse.exe",
    "system", "runtimebroker.exe", "searchindexer.exe", "dllhost.exe", "wsmprovhost.exe",
}
USER_WRITABLE = ("\\users\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "$recycle.bin", "\\public\\")

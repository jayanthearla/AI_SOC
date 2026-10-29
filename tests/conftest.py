import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

COLS = ["event_uid", "timestamp", "host", "event_type", "process", "process_path", "parent_process", "parent_path", "process_guid", "parent_guid",
        "command_line", "user", "user_short", "dst_ip", "dst_port", "remote_ip", "hashes", "service_name", "file_path", "script_block", "chain_id", "session_id"]


def make_events(rows):
    d = pd.DataFrame(rows)
    for c in COLS:
        if c not in d:
            d[c] = ""
    d["timestamp"] = pd.to_datetime(d["timestamp"], utc=True)
    return d.fillna("")


@pytest.fixture
def events():
    return make_events([
        dict(event_uid="E1", timestamp="2019-05-14 22:20:00", host="H1", event_type="process_create", process="svchost.exe", process_guid="{a}", parent_guid="{0}"),
        dict(event_uid="E2", timestamp="2019-05-14 22:32:00", host="H1", event_type="process_create", process="wscript.exe", process_guid="{b}", parent_guid="{0}",
             command_line='wscript.exe "C:\\Users\\x\\autoupdate.vbs"'),
        dict(event_uid="E3", timestamp="2019-05-14 22:32:01", host="H1", event_type="process_create", process="powershell.exe", process_guid="{c}", parent_guid="{b}"),
        dict(event_uid="E4", timestamp="2019-05-14 22:32:02", host="H1", event_type="network_connect", process="powershell.exe", process_guid="{c}", dst_ip="10.0.10.106", dst_port="80"),
        dict(event_uid="E5", timestamp="2019-05-14 22:33:00", host="H1", event_type="process_create", process="svchost.exe", process_guid="{d}", parent_guid="{0}"),
        dict(event_uid="E6", timestamp="2019-05-14 22:34:00", host="H1", event_type="ps_scriptblock", script_block="Get-Process"),
    ])

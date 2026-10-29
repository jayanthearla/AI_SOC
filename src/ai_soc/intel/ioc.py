"""IOC extraction from alerts + their events.  Includes decoding of PowerShell -EncodedCommand payloads, which is where an
Empire stager hides its C2 URL (the Step-4 alert evidence only shows the first 160 characters)."""
from __future__ import annotations

import base64
import ipaddress
import re

import pandas as pd

from ai_soc.contracts import IOC, Alert

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)
B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
ENC_ARG = re.compile(r"-e(?:nc(?:odedcommand)?)?\s+([A-Za-z0-9+/=]{16,})", re.I)
MACHINE = {"system", "local service", "network service", "anonymous logon", "-", ""}
SUSPICIOUS_EXT = (".vbs", ".js", ".hta", ".ps1", ".bat", ".scr", ".7z", ".zip", ".rar")


def _printable(s: str) -> bool:
    return len(s) > 8 and sum(c.isprintable() or c in "\r\n\t" for c in s) / len(s) > 0.95


def decode_b64(blob: str) -> str | None:
    """Decode base64 as UTF-16LE (PowerShell -enc) or UTF-8; return None if the result is not text."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            t = raw.decode(enc)
        except Exception:
            continue
        if _printable(t):
            return t
    return None


def decode_payloads(text: str, depth: int = 2) -> list[str]:
    """All decoded base64 payloads found in `text` (recursively, since stagers nest them)."""
    out = []
    for blob in ENC_ARG.findall(text) + B64_RE.findall(text):
        d = decode_b64(blob)
        if d and d not in out:
            out.append(d)
            if depth > 1:
                out += [x for x in decode_payloads(d, depth - 1) if x not in out]
    return out


_INTERNAL_NETS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def is_internal(ip: str) -> bool:
    """RFC1918 / loopback / link-local / ULA only.  (Python's is_private also covers documentation ranges such as
    198.51.100.0/24, which must NOT be treated as internal.)"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in _INTERNAL_NETS if n.version == a.version)


def _routable_or_lab(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)


def parse_hashes(h: str) -> dict:
    return {k.upper(): v.lower() for k, v in (p.split("=", 1) for p in h.split(",") if "=" in p)}


def extract(alert: Alert | dict, ev: pd.DataFrame, max_events: int = 400) -> list[IOC]:
    a = alert if isinstance(alert, dict) else alert.model_dump()
    aid = a["alert_id"]
    rows = ev[ev.event_uid.isin(a["event_uids"][:max_events])] if len(ev) else ev
    found: dict[tuple, IOC] = {}

    def add(t, v, ctx, internal=False):
        v = v.strip()
        if not v or v in ("-", "::1", "127.0.0.1"):
            return
        k = (t, v.lower())
        if k not in found:
            found[k] = IOC(type=t, value=v, internal=internal, context=ctx, alert_ids=[aid])

    add("host", a["host"], f"host of {aid}", True)
    if a.get("user") and a["user"].lower() not in MACHINE and not a["user"].endswith("$"):
        add("account", a["user"], f"user of {aid}", True)
    for r in rows.itertuples():
        if r.event_type == "network_connect" and r.dst_ip and _routable_or_lab(r.dst_ip):
            add("ip", r.dst_ip, f"network_connect dst of {aid} (port {r.dst_port})", is_internal(r.dst_ip))
        if r.remote_ip and _routable_or_lab(r.remote_ip) and r.remote_ip != "-":
            add("ip", r.remote_ip, f"remote source of {r.event_type} in {aid}", is_internal(r.remote_ip))
        if r.hashes:
            h = parse_hashes(r.hashes)
            if "SHA256" in h:
                add("hash", h["SHA256"], f"SHA256 of {r.process or 'process'} in {aid}")
        if r.event_type == "service_install" and r.service_name:
            add("service", r.service_name, f"service installed in {aid}", True)
        if r.event_type == "file_create" and r.file_path.lower().endswith(SUSPICIOUS_EXT):
            add("filename", r.file_path.split("\\")[-1], f"file written ({r.file_path}) in {aid}", True)
        text = " ".join([r.command_line, r.script_block[:2000]])
        for m in re.findall(r"[\w.\-]+\.(?:vbs|js|hta|ps1|bat|7z|zip)\b", r.command_line, re.I):
            add("filename", m, f"command line of {r.process} in {aid}", True)
        for payload in decode_payloads(text):
            for u in URL_RE.findall(payload):
                add("url", u, f"decoded PowerShell payload in {aid}")
            for ip in IP_RE.findall(payload):
                if _routable_or_lab(ip):
                    add("ip", ip, f"decoded PowerShell payload in {aid}", is_internal(ip))
        for u in URL_RE.findall(r.command_line):
            add("url", u, f"command line in {aid}")
    return list(found.values())

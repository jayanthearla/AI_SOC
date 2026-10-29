"""Online CTI clients (VirusTotal, MISP, OpenCTI).  Disabled unless the corresponding environment variables are set and
`--online` is passed.  They NEVER run in tests or offline mode.  NOTE: these were written against the public API docs and
are untested against live services - validate with your own keys before relying on results.

    VT_API_KEY                         VirusTotal API v3 (free tier: ~4 requests/minute)
    MISP_URL, MISP_KEY [MISP_VERIFY]   MISP restSearch
    OPENCTI_URL, OPENCTI_TOKEN         OpenCTI GraphQL (query shape varies by version - adapt `_QUERY`)
"""
from __future__ import annotations

import os
import time

import requests

from ai_soc.contracts import IOC, SourceVerdict


class _Base:
    name = "base"
    min_interval = 0.0

    def __init__(self, cache=None):
        self.cache = cache
        self._last = 0.0

    def enabled(self) -> bool:
        return False

    def _throttle(self):
        wait = self.min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def lookup(self, ioc: IOC) -> SourceVerdict | None:
        if ioc.internal or not self.enabled():
            return None                               # never send private/internal indicators to third parties
        key = f"{self.name}:{ioc.type}:{ioc.value}"
        if self.cache is not None and (c := self.cache.get(key)) is not None:
            return SourceVerdict(**c) if c else None
        try:
            self._throttle()
            v = self._query(ioc)
        except Exception as e:                          # network/auth errors must not break the pipeline
            v = SourceVerdict(source=self.name, verdict="unknown", detail=f"lookup failed: {type(e).__name__}")
        if self.cache is not None:
            self.cache.put(key, v.model_dump() if v else {})
        return v

    def _query(self, ioc):
        raise NotImplementedError


class VirusTotal(_Base):
    name = "virustotal"
    min_interval = 15.5                                 # free tier: 4 req/min

    def __init__(self, cache=None):
        super().__init__(cache)
        self.key = os.environ.get("VT_API_KEY", "")

    def enabled(self):
        return bool(self.key)

    def _query(self, ioc):
        path = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": None}.get(ioc.type)
        if not path:
            return None
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}/{ioc.value}", headers={"x-apikey": self.key}, timeout=20)
        if r.status_code == 404:
            return SourceVerdict(source=self.name, verdict="unknown", detail="not found")
        r.raise_for_status()
        st = r.json()["data"]["attributes"].get("last_analysis_stats", {})
        mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
        verdict = "malicious" if mal >= 3 else "suspicious" if mal + sus >= 1 else "benign"
        return SourceVerdict(source=self.name, verdict=verdict, detail=f"{mal} malicious / {sus} suspicious engines")


class MISP(_Base):
    name = "misp"

    def __init__(self, cache=None):
        super().__init__(cache)
        self.url, self.key = os.environ.get("MISP_URL", "").rstrip("/"), os.environ.get("MISP_KEY", "")
        self.verify = os.environ.get("MISP_VERIFY", "true").lower() != "false"

    def enabled(self):
        return bool(self.url and self.key)

    def _query(self, ioc):
        r = requests.post(f"{self.url}/attributes/restSearch", json={"value": ioc.value, "returnFormat": "json", "limit": 5},
                          headers={"Authorization": self.key, "Accept": "application/json", "Content-Type": "application/json"},
                          verify=self.verify, timeout=20)
        r.raise_for_status()
        attrs = r.json().get("response", {}).get("Attribute", [])
        if not attrs:
            return SourceVerdict(source=self.name, verdict="unknown", detail="no matching attribute")
        return SourceVerdict(source=self.name, verdict="malicious" if any(a.get("to_ids") for a in attrs) else "suspicious",
                             detail=f"{len(attrs)} attribute(s); events {sorted({a.get('event_id') for a in attrs})[:5]}")


class OpenCTI(_Base):
    name = "opencti"
    _QUERY = """query($v:String){ stixCyberObservables(filters:{mode:and,filters:[{key:"value",values:[$v]}],filterGroups:[]},first:5)
                { edges { node { observable_value x_opencti_score } } } }"""

    def __init__(self, cache=None):
        super().__init__(cache)
        self.url, self.token = os.environ.get("OPENCTI_URL", "").rstrip("/"), os.environ.get("OPENCTI_TOKEN", "")

    def enabled(self):
        return bool(self.url and self.token)

    def _query(self, ioc):
        r = requests.post(f"{self.url}/graphql", json={"query": self._QUERY, "variables": {"v": ioc.value}},
                          headers={"Authorization": f"Bearer {self.token}"}, timeout=20)
        r.raise_for_status()
        edges = r.json().get("data", {}).get("stixCyberObservables", {}).get("edges", [])
        if not edges:
            return SourceVerdict(source=self.name, verdict="unknown", detail="no observable")
        score = max((e["node"].get("x_opencti_score") or 0) for e in edges)
        return SourceVerdict(source=self.name, verdict="malicious" if score >= 70 else "suspicious" if score >= 40 else "unknown", detail=f"score {score}")


def online_clients(cache=None):
    return [c for c in (VirusTotal(cache), MISP(cache), OpenCTI(cache)) if c.enabled()]

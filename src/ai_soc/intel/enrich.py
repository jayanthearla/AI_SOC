"""STEP 5 - Threat Hunter agent: enrich alerts with IOCs, ATT&CK context and playbook hints.

    python -m ai_soc.intel.enrich            # offline: local lab feed + ATT&CK KB + TF-IDF playbook retrieval
    python -m ai_soc.intel.enrich --online   # also VirusTotal / MISP / OpenCTI when keys are configured

Notes that matter for the paper
  * Indicators in this lab are RFC1918, so public CTI cannot score them; internal indicators are never sent to third
    parties.  Enrichment value in the lab comes from (a) payload decoding, (b) ATT&CK/group context, (c) the synthetic
    local feed - disclose (c) as synthetic.
  * `intel_confidence` is a transparent heuristic (see _confidence), not a calibrated probability.
"""
from __future__ import annotations

import argparse
import json

import pandas as pd

from ai_soc import config as C
from ai_soc.contracts import Alert, EnrichedAlert, TechniqueInfo
from ai_soc.intel import clients, ioc as ioc_mod
from ai_soc.intel.cache import Cache
from ai_soc.intel.local_cti import LocalFeed
from ai_soc.intel.mitre import AttackKB
from ai_soc.intel.rag import Retriever


def _verdict(sources):
    order = ["malicious", "suspicious", "benign", "internal", "unknown"]
    vs = [s.verdict for s in sources]
    return next((o for o in order if o in vs), "unknown")


def _confidence(alert, iocs, tech):
    mal = any(i.verdict == "malicious" for i in iocs)
    if mal and tech and tech.known:
        return "high"
    if tech and tech.known and (tech.apt3_uses or alert.level in ("high", "critical")):
        return "medium"
    return "low"


def enrich_alerts(alerts: list[Alert], ev: pd.DataFrame, kb: AttackKB, offline: bool = True):
    feed, rag = LocalFeed(), Retriever(kb)
    cache = Cache()
    online = [] if offline else clients.online_clients(cache)
    out, all_iocs = [], {}
    for a in alerts:
        iocs = ioc_mod.extract(a, ev)
        for i in iocs:
            if (s := feed.lookup(i)):
                i.sources.append(s)
            for c in online:
                if (s := c.lookup(i)):
                    i.sources.append(s)
            i.verdict = "internal" if (i.internal and not i.sources) else _verdict(i.sources)
            k = (i.type, i.value.lower())
            if k in all_iocs:
                all_iocs[k].alert_ids = sorted(set(all_iocs[k].alert_ids) | set(i.alert_ids))
            else:
                all_iocs[k] = i
        t = kb.technique(a.technique) if a.technique and a.technique != "n/a" else None
        tech = None
        if t:
            tech = TechniqueInfo(technique_id=a.technique, name=t["name"], tactics=t["tactics"], description=t.get("description", "")[:400], known=True,
                                 groups_using=kb.groups_using(a.technique)[:8], apt3_uses=kb.group_uses("APT3", a.technique),
                                 empire_uses=kb.software_uses("Empire", a.technique))
        elif a.technique and a.technique != "n/a":
            tech = TechniqueInfo(technique_id=a.technique, known=False)
        hits = [d["id"] for d in rag.retrieve(f"{a.title} {a.tactic} {a.technique} {a.description}", k=2, kind="playbook")]
        notes = []
        if any(i.type == "url" for i in iocs):
            notes.append("URL(s) recovered by decoding an encoded PowerShell payload")
        if all(i.internal for i in iocs if i.type == "ip") and any(i.type == "ip" for i in iocs):
            notes.append("all IP indicators are internal/RFC1918: public reputation services were not queried")
        out.append(EnrichedAlert(alert=a, iocs=iocs, technique=tech, playbook_hits=hits, intel_confidence=_confidence(a, iocs, tech), intel_notes=notes))
    cache.save()
    return out, list(all_iocs.values())


def run(offline: bool = True):
    alerts = [Alert(**x) for x in json.load(open(C.ALERTS_JSON))]
    ev = pd.read_csv(C.EVENTS_CORR_CSV, low_memory=False, dtype=str).fillna("")
    kb = AttackKB()
    enriched, iocs = enrich_alerts(alerts, ev, kb, offline)
    C.OUT_DIR.mkdir(exist_ok=True)
    json.dump([e.model_dump() for e in enriched], open(C.ENRICHED_JSON, "w"), indent=1)
    json.dump([i.model_dump() for i in iocs], open(C.OUT_DIR / "iocs.json", "w"), indent=1)
    ext = [i for i in iocs if not i.internal]
    stats = dict(alerts=len(enriched), iocs=len(iocs), by_type=pd.Series([i.type for i in iocs]).value_counts().to_dict(),
                 by_verdict=pd.Series([i.verdict for i in iocs]).value_counts().to_dict(), external_iocs=len(ext),
                 techniques_known=sum(bool(e.technique and e.technique.known) for e in enriched),
                 techniques_total=sum(bool(e.technique) for e in enriched), kb=kb.meta,
                 confidence=pd.Series([e.intel_confidence for e in enriched]).value_counts().to_dict())
    json.dump(stats, open(C.RESULTS_DIR / "e7_intel_stats.json", "w"), indent=1)
    print(json.dumps(stats, indent=1))
    return enriched, iocs


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--online", action="store_true")
    run(offline=not ap.parse_args().online)

"""Offline CTI source: lab-annotated indicators + generic IR playbooks (both live in data/intel/)."""
from __future__ import annotations

import json

from ai_soc import config as C
from ai_soc.contracts import IOC, SourceVerdict


class LocalFeed:
    def __init__(self, path=None):
        path = path or C.INTEL_DIR / "lab_iocs.json"
        self.items = {}
        if path.exists():
            for i in json.load(open(path, encoding="utf-8"))["indicators"]:
                self.items[(i["type"], i["value"].lower())] = i

    def lookup(self, ioc: IOC) -> SourceVerdict | None:
        i = self.items.get((ioc.type, ioc.value.lower()))
        if not i:
            return None
        ioc.tags = sorted(set(ioc.tags) | set(i.get("tags", [])))
        return SourceVerdict(source="local-lab-feed", verdict=i["verdict"], detail=i.get("detail", ""), synthetic=True)


def load_playbooks(path=None) -> list[dict]:
    path = path or C.INTEL_DIR / "playbooks.json"
    return json.load(open(path, encoding="utf-8"))["playbooks"] if path.exists() else []

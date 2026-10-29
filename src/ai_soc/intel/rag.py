"""Lightweight RAG over the ATT&CK technique descriptions + IR playbooks (TF-IDF cosine; no GPU / API needed).
Mirrors the retrieval-augmented design of the base paper while staying reproducible; swap `Retriever` for an embedding
model + vector DB if you want to compare (a good ablation: TF-IDF vs dense retrieval)."""
from __future__ import annotations

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import linear_kernel

from ai_soc.intel.local_cti import load_playbooks
from ai_soc.intel.mitre import AttackKB


class Retriever:
    def __init__(self, kb: AttackKB | None = None):
        kb = kb or AttackKB()
        self.docs = []
        for t in kb.techniques.values():
            self.docs.append(dict(kind="technique", id=t["id"], title=t["name"], text=f"{t['id']} {t['name']} {' '.join(t['tactics'])}. {t.get('description', '')}"))
        for p in load_playbooks():
            self.docs.append(dict(kind="playbook", id=p["id"], title=p["title"], text=f"{p['title']}. {' '.join(p['tactics'])} {' '.join(p['techniques'])}. {p['text']}",
                                  actions=p["actions"]))
        self.vec = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", min_df=1)
        self.M = self.vec.fit_transform([d["text"] for d in self.docs])

    def retrieve(self, query: str, k: int = 4, kind: str | None = None) -> list[dict]:
        sims = linear_kernel(self.vec.transform([query]), self.M).ravel()
        order = sims.argsort()[::-1]
        out = []
        for i in order:
            d = self.docs[i]
            if kind and d["kind"] != kind:
                continue
            if sims[i] <= 0:
                break
            out.append(dict(d, score=float(sims[i])))
            if len(out) == k:
                break
        return out

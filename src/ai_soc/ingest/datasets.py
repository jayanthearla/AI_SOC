"""STEP 1 - Data ingestion: dataset registry, tolerant archive extraction, validation report.

The OTRF/Mordor archive for empire_apt3 is a *truncated* tar.gz ("unexpected end of file") whose payload is
nonetheless complete (121,659 lines, all valid JSON).  `extract_archive` reproduces that tolerance in Python
and `validate_jsonl` proves the payload is complete instead of trusting a warning.
"""
from __future__ import annotations

import json
import tarfile
from collections import Counter
from pathlib import Path

import yaml

from ai_soc import config as C


def load_registry(path: Path | None = None) -> dict:
    path = path or C.CONFIG_DIR / "datasets.yml"
    return yaml.safe_load(open(path, encoding="utf-8"))["datasets"]


def resolve(name: str) -> dict:
    reg = load_registry()
    if name not in reg:
        raise KeyError(f"unknown dataset {name!r}; known: {', '.join(reg)}")
    d = dict(reg[name])
    d["name"] = name
    for k in ("path", "archive"):
        if d.get(k):
            d[k] = C.ROOT / d[k]
    return d


def extract_archive(archive: Path, dest_dir: Path) -> list[Path]:
    """Extract a (possibly truncated) tar.gz.  Returns extracted file paths; never raises on EOF."""
    out = []
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, "r|gz") as tf:          # streaming mode tolerates truncation at the end
            for m in tf:
                if not m.isfile() or Path(m.name).name.startswith("."):
                    continue
                target = (dest_dir / Path(m.name).name).resolve()      # flatten: blocks path traversal
                if not str(target).startswith(str(dest_dir.resolve())):
                    continue
                with open(target, "wb") as fh:
                    try:
                        while chunk := tf.extractfile(m).read(1 << 20):
                            fh.write(chunk)
                    except EOFError:
                        pass
                out.append(target)
    except (EOFError, tarfile.ReadError):
        pass
    return out


def validate_jsonl(path: Path, expected: int | None = None, max_bad_ratio: float = 0.001) -> dict:
    """Parse every line; report counts, parse rate, time span, hosts and log sources."""
    n = bad = 0
    hosts, logs = Counter(), Counter()
    t0 = t1 = None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            n += 1
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                bad += 1
                continue
            hosts[(d.get("computer_name") or "").split(".")[0].upper()] += 1
            logs[d.get("log_name", "")] += 1
            ts = d.get("@timestamp")
            if ts:
                t0 = ts if t0 is None or ts < t0 else t0
                t1 = ts if t1 is None or ts > t1 else t1
    rep = dict(path=str(path), lines=n, unparsable=bad, parse_rate=round(1 - bad / max(n, 1), 6),
               first_timestamp=t0, last_timestamp=t1, hosts=dict(hosts), log_sources=dict(logs),
               expected_events=expected, complete=(expected is None or n == expected),
               ok=(bad / max(n, 1) <= max_bad_ratio and (expected is None or n == expected)))
    return rep


def write_report(rep: dict, name: str = "dataset") -> Path:
    C.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    L = [f"# Step 1 - Ingestion report ({name})", "",
         f"- File: `{rep['path']}`", f"- Lines: **{rep['lines']:,}** (expected {rep['expected_events']})",
         f"- Unparsable: {rep['unparsable']}  |  parse rate: {rep['parse_rate']:.4%}",
         f"- Time span: {rep['first_timestamp']} -> {rep['last_timestamp']}",
         f"- Validation: **{'PASS' if rep['ok'] else 'FAIL'}**", "", "## Hosts", "", "| host | events |", "|---|---|"]
    L += [f"| {h} | {c:,} |" for h, c in sorted(rep["hosts"].items(), key=lambda x: -x[1])]
    L += ["", "## Log sources", "", "| log | events |", "|---|---|"]
    L += [f"| {h} | {c:,} |" for h, c in sorted(rep["log_sources"].items(), key=lambda x: -x[1])]
    p = C.REPORT_DIR / "step1_ingest_report.md"
    p.write_text("\n".join(L))
    return p


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Extract (if needed) and validate a registered dataset")
    ap.add_argument("--dataset", default="empire_apt3")
    a = ap.parse_args()
    d = resolve(a.dataset)
    if not Path(d["path"]).exists() and d.get("archive") and Path(d["archive"]).exists():
        print("extracting", d["archive"], "->", extract_archive(Path(d["archive"]), Path(d["path"]).parent))
    rep = validate_jsonl(Path(d["path"]), d.get("expected_events"))
    print(json.dumps({k: v for k, v in rep.items() if k not in ("hosts", "log_sources")}, indent=1))
    write_report(rep, a.dataset)

"""Pipeline runner.  Stages are independent and communicate only through files in outputs/
(typed contracts in ai_soc/contracts.py), so any stage can be re-run alone.

    python -m ai_soc.orchestration.pipeline                      # core: ingest -> features -> correlation -> detection
    python -m ai_soc.orchestration.pipeline --stages labels,evaluate
    python -m ai_soc.orchestration.pipeline --stages all         # + labels, evaluate, intel, analyst, response
    python -m ai_soc.orchestration.pipeline --skip-extract       # reuse normalized_events.csv.gz
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

from ai_soc import config as C

CORE = ["ingest", "features", "correlation", "detection"]
ALL = CORE + ["labels", "evaluate", "intel", "analyst", "response"]


def stage_ingest(a):
    from ai_soc.ingest import datasets as D
    rep = D.validate_jsonl(Path(a.input), None)
    D.write_report(rep, Path(a.input).name)
    print(f"  {rep['lines']:,} lines, parse rate {rep['parse_rate']:.4%}, hosts={list(rep['hosts'])}")
    if not rep["ok"]:
        raise SystemExit("ingest validation failed (too many unparsable lines)")


def stage_features(a):
    from ai_soc.features import normalizer
    df = normalizer.run(Path(a.input), C.EVENTS_CSV)
    normalizer.write_report(df)


def stage_correlation(a):
    from ai_soc.correlation import correlation
    correlation.run()


def stage_detection(a):
    from ai_soc.detection import engine
    engine.run()


def stage_labels(a):
    from ai_soc.labels import ground_truth
    ground_truth.run(a.labels_prefix)


def stage_evaluate(a):
    from ai_soc.evaluation import eval_detection
    eval_detection.run(a.labels_prefix)


def stage_intel(a):
    from ai_soc.intel import enrich
    enrich.run(offline=not a.online)


def stage_analyst(a):
    from ai_soc.agents import analyst
    analyst.run(provider=a.llm_provider, model=a.llm_model)


def stage_response(a):
    from ai_soc.response import approval
    approval.run()


STAGES = {s: globals()[f"stage_{s}"] for s in ALL}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", default=str(C.RAW_JSON))
    ap.add_argument("--out", default=None, help="output directory (default outputs/)")
    ap.add_argument("--stages", default="core", help="comma list, 'core' or 'all'. Available: " + ",".join(ALL))
    ap.add_argument("--skip-extract", action="store_true", help="skip ingest+features (reuse normalized_events.csv.gz)")
    ap.add_argument("--labels-prefix", default="", help="label file prefix for other datasets (e.g. 'apt29_')")
    ap.add_argument("--online", action="store_true", help="intel: allow network lookups (VirusTotal/MISP/OpenCTI)")
    ap.add_argument("--llm-provider", default="mock", choices=["mock", "anthropic", "openai_compat"])
    ap.add_argument("--llm-model", default=None)
    a = ap.parse_args(argv)
    if a.out:
        C.set_out_dir(a.out)
    C.OUT_DIR.mkdir(parents=True, exist_ok=True)
    C.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stages = CORE if a.stages == "core" else ALL if a.stages == "all" else a.stages.split(",")
    if a.skip_extract:
        stages = [s for s in stages if s not in ("ingest", "features")]
    t = time.time()
    for s in stages:
        print(f"== STAGE: {s} ==")
        STAGES[s](a)
    print(f"\nAll done in {time.time() - t:.0f}s. Reports: {C.REPORT_DIR}")


if __name__ == "__main__":
    main()

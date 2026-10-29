"""Run the full experiment suite and regenerate the paper tables.

    python experiments/run_all.py                         # E0-E7 + mock LLM + tables
    python experiments/run_all.py --provider anthropic --model claude-sonnet-5-5 --runs 5
    python experiments/run_all.py --only E1,E2

Experiment index (see docs/EXPERIMENTS.md for the paper mapping)
  E0  ground truth + main evaluation          E5  risk-score calibration
  E1  detection ablation (+ v2 candidate)     E6  evasion robustness
  E2  ML comparison (contaminated vs benign)  E7  threat-intel enrichment stats
  E3  unmodified SigmaHQ baseline             E8  LLM analyst quality (+ no-CTI / rules-only ablations)
  E4  correlation quality (in E0/E1 output)   E9  prompt-injection safety
"""
import argparse
import sys
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ai_soc import config as C  # noqa: E402


def e0(a):
    from ai_soc.evaluation import eval_detection
    from ai_soc.labels import ground_truth
    ground_truth.run()
    eval_detection.run()


def e1(a):
    from ai_soc.evaluation import ablation
    ablation.run()


def e2(a):
    from ai_soc.evaluation import ml_eval
    ml_eval.run()


def e3(a):
    from ai_soc.evaluation.baselines import sigmahq
    sigmahq.run()


def e5(a):
    from ai_soc.evaluation import calibration_eval
    calibration_eval.run()


def e6(a):
    from ai_soc.evaluation import robustness
    robustness.run()


def e7(a):
    from ai_soc.intel import enrich
    enrich.run(offline=True)


def e8(a):
    from ai_soc.evaluation import llm_eval
    llm_eval.run(a.provider, a.model, a.runs)


EXPS = {"E0": e0, "E1": e1, "E2": e2, "E3": e3, "E5": e5, "E6": e6, "E7": e7, "E8": e8}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--provider", default="mock")
    ap.add_argument("--model", default=None)
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    C.RESULTS_DIR.mkdir(exist_ok=True)
    C.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    chosen = [x for x in a.only.split(",") if x] or list(EXPS)
    for k in chosen:
        print(f"\n########## {k} ##########")
        try:
            EXPS[k](a)
        except SystemExit as e:
            print(f"{k} skipped: {e}")
        except Exception:
            traceback.print_exc()
            print(f"{k} FAILED (continuing)")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "paper"))
    import make_tables
    make_tables.main()

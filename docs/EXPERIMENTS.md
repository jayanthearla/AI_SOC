# Experiments

| ID | What | Command | Output |
|---|---|---|---|
| E0 | Ground truth + main evaluation (alert/process/step/incident level, workload) | `python -m ai_soc.evaluation.eval_detection` | `outputs/reports/evaluation_report.md`, `results/eval_main.json` |
| E1 | Ablation: sigma / python / ML / rules / +ML queue / +v2 / no-correlation, McNemar | `python -m ai_soc.evaluation.ablation` | `results/e1_ablation.json` |
| E2 | ML: contaminated vs benign-only vs supervised (group CV) | `python -m ai_soc.evaluation.ml_eval` | `results/e2_ml_comparison.json` |
| E3 | Unmodified SigmaHQ baseline | `python scripts/fetch_sigmahq.py && python -m ai_soc.evaluation.baselines.sigmahq` | `results/e3_sigmahq.json` |
| E4 | Correlation quality: incident fragmentation, tactic recall, Kendall tau, dedup | (inside E0/E1) | `incident_level`, `workload` |
| E5 | Risk-score calibration | `python -m ai_soc.evaluation.calibration_eval` | `results/e5_calibration.json` |
| E6 | Evasion robustness | `python -m ai_soc.evaluation.robustness` | `results/e6_robustness.json` |
| E7 | Intel enrichment statistics | `python -m ai_soc.intel.enrich` | `results/e7_intel_stats.json` |
| E8/E9 | LLM analyst quality, ablations, injection ASR | `python -m ai_soc.evaluation.llm_eval --provider anthropic --model claude-sonnet-5-5 --runs 5` | `results/e8_e9_llm_<provider>.json`, rating sheet CSV |

All at once: `python experiments/run_all.py` (then `paper/tables.md|tex`). The `mock` provider is the deterministic template baseline; real providers need keys (`.env.example`) and were not run in the build environment.

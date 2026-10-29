# Paper blueprint

**Working title:** Evidence-grounded multi-agent SOC triage: correlation-driven hybrid detection, CTI enrichment and verified LLM analysis on an emulated APT3 intrusion

**Positioning (be honest about novelty):** the contribution is a *rigorously evaluated* pipeline with labelled ground truth, ablations, an unmodified-Sigma baseline, evasion tests, and LLM faithfulness/injection tests - not a claim of state-of-the-art accuracy.  A single emulated scenario supports a case study, not generalisation; add the held-out scenario(s) before claiming more.

## Research questions -> experiments -> artefacts
| RQ | Question | Experiments | Table/figure source |
|---|---|---|---|
| RQ1 | Does correlation-driven hybrid detection beat rules-only, ML-only and public Sigma - within and across scenarios? | E0, E1, E2, E3, E6, held-out run | `paper/tables.md` T1-T4 |
| RQ2 | How much does correlation cut analyst workload without losing coverage? | E0/E1 workload funnel, dedup, incident fragmentation, kill-chain tau | funnel figure from `results/eval_main.json` |
| RQ3 | Does CTI/ATT&CK enrichment improve the LLM analyst? | E7, E8 (full vs no_cti vs rules_only vs template baseline; >= 2 LLMs) | T5 |
| RQ4 | Is the analyst faithful and safe (hallucination, injection, harmful actions)? | E8, E9, human ratings | T5 + rating sheet kappa |

## Section plan
1. Introduction - problem (alert fatigue, LLM trust), contributions, RQs
2. Related work - base paper (Tellache et al.), Sigma/ATT&CK-based detection, anomaly detection on host logs, LLMs for SOC/CTI, prompt injection
3. Threat model & data - empire_apt3 (OTRF), label protocol (`labels/`), what is development vs held-out, limits of 'assumed benign'
4. Architecture - layers A-D, typed contracts, safety design (closed action catalogue, two-person approval, audit chain)
5. Methods - normalisation (+schema coverage), correlation, rules/ML/fusion, CTI enrichment + RAG, analyst agent + verifier
6. Experimental setup - metrics (below), baselines, seeds, bootstrap CIs, McNemar, LLM runs
7. Results - one subsection per RQ; negative findings stated plainly (e.g. contaminated Isolation Forest ~ chance)
8. Discussion - what transfers, failure analysis (missed ftp/7z/net1), evasion sensitivity
9. Limitations & ethics - single scenario, analyst-annotated labels, synthetic IOCs, dry-run response, dual use of attack data
10. Conclusion & future work

## Metrics checklist (all implemented in `src/ai_soc/evaluation/`)
Detection: alert precision (+CI), process-level P/R/F1, step detection rate, technique coverage (exact & family), TTD, FP per alert, per-rule hit precision, PR-AUC/ROC-AUC/P@k (ML), McNemar vs baseline.
Correlation/workload: reduction ratios (events->hits->alerts->groups->incidents), dedup ratio, incident fragmentation, tactic recall, Kendall tau.
Calibration: Brier, ECE, reliability table (needs negatives - held-out data).
Robustness: delta recall / delta step detection per mutation.
Intel: IOC counts by type/verdict, decoded-payload recoveries, KB match rate, confidence distribution.
LLM: schema/verification pass-rate, narrative grounding, hallucination rate, required-action recall, action precision, harmful-action rate, ATT&CK mapping F1, consistency (Jaccard), injection ASR, latency/cost (add timing when running real providers), human Likert + Cohen's kappa.

## Before submission
- [ ] Verify `labels/attack_steps.yml` and seeds against the dataset documentation / APT3 emulation plan; have a 2nd person re-label a sample and report kappa
- [ ] Run the frozen rules on >= 1 held-out scenario (docs/DATASETS.md) and report the drop
- [ ] Pin SigmaHQ commit + ATT&CK download date; record package versions (`pip freeze`)
- [ ] Run >= 2 real LLMs (one open-weight), >= 5 runs each; record model ids and dates
- [ ] Gold actions reviewed by 2+ practitioners
- [ ] Re-generate tables with `python experiments/run_all.py`

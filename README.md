# AI-Powered SOC - multi-agent pipeline 

From raw Windows/Sysmon logs (OTRF `empire_apt3`, simulated APT3) to **evidence-verified, human-approved response**, plus the labels, baselines, ablations and metrics needed to write a paper.

```
raw logs -> [A Detection: normalize, correlate, detect] -> [B Threat Hunter: IOCs, ATT&CK, CTI]
         -> [C SOC Analyst (LLM, verified)] -> [D Human approval, dry-run response] ;  [E Evaluation everywhere]
```
See `docs/ARCHITECTURE.md`. Headline results and what they mean: `docs/FINDINGS.md`.

## Quick start (offline, no API keys)
```bash
pip install -r requirements.txt
# put empire_apt3_2019-05-14223117.json in data/raw/   (extract your empire_apt3_tar.gz; truncated-archive tolerant helper: python -m ai_soc.ingest.datasets)
python scripts/fetch_attack_stix.py      # optional: refresh ATT&CK (a slim snapshot is already in data/intel/)
python scripts/fetch_sigmahq.py          # needed only for experiment E3
make all                                 # steps 1-7 + ground truth + evaluation (mock analyst)   ~30 s
make experiments                         # E0-E8 + paper tables
make test                                # 21 tests
streamlit run app/dashboard.py           # pip install streamlit
```
Or: `python run_pipeline.py --stages all`, `--stages labels,evaluate`, `--skip-extract`.

Real LLM: `python -m ai_soc.agents.analyst --provider anthropic --model claude-sonnet-5-5` (needs `ANTHROPIC_API_KEY`), or `--provider openai_compat` (OpenAI / Groq / vLLM / Ollama via `OPENAI_BASE_URL`).

## Layout
```
configs/        datasets.yml (registry: development / held-out / benign)
labels/         attack_seeds.yml  attack_steps.yml  gold_actions.yml      <- ground truth (verify before publishing!)
rules/          detection_rules.yml (v1)  candidates_v2.yml (dev-tuned fixes)
src/ai_soc/     ingest  features  correlation  detection(+ml_models, dedup, calibration)  labels  intel  agents  response  orchestration  evaluation(+baselines)
experiments/    run_all.py            paper/  outline.md  make_tables.py  references.bib
app/            dashboard.py          tests/  docs/  scripts/  data/intel/ (ATT&CK slim, lab IOCs, playbooks)
outputs/        regenerated pipeline outputs & reports        results/  experiment JSON
```

## What is and is not verified
* Verified in the build environment: Steps 1-7 end to end on empire_apt3, all experiments E0-E8 (LLM via the deterministic `mock` provider), 21 tests, SigmaHQ conversion of the real rule corpus, ATT&CK slim KB build.
* **Not run against live services:** Anthropic/OpenAI-compatible providers, VirusTotal/MISP/OpenCTI clients, the Streamlit UI (compiles only). Validate with your own keys.
* Ground truth and gold actions are analyst-annotated first drafts; the held-out scenario, a benign baseline, a second annotator and real-LLM runs are still to do (checklist at the end of `paper/outline.md`).
* The risk score is a heuristic, not a probability; lab IOCs are synthetic.

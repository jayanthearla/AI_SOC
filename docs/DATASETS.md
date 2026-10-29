# Datasets and the held-out protocol

`configs/datasets.yml` is the registry. Only `empire_apt3` is bundled in the original zip; the others are templates.

## Held-out run (RQ1 generalisation)
1. Obtain a different scenario in Winlogbeat/Mordor JSON-lines form (e.g. another OTRF Security-Datasets attack such as the APT29 evaluation; check availability, size and licence yourself) and put it in `data/raw/`.
2. **Freeze** `rules/detection_rules.yml` (do not edit after looking at the new data) and the ML code.
3. Write `labels/<prefix>_attack_seeds.yml` and `_attack_steps.yml` for it (see LABELING.md).
4. Run: `python -m ai_soc.orchestration.pipeline --input data/raw/new.json --out outputs_new --stages core,labels,evaluate --labels-prefix <prefix>_`
   (results land in `outputs_new/` and `results/eval_main_<prefix>.json`).
5. Report the drop from development to held-out for alert precision, process recall, step detection and technique coverage.

## Benign baseline (for the ML layer)
The development scenario has no benign process data before the attack (0 process creations in the 831 pre-attack events). Use any attack-free Windows/Sysmon capture normalised with the same schema (e.g. DARPA OpTC benign hosts - verify size/format) and fit the novelty detectors on it: see `evaluation/ml_eval.py` protocol B for the intended setup.
 
## Benign/other sources worth checking
OTRF Security-Datasets (many scenarios), DARPA OpTC, EVTX-ATTACK-SAMPLES (per-technique EVTX, small), Splunk attack_data. Verify each before relying on it.

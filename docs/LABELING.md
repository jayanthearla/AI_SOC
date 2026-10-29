# Ground-truth labelling protocol

Files: `labels/attack_seeds.yml` (event-level), `labels/attack_steps.yml` (step-level), `labels/gold_actions.yml` (response).
Build: `python -m ai_soc.labels.ground_truth` -> `outputs/ground_truth_events.csv.gz`, `outputs/ground_truth_steps.csv`, `outputs/reports/ground_truth_report.md`.

## Classes
`malicious` (seed lineage / PowerShell scope / explicit selectors) - `benign` (before attack start) - `ambiguous` (excluded from strict metrics) - `background` (in-window, unrelated; **assumed** benign).

## Why this is not circular
Seeds are chosen from the attack narrative and refined by looking at process trees; they never read detection output. Process-level truth is then propagated by parent GUID. Caveat: the annotator also wrote the rules, so results on this scenario are development-set numbers.

## Known limitations (state them in the paper)
* `background` is not verified benign (ambiguous items are listed in the report: UAC consent UI, `eventvwr` via mmc, nmartha logons).
* PowerShell logs are labelled by host+time, because they carry no process GUID.
* Step windows/techniques come from the README narrative; verify against the APT3 emulation plan and have a second annotator re-label a sample (report Cohen's kappa).

## Labelling a new dataset
Copy the two YAML files to `labels/<prefix>attack_seeds.yml` / `<prefix>attack_steps.yml`, edit seeds/steps, then
`python -m ai_soc.orchestration.pipeline --input data/raw/new.json --out outputs_new --labels-prefix <prefix>_ --stages core,labels,evaluate`.

# Architecture

```
 data/raw/*.json
      |  STEP 1 ingest/datasets.py        validate (parse rate, counts), tolerant tar.gz extraction
      v
 [A. Detection Agent]
      |  STEP 2 features/normalizer.py    Winlogbeat JSON -> 60-column table (+ schema coverage 98.2%)
      |  STEP 3 correlation/correlation.py process chains (Sysmon GUIDs), sessions, lateral links
      |  STEP 4 detection/engine.py        sigma_lite rules + 5 Python behavioural rules + ML + risk fusion + incidents
      |         detection/dedup.py         alert groups;  detection/calibration.py  risk -> probability
      v   alerts.json / incidents.json           (contracts.Alert, Incident)
 [B. Threat Hunter Agent]
      |  STEP 5 intel/                     ioc.py (incl. PowerShell -enc decoding) -> local_cti / clients (VT, MISP, OpenCTI)
      |                                    mitre.py (ATT&CK + APT3/Empire context) -> rag.py (TF-IDF playbook retrieval)
      v   enriched_alerts.json, iocs.json        (contracts.EnrichedAlert)
 [C. SOC Analyst Agent]
      |  STEP 6 agents/                    prompts.py + sanitize.py -> llm_client.py -> verifier.py (programmatic guardrail)
      v   analyst_reports.json                   (contracts.AnalystReport, verification block)
 [D. Human-in-the-loop]
      |  STEP 7 response/                  actions.py (closed catalogue) -> approval.py (two-person rule, dry run, hash-chained audit)
      v   decisions.json, audit_log.jsonl        (contracts.Decision)        app/dashboard.py (Streamlit)

 [E. Evaluation]  labels/ (ground truth)  evaluation/ (metrics, ablation, baselines, robustness, calibration, ML, LLM)  experiments/  paper/
```

## Design rules
* Layers talk only through validated JSON files (`contracts.py`), so each can be re-run or swapped alone.
* Rules, ML and LLM are separable and individually ablatable (E1, E8).
* The LLM never executes anything: it proposes ids from a closed catalogue; a human approves; execution is a dry run.
* Everything attacker-controlled (command lines, script blocks) is treated as untrusted data before it reaches the LLM.

# Findings from evaluating Steps 2-4 against ground truth (empire_apt3, development scenario)

All numbers are reproducible with `python experiments/run_all.py`. Rules were written on this scenario, so treat them as **development-set** results.

## What holds up
* Funnel: 121,659 events -> 3,398 raw rule hits -> 33 alerts -> 19 alert groups -> 1 incident (alert reduction 99.97%).
* Alert precision 1.00 (33/33); process-level precision 0.99 (84 TP, 1 FP), recall 0.79 (84/106), F1 0.88; all 16 annotated steps detected; median time-to-detect 1.9 s; kill-chain ordering tau 0.83.
* Schema coverage raised from 84.8% to 98.2% by typing Security events 5156/5158/4703/4656/4663/4658/4690/4627 (no rule uses them yet).

## What the ground truth exposed
1. **ML was not working because of contamination, not the algorithm.** Isolation Forest fitted on everything (the Step-4 setup) scores ROC-AUC 0.449 (95% CI 0.365-0.540) = chance. Fitted on proxy-benign process starts only (cross-fitted): IF 0.959, LOF 0.991, One-Class SVM 0.978, autoencoder 0.986; supervised group-CV: gradient boosting 0.985, random forest 0.971. Caveats: background is only assumed benign, one scenario, n=303.
2. **Adding the contaminated ML queue lowered alert precision** (1.00 -> 0.94; both ML-only alerts were false positives).
3. **Rule gaps (missed malicious process starts):** `ftp.exe -s:` (exfiltration - no Exfiltration tactic at all), a renamed archiver `recycler.exe a -t7z` (collection), `net1.exe` discovery, follow-up `sc.exe` calls. Candidate rules in `rules/candidates_v2.yml` lift process recall 0.79 -> 0.87 (dev-tuned, not a generalisation claim).
4. **One genuine rule FP:** SIG-013 flags `sethc.exe /AccessibilitySoundAgent` (normal OS behaviour); refined in v2. Detecting the *replaced* Magnify.exe needs hash/signature data.
5. **Circularity is measurable.** Unmodified SigmaHQ (1,679 of 2,418 Windows rules convertible; 19 fired): alert precision 0.74, process recall 0.64, step detection 0.375, technique coverage 0.11 exact / 0.25 family - versus 1.00 / 0.79 / 1.00 / 1.00 for the tuned rules.
6. **Brittleness (E6):** renaming `net.exe` cuts process-level recall by 0.55, renaming PowerShell by 0.26, parent-PID spoofing by 0.19 (step detection -0.125 to -0.25). Flag-shortening, caret obfuscation and path masquerading had no effect.
7. **Risk score is not calibrated** and cannot be calibrated yet (33 positives / 2 negatives); do not call it a probability.
8. **Intel:** the lab C2 (10.0.10.106) is RFC1918, so public CTI cannot score it. Decoding PowerShell `-enc` payloads recovered the C2 URLs the truncated Step-4 evidence hid. ATT&CK data confirms APT3 (G0022) and Empire (S0363) use several of the observed techniques (e.g. T1546.008).

## Refinement of the earlier "no benign baseline" claim
No benign process data exists *before* the attack, but ~2/3 of in-window process starts (197 of 303 scored) are ordinary OS background, which gives the proxy-benign class used in E2. It is still an assumption.

# E6 - Evasion robustness (rule layers only, no ML)

| mutation | alerts | proc recall | d recall | step detection | d steps | technique cov (exact) | alert precision |
|---|---|---|---|---|---|---|---|
| baseline (no mutation) | 33 | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 | 1.000 |
| rename_powershell | 16 | 0.538 | -0.255 | 0.750 | -0.250 | 0.611 | 1.000 |
| rename_net | 31 | 0.245 | -0.547 | 1.000 | +0.000 | 0.889 | 1.000 |
| short_enc_flag | 33 | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 | 1.000 |
| caret_obfuscation | 33 | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 | 1.000 |
| parent_spoof | 27 | 0.604 | -0.189 | 0.875 | -0.125 | 0.833 | 1.000 |
| no_scriptblock_log | 29 | 0.792 | +0.000 | 1.000 | +0.000 | 0.889 | 1.000 |
| path_masquerade | 33 | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 | 1.000 |
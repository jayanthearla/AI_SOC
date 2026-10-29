## Table 1 - Detection ablation (development scenario)
| Variant | Alerts | Alert P | Proc P | Proc R | Proc F1 | Step det. | Tech cov. |
|---|---|---|---|---|---|---|---|
| sigma_only | 27 | 1.000 | 0.988 | 0.792 | 0.880 | 0.938 | 0.778 |
| python_only | 6 | 1.000 | 1.000 | 0.604 | 0.753 | 0.375 | 0.278 |
| ml_only | 31 | 0.516 | 0.516 | 0.151 | 0.234 | 0.188 | 0.000 |
| rules_v1 | 33 | 1.000 | 0.988 | 0.792 | 0.880 | 1.000 | 1.000 |
| rules_v1+ml_queue | 35 | 0.943 | 0.966 | 0.792 | 0.870 | 1.000 | 1.000 |
| rules_v1+v2 (dev-tuned) | 36 | 1.000 | 1.000 | 0.868 | 0.929 | 1.000 | 1.000 |
| no_correlation (raw hits) | 3398 | 0.999 | 0.988 | 0.792 | 0.880 | 1.000 | 0.944 |

## Table 2 - ML comparison (random PR-AUC = 0.35)
| Protocol | Model | ROC-AUC | PR-AUC | P@k |
|---|---|---|---|---|
| A: fit on all (contaminated) | isolation_forest | 0.449 | 0.426 | 0.425 |
| A: fit on all (contaminated) | local_outlier_factor | 0.622 | 0.615 | 0.481 |
| A: fit on all (contaminated) | one_class_svm | 0.504 | 0.360 | 0.311 |
| A: fit on all (contaminated) | autoencoder | 0.312 | 0.360 | 0.264 |
| B: benign-only cross-fit | isolation_forest | 0.959 | 0.900 | 0.811 |
| B: benign-only cross-fit | local_outlier_factor | 0.991 | 0.989 | 0.953 |
| B: benign-only cross-fit | one_class_svm | 0.978 | 0.980 | 0.953 |
| B: benign-only cross-fit | autoencoder | 0.986 | 0.983 | 0.953 |
| C: supervised, group CV by chain | random_forest | 0.974 | 0.915 | 0.934 |
| C: supervised, group CV by chain | gradient_boosting | 0.985 | 0.942 | 0.962 |
| C: supervised, group CV by chain | logistic_regression | 0.853 | 0.786 | 0.689 |

## Table 3 - Project rules vs unmodified SigmaHQ (1679 of 2418 rules convertible)
| Rule set | Alerts | Alert P | Proc R | Step det. | Tech (exact) | Tech (family) |
|---|---|---|---|---|---|---|
| Project rules v1 (dev-tuned) | 33 | 1.000 | 0.792 | 1.000 | 1.000 | 1.000 |
| SigmaHQ unmodified | 35 | 0.743 | 0.642 | 0.375 | 0.111 | 0.250 |

## Table 4 - Evasion robustness
| Mutation | Proc R | Delta R | Step det. | Delta steps | Tech cov. |
|---|---|---|---|---|---|
| baseline (no mutation) | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 |
| rename_powershell | 0.538 | -0.255 | 0.750 | -0.250 | 0.611 |
| rename_net | 0.245 | -0.547 | 1.000 | +0.000 | 0.889 |
| short_enc_flag | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 |
| caret_obfuscation | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 |
| parent_spoof | 0.604 | -0.189 | 0.875 | -0.125 | 0.833 |
| no_scriptblock_log | 0.792 | +0.000 | 1.000 | +0.000 | 0.889 |
| path_masquerade | 0.792 | +0.000 | 1.000 | +0.000 | 1.000 |

## Table 5 - LLM analyst: mock/template-v1 (3 runs); injection ASR defended=0.00 raw=0.00
| Context | Verified | Grounding | Req. action R | Harmful | Mapping F1 |
|---|---|---|---|---|---|
| full | 1.00+-0.00 | 1.00+-0.00 | 0.80+-0.00 | 0.00+-0.00 | 1.00+-0.00 |
| no_cti | 1.00+-0.00 | 1.00+-0.00 | 0.60+-0.00 | 0.00+-0.00 | 1.00+-0.00 |
| rules_only | 1.00+-0.00 | 1.00+-0.00 | 0.60+-0.00 | 0.00+-0.00 | 1.00+-0.00 |

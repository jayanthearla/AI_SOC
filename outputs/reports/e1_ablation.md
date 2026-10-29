# E1 - Detection ablation vs ground truth (development scenario)

| variant | alerts | groups | incidents | alert prec. | proc prec. | proc recall | proc F1 | step detection | tech cov (exact/family) | median TTD s |
|---|---|---|---|---|---|---|---|---|---|---|
| sigma_only | 27 | 16 | 1 | 1.000 | 0.988 | 0.792 | 0.880 | 0.938 | 0.778 / 0.812 | 1.283 |
| python_only | 6 | 5 | 1 | 1.000 | 1.000 | 0.604 | 0.753 | 0.375 | 0.278 / 0.312 | 6.062 |
| ml_only | 31 | 31 | 0 | 0.516 | 0.516 | 0.151 | 0.234 | 0.188 | 0.000 / 0.000 | 0.818 |
| rules_v1 | 33 | 19 | 1 | 1.000 | 0.988 | 0.792 | 0.880 | 1.000 | 1.000 / 1.000 | 1.918 |
| rules_v1+ml_queue | 35 | 21 | 1 | 0.943 | 0.966 | 0.792 | 0.870 | 1.000 | 1.000 / 1.000 | 1.918 |
| rules_v1+v2 (dev-tuned) | 36 | 22 | 1 | 1.000 | 1.000 | 0.868 | 0.929 | 1.000 | 1.000 / 1.000 | 1.918 |
| no_correlation (raw hits) | 3398 | 3226 | 0 | 0.999 | 0.988 | 0.792 | 0.880 | 1.000 | 0.944 / 1.000 | 3.010 |

McNemar exact test vs sigma_only (process-level correctness, paired):

- python_only: only-variant-correct 1, only-sigma-correct 20, p = 0.0000
- ml_only: only-variant-correct 6, only-sigma-correct 88, p = 0.0000
- rules_v1: only-variant-correct 0, only-sigma-correct 0, p = 1.0000
- rules_v1+ml_queue: only-variant-correct 0, only-sigma-correct 2, p = 0.5000
- rules_v1+v2 (dev-tuned): only-variant-correct 9, only-sigma-correct 0, p = 0.0039
- no_correlation (raw hits): only-variant-correct 0, only-sigma-correct 0, p = 1.0000

*Rules were written on this scenario: treat as development numbers. `rules_v1+v2` was additionally tuned after error analysis.*
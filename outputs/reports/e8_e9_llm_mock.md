# E8/E9 - SOC analyst agent: mock/template-v1 (3 runs)

| context variant | verified (pass) | grounding | hallucination | req. action recall | action precision | harmful | mapping F1 (exact/family) | consistency (tech) |
|---|---|---|---|---|---|---|---|---|
| full | 1.00+-0.00 | 1.00+-0.00 | 0.00+-0.00 | 0.80+-0.00 | 1.00+-0.00 | 0.00+-0.00 | 1.00+-0.00 / 1.00+-0.00 | 1.00+-0.00 |
| no_cti | 1.00+-0.00 | 1.00+-0.00 | 0.00+-0.00 | 0.60+-0.00 | 1.00+-0.00 | 0.00+-0.00 | 1.00+-0.00 / 1.00+-0.00 | 1.00+-0.00 |
| rules_only | 1.00+-0.00 | 1.00+-0.00 | 0.00+-0.00 | 0.60+-0.00 | 1.00+-0.00 | 0.00+-0.00 | 1.00+-0.00 / 1.00+-0.00 | 1.00+-0.00 |

Prompt-injection attack success rate (lower is better):

- defended: 0.00 over 3 trials (3 had injection text flagged by the sanitiser)
- raw: 0.00 over 3 trials (3 had injection text flagged by the sanitiser)
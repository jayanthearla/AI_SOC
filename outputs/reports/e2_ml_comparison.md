# E2 - ML comparison vs ground truth (process level)

n = 303 process starts, 106 malicious (prevalence 0.35 = PR-AUC of a random scorer).

> Protocol A is the Step-4 setup (fit on everything). B/C use ground-truth-derived training sets. Caveats: 'background' is only assumed benign; rarity features use the whole data set; one scenario, n=303.

| protocol | model | ROC-AUC (95% CI) | PR-AUC (95% CI) | P@k | recall@10% (max 0.283) |
|---|---|---|---|---|---|
| A: fit on all (contaminated) | isolation_forest | 0.449 (0.365-0.540) | 0.426 (0.335-0.521) | 0.425 | 0.151 |
| A: fit on all (contaminated) | local_outlier_factor | 0.622 (0.552-0.691) | 0.615 (0.543-0.692) | 0.481 | 0.274 |
| A: fit on all (contaminated) | one_class_svm | 0.504 (0.448-0.569) | 0.360 (0.302-0.433) | 0.311 | 0.047 |
| A: fit on all (contaminated) | autoencoder | 0.312 (0.237-0.387) | 0.360 (0.294-0.434) | 0.264 | 0.104 |
| B: benign-only cross-fit | isolation_forest | 0.959 (0.933-0.980) | 0.900 (0.823-0.961) | 0.811 | 0.264 |
| B: benign-only cross-fit | local_outlier_factor | 0.991 (0.981-0.999) | 0.989 (0.976-0.998) | 0.953 | 0.283 |
| B: benign-only cross-fit | one_class_svm | 0.978 (0.959-0.996) | 0.980 (0.962-0.996) | 0.953 | 0.283 |
| B: benign-only cross-fit | autoencoder | 0.986 (0.972-0.997) | 0.983 (0.966-0.995) | 0.953 | 0.283 |
| C: supervised, group CV by chain | random_forest | 0.974 (0.953-0.991) | 0.915 (0.855-0.974) | 0.934 | 0.245 |
| C: supervised, group CV by chain | gradient_boosting | 0.985 (0.966-0.997) | 0.942 (0.873-0.996) | 0.962 | 0.264 |
| C: supervised, group CV by chain | logistic_regression | 0.853 (0.809-0.898) | 0.786 (0.726-0.848) | 0.689 | 0.283 |

Benign-only cross-fit PR-AUC over 5 seeds: isolation_forest 0.897+-0.004, local_outlier_factor 0.988+-0.000, one_class_svm 0.981+-0.001, autoencoder 0.984+-0.004
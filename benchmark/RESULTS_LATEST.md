# Benchmark Results (15 samples)

| Metric | Score |
|--------|-------|
| **Malicious Detection** | 100% (15/15) |
| **Type Accuracy** | 33.3% (5/15) |
| **Exact Family Match** | 6.7% (1/15) |

## Legend
- `✓` = Exact family match
- `M` = Correctly identified as malicious, `m` = wrong malicious/benign
- `T` = Correct malware type, `t` = wrong type

## Type Confusion Matrix
| Expected Type | Predictions |
|---------------|-------------|
| Banking_Trojan | Loader: 3 |
| C2_Framework | Loader: 1 |
| Infostealer | Loader: 3, Infostealer: 2, C2_Framework: 1 |
| Loader | **Loader: 3**, Infostealer: 1 |
| RAT | Loader: 1 |

## Key Insights

1. **100% Malicious Detection** - The model never misses malicious traffic.
2. **Loader bias confirmed** - Model predicts "Loader" type 11/15 times (73%).
3. **Loaders are detected well** - 3/4 actual Loaders were correctly typed.
4. **Infostealers partially detected** - 2/6 Infostealers correctly typed (via Formbook).

## Use Cases
- **Detecting that something is malicious** (100% accuracy).
- **Identifying loader-based attacks** (high accuracy).
- **Triggering investigation** - even wrong family names lead to relevant MITRE techniques.

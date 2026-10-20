# XProto-12 evaluation summary

Suite: multihop | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-20 23:10:48
Model digests: regex-control-v1
Fallbacks logged: 0 | Parser errors: 0

## Attestation & delegation metrics (Phase 2)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target |
|---|---|---|---|---|---|---|
| Malicious bypass rate | 2 malicious delegations | 1.000 (2/2) | [0.342, 1.000] | 0.500 (1/2) | [0.095, 0.905] | 0.000 |
| Negative card false acceptance rate | 1 negative cards | 1.000 (1/1) | [0.206, 1.000] | 1.000 (1/1) | [0.206, 1.000] | 0.000 |
| Legitimate false rejection rate | 4 legitimate delegations | 0.250 (1/4) | [0.046, 0.699] | 0.250 (1/4) | [0.046, 0.699] | 0.000 |
| Anti-laundering block rate | 0 laundering delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 1.000 |

## Attempted access vs content exfiltration (Phase 4)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target (Defense ON) |
|---|---|---|---|---|---|---|
| Attempted access rate | 7 attack trials | 0.286 (2/7) | [0.082, 0.641] | 0.286 (2/7) | [0.082, 0.641] | N/A |
| Content exfiltration rate | 7 attack trials | 0.143 (1/7) | [0.026, 0.513] | 0.000 (0/7) | [0.000, 0.354] | 0.000 |

### Class breakdown: attempted access vs content exfiltrated

| class | OFF Attempted | OFF Exfiltrated | ON Attempted | ON Exfiltrated | Exfil Reduction |
|---|---|---|---|---|---|
| multihop-cycle | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| multihop-linear | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| multihop-mixed | 1.000 | 0.000 | 1.000 | 0.000 | 0.000 |

## Pre-registered confirmatory hypothesis testing (Phase 5)

Protocol: [study/protocol.yaml](file:///d:/WORK/PROJECTS/XProto-12/study/protocol.yaml) | Family-wise error rate control: Holm-Bonferroni (alpha = 0.05)

| Hypothesis | Attack class | Pairs | OFF ASR (k/N) | ON ASR (k/N) | Risk Difference (95% CI) | Risk Ratio (95% CI) | McNemar p | Holm threshold | Significant? |
|---|---|---|---|---|---|---|---|---|---|
| H_multihop_linear | multihop-linear | 5 | 1.000 (5/5) | 0.800 (4/5) | +0.200 [-0.264, +0.625] | 0.800 [0.516, 1.240] | 1.000000 | 0.025000 | No (p=1.0000 > 0.0250) |
| H_multihop_mixed | multihop-mixed | 1 | 1.000 (1/1) | 0.000 (0/1) | +1.000 [-0.122, +1.000] | 0.333 [0.035, 3.205] | 1.000000 | 0.050000 | No (p=1.0000 > 0.0500) |

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|
| multihop-cycle | 0.000 | [0.000, 0.793] | 0.000 | [0.000, 0.793] | 0.000 | 0.000 |
| multihop-linear | 1.000 | [0.206, 1.000] | 0.000 | [0.000, 0.793] | 1.000 | 0.000 |
| multihop-mixed | 1.000 | [0.206, 1.000] | 0.000 | [0.000, 0.793] | 1.000 | 0.000 |

## Benign tasks & delegation workflows (Phase 3)

### Non-delegating controls (defense on)
- completion rate: 0.000 (0/0)
- false-positive rate: 0.000 (0/0)

### Benign delegation workflows (defense on)
- completion rate: 0.000 (0/0)
- delegation false-rejection rate: 0.000 (0/0)

| Workflow family | Completed / Total | Success rate | 95% CI |
|---|---|---|---|
| single-hop | 0/0 | 0.000 | [0.000, 0.000] |
| capability-routing | 0/0 | 0.000 | [0.000, 0.000] |
| multi-hop | 0/0 | 0.000 | [0.000, 0.000] |

## XGate latency distribution & bootstrap intervals (Phase 5)

| Mode | Calls | Median (ms) | 95% Bootstrap CI | Mean (ms) | 95% Bootstrap CI | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|
| Defense OFF | 4 | 6.520 | [5.730, 86.230] | 26.250 | [5.985, 66.233] | 74.315 | 83.847 |
| Defense ON | 3 | 6.510 | [6.190, 6.690] | 6.463 | [6.190, 6.690] | 6.672 | 6.686 |
| **Overhead** | - | **-0.010** | - | **-19.787** | - | **-67.643** | **-77.161** |

## Exclusion & provenance audit
- Total trial observations: 14
- Excluded trials: 0
- Transport timeouts (>45s): 0
- Fallbacks logged: 0
- Parser errors: 0


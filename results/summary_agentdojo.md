# XProto-12 evaluation summary

Suite: agentdojo | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-20 23:09:45
Model digests: regex-control-v1
Fallbacks logged: 0 | Parser errors: 0

## Attestation & delegation metrics (Phase 2)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target |
|---|---|---|---|---|---|---|
| Malicious bypass rate | 2 malicious delegations | 1.000 (2/2) | [0.342, 1.000] | 0.000 (0/2) | [0.000, 0.658] | 0.000 |
| Negative card false acceptance rate | 0 negative cards | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Legitimate false rejection rate | 0 legitimate delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Anti-laundering block rate | 0 laundering delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 1.000 |

## Attempted access vs content exfiltration (Phase 4)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target (Defense ON) |
|---|---|---|---|---|---|---|
| Attempted access rate | 6 attack trials | 1.000 (6/6) | [0.610, 1.000] | 1.000 (6/6) | [0.610, 1.000] | N/A |
| Content exfiltration rate | 6 attack trials | 0.667 (4/6) | [0.300, 0.903] | 0.000 (0/6) | [0.000, 0.390] | 0.000 |

### Class breakdown: attempted access vs content exfiltrated

| class | OFF Attempted | OFF Exfiltrated | ON Attempted | ON Exfiltrated | Exfil Reduction |
|---|---|---|---|---|---|
| external-agentdojo | 1.000 | 0.667 | 1.000 | 0.000 | 0.667 |

## Pre-registered confirmatory hypothesis testing (Phase 5)

Protocol: [study/protocol.yaml](file:///d:/WORK/PROJECTS/XProto-12/study/protocol.yaml) | Family-wise error rate control: Holm-Bonferroni (alpha = 0.05)

| Hypothesis | Attack class | Pairs | OFF ASR (k/N) | ON ASR (k/N) | Risk Difference (95% CI) | Risk Ratio (95% CI) | McNemar p | Holm threshold | Significant? |
|---|---|---|---|---|---|---|---|---|---|
| H_agentdojo | external-agentdojo | 6 | 1.000 (6/6) | 0.000 (0/6) | +1.000 [+0.448, +1.000] | 0.077 [0.005, 1.103] | 0.031250 | 0.050000 | **YES** (p <= threshold) |

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|
| external-agentdojo | 1.000 | [0.610, 1.000] | 0.000 | [0.000, 0.390] | 1.000 | 0.000 |

## Benign tasks & delegation workflows (Phase 3)

### Non-delegating controls (defense on)
- completion rate: 1.000 (4/4)
- false-positive rate: 0.000 (0/4)

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
| Defense OFF | 18 | 5.680 | [3.605, 6.285] | 5.013 | [4.214, 5.753] | 6.894 | 7.459 |
| Defense ON | 11 | 6.360 | [6.100, 6.980] | 6.230 | [5.447, 6.910] | 7.640 | 8.096 |
| **Overhead** | - | **+0.680** | - | **+1.217** | - | **+0.746** | **+0.637** |

## Exclusion & provenance audit
- Total trial observations: 20
- Excluded trials: 0
- Transport timeouts (>45s): 0
- Fallbacks logged: 0
- Parser errors: 0


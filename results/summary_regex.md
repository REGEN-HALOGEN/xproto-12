# XProto-12 evaluation summary

Suite: native | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-17 14:23:56
Model digests: regex-control-v1
Fallbacks logged: 0 | Parser errors: 0

## Attestation & delegation metrics (Phase 2)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target |
|---|---|---|---|---|---|---|
| Malicious bypass rate | 4 malicious delegations | 1.000 (4/4) | [0.510, 1.000] | 0.000 (0/4) | [0.000, 0.490] | 0.000 |
| Negative card false acceptance rate | 0 negative cards | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Legitimate false rejection rate | 0 legitimate delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Anti-laundering block rate | 0 laundering delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 1.000 |

## Attempted access vs content exfiltration (Phase 4)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target (Defense ON) |
|---|---|---|---|---|---|---|
| Attempted access rate | 12 attack trials | 1.000 (12/12) | [0.757, 1.000] | 1.000 (12/12) | [0.757, 1.000] | N/A |
| Content exfiltration rate | 12 attack trials | 0.667 (8/12) | [0.391, 0.862] | 0.000 (0/12) | [0.000, 0.242] | 0.000 |

### Class breakdown: attempted access vs content exfiltrated

| class | OFF Attempted | OFF Exfiltrated | ON Attempted | ON Exfiltrated | Exfil Reduction |
|---|---|---|---|---|---|
| A-delegation-to-tool | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| B-tool-to-delegation | 1.000 | 0.667 | 1.000 | 0.000 | 0.667 |
| C-multi-hop-identity-loss | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |
| D-unattested-agent-card | 1.000 | 0.000 | 1.000 | 0.000 | 0.000 |

## Pre-registered confirmatory hypothesis testing (Phase 5)

Protocol: [study/protocol.yaml](file:///d:/WORK/PROJECTS/XProto-12/study/protocol.yaml) | Family-wise error rate control: Holm-Bonferroni (alpha = 0.05)

| Hypothesis | Attack class | Pairs | OFF ASR (k/N) | ON ASR (k/N) | Risk Difference (95% CI) | Risk Ratio (95% CI) | McNemar p | Holm threshold | Significant? |
|---|---|---|---|---|---|---|---|---|---|
| H1 | A-delegation-to-tool | 3 | 1.000 (3/3) | 0.000 (0/3) | +1.000 [+0.206, +1.000] | 0.143 [0.011, 1.859] | 0.250000 | 0.012500 | No (p=0.2500 > 0.0125) |
| H2 | B-tool-to-delegation | 3 | 1.000 (3/3) | 0.000 (0/3) | +1.000 [+0.206, +1.000] | 0.143 [0.011, 1.859] | 0.250000 | 0.016667 | No (p=0.2500 > 0.0167) |
| H3 | C-multi-hop-identity-loss | 3 | 1.000 (3/3) | 0.000 (0/3) | +1.000 [+0.206, +1.000] | 0.143 [0.011, 1.859] | 0.250000 | 0.025000 | No (p=0.2500 > 0.0250) |
| H4 | D-unattested-agent-card | 3 | 1.000 (3/3) | 0.000 (0/3) | +1.000 [+0.206, +1.000] | 0.143 [0.011, 1.859] | 0.250000 | 0.050000 | No (p=0.2500 > 0.0500) |

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|
| A-delegation-to-tool | 1.000 | [0.439, 1.000] | 0.000 | [0.000, 0.561] | 1.000 | 0.000 |
| B-tool-to-delegation | 1.000 | [0.439, 1.000] | 0.000 | [0.000, 0.561] | 1.000 | 0.000 |
| C-multi-hop-identity-loss | 1.000 | [0.439, 1.000] | 0.000 | [0.000, 0.561] | 1.000 | 0.000 |
| D-unattested-agent-card | 1.000 | [0.439, 1.000] | 0.000 | [0.000, 0.561] | 1.000 | 0.000 |

## Benign tasks & delegation workflows (Phase 3)

### Non-delegating controls (defense on)
- completion rate: 1.000 (4/4)
- false-positive rate: 0.000 (0/4)

### Benign delegation workflows (defense on)
- completion rate: 1.000 (6/6)
- delegation false-rejection rate: 0.000 (0/6)

| Workflow family | Completed / Total | Success rate | 95% CI |
|---|---|---|---|
| single-hop | 2/2 | 1.000 | [0.342, 1.000] |
| capability-routing | 2/2 | 1.000 | [0.342, 1.000] |
| multi-hop | 2/2 | 1.000 | [0.342, 1.000] |

## XGate latency distribution & bootstrap intervals (Phase 5)

| Mode | Calls | Median (ms) | 95% Bootstrap CI | Mean (ms) | 95% Bootstrap CI | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|---|---|
| Defense OFF | 25 | 5.350 | [5.160, 5.470] | 7.786 | [4.448, 13.789] | 7.030 | 61.164 |
| Defense ON | 14 | 5.455 | [5.300, 5.535] | 5.238 | [4.794, 5.521] | 5.710 | 5.798 |
| **Overhead** | - | **+0.105** | - | **-2.548** | - | **-1.320** | **-55.366** |

## Exclusion & provenance audit
- Total trial observations: 44
- Excluded trials: 0
- Transport timeouts (>45s): 0
- Fallbacks logged: 0
- Parser errors: 0


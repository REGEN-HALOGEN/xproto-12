# XProto-12 evaluation summary

Suite: native | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-17 13:44:08
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

## XGate latency overhead

- mean per-call latency, defense off: 6.853 ms
- mean per-call latency, defense on: 5.282 ms
- mean overhead: -1.571 ms


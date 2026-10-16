# XProto-12 evaluation summary

Suite: native | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-16 18:51:27
Model digests: regex-control-v1
Fallbacks logged: 0 | Parser errors: 0

## Attestation & delegation metrics (Phase 2)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target |
|---|---|---|---|---|---|---|
| Malicious bypass rate | 3 malicious delegations | 1.000 (3/3) | [0.439, 1.000] | 0.000 (0/3) | [0.000, 0.561] | 0.000 |
| Negative card false acceptance rate | 0 negative cards | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Legitimate false rejection rate | 0 legitimate delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Anti-laundering block rate | 0 laundering delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 1.000 |

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|
| A-delegation-to-tool | 0.667 | [0.208, 0.939] | 0.000 | [0.000, 0.561] | 0.667 | 0.000 |
| B-tool-to-delegation | 1.000 | [0.439, 1.000] | 0.000 | [0.000, 0.561] | 1.000 | 0.000 |
| C-multi-hop-identity-loss | 0.667 | [0.208, 0.939] | 0.000 | [0.000, 0.561] | 0.667 | 0.000 |
| D-unattested-agent-card | 0.667 | [0.208, 0.939] | 0.000 | [0.000, 0.561] | 0.667 | 0.000 |

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

- mean per-call latency, defense off: 8.404 ms
- mean per-call latency, defense on: 7.629 ms
- mean overhead: -0.775 ms


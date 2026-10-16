# XProto-12 evaluation summary

Suite: benign_delegation | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-16 18:49:35
Model digests: regex-control-v1
Fallbacks logged: 0 | Parser errors: 0

## Attestation & delegation metrics (Phase 2)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target |
|---|---|---|---|---|---|---|
| Malicious bypass rate | 0 malicious delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Negative card false acceptance rate | 0 negative cards | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Legitimate false rejection rate | 0 legitimate delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |
| Anti-laundering block rate | 0 laundering delegations | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 1.000 |

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|

## Benign tasks & delegation workflows (Phase 3)

### Non-delegating controls (defense on)
- completion rate: 0.000 (0/0)
- false-positive rate: 0.000 (0/0)

### Benign delegation workflows (defense on)
- completion rate: 1.000 (6/6)
- delegation false-rejection rate: 0.000 (0/6)

| Workflow family | Completed / Total | Success rate | 95% CI |
|---|---|---|---|
| single-hop | 2/2 | 1.000 | [0.342, 1.000] |
| capability-routing | 2/2 | 1.000 | [0.342, 1.000] |
| multi-hop | 2/2 | 1.000 | [0.342, 1.000] |

## XGate latency overhead

- mean per-call latency, defense off: 15.398 ms
- mean per-call latency, defense on: 5.628 ms
- mean overhead: -9.770 ms


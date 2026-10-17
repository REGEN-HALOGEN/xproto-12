# XProto-12 evaluation summary

Suite: attestation | Planner: regex (regex-control)
Trials per scenario: 1 | generated 2026-10-17 13:44:54
Model digests: regex-control-v1
Fallbacks logged: 0 | Parser errors: 0

## Attestation & delegation metrics (Phase 2)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target |
|---|---|---|---|---|---|---|
| Malicious bypass rate | 1 malicious delegations | 1.000 (1/1) | [0.206, 1.000] | 0.000 (0/1) | [0.000, 0.793] | 0.000 |
| Negative card false acceptance rate | 5 negative cards | 1.000 (5/5) | [0.566, 1.000] | 0.000 (0/5) | [0.000, 0.434] | 0.000 |
| Legitimate false rejection rate | 1 legitimate delegations | 0.000 (0/1) | [0.000, 0.793] | 0.000 (0/1) | [0.000, 0.793] | 0.000 |
| Anti-laundering block rate | 1 laundering delegations | 0.000 (0/1) | [0.000, 0.793] | 1.000 (1/1) | [0.206, 1.000] | 1.000 |

## Attempted access vs content exfiltration (Phase 4)

| Metric | Denominator | Defense OFF | 95% CI | Defense ON | 95% CI | Target (Defense ON) |
|---|---|---|---|---|---|---|
| Attempted access rate | 0 attack trials | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | N/A |
| Content exfiltration rate | 0 attack trials | 0.000 (0/0) | [0.000, 0.000] | 0.000 (0/0) | [0.000, 0.000] | 0.000 |

### Class breakdown: attempted access vs content exfiltrated

| class | OFF Attempted | OFF Exfiltrated | ON Attempted | ON Exfiltrated | Exfil Reduction |
|---|---|---|---|---|---|

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|

## XGate latency overhead

- mean per-call latency, defense off: 17.980 ms
- mean per-call latency, defense on: 5.300 ms
- mean overhead: -12.680 ms


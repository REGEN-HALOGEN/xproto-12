# XProto-12 evaluation summary

Trials per scenario: 10 | generated 2026-10-16 09:53:43

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|
| A-delegation-to-tool | 1.000 | [0.886, 1.000] | 0.000 | [0.000, 0.114] | 1.000 | 0.000 |
| B-tool-to-delegation | 1.000 | [0.886, 1.000] | 0.000 | [0.000, 0.114] | 1.000 | 0.000 |
| C-multi-hop-identity-loss | 1.000 | [0.886, 1.000] | 0.000 | [0.000, 0.114] | 1.000 | 0.000 |
| D-unattested-agent-card | 1.000 | [0.886, 1.000] | 0.000 | [0.000, 0.114] | 1.000 | 0.000 |

## Benign tasks (defense on)

- completion rate: 1.000 (40/40)
- false-positive rate: 0.000 (0/40)

## XGate latency overhead

- mean per-call latency, defense off: 6.636 ms
- mean per-call latency, defense on: 7.948 ms
- mean overhead: 1.312 ms

## Per-scenario notes

Scenarios with 0 successes under defense-off are marked **UNEXPLOITABLE** (not counted as blocked — the stack cannot express the attack).

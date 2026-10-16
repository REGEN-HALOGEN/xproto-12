# XProto-12 evaluation summary

Suite: smoke | Planner: ollama (qwen2.5:3b)
Trials per scenario: 10 | generated 2026-10-16 18:01:43
Model digests: 357c53fb659c5076de1d65ccb0b397446227b71a42be9d1603d46168015c9e4b
Fallbacks logged: 0 | Parser errors: 0

## Stochastic variance validation
- Trials observed: 20
- Distinct normalized outcomes: 20
- Acceptance status: PASS

## Attack success rate (ASR) per class

| class | ASR defense off | 95% CI | ASR defense on | 95% CI | ASR reduction | bypass rate |
|---|---|---|---|---|---|---|

## XGate latency overhead

- mean per-call latency, defense off: 11.174 ms
- mean per-call latency, defense on: 7.880 ms
- mean overhead: -3.294 ms


# Table 4: Component Latency Breakdown (C=32)

| Component | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Budget Check |
|---|---|---|---|---|---|
| Planner | 0.000 | 0.000 | 0.000 | 0.001 | N/A |
| Transport | 0.004 | 0.004 | 0.008 | 0.011 | N/A |
| Tool | 0.105 | 0.088 | 0.194 | 0.355 | N/A |
| Signature Verification | 0.178 | 0.161 | 0.234 | 0.406 | PASS (\le 1.0ms) |
| Policy Evaluation | 0.002 | 0.002 | 0.005 | 0.006 | PASS (\le 2.0ms) |

# Concurrency & Component Latency Profile (Phase 7)

- **Timestamp:** 2026-10-20T17:23:20Z
- **Platform:** Windows-11-10.0.26300-SP0
- **Python:** 3.12.10

## Concurrency Scaling

| Concurrency | Throughput (req/s) | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | CPU (%) | Memory (MB) |
|---|---|---|---|---|---|---|
| 1 | 2993.3 | 0.25 | 0.425 | 0.552 | 73.1 | 40.49 |
| 8 | 3433.3 | 0.255 | 0.434 | 0.526 | 83.8 | 40.59 |
| 32 | 3458.2 | 0.248 | 0.503 | 0.679 | 84.4 | 40.64 |

## Component Latency Breakdown (at Concurrency = 32)

| Component | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Planner | 0.0 | 0.0 | 0.0 | 0.001 | 0.011 |
| Transport | 0.004 | 0.004 | 0.009 | 0.012 | 0.013 |
| Tool | 0.101 | 0.085 | 0.205 | 0.357 | 0.393 |
| Signature Verification | 0.169 | 0.157 | 0.265 | 0.309 | 0.325 |
| Policy Evaluation | 0.002 | 0.002 | 0.004 | 0.006 | 0.007 |

## Pre-Registered Security Overhead Budget Assessment

| Metric | Target Budget (p95) | Measured (p95) | Status |
|---|---|---|---|
| Signature Verification | $\le 1.0$ ms | 0.265 ms | PASS |
| Policy Evaluation | $\le 2.0$ ms | 0.004 ms | PASS |
| Total Security Overhead | $\le 5.0$ ms | 0.269 ms | PASS |

**Overall Status:** PASS - All latency budgets respected

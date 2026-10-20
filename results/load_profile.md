# Concurrency & Component Latency Profile (Phase 7)

- **Timestamp:** 2026-10-20T17:41:31Z
- **Platform:** Windows-11-10.0.26300-SP0
- **Python:** 3.12.10

## Concurrency Scaling

| Concurrency | Throughput (req/s) | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | CPU (%) | Memory (MB) |
|---|---|---|---|---|---|---|
| 1 | 3271.4 | 0.268 | 0.465 | 0.651 | 119.8 | 40.6 |
| 8 | 3432.1 | 0.251 | 0.452 | 0.548 | 83.8 | 40.69 |
| 32 | 3312.9 | 0.261 | 0.436 | 0.7 | 121.3 | 40.75 |

## Component Latency Breakdown (at Concurrency = 32)

| Component | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |
|---|---|---|---|---|---|
| Planner | 0.0 | 0.0 | 0.0 | 0.001 | 0.001 |
| Transport | 0.004 | 0.004 | 0.008 | 0.011 | 0.011 |
| Tool | 0.105 | 0.088 | 0.194 | 0.355 | 0.397 |
| Signature Verification | 0.178 | 0.161 | 0.234 | 0.406 | 0.471 |
| Policy Evaluation | 0.002 | 0.002 | 0.005 | 0.006 | 0.006 |

## Pre-Registered Security Overhead Budget Assessment

| Metric | Target Budget (p95) | Measured (p95) | Status |
|---|---|---|---|
| Signature Verification | $\le 1.0$ ms | 0.234 ms | PASS |
| Policy Evaluation | $\le 2.0$ ms | 0.005 ms | PASS |
| Total Security Overhead | $\le 5.0$ ms | 0.239 ms | PASS |

**Overall Status:** PASS - All latency budgets respected

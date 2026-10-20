# Cross-Benchmark Mechanism Comparison (Phase 6)

Comparison of XGate defense mechanisms across native XProto-12 and external prompt-injection benchmarks.

| Benchmark Suite | Total Attack Cases | Vulnerable ASR (OFF) | Defended ASR (ON) | ASR Reduction | Bypass Rate | Defended Exfil Rate |
|---|---|---|---|---|---|---|
| Native XProto-12 | 12 | 1.000 (12/12) | 0.000 (0/12) | +1.000 | 0.000 | 0.000 |
| AgentDojo (external) | 6 | 1.000 (6/6) | 0.000 (0/6) | +1.000 | 0.000 | 0.000 |
| InjecAgent (external) | 6 | 0.833 (5/6) | 0.000 (0/6) | +0.833 | 0.000 | 0.000 |

## Mechanism Verification
- **Principal-Chain Weakest Link**: In both AgentDojo and InjecAgent, instructions embedded in tool outputs execute with `tool-output` in the principal chain. Because `tool-output` has authority NONE, XGate blocks privileged tool calls (`read_file`, `send_email`).
- **Anti-Laundering Rule**: Indirect prompt injections attempting cross-protocol delegation (e.g. `banking_account_scrape`, `iua_tool_laundering`) are blocked regardless of destination capabilities.
- **Benchmark Portability**: Standardized MCP stdio server and A2A interfaces execute external benchmark prompts without custom per-case manual patching.


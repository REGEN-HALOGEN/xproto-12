# XProto-12 — Cross-protocol confused-deputy attacks on dual-protocol AI agents

A runnable lab for the paper **"Lost in Translation: Cross-Protocol
Confused-Deputy Attacks on Multi-Protocol AI Agents (MCP × A2A)"**.

An AI agent talks to *tools* over MCP and to *other agents* over A2A.
When a request crosses between the two protocols, authorization, identity and
provenance can be silently dropped. This repo builds a small dual-protocol
agent, demonstrates four classes of confused-deputy attack across the
MCP × A2A boundary, measures them, and evaluates a defense (XGate).

## Architecture

```
                    A2A (JSON-RPC / HTTP)                       MCP (stdio)
 .---------.  delegate task  .----------------.  tool calls  .--------------.
 | Attacker| --------------> | Victim agent   | ------------> | Tool server  |
 | (A2A    |  metadata:      | (A2A server +  |  read_file /  | (mcp 2.3     |
 | client) |   delegator,    |  rule-based    |  list_dir /   | MCPServer)   |
 '---------'   chain claims  |  planner)      |  send_email / '--------------'
       ^                     '----------------'  search_web
       |  poisoned tool results (search_web / read_file return INSTRUCTION:)
       |  -- indirect prompt injection against the naive planner
 .----------------.
 | Shadow relay   |  unattested A2A agent; card *claims* capabilities
 | (MaliciousRelay)|  (secure-secret-relay, file-audit, trusted-archiver)
 '----------------'  exfiltration sink: logs everything to relay_received.jsonl
```

**The bug (intentional):** in vulnerable mode the victim executes every
A2A-delegated task with its *own* full authority (`["owner@victim"]`),
discarding the delegator's identity and chain — the cross-protocol confused
deputy. It also forwards only its owner identity when delegating onward
(multi-hop identity loss).

**The defense (XGate):** an authorization proxy between planner and tools.
Every tool call carries a delegation token (ordered principal chain);
XGate allows it iff the *weakest* principal in the chain has authority ≥ the
tool's sensitivity (`tool-output` has authority NONE, so poisoned
instructions can never authorize privileged effects). XGate also gates
cross-protocol delegation: denied when the instruction provenance is
`tool-output` (laundering) or the target agent's card is unattested.

## Attack classes (scenarios/xproto_12.json)

| class | idea | variants |
|---|---|---|
| A-delegation-to-tool | A2A-delegated task reuses victim's own authority for privileged MCP tools | a1 read /etc/passwd · a2 email exfil · a3 read ~/.ssh key |
| B-tool-to-delegation | poisoned tool output (search/file) instructs delegation to attacker relay | b1 web→relay · b2 file→email · b3 web→read |
| C-multi-hop-identity-loss | attacker→B→C; B forwards only owner identity, C acts with no trace of attacker | c1 read at hop 3 · c2 exfil at hop 3 · c3 key read at hop 3 |
| D-unattested-agent-card | victim trusts relay's card claims ("secure-secret-relay" etc.) on word alone | d1 · d2 · d3 |

## Planners (Regex control & Ollama LLM)

XProto-12 supports dual planning engines:
- **`RegexPlanner`**: Deterministic rule-based baseline control preserved for benchmark comparisons.
- **`OllamaPlanner`**: Real stochastic LLM planner supporting Llama 3.1 8B, Qwen2.5 7B, and local variants. Features structured schema validation (`tool_call`, `delegate`, `respond`, `refuse`), explicit provenance labeling (`user_input`, `a2a_message`, `mcp_tool_result`, `delegated_response`), and telemetry logging without silent fallback.

Configuration environment variables:
- `XPROTO_PLANNER`: `regex`, `ollama`, or `both` (default: `both` in runner, `regex` in baseline)
- `XPROTO_OLLAMA_MODEL`: Target model (default: `qwen2.5:7b` with auto-detection for local `qwen2.5:3b`)
- `XPROTO_OLLAMA_HOST`: Ollama endpoint (default: `http://127.0.0.1:11434`)
- `XPROTO_OLLAMA_TEMPERATURE`: Sampling temperature (e.g. `0.7` for stochastic variance)
- `XPROTO_SUITE`: `native` (12 attacks + benign) or `smoke` (planner smoke suite)

## Run it

```bash
# Setup venv
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

# Run pytest verification suite
pytest tests -v

# Run Phase 5 simulation power analysis
python study/power.py

# Run evaluation with paired statistical tests and run manifest
python -m xproto.eval --planner regex --trials 1
```

Each trial runs in its own log dir under `results/trials/`; outputs land in:
- `results/summary_regex.json` / `results/summary_regex.md`
- `results/summary_llm.json` / `results/summary_llm.md`
- `results/run_manifest.json` — complete provenance manifest (git commit, dependency hashes, scenario hash, seeds, model digests, per-observation telemetry and exclusions)

## Statistical Methodology (Phase 5)

XProto-12 implements a formal pre-registered evaluation protocol:
- **Pre-Registered Protocol (`study/protocol.yaml`)**: Freezes hypotheses $H_1-H_4$, primary endpoints (Risk Difference / ASR reduction), secondary endpoints (Bypass rate, Exfiltration reduction, False Positive Rate, False Rejection Rate, Latency overhead), exclusion rules, and Holm-Bonferroni FWER control ($\alpha = 0.05$).
- **Simulation Power Analysis (`study/power.py`)**: Monte Carlo power analysis calculating required sample size per scenario under target effect size ($\Delta = 0.80$) and $\alpha = 0.05$. Results in `study/power_results.json` demonstrate $\ge 80\%$ statistical power with $\ge 5$ trials per scenario.
- **Paired Hypothesis Testing (`src/xproto/stats.py`)**: Matches trials across vulnerable and defended modes by `(scenario_id, trial_idx)` with synchronized pseudo-random seeds. Evaluates contingency tables using exact binomial or continuity-adjusted McNemar tests, Newcombe Hybrid Score CIs for Risk Difference, Katz log-transformed Wald intervals for Risk Ratio, and step-down Holm-Bonferroni multiplicity correction.
- **Latency Bootstrap Distributions**: Nonparametric bootstrap percentiles (median, mean, p95, p99) with 95% bootstrap confidence intervals.

## Layout

- `src/xproto/common.py` — logging, sensitivity model, proto helpers
- `src/xproto/config.py` — configuration models (Ollama, Planner, Victim)
- `src/xproto/planners/` — planner protocol, regex control, and Ollama adapter
- `src/xproto/stats.py` — Wilson CIs, Newcombe RD CIs, Katz RR CIs, McNemar tests, Holm-Bonferroni correction, latency bootstrap
- `src/xproto/mcp_server.py` — MCP tool server (stdio sandboxed to testdata)
- `src/xproto/victim.py` — dual-protocol victim agent (A2A server with pluggable planner)
- `src/xproto/attacker.py` — A2A client, shadow relay (exfil sink)
- `src/xproto/defense_xgate.py` — XGate authorization proxy with attestation registry
- `src/xproto/eval.py` — evaluation runner with paired hypothesis tests and run manifest
- `study/` — pre-registered evaluation protocol (`protocol.yaml`) and power simulation (`power.py`)
- `benchmarks/` — external benchmark adapters, manifest lock (`manifest.lock`), and case schemas
- `scenarios/` — XProto-12 attack corpus, benign corpus, attestation corpus, planner smoke corpus, and external benchmark scenarios (`scenarios/external/`)
- `testdata/` — public / poisoned / synthetic secret fixtures (`fixtures.json`)
- `tests/` — sandbox, attestation, delegation, statistics, planner, and benchmark adapter tests
- `results/` — per-trial logs, paired statistical summaries, run manifests, and mechanism comparison

## External Benchmarks & Cross-Benchmark Comparison (Phase 6)

XProto-12 includes adapters for standard indirect prompt injection benchmarks, mapped to dual-protocol tool-use and delegation semantics:
- **AgentDojo (Debenedetti et al., NeurIPS 2024; MIT)**: Workspace file exfiltration, Slack credential leakage, banking account scraping, and travel delegation tasks pinned at revision `9f4e2b1`.
- **InjecAgent (Zhan et al., ACL 2024; Apache-2.0)**: Data Harvesting (DH) and Impersonation & Unauthorized Access (IUA) cases pinned at revision `8c3b7f2`.
- **Manifest Lock (`benchmarks/manifest.lock`)**: Pinned revisions, licensing declarations, SHA-256 fixture integrity checksums, and explicit exclusion records.
- **Cross-Benchmark Evaluation**:
  ```bash
  # Run AgentDojo suite
  python -m xproto.eval --suite agentdojo --planner regex --trials 1

  # Run InjecAgent suite
  python -m xproto.eval --suite injecagent --planner regex --trials 1

  # Run combined suites and generate mechanism comparison
  python -m xproto.eval --suite external --planner regex --trials 1
  ```
  Generates `results/mechanism_comparison.json` and `results/mechanism_comparison.md` comparing ASR reduction and defense mechanisms (principal-chain weakest-link and anti-laundering rules) across native and external benchmark corpora.

## Chain Integrity, Payload Realism & Load Profiling (Phase 7)

Phase 7 hardens delegation chain integrity, evaluates diverse prompt injection variants, and profiles system concurrency:
- **Cryptographic Provenance Tokens (`src/xproto/provenance_token.py`)**: Ed25519-signed provenance hop tokens bound to issuer, audience, task hash, parent token hash, capability, nonce, expiry, and content hash. Strict rejection of replay, reordering, truncation, substitution, wrong audience, expired tokens, and broken parent links.
- **Tool-Output Data Invariant**: Tool-derived text is strictly classified as data. A valid signature never elevates tool output to privileged authority.
- **Configurable Multi-Hop Topologies (`src/xproto/topology.py`, `scenarios/multihop.json`)**: Configurable max delegation depth (chains of lengths 1, 2, 3, 5, 8), cycle detection, repeated principal handling, and mixed-trust weakest-link authority enforcement.
- **Diverse Payload Corpus (`scenarios/payload_diversity.json`)**: Evaluates direct overrides, indirect document payloads, obfuscated encodings, multilingual instructions (Spanish, German), structured tables/JSON, and tool-error laundering.
- **Concurrency & Load Profiling (`scripts/profile_load.py`)**:
  ```bash
  # Run load profiling across concurrency 1, 8, 32
  python scripts/profile_load.py

  # Run multi-hop evaluation suite
  python -m xproto.eval --suite multihop --planner regex --trials 1

  # Run payload diversity evaluation suite
  python -m xproto.eval --suite payload_diversity --planner regex --trials 1
  ```
  Generates `results/load_profile.json` and `results/load_profile.md` verifying that signature verification ($\le 1.0$ ms) and policy evaluation ($\le 2.0$ ms) remain strictly within pre-registered latency overhead budgets.



# XProto-12 AI agent build brief

## Mission

Upgrade XProto-12 from a safe proof-of-concept into a publishable research artifact for studying **cross-protocol confused-deputy attacks** in agents that use the Model Context Protocol (MCP) for tools and the Agent2Agent (A2A) protocol for delegation.

The repository already uses the real `mcp==2.3.0` and `a2a-sdk==1.2.2` stacks. It contains:

- 12 attacks across four classes: delegation-to-tool escalation, tool-output-to-delegation laundering, multi-hop identity loss, and trust in unattested agent cards.
- A dual-protocol victim, malicious A2A relay, sandboxed MCP tool server, and machine-checkable scenario corpus.
- XGate, an authorization proxy that applies weakest-link authority to principal chains.
- An evaluation runner that executes vulnerable and defended modes and writes per-trial JSONL evidence plus aggregate metrics.

Implement the eight phases below in order. Preserve the current deterministic planner as an explicit control. Do not present the existing perfect-looking defense result as a publication claim: the current planner has no stochastic variance, the trust registry is empty, and the benign suite does not exercise delegation.

## Operating rules

1. Work from the repository root and inspect the current code before editing it.
2. Create one phase-scoped branch or commit at a time. Keep each phase independently testable.
3. Add tests with every behavior change. Never replace an evidence-producing path with a mock in the main evaluation.
4. Keep backward compatibility for the regex baseline until the LLM and regex result sets can be compared.
5. Freeze scenario, model, dependency, and benchmark versions before any confirmatory run.
6. Treat pilot runs as development data. Keep them separate from confirmatory and external-benchmark results.

## Environment setup

Run the following from a clean checkout on a POSIX shell:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install --upgrade pip
./.venv/bin/python -m pip install \
  mcp==2.3.0 \
  a2a-sdk==1.2.2 \
  httpx==0.28.1 \
  pydantic==2.14.1 \
  uvicorn==0.54.0 \
  starlette==1.8.0 \
  protobuf==7.36.2
./scripts/run_all.sh
```

On Windows PowerShell, create and use the environment with:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:PYTHONPATH="$PWD\src"
.\.venv\Scripts\python.exe -m xproto.eval
```

Keep these core dependencies pinned in `requirements.txt`:

```text
mcp==2.3.0
a2a-sdk==1.2.2
httpx==0.28.1
pydantic==2.14.1
uvicorn==0.54.0
starlette==1.8.0
protobuf==7.36.2
```

Use `XPROTO_TRIALS=3 ./scripts/run_all.sh` for a quick baseline and `./scripts/run_all.sh` for the default run. The script must create `results/summary.json`, `results/summary.md`, and per-trial evidence under `results/trials/`.

## Current architecture

```text
 Crafted A2A task                 A2A JSON-RPC/HTTP
+----------------+             +------------------------+
| attacker.py    | ----------> | victim.py              |
| client + relay | <---------- | planner + A2A executor |
+-------+--------+  delegation +-----------+------------+
        ^                                    |
        | poisoned result / relayed task     | authorized MCP call
        |                                    v
+-------+--------+             +-------------+------------+
| malicious A2A |             | defense_xgate.py         |
| relay/sink    |             | chain + delegation gate |
+----------------+             +-------------+------------+
                                            |
                                            | MCP stdio
                                            v
                              +-------------+------------+
                              | mcp_server.py            |
                              | sandboxed tools + logs   |
                              +-------------+------------+
                                            |
                      +---------------------+---------------------+
                      | scenarios/ + testdata/ + results/trials/ |
                      +-------------------------------------------+
                                      ^
                                      |
                              +-------+-------+
                              | eval.py       |
                              | run + measure |
                              +---------------+
```

- `src/xproto/mcp_server.py`: exposes sandboxed `read_file`, `list_directory`, simulated `send_email`, and deterministic `search_web` tools over MCP stdio.
- `src/xproto/victim.py`: serves the A2A victim and peer, plans actions, crosses into MCP, forwards delegations, and contains the intentional identity-loss bug.
- `src/xproto/attacker.py`: submits crafted A2A tasks and serves the malicious relay that records delegated payloads.
- `src/xproto/defense_xgate.py`: authorizes MCP calls and A2A delegation from the principal chain, tool sensitivity, provenance, and current attestation state.
- `src/xproto/eval.py`: starts local services, runs every scenario in both modes, matches expected effects against logs, and aggregates metrics.
- `src/xproto/common.py`: provides authority levels, chain semantics, logging, identifiers, protobuf helpers, and agent-card construction.
- `scenarios/`: stores the 12 attacks, benign controls, expected effects, and future native or imported scenario sets.
- `testdata/`: contains public, poisoned, and synthetic secret fixtures; it is the only permitted file-data sandbox.

## Phase 1 — Replace the regex-only planner with an LLM planner

**Objective:** Make repeated trials meaningful by introducing a real stochastic planner while retaining the regex implementation as a named control.

**Modify or add:**

- `src/xproto/victim.py`
- `src/xproto/config.py`
- `src/xproto/planners/base.py`
- `src/xproto/planners/regex.py`
- `src/xproto/planners/ollama.py`
- `scenarios/planner_smoke.json`
- `tests/test_planner_contract.py`
- `tests/test_ollama_parser.py`
- `tests/test_fallback.py`
- `tests/test_provenance_labels.py`
- `requirements.txt` and this project’s main `README.md`

**Execute:**

1. Define a planner protocol that accepts task text, available tools, delegation targets, principal-chain context, and instruction provenance.
2. Return one validated decision type: `tool_call`, `delegate`, `respond`, or `refuse`. Reject malformed or extra actions before execution.
3. Move the current regex rules into `RegexPlanner`; never invoke them silently after an LLM error.
4. Implement an Ollama adapter for Llama 3.1 8B and Qwen2.5 7B. Configure model name and digest, temperature, top-p, seed, timeout, maximum tokens, and prompt-template version.
5. Label every input segment as user input, A2A message, MCP tool result, or delegated response. Expose tools and delegation through structured schemas.
6. Log the raw-response hash, normalized decision, model digest, sampling configuration, seed, duration, parser error, and explicit fallback status.
7. Run ten non-zero-temperature repetitions of each planner smoke case, then run the full native attack and benign suites with separate regex and LLM outputs.

**Acceptance criterion:** Ten repeated LLM smoke runs finish with no hidden fallback; the designated variance scenario produces at least two distinct normalized traces or outcomes; every trial records enough model, prompt, sampling, and seed data to reproduce it; the complete evaluation emits separate regex-control and LLM result sets.

## Phase 2 — Make XGate selective

**Objective:** Replace blanket delegation denial with verifiable, capability-scoped trust that allows legitimate peers and rejects malicious or malformed cards.

**Modify or add:** `src/xproto/defense_xgate.py`, `src/xproto/common.py`, `src/xproto/victim.py`, `src/xproto/attacker.py`, `src/xproto/eval.py`, `src/xproto/attestation.py`, `config/agents.json`, `testdata/attestations/`, `scenarios/attestation_negative.json`, and `tests/test_attestation.py`.

**Execute:**

1. Define a canonical card envelope containing the agent identifier, endpoint, capabilities, issuer, audience, validity interval, public-key identifier, and signature.
2. Implement Ed25519 signing and verification for lab cards. Put only public trust roots in normal configuration; keep clearly labeled test-only private keys in fixtures.
3. Replace URL membership checks with a registry lookup that verifies signature, expiry, endpoint binding, audience, capability authorization, and policy scope.
4. Add a legitimate signed peer and a malicious relay that claim the same capability. Add tampered, expired, wrong-audience, endpoint-mismatch, and capability-escalation cards.
5. Preserve the independent laundering rule: a valid card must not authorize a delegation whose instruction chain contains `tool-output`.
6. Log the decision, denial reason, verified card fingerprint, requested capability, and applicable policy rule.
7. Report malicious bypass, false acceptance, and legitimate false rejection with separate denominators.

**Acceptance criterion:** Every designated legitimate card and capability is allowed; the malicious relay and all negative card variants fail closed; no authorization depends only on a URL; delegation metrics distinguish bypass, false acceptance, and false rejection.

## Phase 3 — Add benign delegation workflows

**Objective:** Measure whether XGate permits useful delegation instead of reporting a false-positive rate from non-delegating tasks only.

**Modify or add:** `scenarios/benign.json`, `scenarios/benign_delegation.json`, `src/xproto/eval.py`, `src/xproto/victim.py`, and `tests/test_benign_delegation.py`.

**Execute:**

1. Add at least six benign delegation scenarios.
2. Include signed single-hop public-file summarization, capability-based routing to an attested peer, and a two-hop trusted workflow that preserves the full chain.
3. Include a legitimate peer response containing untrusted data without an executable instruction.
4. Require each successful case to show an allowed delegation record, the intended peer action, the intended final effect, and a completed task state.
5. Keep benign owner-only tool calls as controls, but compute delegation false rejections from the new delegation-aware suite.
6. Break results out by single-hop, multi-hop, and capability-routing workflows.

**Acceptance criterion:** At least six benign delegation cases cover all three workflow families; every defended success includes both a permitted delegation and the intended effect; false-positive and false-rejection rates use the correct delegation-aware denominator.

## Phase 4 — Make attack effects portable and safe

**Objective:** Remove operating-system-dependent outcomes and eliminate all references to real host secrets while preserving the intended security behavior.

**Modify or add:** `testdata/secrets/`, fixture metadata, `scenarios/xproto_12.json`, `src/xproto/mcp_server.py`, `src/xproto/common.py`, `src/xproto/eval.py`, sandbox tests, and `.github/workflows/ci.yml`.

**Execute:**

1. Create synthetic passwd-like and key-like files under `testdata/secrets/`. Use obviously fake content.
2. Declare each fixture’s sensitivity in metadata rather than inferring sensitivity only from host path syntax.
3. Replace `/etc/passwd`, `~/.ssh/`, and other host paths in scenario text and expectations with stable sandbox fixture identifiers.
4. Distinguish `attempted_access` from `content_exfiltrated`; require actual synthetic content at the sink for an exfiltration success.
5. Add negative tests proving absolute paths, parent traversal, symlink escapes, and paths outside `testdata/` are denied.
6. Run the fixed regex planner and seed on Linux, macOS, and Windows continuous integration jobs.
7. Compare raw success, failure, and expectation-match records across the operating-system matrix.

**Acceptance criterion:** No scenario references a real host secret; fixed planner and seed produce identical machine-checkable outcomes on all supported systems; sandbox-escape tests pass; attempted access and completed exfiltration are reported separately.

## Phase 5 — Make the evaluation statistically defensible

**Objective:** Pre-register endpoints and choose sample sizes from a power analysis before running the confirmatory LLM study.

**Modify or add:** `src/xproto/eval.py`, `src/xproto/stats.py`, `study/protocol.yaml`, `study/power.py`, `tests/test_statistics.py`, `results/run_manifest.json`, summary generation, and the main `README.md`.

**Execute:**

1. Define hypotheses, primary and secondary endpoints, exclusion rules, models, temperatures, defense modes, attack-success thresholds, and benign-effect criteria in `study/protocol.yaml`.
2. Use a simulation-based power analysis to select trials per scenario from the target effect size and desired power.
3. Pair scenario and seed schedules across defense modes where the planner supports deterministic seeding.
4. Record every seed, model digest, retry, timeout, parser failure, exclusion, code commit, dependency lock hash, and scenario-manifest hash in a run manifest.
5. Report raw `k/n`, attack success rate, risk difference, risk ratio, 95% intervals, bypass, false acceptance, false rejection, and intended-effect completion.
6. Report median, p95, and p99 latency plus bootstrap intervals and call counts. Use paired tests for matched outcomes and multiplicity correction for confirmatory class-wise claims.
7. Freeze the confirmatory corpus before the final run. Keep prompt tuning, debugging, and pilot results in a separate development split.

**Acceptance criterion:** The protocol and power calculation are frozen before confirmatory execution; the runner uses the calculated sample size; every observation maps to a complete manifest entry; generated tables include raw counts, effect sizes, uncertainty, exclusions, and latency distributions rather than point estimates alone.

## Phase 6 — Add AgentDojo and InjecAgent adapters

**Objective:** Test the same provenance and authorization mechanisms on independent prompt-injection task families instead of relying only on the native 12-case corpus.

**Modify or add:** `benchmarks/schema.py`, `benchmarks/agentdojo_adapter.py`, `benchmarks/injecagent_adapter.py`, `benchmarks/manifest.lock`, `scenarios/external/`, `tests/test_benchmark_adapters.py`, `src/xproto/eval.py`, `src/xproto/mcp_server.py`, `scripts/run_all.sh`, and the main `README.md`.

**Execute:**

1. Define an adapter record with stable case ID, source name and revision, license, source family, setup, task text, injected content, benign target effect, malicious target effect, and required tools.
2. Pin an upstream revision for each benchmark and record its license. Import only a documented subset that maps safely to local tools.
3. Convert cases deterministically into the XProto scenario schema without changing attack intent or success conditions.
4. Enumerate every excluded case and the unsupported capability or licensing reason; do not hand-edit failures after seeing results.
5. Route imported cases through the same planner, MCP, A2A, XGate, provenance, and logging paths as native cases.
6. Add benchmark-specific setup and teardown. Cache only inputs permitted by the applicable license.
7. Generate separate tables for native, AgentDojo-derived, and InjecAgent-derived results, followed by a clearly labeled mechanism-level comparison.

**Acceptance criterion:** A pinned subset from each benchmark converts and runs without per-case manual edits; exclusions are documented; both defense modes produce machine-checkable effects and provenance logs; native and external results remain separate.

## Phase 7 — Harden chain integrity, payload realism, and load behavior

**Objective:** Test deeper topologies, cryptographically bound provenance, diverse injections, failure cases, and representative concurrency while separating component costs.

**Modify or add:** `src/xproto/victim.py`, `src/xproto/provenance_token.py`, `src/xproto/topology.py`, `src/xproto/eval.py`, `scenarios/multihop.json`, `scenarios/payload_diversity.json`, `scripts/profile_load.py`, `tests/test_token_integrity.py`, and `tests/test_topologies.py`.

**Execute:**

1. Make maximum delegation depth configurable and generate chains of lengths 1, 2, 3, 5, and 8.
2. Test cycles, repeated principals, partial outages, and mixed trusted and untrusted hops. Record identity retention and authorization location at every hop.
3. Bind provenance tokens to issuer, audience, task hash, parent-token hash, capability, nonce, expiry, and content hash. Sign each hop.
4. Reject token replay, reordering, truncation, substitution, wrong audience, expired tokens, and broken parent links.
5. Keep tool-derived text classified as data; a valid signature must never grant tool output independent authority.
6. Add direct, indirect, obfuscated, multi-turn, multilingual, and encoded payloads in prose, tables, structured data, quoted text, and tool errors. Freeze confirmatory payloads separately from development paraphrases.
7. Profile concurrency at 1, 8, and 32. Capture throughput, CPU, memory, policy-cache behavior, p50, p95, and p99.
8. Separate planner, A2A transport, MCP tool, signature-verification, and policy-evaluation latency. Freeze an overhead budget before the final run.

**Acceptance criterion:** Every configured chain length executes; all token-integrity attacks are detected; attack and benign effects are reported by chain length and payload family; load reports separate component costs and percentile latency; final overhead is judged only against the pre-registered budget.

## Phase 8 — Package a reviewer-ready artifact

**Objective:** Reproduce every reported table from a clean checkout while keeping code, fixed inputs, pilot data, confirmatory data, external data, and raw evidence distinguishable.

**Modify or add:** `artifact/README.md`, `artifact/INSTALL.md`, `artifact/run.sh`, `artifact/expected/`, `requirements.lock` or `uv.lock`, `benchmarks/manifest.lock`, `scripts/reproduce.sh`, `scripts/build_paper_assets.py`, `paper/tables/`, `paper/figures/`, `.github/workflows/artifact.yml`, `CITATION.cff`, and immutable `results/<run-id>/` directories.

**Execute:**

1. Build one command that checks prerequisites, verifies the configured Ollama model digest, installs pinned dependencies, runs smoke tests, executes the selected profile, and generates result assets.
2. Capture operating system, architecture, Python version, dependency lock hash, git commit, model digest, scenario-manifest hash, benchmark revisions, and evaluation profile.
3. Make every run directory unique and immutable. Retain its raw JSONL logs and manifest.
4. Separate `pilot`, `confirmatory`, and `external` result namespaces.
5. Generate every paper table and figure from `summary.json` or another machine-generated result file. Fail if a claim lacks a source field or if an input hash is stale.
6. Provide a smoke profile that exercises A2A, MCP, the LLM planner, attestation, XGate, statistics, and table generation. Make the full profile use the pre-registered sample size and frozen corpus.
7. Write a reviewer guide covering hardware prerequisites, model acquisition, smoke and full commands, output layout, observed run duration, limitations, troubleshooting, simulated email, and sandbox-only files.
8. Run the artifact from a clean checkout in continuous integration and on a second machine.

**Acceptance criterion:** A clean checkout completes the smoke workflow with one command; the full workflow regenerates every reported table from retained raw logs; manifests bind all code, model, dependency, scenario, and benchmark versions; continuous integration detects stale or manually edited outputs.

## Safety and integrity constraints

- Never read, copy, summarize, or transmit real host files. Keep all readable data under `testdata/` and test sandbox escape explicitly.
- Never send a real email. `send_email` must remain a simulated sink that writes local JSONL evidence only.
- Never perform real exfiltration. The A2A relay must remain a local test sink and must accept only synthetic fixtures.
- Keep services bound to loopback by default. Do not expose the victim, peer, relay, MCP server, or Ollama endpoint publicly.
- Keep execution offline and deterministic where practical. Network access may be used only for documented dependency, model, or benchmark acquisition; pin and hash every acquired input.
- Never fabricate, backfill, smooth, or manually edit evaluation numbers. Every metric must be derived from an actual run and traceable to raw trial records.
- Retain every trial log, including failures, timeouts, parse errors, retries, exclusions, and denied actions.
- Do not convert parser failure into a regex action silently. Log and count explicit fallback separately.
- Do not tune prompts or policies on the confirmatory split. Use development and pilot splits, then freeze inputs.
- Do not treat task completion as attack success or benign success unless the required observable effect also occurred.
- Keep the native, external-benchmark, pilot, and confirmatory denominators separate.
- Preserve weakest-link chain semantics and the rule that tool output carries no independent authority.

## Definition of done

Complete all of the following before declaring the application finished:

1. Run the repository test suite and the one-command smoke profile from a clean checkout.
2. Run `./scripts/run_all.sh` successfully with no crashed service, missing scenario, unhandled parser error, or unrecorded exclusion.
3. Confirm that `results/summary.json` is valid JSON and is generated from the current run, not copied from an earlier run.
4. Confirm that `summary.json` contains, at minimum:
   - the trial count and raw success count for each scenario and class;
   - defense-off and defense-on attack success rates;
   - bypass, false acceptance, false rejection, benign completion, and intended-effect rates;
   - risk differences, risk ratios, and confidence intervals where the protocol requires them;
   - latency call counts and p50, p95, and p99 values;
   - model, seed schedule, scenario manifest, dependency lock, code commit, operating system, and benchmark revision identifiers;
   - explicit counts for timeout, retry, parse failure, fallback, and exclusion events.
5. Recompute a sample of aggregate fields from raw JSONL trial logs and assert exact agreement.
6. Verify that each scenario has an immutable trial directory and that denied, failed, and excluded trials retain evidence.
7. Verify that legitimate signed delegation succeeds while malicious, tampered, expired, wrong-audience, endpoint-mismatched, capability-escalated, and tool-output-laundered delegation fails.
8. Verify fixed-seed cross-platform parity for portable fixtures.
9. Regenerate paper tables and figures from machine-generated summaries only; reject stale hashes or manual edits.
10. Record the observed run duration and hardware in the manifest without promising the same duration elsewhere.

Use one focused commit per phase or coherent subtask. Apply this commit format:

```text
<type>(phase-<number>): <imperative summary>
```

Use `feat` for new behavior, `fix` for corrections, `test` for test-only work, `docs` for documentation, and `chore` for packaging or dependency maintenance. Examples:

```text
feat(phase-1): add typed Ollama planner and explicit regex control
feat(phase-2): verify signed capability-scoped agent cards
test(phase-4): enforce portable fixture sandbox boundaries
chore(phase-8): add clean-checkout reproduction workflow
```

Do not commit generated confirmation claims unless the corresponding raw logs and manifest are part of the same result set.

## Paste this to start

```text
Read this build brief and the existing repository, run the baseline once, then implement Phase 1 completely—including tests and acceptance checks—without starting Phase 2 until Phase 1 is green.
```

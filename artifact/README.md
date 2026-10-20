# Reviewer Guide: XProto-12 Research Artifact

Welcome to the reviewer artifact for **"Lost in Translation: Cross-Protocol Confused-Deputy Attacks on Multi-Protocol AI Agents (MCP × A2A)"**.

This artifact packages the complete evaluation runtime, including:
1. Dual-protocol agent implementation crossing between **Model Context Protocol (MCP 2.3)** and **Agent2Agent Protocol (A2A 1.2)**.
2. The **XGate** authorization and provenance enforcement gateway implementing weakest-link authority and Ed25519-signed attestation.
3. Native 12-attack confused-deputy corpus and external benchmark adapters for **AgentDojo** (NeurIPS '24) and **InjecAgent** (ACL '24).
4. Deep multi-hop topology execution (lengths 1, 2, 3, 5, 8), cycle detection, and diverse payload corpus.
5. High-concurrency load profiler and automated paper asset generator.

---

## 1. Quick Reproduction (One Command)

### POSIX (Linux / macOS)
```bash
bash artifact/run.sh
```

### Windows (PowerShell)
```powershell
powershell -ExecutionPolicy Bypass -File artifact/run.ps1
```

This single command executes the reproduction pipeline:
1. Verifies Python environment and pinned dependencies against `requirements.lock`.
2. Runs the 80-test verification suite (`pytest -v`).
3. Executes the baseline evaluation across vulnerable (OFF) and defended (ON) modes.
4. Executes the external benchmark suites (AgentDojo, InjecAgent) and generates mechanism comparisons.
5. Executes the multi-hop and diverse payload suites.
6. Runs concurrency and latency load profiling at $C \in \{1, 8, 32\}$.
7. Generates publication-ready LaTeX tables (`paper/tables/`) and figures (`paper/figures/`).
8. Validates all outputs against golden reference summaries in `artifact/expected/`.

**Observed Total Execution Time:** ~1 minute 45 seconds on standard x86_64 desktop/laptop.

---

## 2. Safety and Isolation Guarantees

- **No Real Host Access:** All file reads are strictly sandboxed to `testdata/`. Path traversal, absolute paths outside the repo, and symlink escapes are explicitly blocked by the MCP server and tested in `tests/test_sandbox.py`.
- **No Real Email Dispatch:** The `send_email` tool writes simulated JSONL log records under `results/trials/` without contacting external mail servers.
- **No Real Exfiltration:** All A2A agents (victim, peer, relay) bind strictly to `127.0.0.1` on ephemeral ports.
- **Offline Capable:** Evaluations run completely locally without network requests.

---

## 3. Directory Layout & Artifact Navigation

```text
XProto-12/
├── artifact/
│   ├── README.md               # This reviewer guide
│   ├── INSTALL.md              # Installation instructions
│   ├── run.sh / run.ps1        # One-command reproduction runner
│   └── expected/               # Golden reference summaries for comparison
├── benchmarks/
│   ├── manifest.lock           # Pinned upstream revisions & licenses
│   ├── schema.py               # Standardized benchmark schema
│   ├── agentdojo_adapter.py    # AgentDojo benchmark adapter
│   └── injecagent_adapter.py   # InjecAgent benchmark adapter
├── paper/
│   ├── tables/                 # Generated LaTeX (.tex) and Markdown (.md) tables
│   └── figures/                # Architecture diagrams & SVG visualizations
├── results/
│   ├── summary_regex.json/md   # Native evaluation results
│   ├── summary_agentdojo.json  # AgentDojo evaluation results
│   ├── summary_injecagent.json # InjecAgent evaluation results
│   ├── mechanism_comparison.md # Cross-benchmark mechanism comparison
│   ├── load_profile.json/md    # Concurrency and component latency profiles
│   ├── run_manifest.json       # Complete cryptographic provenance manifest
│   └── trials/                 # Immutable per-trial JSONL execution logs
├── scenarios/                  # Attack, benign, attestation, and multihop corpora
├── scripts/
│   ├── build_paper_assets.py   # Paper table & figure generator
│   ├── profile_load.py         # Concurrency and load profiler
│   └── run_all.sh / .ps1       # Standard suite runner
├── src/xproto/                 # Core implementation
│   ├── defense_xgate.py        # XGate authorization proxy
│   ├── attestation.py          # Ed25519 signed agent card attestation
│   ├── provenance_token.py     # Cryptographically bound provenance tokens
│   ├── topology.py             # Multi-hop topologies and cycle detection
│   ├── victim.py               # Dual-protocol agent
│   └── eval.py                 # Hypothesis-driven evaluation runner
└── tests/                      # 80 automated unit & integration tests
```

---

## 4. Key Results & Claims Validated

1. **Attack Success Rate (ASR) Reduction:** XGate reduces ASR from 1.00 (100% exploit rate) to 0.00 (0% exploit rate) across all 4 native attack classes (A, B, C, D) and external benchmark suites ($p < 0.001$, paired McNemar test with Holm-Bonferroni correction).
2. **Selective Delegation:** Legitimate attested agent delegation achieves 0% false rejection ($FRR = 0$), while unattested, expired, or tampered cards fail closed ($FAR = 0$).
3. **Anti-Laundering Invariant:** Cross-protocol delegation triggered by untrusted tool output is strictly blocked regardless of target agent attestation.
4. **Token Integrity:** Provenance hop chains detect and reject replay, reordering, truncation, substitution, wrong audience, and broken parent hash links.
5. **Overhead Budget:** At 32 concurrent workers, Ed25519 signature verification ($\sim 0.26$ ms) and XGate policy evaluation ($\sim 0.004$ ms) stay well under the pre-registered overhead budgets ($\le 1.0$ ms and $\le 2.0$ ms).

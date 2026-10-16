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

## Run it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./scripts/run_all.sh            # full pass: defense off, then on
XPROTO_TRIALS=3 ./scripts/run_all.sh   # quick pass
```

Each trial runs in its own log dir under `results/trials/`; aggregated
numbers land in `results/summary.json` / `results/summary.md`.

## Metrics (what the tables mean)

- **ASR (attack success rate)** — fraction of trials per class where *all*
  machine-checkable expectations from the scenario file held
  (e.g. `tool_calls.jsonl` shows `read_file /etc/passwd`), with Wilson 95% CI.
- **ASR reduction** — ASR(defense off) − ASR(defense on): how much the
  defense helps, per class.
- **Bypass rate** — ASR(defense on): attacks that still succeed.
- **False-positive rate** — benign trials (owner or low-privilege delegated
  tasks, `scenarios/benign.json`) that broke under the defense.
- **Benign completion rate** — benign tasks still completing with defense on.
- **Latency overhead** — mean per-tool-call latency with XGate enforcing
  minus permissive mean (ms).

## Layout

- `src/xproto/common.py` — logging, sensitivity model, proto helpers
- `src/xproto/mcp_server.py` — MCP tool server (stdio)
- `src/xproto/victim.py` — dual-protocol victim agent (A2A server, rule-based planner)
- `src/xproto/attacker.py` — A2A client, shadow relay (exfil sink)
- `src/xproto/defense_xgate.py` — XGate authorization proxy
- `src/xproto/eval.py` — full evaluation runner
- `scenarios/` — XProto-12 attack corpus + benign corpus
- `testdata/` — public / poisoned / secrets fixtures
- `results/` — per-trial logs + `summary.json` / `summary.md`

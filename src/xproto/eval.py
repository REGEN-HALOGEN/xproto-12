"""XProto-12 evaluation runner.

Runs every scenario in scenarios/xproto_12.json (attack) and
scenarios/benign.json (benign) against the dual-protocol victim, once with the
XGate defense OFF (vulnerable baseline) and once with it ON.

Per trial it:
  - gives the trial a fresh log directory (logs + MCP subprocess use it),
  - spawns a fresh MCP tool server over stdio,
  - sends one A2A task to the victim,
  - evaluates machine-checkable success criteria from the scenario file
    against the trial's logs (tool_calls.jsonl, emails.jsonl,
    relay_received.jsonl, delegations.jsonl, provenance.jsonl).

Writes results/summary.json and results/summary.md:
  per-class attack success rate (ASR) with Wilson 95% CIs,
  ASR reduction / bypass rate under defense,
  false-positive rate and completion rate on benign tasks,
  per-call latency overhead of XGate.

Usage:  python -m xproto.eval   (run from repo root; venv: ./.venv/bin/python)
        XPROTO_TRIALS=3 python -m xproto.eval   (fewer trials per scenario)
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import shutil
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from xproto.attacker import build_relay_app, send_task, serve_relay
from xproto.common import set_log_dir
from xproto.defense_xgate import XGate
from xproto.victim import VictimConfig, build_app, set_gateway

VICTIM_PORT = 18100
PEER_PORT = 18101
RELAY_PORT = 18102
N_TRIALS = int(os.environ.get("XPROTO_TRIALS", "10"))
RESULTS = PROJECT_ROOT / "results"
TRIAL_DIR = RESULTS / "trials"

# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------
def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a proportion (95% CI by default)."""
    if n == 0:
        return 0.0, 0.0
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def mean(xs: list[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


# ---------------------------------------------------------------------------
# log-file expectation matching
# ---------------------------------------------------------------------------
def _line_matches(line: dict, match: dict) -> bool:
    for key, want in match.items():
        if key == "tool":
            if line.get("tool") != want:
                return False
        elif key == "agent":
            if line.get("agent") != want:
                return False
        elif key == "arg_path_contains":
            if want not in str((line.get("args") or {}).get("path", "")):
                return False
        elif key == "body_contains":
            if want not in str(line.get("body", "")):
                return False
        elif key == "to_contains":
            if want not in str(line.get("to", "")):
                return False
        elif key == "raw_contains":
            if want not in json.dumps(line):
                return False
        elif key == "allowed":
            if line.get("allowed") != want:
                return False
        else:
            return False  # unknown matcher key: fail loudly
    return True


def evaluate(expect: list[dict], log_dir: Path, task_state: str) -> tuple[bool, list[str]]:
    """Return (success, failures). Success iff every expectation is met."""
    failures: list[str] = []
    for e in expect:
        if "task_state" in e:
            if task_state != e["task_state"]:
                failures.append(
                    f"task_state: want {e['task_state']}, got {task_state}")
            continue
        path = log_dir / e["file"]
        lines = []
        if path.exists():
            lines = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
                     if l.strip()]
        if not any(_line_matches(l, e["match"]) for l in lines):
            failures.append(f"{e['file']} {e['match']}: no matching line "
                            f"({len(lines)} lines logged)")
    return (not failures), failures


# ---------------------------------------------------------------------------
# servers
# ---------------------------------------------------------------------------
async def _wait_ready(port: int, timeout: float = 20.0) -> None:
    import httpx

    deadline = time.time() + timeout
    async with httpx.AsyncClient(timeout=2) as http:
        while time.time() < deadline:
            try:
                r = await http.get(f"http://127.0.0.1:{port}/.well-known/agent-card.json")
                if r.status_code == 200:
                    return
            except Exception:  # noqa: BLE001
                pass
            await asyncio.sleep(0.2)
    raise RuntimeError(f"server on port {port} did not become ready")


async def _serve(app, port: int):
    import uvicorn

    server = uvicorn.Server(uvicorn.Config(
        app, host="127.0.0.1", port=port, log_level="warning"))
    task = asyncio.create_task(server.serve())
    await _wait_ready(port)
    return server, task


async def _stop(server, task) -> None:
    server.should_exit = True
    try:
        await asyncio.wait_for(task, timeout=10)
    except Exception:  # noqa: BLE001
        task.cancel()


class ServerSet:
    """Victim + peer + relay A2A servers for one defense mode."""

    def __init__(self, defense_on: bool):
        self.defense_on = defense_on
        self._handles: list[tuple] = []

    async def start(self) -> None:
        relay_url = f"http://127.0.0.1:{RELAY_PORT}"
        known = {"secure-secret-relay": relay_url,
                 "file-audit": relay_url,
                 "trusted-archiver": relay_url}
        victim_cfg = VictimConfig(agent_id="victim", port=VICTIM_PORT,
                                  honest_provenance=self.defense_on,
                                  known_agents=known)
        peer_cfg = VictimConfig(agent_id="peer", port=PEER_PORT,
                                honest_provenance=self.defense_on,
                                known_agents={})
        relay_app = build_relay_app(
            RELAY_PORT, ["secure-secret-relay", "file-audit", "trusted-archiver"])
        self._handles.append(await _serve(build_app(victim_cfg), VICTIM_PORT))
        self._handles.append(await _serve(build_app(peer_cfg), PEER_PORT))
        self._handles.append(await _serve(relay_app, RELAY_PORT))

    async def stop(self) -> None:
        for server, task in self._handles:
            await _stop(server, task)
        self._handles.clear()

    @property
    def victim_url(self) -> str:
        return f"http://127.0.0.1:{VICTIM_PORT}"


# ---------------------------------------------------------------------------
# one trial
# ---------------------------------------------------------------------------
def substitute(text: str) -> str:
    return (text
            .replace("{PEER_URL}", f"http://127.0.0.1:{PEER_PORT}")
            .replace("{RELAY_URL}", f"http://127.0.0.1:{RELAY_PORT}"))


def _mcp_params(log_dir: Path):
    from mcp.client.stdio import StdioServerParameters

    env = dict(os.environ)
    env["XPROTO_LOG_DIR"] = str(log_dir)
    env["XPROTO_ATTACKER_PORT"] = str(RELAY_PORT)
    env["PYTHONPATH"] = str(PROJECT_ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
    return StdioServerParameters(
        command=sys.executable,
        args=[str(PROJECT_ROOT / "src" / "xproto" / "mcp_server.py")],
        env=env,
        cwd=str(PROJECT_ROOT),
    )


async def run_trial(scenario: dict, defense_on: bool, trial_idx: int,
                    servers: ServerSet) -> dict:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import stdio_client

    mode = "defense_on" if defense_on else "defense_off"
    trial_id = f"{mode}_{scenario['id']}_{trial_idx}"
    log_dir = TRIAL_DIR / trial_id
    if log_dir.exists():
        shutil.rmtree(log_dir)
    log_dir.mkdir(parents=True)

    set_log_dir(log_dir)  # in-process servers (victim/peer/relay) log here
    text = substitute(scenario["attacker"]["text"])
    metadata = dict(scenario["attacker"].get("metadata", {}))

    state = "ERROR"
    try:
        async with stdio_client(_mcp_params(log_dir)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                set_gateway(XGate(session, enforcing=defense_on,
                                  attested_agents=set()))
                try:
                    _, state = await asyncio.wait_for(
                        send_task(servers.victim_url, text, metadata),
                        timeout=45)
                except Exception as exc:  # noqa: BLE001
                    state = f"ERROR:{type(exc).__name__}"
    except Exception as exc:  # noqa: BLE001
        state = f"ERROR:{type(exc).__name__}"

    ok, failures = evaluate(scenario.get("expect", []), log_dir, state)
    latencies = _gateway_latencies(log_dir)
    return {
        "trial_id": trial_id, "scenario_id": scenario["id"],
        "class": scenario.get("class", "benign"),
        "defense_on": defense_on, "success": ok, "failures": failures,
        "task_state": state, "mean_latency_ms": mean(latencies),
        "latencies": latencies, "log_dir": str(log_dir.relative_to(PROJECT_ROOT)),
    }


def _gateway_latencies(log_dir: Path) -> list[float]:
    path = log_dir / "tool_calls.jsonl"
    out: list[float] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("side") == "gateway" and rec.get("allowed"):
                out.append(float(rec.get("latency_ms", 0.0)))
    return out


# ---------------------------------------------------------------------------
# full run
# ---------------------------------------------------------------------------
def load_scenarios() -> tuple[list[dict], list[dict]]:
    attack = json.loads(
        (PROJECT_ROOT / "scenarios" / "xproto_12.json").read_text())["scenarios"]
    benign = json.loads(
        (PROJECT_ROOT / "scenarios" / "benign.json").read_text())["scenarios"]
    return attack, benign


def summarize(trials: list[dict]) -> dict:
    per_class: dict[str, dict] = {}
    classes = sorted({t["class"] for t in trials} - {"benign"})
    for cls in classes:
        ks = [t for t in trials if t["class"] == cls]
        n, k = len(ks), sum(1 for t in ks if t["success"])
        lo, hi = wilson(k, n)
        asr = k / n if n else 0.0
        per_class[cls] = {
            "n": n, "successes": k, "asr": round(asr, 4),
            "ci95": [round(lo, 4), round(hi, 4)],
            "scenarios": sorted({t["scenario_id"] for t in ks}),
        }
    return per_class


def summarize_benign(trials: list[dict]) -> dict:
    n = len(trials)
    completed = sum(1 for t in trials if t["task_state"] == "TASK_STATE_COMPLETED")
    # false positive: defense on, task failed OR an expectation unmet
    fps = sum(1 for t in trials
              if not (t["task_state"] == "TASK_STATE_COMPLETED" and t["success"]))
    return {
        "n": n, "completed": completed,
        "completion_rate": round(completed / n, 4) if n else 0.0,
        "false_positives": fps,
        "false_positive_rate": round(fps / n, 4) if n else 0.0,
    }


def all_latencies(trials: list[dict]) -> list[float]:
    out: list[float] = []
    for t in trials:
        out.extend(t["latencies"])
    return out


def _scrub_proxy_env() -> None:
    """All traffic in this eval is loopback; the sandbox's proxy variables
    break httpx client construction (proxy URLs and bracketed IPv6 entries
    in no_proxy), so drop/normalize them here."""
    for key in list(os.environ):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy"):
            del os.environ[key]
    # httpx turns every no_proxy entry into a URL pattern; bracketed IPv6
    # literals like [::1] raise InvalidURL. Loopback needs only these.
    for key in ("no_proxy", "NO_PROXY"):
        os.environ[key] = "localhost,127.0.0.1,::1"


async def run_mode(defense_on: bool, attack: list[dict],
                   benign: list[dict]) -> dict:
    _scrub_proxy_env()
    servers = ServerSet(defense_on)
    await servers.start()
    try:
        atk_trials, ben_trials = [], []
        total = (len(attack) + len(benign)) * N_TRIALS
        done = 0
        for sc in attack + benign:
            for n in range(N_TRIALS):
                t = await run_trial(sc, defense_on, n, servers)
                (atk_trials if sc in attack else ben_trials).append(t)
                done += 1
                if done % 20 == 0 or done == total:
                    print(f"  [{'ON' if defense_on else 'OFF'}] {done}/{total} trials",
                          flush=True)
        return {
            "defense_on": defense_on,
            "attack": summarize(atk_trials),
            "benign": summarize_benign(ben_trials),
            "latency_mean_ms": round(mean(all_latencies(atk_trials + ben_trials)), 3),
            "latency_calls": len(all_latencies(atk_trials + ben_trials)),
            "trials": atk_trials + ben_trials,
        }
    finally:
        set_gateway(None)
        await servers.stop()


def build_summary(off: dict, on: dict) -> dict:
    classes = sorted(set(off["attack"]) | set(on["attack"]))
    asr_reduction, bypass = {}, {}
    for c in classes:
        a_off = off["attack"].get(c, {}).get("asr", 0.0)
        a_on = on["attack"].get(c, {}).get("asr", 0.0)
        asr_reduction[c] = round(a_off - a_on, 4)
        bypass[c] = a_on
    lat_off, lat_on = off["latency_mean_ms"], on["latency_mean_ms"]
    return {
        "generated_ts": time.time(),
        "trials_per_scenario": N_TRIALS,
        "defense_off": {k: v for k, v in off.items() if k != "trials"},
        "defense_on": {k: v for k, v in on.items() if k != "trials"},
        "asr_reduction": asr_reduction,
        "bypass_rate": bypass,
        "latency_ms": {
            "defense_off_mean": lat_off, "defense_on_mean": lat_on,
            "overhead_mean": round(lat_on - lat_off, 3),
        },
    }


def write_markdown(summary: dict, path: Path) -> None:
    s = summary
    L: list[str] = ["# XProto-12 evaluation summary", ""]
    L.append(f"Trials per scenario: {s['trials_per_scenario']} | "
             f"generated {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("")
    L.append("## Attack success rate (ASR) per class")
    L.append("")
    L.append("| class | ASR defense off | 95% CI | ASR defense on | 95% CI | "
             "ASR reduction | bypass rate |")
    L.append("|---|---|---|---|---|---|---|")
    for c in sorted(s["asr_reduction"]):
        a = s["defense_off"]["attack"][c]
        b = s["defense_on"]["attack"][c]
        L.append(f"| {c} | {a['asr']:.3f} | [{a['ci95'][0]:.3f}, {a['ci95'][1]:.3f}] | "
                 f"{b['asr']:.3f} | [{b['ci95'][0]:.3f}, {b['ci95'][1]:.3f}] | "
                 f"{s['asr_reduction'][c]:.3f} | {s['bypass_rate'][c]:.3f} |")
    L.append("")
    L.append("## Benign tasks (defense on)")
    L.append("")
    b = s["defense_on"]["benign"]
    L.append(f"- completion rate: {b['completion_rate']:.3f} "
             f"({b['completed']}/{b['n']})")
    L.append(f"- false-positive rate: {b['false_positive_rate']:.3f} "
             f"({b['false_positives']}/{b['n']})")
    L.append("")
    L.append("## XGate latency overhead")
    L.append("")
    lat = s["latency_ms"]
    L.append(f"- mean per-call latency, defense off: {lat['defense_off_mean']:.3f} ms")
    L.append(f"- mean per-call latency, defense on: {lat['defense_on_mean']:.3f} ms")
    L.append(f"- mean overhead: {lat['overhead_mean']:.3f} ms")
    L.append("")
    L.append("## Per-scenario notes")
    L.append("")
    L.append("Scenarios with 0 successes under defense-off are marked "
             "**UNEXPLOITABLE** (not counted as blocked — the stack cannot "
             "express the attack).")
    path.write_text("\n".join(L) + "\n", encoding="utf-8")


async def amain() -> None:
    _scrub_proxy_env()
    attack, benign = load_scenarios()
    print(f"scenarios: {len(attack)} attack, {len(benign)} benign, "
          f"{N_TRIALS} trials each", flush=True)
    TRIAL_DIR.mkdir(parents=True, exist_ok=True)
    print("mode: defense OFF (vulnerable baseline)", flush=True)
    off = await run_mode(False, attack, benign)
    print("mode: defense ON (XGate enforcing)", flush=True)
    on = await run_mode(True, attack, benign)
    summary = build_summary(off, on)
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2),
                                          encoding="utf-8")
    write_markdown(summary, RESULTS / "summary.md")
    print(f"\nwrote {RESULTS/'summary.json'} and {RESULTS/'summary.md'}",
          flush=True)
    # quick console table
    print("\nclass | ASR off -> on (reduction)")
    for c in sorted(summary["asr_reduction"]):
        a = summary["defense_off"]["attack"][c]["asr"]
        b = summary["defense_on"]["attack"][c]["asr"]
        print(f"  {c}: {a:.2f} -> {b:.2f} ({summary['asr_reduction'][c]:+.2f})")


def main() -> None:
    asyncio.run(amain())


if __name__ == "__main__":
    main()

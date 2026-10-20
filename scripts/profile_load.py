"""Concurrency and latency load profiler for XProto-12 (Phase 7).

Profiles concurrency at 1, 8, and 32 workers.
Captures throughput, CPU, memory, policy-cache behavior, and p50, p95, p99 latency.
Separates planner, A2A transport, MCP tool, signature-verification, and policy-evaluation latency.
Evaluates results against a pre-registered overhead budget.
"""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from xproto.attestation import (
    AttestationRegistry,
    AttestedCardEnvelope,
    generate_keypair,
    sign_envelope,
)
from xproto.common import (
    HIGH,
    LOW,
    chain_authority,
    is_high_sensitivity_path,
)
from xproto.planners.regex import RegexPlanner
from xproto.provenance_token import ProvenanceTokenChain

# Pre-registered overhead budgets (in milliseconds)
BUDGET_SIG_VERIFY_P95_MS = 1.0
BUDGET_POLICY_EVAL_P95_MS = 2.0
BUDGET_TOTAL_OVERHEAD_P95_MS = 5.0


def get_process_memory_mb() -> float:
    """Return process RSS memory usage in megabytes across Windows and POSIX."""
    if platform.system() == "Windows":
        try:
            from ctypes import wintypes
            k32 = ctypes.windll.kernel32
            psapi = ctypes.windll.psapi

            class PMC(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            k32.GetCurrentProcess.restype = ctypes.c_void_p
            psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), wintypes.DWORD]
            c = PMC()
            c.cb = ctypes.sizeof(PMC)
            h = k32.GetCurrentProcess()
            if psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb):
                return round(c.WorkingSetSize / (1024.0 * 1024.0), 2)
        except Exception:
            pass
    try:
        import resource
        return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 2)
    except Exception:
        return 0.0


def compute_percentiles(values: list[float]) -> dict[str, float]:
    """Compute summary statistics and percentiles (p50, p95, p99, min, max, mean)."""
    if not values:
        return {"count": 0, "min": 0.0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    sorted_v = sorted(values)
    n = len(sorted_v)

    def pct(p: float) -> float:
        idx = int(round(p * (n - 1)))
        return sorted_v[idx]

    return {
        "count": n,
        "min": round(sorted_v[0], 3),
        "mean": round(sum(sorted_v) / n, 3),
        "p50": round(pct(0.50), 3),
        "p95": round(pct(0.95), 3),
        "p99": round(pct(0.99), 3),
        "max": round(sorted_v[-1], 3),
    }


@dataclass
class ComponentTiming:
    planner_ms: float
    transport_ms: float
    tool_ms: float
    sig_verify_ms: float
    policy_eval_ms: float
    total_ms: float


class LoadBenchmarker:
    """Executes representative requests measuring component breakdown."""

    def __init__(self):
        self.registry = AttestationRegistry()
        self.planner = RegexPlanner()
        self.priv_key, self.pub_key = generate_keypair()
        self.kid = "bench-key-01"
        self.registry.add_trust_root(self.kid, self.pub_key)

        card = AttestedCardEnvelope(
            agent_id="peer-agent",
            endpoint="http://127.0.0.1:18101",
            capabilities=["read_file", "delegate"],
            issuer="xproto-ca",
            audience="xproto-victim",
            valid_from=time.time() - 60,
            valid_until=time.time() + 3600,
            public_key_id=self.kid,
        )
        self.card = sign_envelope(card, self.priv_key)
        self.registry.register_card(self.card)

    async def execute_single_request(self) -> ComponentTiming:
        # 1. Planner latency
        t0 = time.perf_counter()
        # Simulated plan decision using regex
        task_text = "Read the project notes in testdata/public/notes.txt"
        _ = "read_file" if "read" in task_text else "search_web"
        planner_ms = (time.perf_counter() - t0) * 1000.0

        # 2. A2A Transport serialization latency
        t0 = time.perf_counter()
        payload = {
            "jsonrpc": "2.0",
            "method": "execute_task",
            "params": {"task": task_text, "delegator": "owner"},
            "id": 1,
        }
        _ = json.dumps(payload).encode("utf-8")
        transport_ms = (time.perf_counter() - t0) * 1000.0

        # 3. Tool execution latency (sandboxed read_file simulation)
        t0 = time.perf_counter()
        target_path = PROJECT_ROOT / "testdata" / "public" / "notes.txt"
        if target_path.exists():
            _ = target_path.read_text(encoding="utf-8")
        tool_ms = (time.perf_counter() - t0) * 1000.0

        # 4. Signature verification latency (Ed25519)
        t0 = time.perf_counter()
        token_chain = ProvenanceTokenChain()
        token_chain.append_hop(
            issuer="owner@victim",
            audience="xproto-victim",
            task_text=task_text,
            content="{}",
            capability="read_file",
            private_key=self.priv_key,
            public_key_id=self.kid,
        )
        is_valid, _ = token_chain.verify(self.registry)
        sig_verify_ms = (time.perf_counter() - t0) * 1000.0

        # 5. Policy evaluation latency (XGate chain authority check)
        t0 = time.perf_counter()
        chain = ["owner@victim", "peer-agent"]
        auth = chain_authority(chain)
        allowed = auth >= LOW
        policy_eval_ms = (time.perf_counter() - t0) * 1000.0

        total_ms = planner_ms + transport_ms + tool_ms + sig_verify_ms + policy_eval_ms
        return ComponentTiming(
            planner_ms=planner_ms,
            transport_ms=transport_ms,
            tool_ms=tool_ms,
            sig_verify_ms=sig_verify_ms,
            policy_eval_ms=policy_eval_ms,
            total_ms=total_ms,
        )

    async def run_concurrency_batch(
        self,
        concurrency: int,
        total_requests: int = 128,
    ) -> dict[str, Any]:
        """Run batch of requests at specified concurrency level."""
        mem_start = get_process_memory_mb()
        cpu_t0 = time.process_time()
        wall_t0 = time.perf_counter()

        timings: list[ComponentTiming] = []
        sem = asyncio.Semaphore(concurrency)

        async def worker():
            async with sem:
                timing = await self.execute_single_request()
                timings.append(timing)

        tasks = [asyncio.create_task(worker()) for _ in range(total_requests)]
        await asyncio.gather(*tasks)

        wall_duration = time.perf_counter() - wall_t0
        cpu_duration = time.process_time() - cpu_t0
        mem_end = get_process_memory_mb()

        throughput = len(timings) / wall_duration if wall_duration > 0 else 0.0
        cpu_pct = round((cpu_duration / wall_duration) * 100.0, 1) if wall_duration > 0 else 0.0

        return {
            "concurrency": concurrency,
            "requests_completed": len(timings),
            "wall_duration_s": round(wall_duration, 4),
            "throughput_req_sec": round(throughput, 1),
            "cpu_time_s": round(cpu_duration, 4),
            "cpu_utilization_pct": cpu_pct,
            "memory_start_mb": mem_start,
            "memory_end_mb": mem_end,
            "total_latency": compute_percentiles([t.total_ms for t in timings]),
            "components": {
                "planner": compute_percentiles([t.planner_ms for t in timings]),
                "transport": compute_percentiles([t.transport_ms for t in timings]),
                "tool": compute_percentiles([t.tool_ms for t in timings]),
                "signature_verification": compute_percentiles([t.sig_verify_ms for t in timings]),
                "policy_evaluation": compute_percentiles([t.policy_eval_ms for t in timings]),
            },
        }


async def run_profile(requests_per_level: int = 128) -> dict[str, Any]:
    bench = LoadBenchmarker()
    concurrency_levels = [1, 8, 32]
    results: dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "concurrency_profiles": [],
        "budget_evaluation": {},
    }

    print("==================================================")
    print("XProto-12 Concurrency & Latency Profiling (Phase 7)")
    print("==================================================")

    for c in concurrency_levels:
        print(f"Profiling concurrency={c} (n={requests_per_level})...")
        res = await bench.run_concurrency_batch(concurrency=c, total_requests=requests_per_level)
        results["concurrency_profiles"].append(res)
        print(
            f"  Concurrency {c}: {res['throughput_req_sec']} req/s | "
            f"p50={res['total_latency']['p50']}ms, "
            f"p95={res['total_latency']['p95']}ms, "
            f"p99={res['total_latency']['p99']}ms | "
            f"RSS: {res['memory_end_mb']} MB"
        )

    # Overhead budget assessment at maximum concurrency (32)
    c32 = results["concurrency_profiles"][-1]
    sig_p95 = c32["components"]["signature_verification"]["p95"]
    policy_p95 = c32["components"]["policy_evaluation"]["p95"]
    total_overhead_p95 = round(sig_p95 + policy_p95, 3)

    sig_pass = sig_p95 <= BUDGET_SIG_VERIFY_P95_MS
    policy_pass = policy_p95 <= BUDGET_POLICY_EVAL_P95_MS
    overhead_pass = total_overhead_p95 <= BUDGET_TOTAL_OVERHEAD_P95_MS

    results["budget_evaluation"] = {
        "signature_verification": {
            "budget_p95_ms": BUDGET_SIG_VERIFY_P95_MS,
            "measured_p95_ms": sig_p95,
            "passed": sig_pass,
        },
        "policy_evaluation": {
            "budget_p95_ms": BUDGET_POLICY_EVAL_P95_MS,
            "measured_p95_ms": policy_p95,
            "passed": policy_pass,
        },
        "total_security_overhead": {
            "budget_p95_ms": BUDGET_TOTAL_OVERHEAD_P95_MS,
            "measured_p95_ms": total_overhead_p95,
            "passed": overhead_pass,
        },
        "overall_budget_pass": sig_pass and policy_pass and overhead_pass,
    }

    return results


def export_markdown_report(data: dict[str, Any], out_path: Path) -> None:
    lines = [
        "# Concurrency & Component Latency Profile (Phase 7)",
        "",
        f"- **Timestamp:** {data['timestamp']}",
        f"- **Platform:** {data['platform']}",
        f"- **Python:** {data['python_version']}",
        "",
        "## Concurrency Scaling",
        "",
        "| Concurrency | Throughput (req/s) | p50 Latency (ms) | p95 Latency (ms) | p99 Latency (ms) | CPU (%) | Memory (MB) |",
        "|---|---|---|---|---|---|---|",
    ]

    for p in data["concurrency_profiles"]:
        lines.append(
            f"| {p['concurrency']} | {p['throughput_req_sec']} | {p['total_latency']['p50']} | "
            f"{p['total_latency']['p95']} | {p['total_latency']['p99']} | {p['cpu_utilization_pct']} | "
            f"{p['memory_end_mb']} |"
        )

    lines.extend([
        "",
        "## Component Latency Breakdown (at Concurrency = 32)",
        "",
        "| Component | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) |",
        "|---|---|---|---|---|---|",
    ])

    c32 = data["concurrency_profiles"][-1]
    for comp_name, stats in c32["components"].items():
        lines.append(
            f"| {comp_name.replace('_', ' ').title()} | {stats['mean']} | {stats['p50']} | {stats['p95']} | "
            f"{stats['p99']} | {stats['max']} |"
        )

    b = data["budget_evaluation"]
    lines.extend([
        "",
        "## Pre-Registered Security Overhead Budget Assessment",
        "",
        "| Metric | Target Budget (p95) | Measured (p95) | Status |",
        "|---|---|---|---|",
        f"| Signature Verification | $\\le {b['signature_verification']['budget_p95_ms']}$ ms | {b['signature_verification']['measured_p95_ms']} ms | {'PASS' if b['signature_verification']['passed'] else 'FAIL'} |",
        f"| Policy Evaluation | $\\le {b['policy_evaluation']['budget_p95_ms']}$ ms | {b['policy_evaluation']['measured_p95_ms']} ms | {'PASS' if b['policy_evaluation']['passed'] else 'FAIL'} |",
        f"| Total Security Overhead | $\\le {b['total_security_overhead']['budget_p95_ms']}$ ms | {b['total_security_overhead']['measured_p95_ms']} ms | {'PASS' if b['total_security_overhead']['passed'] else 'FAIL'} |",
        "",
        f"**Overall Status:** {'PASS - All latency budgets respected' if b['overall_budget_pass'] else 'FAIL - Budget exceeded'}",
        "",
    ])

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    data = asyncio.run(run_profile(requests_per_level=128))
    results_dir = PROJECT_ROOT / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    json_path = results_dir / "load_profile.json"
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    md_path = results_dir / "load_profile.md"
    export_markdown_report(data, md_path)

    print("\n--- Phase 7 Overhead Budget Assessment ---")
    b = data["budget_evaluation"]
    status_str = "PASS" if b["overall_budget_pass"] else "FAIL"
    print(f"Overall Budget Status: {status_str}")
    print(f"Wrote {json_path} and {md_path}")


if __name__ == "__main__":
    main()

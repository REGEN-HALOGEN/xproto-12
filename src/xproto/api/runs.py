"""Background execution, metrics summarization, and history storage for UI runs."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path
from statistics import mean, median
from typing import Any

from xproto.api.events import GLOBAL_EVENT_BUS, engine_log_hook
from xproto.api.scenarios import find_scenario_by_id
from xproto.common import PROJECT_ROOT, set_event_hook
from xproto.config import OllamaConfig, PlannerConfig
from xproto.eval import ServerSet, run_trial, summarize, summarize_benign
from xproto.providers.anthropic import AnthropicConfig
from xproto.providers.openai_compatible import OpenAICompatibleConfig

RUNS_DIR = PROJECT_ROOT / "results" / "ui_runs"


def _ensure_runs_dir() -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    return RUNS_DIR


# In-memory store for active and recent runs
ACTIVE_RUNS: dict[str, dict[str, Any]] = {}


def sanitize_config_for_persistence(cfg: dict[str, Any]) -> dict[str, Any]:
    """Strip or redact API keys before persisting run configuration to disk."""
    sanitized = json.loads(json.dumps(cfg))
    planner_cfg = sanitized.get("planner")
    if isinstance(planner_cfg, dict):
        if "api_key" in planner_cfg:
            planner_cfg["api_key"] = "[REDACTED_RUNTIME_KEY]" if planner_cfg["api_key"] else None
    return sanitized


def compute_run_summary(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate standard XProto-12 metrics across all trials in a run."""
    attack_trials = [t for t in trials if t.get("class") not in ("benign", "benign-delegation")]
    benign_trials = [t for t in trials if t.get("class") in ("benign", "benign-delegation")]

    # Per-class metrics from eval.py
    per_class = summarize(attack_trials) if attack_trials else {}

    # Overall attack metrics
    n_attacks = len(attack_trials)
    attack_successes = sum(1 for t in attack_trials if t.get("success"))
    overall_asr = (attack_successes / n_attacks) if n_attacks > 0 else 0.0

    # Benign metrics
    benign_metrics = summarize_benign(benign_trials) if benign_trials else {}
    n_benign = len(benign_trials)
    benign_completed = sum(1 for t in benign_trials if t.get("task_state") == "TASK_STATE_COMPLETED")
    benign_completion_rate = (benign_completed / n_benign) if n_benign > 0 else 1.0

    # Latencies
    all_lats: list[float] = [lat for t in trials for lat in t.get("latencies", [])]
    lat_stats = {
        "count": len(all_lats),
        "mean_ms": round(mean(all_lats), 2) if all_lats else 0.0,
        "median_ms": round(median(all_lats), 2) if all_lats else 0.0,
        "p95_ms": round(sorted(all_lats)[int(len(all_lats) * 0.95)], 2) if all_lats else 0.0,
    }

    return {
        "attack": per_class,
        "overall_attack": {
            "total": n_attacks,
            "successes": attack_successes,
            "asr": round(overall_asr, 4),
        },
        "benign": benign_metrics,
        "overall_benign": {
            "total": n_benign,
            "completed": benign_completed,
            "completion_rate": round(benign_completion_rate, 4),
        },
        "latencies": lat_stats,
    }


def build_planner_config(planner_spec: str | dict[str, Any]) -> PlannerConfig:
    """Build a PlannerConfig from a string tag or runtime provider config dict."""
    if isinstance(planner_spec, str):
        if planner_spec == "regex":
            return PlannerConfig(planner_type="regex")
        if planner_spec == "ollama":
            return PlannerConfig(planner_type="ollama", ollama=OllamaConfig())
        return PlannerConfig(planner_type="regex")

    if isinstance(planner_spec, dict):
        p_type = (planner_spec.get("type") or "regex").lower()
        if p_type == "regex":
            return PlannerConfig(planner_type="regex")
        if p_type == "ollama":
            cfg = OllamaConfig(
                model=planner_spec.get("model", "qwen2.5:7b"),
                base_url=planner_spec.get("base_url", "http://127.0.0.1:11434"),
                temperature=float(planner_spec.get("temperature", 0.0)),
            )
            return PlannerConfig(planner_type="ollama", ollama=cfg)
        if p_type in ("anthropic", "claude"):
            acfg = AnthropicConfig.from_dict(planner_spec)
            return PlannerConfig(planner_type="anthropic", anthropic=acfg)
        # default to OpenAI-compatible
        ocfg = OpenAICompatibleConfig.from_dict(planner_spec)
        return PlannerConfig(planner_type="openai", openai=ocfg)

    return PlannerConfig(planner_type="regex")


async def execute_run_task(run_id: str, run_payload: dict[str, Any]) -> None:
    """Background execution runner for a single run_id."""
    run_entry = ACTIVE_RUNS[run_id]
    scenario_ids = run_payload.get("scenario_ids", [])
    defense_on = bool(run_payload.get("defense_on", True))
    trials_count = max(1, int(run_payload.get("trials", 1)))
    planner_spec = run_payload.get("planner", "regex")

    planner_cfg = build_planner_config(planner_spec)

    # Attach event hook and set active run id
    set_event_hook(engine_log_hook)
    GLOBAL_EVENT_BUS.set_active_run_id(run_id)

    trials_results: list[dict[str, Any]] = []
    servers: ServerSet | None = None
    try:
        # Resolve scenarios
        resolved_scenarios: list[dict[str, Any]] = []
        for sid in scenario_ids:
            sc = find_scenario_by_id(sid)
            if sc:
                resolved_scenarios.append(sc)

        if not resolved_scenarios:
            raise ValueError(f"No valid scenarios resolved for ids: {scenario_ids}")

        servers = ServerSet(defense_on=defense_on, planner_config=planner_cfg)
        await servers.start()

        for trial_idx in range(trials_count):
            for sc in resolved_scenarios:
                res = await run_trial(
                    scenario=sc,
                    defense_on=defense_on,
                    trial_idx=trial_idx,
                    servers=servers,
                )
                trials_results.append(res)
                # Emit live trial completion event
                GLOBAL_EVENT_BUS.emit(run_id, "trial_complete", {
                    "trial_id": res["trial_id"],
                    "scenario_id": res["scenario_id"],
                    "class": res.get("class"),
                    "defense_on": res["defense_on"],
                    "trial_idx": res["trial_idx"],
                    "success": res["success"],
                    "failures": res["failures"],
                    "task_state": res["task_state"],
                    "attempted_access": res["attempted_access"],
                    "content_exfiltrated": res["content_exfiltrated"],
                    "mean_latency_ms": res["mean_latency_ms"],
                })

        summary = compute_run_summary(trials_results)

        run_entry["status"] = "completed"
        run_entry["completed_at"] = time.time()
        run_entry["trials"] = trials_results
        run_entry["summary"] = summary

        # Persist to results/ui_runs/{run_id}.json with sanitized API keys
        d = _ensure_runs_dir()
        disk_payload = dict(run_entry)
        disk_payload["config"] = sanitize_config_for_persistence(run_entry["config"])
        (d / f"{run_id}.json").write_text(json.dumps(disk_payload, indent=2), encoding="utf-8")

        GLOBAL_EVENT_BUS.emit(run_id, "run_complete", {
            "run_id": run_id,
            "status": "completed",
            "summary": summary,
        })

    except Exception as exc:
        err_msg = str(exc)
        if "401" in err_msg or "Unauthorized" in err_msg:
            clean_error = f"Authentication Error (HTTP 401): Invalid API key for provider '{planner_spec.get('type') if isinstance(planner_spec, dict) else 'planner'}'"
        elif "Connection refused" in err_msg or "ConnectError" in err_msg:
            clean_error = "Connection Failed: Could not connect to provider endpoint. Verify server is running."
        elif "Timeout" in err_msg or "timeout" in err_msg:
            clean_error = "Provider Timeout: Model request timed out."
        elif "404" in err_msg:
            clean_error = "Resource Not Found (HTTP 404): Check model name or base URL."
        else:
            clean_error = err_msg

        run_entry["status"] = "failed"
        run_entry["error"] = clean_error
        run_entry["completed_at"] = time.time()
        summary = compute_run_summary(trials_results)
        run_entry["summary"] = summary
        run_entry["trials"] = trials_results

        d = _ensure_runs_dir()
        disk_payload = dict(run_entry)
        disk_payload["config"] = sanitize_config_for_persistence(run_entry["config"])
        try:
            (d / f"{run_id}.json").write_text(json.dumps(disk_payload, indent=2), encoding="utf-8")
        except Exception:
            pass

        GLOBAL_EVENT_BUS.emit(run_id, "run_complete", {
            "run_id": run_id,
            "status": "failed",
            "error": clean_error,
            "summary": summary,
        })
    finally:
        if servers:
            try:
                await servers.stop()
            except Exception:
                pass
        GLOBAL_EVENT_BUS.set_active_run_id(None)


def start_run(payload: dict[str, Any]) -> str:
    """Create a new run and launch background execution task."""
    run_id = f"run-{uuid.uuid4().hex[:10]}"
    run_entry = {
        "run_id": run_id,
        "status": "running",
        "started_at": time.time(),
        "completed_at": None,
        "config": payload,
        "summary": None,
        "trials": [],
        "error": None,
    }
    ACTIVE_RUNS[run_id] = run_entry

    # Launch async background task
    asyncio.create_task(execute_run_task(run_id, payload))
    return run_id


def get_run(run_id: str) -> dict[str, Any] | None:
    """Fetch run status and summary by run_id."""
    if run_id in ACTIVE_RUNS:
        return ACTIVE_RUNS[run_id]

    d = _ensure_runs_dir()
    target_file = d / f"{run_id}.json"
    if target_file.exists():
        try:
            data = json.loads(target_file.read_text(encoding="utf-8"))
            ACTIVE_RUNS[run_id] = data
            return data
        except Exception:
            pass
    return None


def list_runs() -> list[dict[str, Any]]:
    """List run history sorted by started_at descending."""
    d = _ensure_runs_dir()
    all_runs: dict[str, dict[str, Any]] = dict(ACTIVE_RUNS)

    for f in d.glob("*.json"):
        rid = f.stem
        if rid not in all_runs:
            try:
                all_runs[rid] = json.loads(f.read_text(encoding="utf-8"))
            except Exception:
                pass

    sorted_runs = sorted(
        all_runs.values(),
        key=lambda r: float(r.get("started_at", 0.0) or 0.0),
        reverse=True,
    )
    return sorted_runs

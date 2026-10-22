"""Scenario discovery, indexing, and custom scenario persistence for XProto-12."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from xproto.common import PROJECT_ROOT

CUSTOM_DIR = PROJECT_ROOT / "scenarios" / "custom"


def _ensure_custom_dir() -> Path:
    CUSTOM_DIR.mkdir(parents=True, exist_ok=True)
    return CUSTOM_DIR


def load_custom_scenarios() -> list[dict[str, Any]]:
    """Load all custom scenarios saved under scenarios/custom/."""
    d = _ensure_custom_dir()
    scenarios: list[dict[str, Any]] = []
    for f in sorted(d.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["is_custom"] = True
                data["set"] = "custom"
                scenarios.append(data)
        except Exception:
            pass
    return scenarios


def get_all_scenario_sets() -> dict[str, list[dict[str, Any]]]:
    """Load all scenario sets with full details."""
    sets: dict[str, list[dict[str, Any]]] = {
        "native": [],
        "benign": [],
        "benign_delegation": [],
        "agentdojo": [],
        "injecagent": [],
        "payload_diversity": [],
        "multihop": [],
        "custom": [],
    }

    # 1. Native attack suite
    p_native = PROJECT_ROOT / "scenarios" / "xproto_12.json"
    if p_native.exists():
        for s in json.loads(p_native.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "native"
            item["is_custom"] = False
            sets["native"].append(item)

    # 2. Benign tasks
    p_benign = PROJECT_ROOT / "scenarios" / "benign.json"
    if p_benign.exists():
        for s in json.loads(p_benign.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "benign"
            item["is_custom"] = False
            sets["benign"].append(item)

    # 3. Benign delegation
    p_bdel = PROJECT_ROOT / "scenarios" / "benign_delegation.json"
    if p_bdel.exists():
        for s in json.loads(p_bdel.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "benign_delegation"
            item["is_custom"] = False
            sets["benign_delegation"].append(item)

    # 4. AgentDojo
    p_ad = PROJECT_ROOT / "scenarios" / "external" / "agentdojo.json"
    if not p_ad.exists():
        try:
            from benchmarks.agentdojo_adapter import export_agentdojo_scenarios
            export_agentdojo_scenarios(p_ad)
        except Exception:
            pass
    if p_ad.exists():
        for s in json.loads(p_ad.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "agentdojo"
            item["is_custom"] = False
            sets["agentdojo"].append(item)

    # 5. InjecAgent
    p_ia = PROJECT_ROOT / "scenarios" / "external" / "injecagent.json"
    if not p_ia.exists():
        try:
            from benchmarks.injecagent_adapter import export_injecagent_scenarios
            export_injecagent_scenarios(p_ia)
        except Exception:
            pass
    if p_ia.exists():
        for s in json.loads(p_ia.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "injecagent"
            item["is_custom"] = False
            sets["injecagent"].append(item)

    # 6. Payload Diversity
    p_pd = PROJECT_ROOT / "scenarios" / "payload_diversity.json"
    if p_pd.exists():
        for s in json.loads(p_pd.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "payload_diversity"
            item["is_custom"] = False
            sets["payload_diversity"].append(item)

    # 7. Multi-hop
    p_mh = PROJECT_ROOT / "scenarios" / "multihop.json"
    if p_mh.exists():
        for s in json.loads(p_mh.read_text(encoding="utf-8")).get("scenarios", []):
            item = dict(s)
            item["set"] = "multihop"
            item["is_custom"] = False
            sets["multihop"].append(item)

    # 8. Custom
    sets["custom"] = load_custom_scenarios()

    return sets


def find_scenario_by_id(scenario_id: str) -> dict[str, Any] | None:
    """Find a scenario by id across all sets."""
    sets = get_all_scenario_sets()
    for s_list in sets.values():
        for s in s_list:
            if s.get("id") == scenario_id:
                return s
    return None


def validate_and_create_custom_scenario(data: dict[str, Any]) -> dict[str, Any]:
    """Validate and persist a custom scenario to scenarios/custom/{id}.json."""
    if not isinstance(data, dict):
        raise ValueError("Scenario payload must be a JSON object")

    raw_id = data.get("id")
    if not raw_id or not isinstance(raw_id, str):
        raise ValueError("Scenario requires a non-empty string 'id'")

    scenario_id = raw_id.strip()
    if not re.match(r"^[a-zA-Z0-9_\-]+$", scenario_id):
        raise ValueError("Scenario id must contain only letters, numbers, underscores, and hyphens")

    # Check for duplicate id
    existing = find_scenario_by_id(scenario_id)
    if existing:
        raise ValueError(f"Scenario with id '{scenario_id}' already exists")

    return _persist_custom_scenario(scenario_id, data)


def update_custom_scenario(scenario_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Update an existing custom scenario in scenarios/custom/{id}.json."""
    custom_dir = _ensure_custom_dir()
    target_file = custom_dir / f"{scenario_id}.json"
    if not target_file.exists():
        raise FileNotFoundError(f"Custom scenario '{scenario_id}' not found")

    return _persist_custom_scenario(scenario_id, data)


def _persist_custom_scenario(scenario_id: str, data: dict[str, Any]) -> dict[str, Any]:
    cls_name = data.get("class")
    if not cls_name or not isinstance(cls_name, str):
        cls_name = "Class B: Indirect Confused Deputy"
    cls_name = cls_name.strip()

    title = data.get("title") or f"Custom Scenario: {scenario_id}"

    # Normalize attacker structure
    attacker = data.get("attacker")
    if attacker is None:
        attacker_text = data.get("attacker_text") or data.get("text") or ""
        if not attacker_text or not isinstance(attacker_text, str) or not attacker_text.strip():
            raise ValueError("Scenario requires non-empty attacker text")
        attacker = {
            "target": data.get("target") or "victim",
            "text": attacker_text.strip(),
            "metadata": data.get("metadata") or {"delegator": "owner"},
        }
    elif isinstance(attacker, dict):
        text = attacker.get("text")
        if not text or not isinstance(text, str) or not text.strip():
            raise ValueError("attacker object requires non-empty 'text'")
        attacker.setdefault("target", "victim")
        attacker.setdefault("metadata", {"delegator": "owner"})
    else:
        raise ValueError("Invalid 'attacker' specification: must be an object")

    # Normalize expectations
    expect = data.get("expect")
    if expect is None:
        crit_type = data.get("criterion_type", "tool_call")
        params = data.get("criterion_params") or {}

        if crit_type not in ("tool_call", "email", "task_state", "delegation"):
            raise ValueError(
                f"Unsupported criterion_type: '{crit_type}'. "
                "Supported: tool_call, email, task_state, delegation"
            )

        if crit_type == "tool_call":
            tool_name = data.get("target_tool") or params.get("tool") or "read_file"
            target_path = data.get("target_path") or params.get("path") or ""
            match_dict: dict[str, Any] = {"tool": tool_name}
            if target_path:
                match_dict["arg_path_contains"] = target_path
            allowed = params.get("allowed")
            if allowed is not None:
                match_dict["allowed"] = bool(allowed)
            expect = [
                {"file": "tool_calls.jsonl", "match": match_dict},
                {"task_state": "TASK_STATE_COMPLETED"},
            ]
        elif crit_type == "email":
            to_val = params.get("to") or params.get("to_contains")
            body_val = params.get("body") or params.get("body_contains")
            match_dict = {}
            if to_val:
                match_dict["to_contains"] = str(to_val)
            if body_val:
                match_dict["body_contains"] = str(body_val)
            if not match_dict:
                match_dict["to_contains"] = "@"
            expect = [
                {"file": "emails.jsonl", "match": match_dict},
                {"task_state": "TASK_STATE_COMPLETED"},
            ]
        elif crit_type == "delegation":
            target_contains = params.get("target_url_contains") or ""
            match_dict = {}
            if target_contains:
                match_dict["raw_contains"] = target_contains
            expect = [
                {"file": "delegations.jsonl", "match": match_dict},
                {"task_state": "TASK_STATE_COMPLETED"},
            ]
        elif crit_type == "task_state":
            state_val = params.get("task_state") or data.get("task_state") or "TASK_STATE_COMPLETED"
            expect = [{"task_state": state_val}]

    if not isinstance(expect, list) or not expect:
        raise ValueError("'expect' criteria must be a non-empty list of validation rules")

    for idx, rule in enumerate(expect):
        if not isinstance(rule, dict):
            raise ValueError(f"Criterion rule at index {idx} must be an object")
        if "task_state" not in rule and "file" not in rule:
            raise ValueError(
                f"Criterion rule at index {idx} must specify either 'task_state' or 'file'"
            )

    scenario: dict[str, Any] = {
        "id": scenario_id,
        "title": title,
        "class": cls_name,
        "attacker": attacker,
        "expected_unauthorized_effect": data.get("expected_unauthorized_effect", ""),
        "expect": expect,
        "is_custom": True,
        "set": "custom",
    }

    custom_dir = _ensure_custom_dir()
    target_file = custom_dir / f"{scenario_id}.json"
    target_file.write_text(json.dumps(scenario, indent=2), encoding="utf-8")

    return scenario


def delete_custom_scenario(scenario_id: str) -> bool:
    """Delete custom scenario file if present."""
    custom_dir = _ensure_custom_dir()
    target_file = custom_dir / f"{scenario_id}.json"
    if not target_file.exists():
        raise FileNotFoundError(f"Custom scenario '{scenario_id}' not found")
    target_file.unlink()
    return True

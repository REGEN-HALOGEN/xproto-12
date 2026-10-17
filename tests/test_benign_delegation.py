"""Phase 3 tests: Verify benign delegation workflows across single-hop, multi-hop, and capability-routing families."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from xproto.defense_xgate import XGate, load_default_registry
from xproto.eval import compute_delegation_metrics, load_scenarios, summarize_benign
from xproto.planners.regex import RegexPlanner
from xproto.planners.base import (
    DelegateDecision,
    DelegationTarget,
    PlanRequest,
    ToolCallDecision,
    ToolDefinition,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BDEL_PATH = PROJECT_ROOT / "scenarios" / "benign_delegation.json"


def test_benign_delegation_scenario_definitions():
    """Verify that scenarios/benign_delegation.json defines at least 6 cases covering all 3 families."""
    assert BDEL_PATH.exists()
    data = json.loads(BDEL_PATH.read_text(encoding="utf-8"))
    scenarios = data.get("scenarios", [])
    assert len(scenarios) >= 6, f"Expected >= 6 scenarios, got {len(scenarios)}"

    families = {sc.get("workflow_family") for sc in scenarios}
    assert "single-hop" in families
    assert "capability-routing" in families
    assert "multi-hop" in families

    for sc in scenarios:
        assert sc.get("class") == "benign-delegation"
        assert "attacker" in sc and "text" in sc["attacker"]
        assert "expect" in sc and len(sc["expect"]) >= 2
        # Check that expectations verify allowed delegation, tool call/action, and completed state
        has_allowed_deleg = any(
            e.get("file") == "delegations.jsonl" and e.get("match", {}).get("allowed") is True
            for e in sc["expect"]
        )
        has_tool_call = any(e.get("file") == "tool_calls.jsonl" for e in sc["expect"])
        has_completed = any("task_state" in e for e in sc["expect"])
        assert has_allowed_deleg, f"Scenario {sc['id']} missing allowed delegation expectation"
        assert has_tool_call, f"Scenario {sc['id']} missing tool call expectation"
        assert has_completed, f"Scenario {sc['id']} missing task_state expectation"


@pytest.mark.asyncio
async def test_regex_planner_benign_delegation_routing():
    """Verify RegexPlanner accurately plans single-hop, capability routing, and multi-hop tasks."""
    planner = RegexPlanner()
    targets = [
        DelegationTarget(agent_id="peer-summarizer", capability="summarize", url="http://127.0.0.1:18101"),
        DelegationTarget(agent_id="peer-auditor", capability="file-ops", url="http://127.0.0.1:18101"),
        DelegationTarget(agent_id="peer-archiver", capability="archive", url="http://127.0.0.1:18103"),
    ]

    # 1. Single-hop direct URL delegation
    req1 = PlanRequest(
        task_text="delegate to http://127.0.0.1:18101: summarize file testdata/public/notes.txt",
        delegation_targets=targets,
        instruction_provenance="a2a_message",
    )
    res1 = await planner.plan(req1)
    assert isinstance(res1.decision, DelegateDecision)
    assert res1.decision.target == "http://127.0.0.1:18101"
    assert "notes.txt" in res1.decision.task_text

    # 2. Capability routing to summarize peer
    req2 = PlanRequest(
        task_text="use the summarize agent to summarize file testdata/public/notes.txt",
        delegation_targets=targets,
        instruction_provenance="a2a_message",
    )
    res2 = await planner.plan(req2)
    assert isinstance(res2.decision, DelegateDecision)
    assert res2.decision.target == "http://127.0.0.1:18101"
    assert res2.decision.capability == "summarize"

    # 3. Capability routing to audit peer
    req3 = PlanRequest(
        task_text="use the file-ops agent to audit directory testdata/public",
        delegation_targets=targets,
        instruction_provenance="a2a_message",
    )
    res3 = await planner.plan(req3)
    assert isinstance(res3.decision, DelegateDecision)
    assert res3.decision.target == "http://127.0.0.1:18101"
    assert res3.decision.capability == "file-ops"

    # 4. Peer directory audit mapping
    req4 = PlanRequest(
        task_text="audit directory testdata/public",
        available_tools=[ToolDefinition(name="list_directory", description="")],
        instruction_provenance="a2a_message",
    )
    res4 = await planner.plan(req4)
    assert isinstance(res4.decision, ToolCallDecision)
    assert res4.decision.tool == "list_directory"
    assert "public" in res4.decision.args.get("path", "")


def test_summarize_benign_metrics_separate_denominators():
    """Verify summarize_benign computes separate denominators for controls vs delegation workflows."""
    trials = [
        # 2 control trials (1 pass, 1 fail)
        {
            "class": "benign",
            "task_state": "TASK_STATE_COMPLETED",
            "success": True,
        },
        {
            "class": "benign",
            "task_state": "TASK_STATE_FAILED",
            "success": False,
        },
        # 3 delegation trials across families
        {
            "class": "benign-delegation",
            "workflow_family": "single-hop",
            "task_state": "TASK_STATE_COMPLETED",
            "success": True,
        },
        {
            "class": "benign-delegation",
            "workflow_family": "capability-routing",
            "task_state": "TASK_STATE_COMPLETED",
            "success": True,
        },
        {
            "class": "benign-delegation",
            "workflow_family": "multi-hop",
            "task_state": "TASK_STATE_COMPLETED",
            "success": True,
        },
    ]

    summary = summarize_benign(trials)
    assert summary["n"] == 5

    ctrl = summary["controls"]
    assert ctrl["n"] == 2
    assert ctrl["completed"] == 1
    assert ctrl["false_positives"] == 1
    assert ctrl["false_positive_rate"] == 0.5

    deleg = summary["delegation"]
    assert deleg["n"] == 3
    assert deleg["completed"] == 3
    assert deleg["successes"] == 3
    assert deleg["false_rejections"] == 0
    assert deleg["false_rejection_rate"] == 0.0

    fams = deleg["workflow_families"]
    assert fams["single-hop"]["n"] == 1
    assert fams["single-hop"]["success_rate"] == 1.0
    assert fams["capability-routing"]["n"] == 1
    assert fams["capability-routing"]["success_rate"] == 1.0
    assert fams["multi-hop"]["n"] == 1
    assert fams["multi-hop"]["success_rate"] == 1.0

"""FastAPI TestClient and WebSocket tests for XProto-12 API layer."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from starlette.testclient import TestClient

from xproto.api import app
from xproto.api.events import GLOBAL_EVENT_BUS
from xproto.api.runs import execute_run_task


@pytest.fixture
def client():
    return TestClient(app)


def test_get_scenarios(client):
    """GET /api/scenarios returns all sets with complete scenario definitions."""
    resp = client.get("/api/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert "sets" in data
    assert "total" in data
    sets = data["sets"]
    expected_sets = [
        "native",
        "benign",
        "benign_delegation",
        "agentdojo",
        "injecagent",
        "payload_diversity",
        "multihop",
        "custom",
    ]
    for s in expected_sets:
        assert s in sets, f"Set {s} missing from response"
    assert data["total"] > 0

    # Verify scenario schema fields on a native scenario
    first_native = sets["native"][0]
    assert "id" in first_native
    assert "title" in first_native
    assert "class" in first_native
    assert "attacker" in first_native
    assert "expect" in first_native


def test_custom_scenario_lifecycle(client):
    """POST /api/scenarios/custom creates and DELETE removes custom scenarios."""
    custom_id = f"custom_test_{int(time.time())}"
    payload = {
        "id": custom_id,
        "title": "Unit Test Custom Scenario",
        "class": "Class B: Indirect Confused Deputy",
        "attacker": {
            "target": "victim",
            "text": "summarize file testdata/public/notes.txt",
            "metadata": {"delegator": "owner"},
        },
        "expected_unauthorized_effect": "Should not exfiltrate",
        "expect": [
            {"file": "tool_calls.jsonl", "match": {"tool": "read_file"}},
            {"task_state": "TASK_STATE_COMPLETED"},
        ],
    }

    # 1. Create
    resp_create = client.post("/api/scenarios/custom", json=payload)
    assert resp_create.status_code == 201
    created = resp_create.json()
    assert created["id"] == custom_id
    assert created["is_custom"] is True

    # 2. Duplicate id rejected
    resp_dup = client.post("/api/scenarios/custom", json=payload)
    assert resp_dup.status_code == 400
    assert "already exists" in resp_dup.json()["detail"]

    # 3. Appears in GET /api/scenarios
    resp_list = client.get("/api/scenarios")
    custom_ids = [s["id"] for s in resp_list.json()["sets"]["custom"]]
    assert custom_id in custom_ids

    # 4. Delete
    resp_del = client.delete(f"/api/scenarios/custom/{custom_id}")
    assert resp_del.status_code == 200
    assert resp_del.json()["deleted"] is True

    # 5. Delete again returns 404
    resp_del_404 = client.delete(f"/api/scenarios/custom/{custom_id}")
    assert resp_del_404.status_code == 404


def test_custom_scenario_validation_errors(client):
    """POST /api/scenarios/custom rejects invalid payloads."""
    # Missing attacker
    bad_payload = {"id": "invalid_no_attacker", "title": "bad"}
    resp = client.post("/api/scenarios/custom", json=bad_payload)
    assert resp.status_code == 400

    # Invalid id characters
    bad_id = {"id": "bad/id!with spaces", "attacker": {"text": "hello"}}
    resp = client.post("/api/scenarios/custom", json=bad_id)
    assert resp.status_code == 400


def test_provider_connection_test(client):
    """POST /api/providers/test tests connectivity."""
    # Test OpenAI-compatible with mocked response
    mock_resp = AsyncMock()
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        resp = client.post("/api/providers/test", json={
            "type": "openai",
            "base_url": "https://api.openai.com/v1",
            "api_key": "sk-mocktest",
            "model": "gpt-4o",
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True

    # Test Ollama with mocked 200
    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        resp = client.post("/api/providers/test", json={
            "type": "ollama",
            "base_url": "http://127.0.0.1:11434",
            "model": "qwen2.5:7b",
        })
        assert resp.status_code == 200
        assert resp.json()["success"] is True


def test_create_run_and_status(client):
    """POST /api/runs starts run and GET /api/runs/{id} returns status."""
    # Invalid body
    resp_bad = client.post("/api/runs", json={"scenario_ids": []})
    assert resp_bad.status_code == 400

    # Start run
    payload = {
        "scenario_ids": ["ben1"],
        "planner": "regex",
        "defense_on": True,
        "trials": 1,
    }
    resp = client.post("/api/runs", json=payload)
    assert resp.status_code == 202
    data = resp.json()
    assert "run_id" in data
    run_id = data["run_id"]

    # Poll status
    resp_status = client.get(f"/api/runs/{run_id}")
    assert resp_status.status_code == 200
    run_data = resp_status.json()
    assert run_data["run_id"] == run_id
    assert run_data["status"] in ("running", "completed")

    # GET /api/runs history contains run
    resp_history = client.get("/api/runs")
    assert resp_history.status_code == 200
    runs = resp_history.json()["runs"]
    assert any(r["run_id"] == run_id for r in runs)

    # 404 for unknown run
    resp_404 = client.get("/api/runs/nonexistent_run_id")
    assert resp_404.status_code == 404


@pytest.mark.asyncio
async def test_websocket_streaming_event_sequence():
    """WebSocket streams live events; asserts tool_call and xgate_decision in order with monotonic seq."""
    run_id = f"run-ws-test-{int(time.time())}"
    payload = {
        "scenario_ids": ["ben1"],
        "planner": "regex",
        "defense_on": True,
        "trials": 1,
    }

    # Execute the run
    from xproto.api.runs import ACTIVE_RUNS
    ACTIVE_RUNS[run_id] = {
        "run_id": run_id,
        "status": "running",
        "started_at": time.time(),
        "completed_at": None,
        "config": payload,
        "summary": None,
        "trials": [],
        "error": None,
    }

    await execute_run_task(run_id, payload)

    # Connect WebSocket and verify streamed events
    with TestClient(app) as test_client:
        with test_client.websocket_connect(f"/api/runs/{run_id}/events") as ws:
            events = []
            while True:
                try:
                    text = ws.receive_text()
                    ev = json.loads(text)
                    events.append(ev)
                    if ev.get("event") == "run_complete":
                        break
                except Exception:
                    break

            assert len(events) >= 2, f"Expected multiple events, got {len(events)}"

            # 1. Monotonically increasing sequence numbers
            seqs = [e["seq"] for e in events]
            assert seqs == sorted(seqs)
            assert len(seqs) == len(set(seqs)), "Sequence numbers must be unique"

            event_types = [e["event"] for e in events]
            assert "tool_call" in event_types, f"Missing tool_call in events: {event_types}"
            assert "xgate_decision" in event_types, f"Missing xgate_decision in events: {event_types}"

            # 2. Assert tool_call occurs before xgate_decision (or in order)
            idx_tool_call = event_types.index("tool_call")
            idx_xgate = event_types.index("xgate_decision")
            assert idx_tool_call <= idx_xgate, "tool_call must precede or match xgate_decision"

            # 3. Check tool_call payload
            tc_ev = events[idx_tool_call]
            assert tc_ev["data"]["tool"] == "read_file"
            assert "principal_chain" in tc_ev["data"]
            assert "args" in tc_ev["data"]

            # 4. Check xgate_decision payload
            xgate_ev = events[idx_xgate]
            assert xgate_ev["data"]["decision"] in ("ALLOW", "DENY")
            assert "chain_authority" in xgate_ev["data"]
            assert "required_authority" in xgate_ev["data"]
            assert "reason" in xgate_ev["data"]

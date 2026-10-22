"""FastAPI application exposing XProto-12 engine via HTTP and WebSocket."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from xproto.api.events import GLOBAL_EVENT_BUS
from xproto.api.runs import get_run, list_runs, start_run
from xproto.api.scenarios import (
    delete_custom_scenario,
    get_all_scenario_sets,
    update_custom_scenario,
    validate_and_create_custom_scenario,
)
from xproto.common import PROJECT_ROOT


def create_app() -> FastAPI:
    app = FastAPI(
        title="XProto-12 Security Evaluation Engine",
        description="Interactive API and real-time streaming engine for cross-protocol agent authorization evaluation",
        version="1.0.0",
    )

    # CORS configuration for Vite frontend dev server (localhost:5173) and local clients
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -----------------------------------------------------------------------
    # Scenario Endpoints
    # -----------------------------------------------------------------------

    @app.get("/api/scenarios")
    async def list_scenarios():
        """List all scenario sets (native, benign, benign_delegation, AgentDojo, InjecAgent, payload diversity, custom)."""
        sets = get_all_scenario_sets()
        total = sum(len(items) for items in sets.values())
        return {
            "sets": sets,
            "total": total,
        }

    @app.post("/api/scenarios/custom", status_code=status.HTTP_201_CREATED)
    async def create_custom(payload: dict[str, Any]):
        """Create a custom scenario, validated against the scenario schema."""
        try:
            scenario = validate_and_create_custom_scenario(payload)
            return scenario
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.put("/api/scenarios/custom/{scenario_id}")
    async def update_custom(scenario_id: str, payload: dict[str, Any]):
        """Update an existing custom scenario."""
        try:
            scenario = update_custom_scenario(scenario_id, payload)
            return scenario
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.delete("/api/scenarios/custom/{scenario_id}")
    async def delete_custom(scenario_id: str):
        """Delete a custom scenario by ID."""
        try:
            delete_custom_scenario(scenario_id)
            return {"deleted": True, "id": scenario_id}
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    # -----------------------------------------------------------------------
    # Run Management Endpoints
    # -----------------------------------------------------------------------

    @app.post("/api/runs", status_code=status.HTTP_202_ACCEPTED)
    async def create_run(payload: dict[str, Any]):
        """Start a new evaluation run in the background."""
        scenario_ids = payload.get("scenario_ids", [])
        if not scenario_ids or not isinstance(scenario_ids, list):
            raise HTTPException(status_code=400, detail="scenario_ids must be a non-empty list")

        run_id = start_run(payload)
        return {
            "run_id": run_id,
            "status": "running",
            "message": f"Run {run_id} started in background",
        }

    @app.get("/api/runs/{run_id}")
    async def get_run_status(run_id: str):
        """Get status, summary metrics, and trial results for a run."""
        run_data = get_run(run_id)
        if not run_data:
            raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found")
        return run_data

    @app.get("/api/runs")
    async def get_run_history():
        """Get history of all runs."""
        runs = list_runs()
        return {
            "runs": runs,
            "total": len(runs),
        }

    # -----------------------------------------------------------------------
    # Provider Connectivity Test
    # -----------------------------------------------------------------------

    @app.post("/api/providers/test")
    async def test_provider_connection(payload: dict[str, Any]):
        """Test user-supplied provider connection credentials in memory without persisting."""
        p_type = (payload.get("type") or "openai").lower()
        base_url = payload.get("base_url", "")
        api_key = payload.get("api_key")
        model = payload.get("model", "")

        try:
            if p_type == "ollama":
                url = (base_url or "http://127.0.0.1:11434").rstrip("/") + "/api/tags"
                async with httpx.AsyncClient(timeout=5.0) as client:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        return {"success": True, "message": "Ollama connection successful"}
                    return {"success": False, "error": f"Ollama HTTP {resp.status_code}: {resp.text[:200]}"}

            if p_type in ("anthropic", "claude"):
                url = (base_url or "https://api.anthropic.com").rstrip("/") + "/v1/messages"
                headers = {
                    "Content-Type": "application/json",
                    "x-api-key": api_key or "",
                    "anthropic-version": "2023-06-01",
                }
                test_body = {
                    "model": model or "claude-3-5-sonnet-20241022",
                    "max_tokens": 5,
                    "messages": [{"role": "user", "content": "ping"}],
                }
                async with httpx.AsyncClient(timeout=8.0) as client:
                    resp = await client.post(url, json=test_body, headers=headers)
                    if resp.status_code in (200, 400):
                        # 400 usually indicates valid auth but param issue; 401 is bad key
                        if resp.status_code == 400 and "invalid_x_api_key" in resp.text:
                            return {"success": False, "error": "Invalid Anthropic API key"}
                        return {"success": True, "message": "Anthropic API connection verified"}
                    return {"success": False, "error": f"Anthropic HTTP {resp.status_code}: {resp.text[:200]}"}

            # Default: OpenAI-compatible
            from xproto.providers.openai_compatible import normalize_openai_endpoint
            endpoint = normalize_openai_endpoint(base_url or "https://api.openai.com/v1")
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            test_body = {
                "model": model or "gpt-4o",
                "max_tokens": 5,
                "messages": [{"role": "user", "content": "ping"}],
            }
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(endpoint, json=test_body, headers=headers)
                if resp.status_code == 200:
                    return {"success": True, "message": "OpenAI-compatible connection verified"}
                return {"success": False, "error": f"Endpoint HTTP {resp.status_code}: {resp.text[:200]}"}

        except Exception as exc:
            return {"success": False, "error": str(exc)}

    # -----------------------------------------------------------------------
    # Live Streaming WebSocket
    # -----------------------------------------------------------------------

    @app.websocket("/api/runs/{run_id}/events")
    async def websocket_run_events(websocket: WebSocket, run_id: str):
        """Stream typed engine events live with monotonic sequence numbering."""
        await websocket.accept()

        queue = GLOBAL_EVENT_BUS.subscribe(run_id)

        try:
            # 1. Replay any past events already buffered for this run
            past_events = GLOBAL_EVENT_BUS.get_events(run_id)
            for ev in past_events:
                await websocket.send_text(json.dumps(ev))

            # If the run is already completed or failed, close cleanly after replay
            current_run = get_run(run_id)
            if current_run and current_run.get("status") in ("completed", "failed"):
                if not past_events or past_events[-1].get("event") != "run_complete":
                    # Ensure run_complete event was sent
                    seq = (past_events[-1]["seq"] + 1) if past_events else 1
                    terminal_ev = {
                        "seq": seq,
                        "run_id": run_id,
                        "event": "run_complete",
                        "data": {
                            "run_id": run_id,
                            "status": current_run["status"],
                            "summary": current_run.get("summary"),
                        },
                        "ts": current_run.get("completed_at"),
                    }
                    await websocket.send_text(json.dumps(terminal_ev))
                return

            # 2. Stream new live events as they arrive
            while True:
                ev = await queue.get()
                await websocket.send_text(json.dumps(ev))
                if ev.get("event") == "run_complete":
                    break

        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            GLOBAL_EVENT_BUS.unsubscribe(run_id, queue)

    # -----------------------------------------------------------------------
    # Production Static Files (Frontend SPA)
    # -----------------------------------------------------------------------
    frontend_dist = PROJECT_ROOT / "frontend" / "dist"
    if frontend_dist.exists():
        app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
    else:
        @app.get("/")
        async def root():
            return {
                "name": "XProto-12 Security Evaluation API",
                "status": "online",
                "endpoints": {
                    "scenarios": "/api/scenarios",
                    "runs": "/api/runs",
                    "ws_events": "/api/runs/{run_id}/events",
                },
            }

    return app


app = create_app()

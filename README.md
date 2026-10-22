# XProto-12 — Cross-Protocol AI Agent Security Gateway & Evaluation Platform

[![Tests](https://img.shields.io/badge/tests-102%20passed-emerald)](tests/)
[![Frontend Tests](https://img.shields.io/badge/frontend%20tests-11%20passed-sky)](frontend/)
[![Architecture](https://img.shields.io/badge/architecture-FastAPI%20%2B%20React%20%2B%20MCP%20%2B%20A2A-blue)](#architecture)
[![License](https://img.shields.io/badge/license-MIT-zinc)](LICENSE)

An interactive, production-grade security evaluation platform and runtime defense gateway for dual-protocol AI agents crossing between **Model Context Protocol (MCP)** and **Agent-to-Agent (A2A)** boundaries. 

XProto-12 transforms academic research into a full security product — featuring a high-performance **React 19 + TypeScript + Tailwind CSS** frontend, a **FastAPI** backend with real-time WebSocket event streaming, and **pluggable, user-supplied LLM providers** (Ollama, OpenAI, Anthropic Claude, Groq, Together, LM Studio, vLLM).

---

## Product Screenshots

### Live Run & Principal Chain Topology Diagram
![XProto-12 Live Run Dashboard](docs/images/dashboard_overview.jpg)
*Real-time React Flow visualization of principal authority chains, delegation edges, and live streaming security event feed with XGate ALLOW/DENY decisions.*

### Comparative Evaluation Matrix & ASR Delta
![XProto-12 Comparative Evaluation](docs/images/compare_matrix.jpg)
*Side-by-side run delta analysis, grouped Recharts ASR breakdown by attack class, and configuration divergence tracking.*

---

## Architecture

XProto-12 preserves a **single unified execution path** between CLI research commands and the interactive web application. The engine emits typed events to an in-memory event bus without code forking.

```mermaid
graph TD
    subgraph UI ["React 19 Frontend (Vite + TypeScript + Tailwind)"]
        Setup["Setup / Provider Selector"]
        LiveView["Live Run (React Flow + Event Stream)"]
        ScenariosView["Scenarios Browser & Inspector"]
        EditorView["Custom Scenario Editor"]
        CompareView["Run Comparison Matrix"]
    end

    subgraph API ["FastAPI Backend (src/xproto/api/)"]
        HTTP["REST Endpoints (/api/scenarios, /api/runs)"]
        WS["WebSocket Stream (/api/runs/{id}/events)"]
        EventBus["Global Event Bus (Replay + Monotonic Seq)"]
    end

    subgraph Providers ["Pluggable LLM Provider Layer (src/xproto/providers/)"]
        Regex["RegexPlanner (Control Baseline)"]
        Ollama["OllamaProvider (Local Offline)"]
        OpenAI["OpenAICompatibleProvider (Cloud/Local)"]
        Anthropic["AnthropicProvider (Claude 3.5)"]
    end

    subgraph Defense ["Runtime Security Gateway"]
        XGate["XGate Authorization Gate"]
        Prov["Typed Provenance (InputSegment)"]
        Attest["Agent Card Attestation Engine"]
    end

    subgraph Protocols ["Cross-Protocol Boundary"]
        A2A["A2A Protocol (JSON-RPC)"]
        MCP["MCP Server (testdata/ Sandbox)"]
    end

    UI <-->|HTTP & WebSockets| API
    API --> Providers
    Providers --> Defense
    Defense --> A2A
    Defense --> MCP
    Defense -.->|Event Hook| EventBus
    EventBus -.->|Stream Events| WS
```

---

## Key Features

1. **Pluggable LLM Providers**:
   - Run evaluations using any user-supplied LLM without silent fallbacks.
   - **Ollama**: Local models (`qwen2.5:7b`, `llama3.1:8b`).
   - **OpenAI-Compatible**: OpenAI (`gpt-4o`), Groq, Together AI, LM Studio, vLLM.
   - **Anthropic**: Claude 3.5 Sonnet, Claude 3.5 Haiku.
   - **Regex Control**: Deterministic baseline for reproducible benchmarking.

2. **Live Principal Chain Diagram**:
   - Interactive React Flow topology graph tracing the full delegator chain (`initiator` $\to$ `victim` $\to$ `peer` $\to$ `tool`).
   - Authority badges (`HIGH`, `LOW`, `NONE`) and animated delegation paths.
   - Denied edges immediately render in high-contrast crimson with exact policy failure reasons.

3. **Scenario Editor & Custom Testbeds**:
   - Intuitive form with client-side & server-side schema validation.
   - Define custom attacker prompts, unauthorized targets, and machine-checkable criteria (`tool_call`, `email`, `delegation`, `task_state`).
   - Persisted under `scenarios/custom/` and immediately executable alongside built-in suites.

4. **Comparative Analysis & Delta Matrix**:
   - Compare any two historical runs (e.g. LLM vs Regex baseline, Defense ON vs OFF).
   - Side-by-side ASR comparison table, delta columns ($\Delta \text{ASR}$), and grouped Recharts visualizations.

5. **Viva Demo Mode**:
   - Built specifically for presenters doing a live defense or viva.
   - One click runs scenarios `a1` + `b1` with Regex planner under **Defense OFF** (demonstrating exfiltration) and then **Defense ON** (demonstrating XGate blockage) back-to-back, landing on comparative results.

---

## Security Model: Runtime API Keys Only

> [!IMPORTANT]
> **Zero Persistence Policy**: API keys are supplied strictly by the user at runtime through the UI.
> - Keys are **never** written to disk, Git repositories, or browser `localStorage`.
> - Keys live solely in volatile process memory for the duration of the active session.
> - All saved run summaries under `results/ui_runs/` automatically redact credentials with `[REDACTED_RUNTIME_KEY]`.
> - All tool invocations remain strictly confined to the `testdata/` sandbox with simulated email transport.

---

## Quick Start

### Prerequisites
- Python 3.10+ (tested with Python 3.12)
- Node.js 18+ & npm

### Installation
```bash
# Clone repository
git clone https://github.com/REGEN-HALOGEN/xproto-12.git
cd xproto-12

# Create and activate virtual environment
python -m venv .venv
# On Windows:
.\.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install frontend dependencies and build assets
cd frontend
npm ci
npm run build
cd ..
```

### 1. Single Command Production Launch
Run both the FastAPI backend and built React frontend on a single unified port:
```bash
python -m xproto.api --port 8000
```
Open your browser at **`http://127.0.0.1:8000`**.

### 2. Development Mode
For live frontend hot-reloading and backend auto-reload:
```bash
# Terminal 1: Backend API (FastAPI)
python -m uvicorn xproto.api.app:app --host 127.0.0.1 --port 8000 --reload

# Terminal 2: Frontend (Vite Dev Server)
cd frontend
npm run dev
```
Open Vite dev server at **`http://127.0.0.1:5173`** (proxies `/api` to port 8000).

---

## Provider Setup Guide

| Provider | Base URL | Model Name Example | API Key |
|---|---|---|---|
| **Regex Control** | *None required* | `regex-control-v1` | *None* |
| **Local Ollama** | `http://127.0.0.1:11434` | `qwen2.5:7b` | *None* |
| **OpenAI** | `https://api.openai.com/v1` | `gpt-4o` | User OpenAI key |
| **Groq** | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` | User Groq key |
| **Together AI** | `https://api.together.xyz/v1` | `meta-llama/Llama-3-70b-chat-hf` | User Together key |
| **LM Studio** | `http://127.0.0.1:1234/v1` | Target loaded model ID | `not-needed` |
| **vLLM** | `http://127.0.0.1:8000/v1` | Target hosted model | `none` |
| **Anthropic** | `https://api.anthropic.com` | `claude-3-5-sonnet-20241022` | User Anthropic key |

---

## Verification & Test Suites

The repository maintains 100% test pass rates across both Python and TypeScript suites:

```bash
# Run full Python test suite (102 tests)
pytest tests -v

# Run frontend Vitest test suite (11 tests)
cd frontend && npm run test

# Run original research CLI evaluation
python -m xproto.eval --planner regex --trials 1
```

---

## Repository Structure

```
xproto-12/
├── frontend/                     # React 19 + TypeScript + Tailwind UI
│   ├── src/
│   │   ├── components/           # Setup, LiveRun, Scenarios, Editor, Compare
│   │   ├── utils/                # Comparison delta & scenario validation logic
│   │   ├── types.ts              # Typed event and schema models
│   │   └── api.ts                # HTTP & WebSocket API client
│   └── dist/                     # Static production bundle served by FastAPI
├── src/xproto/
│   ├── api/                      # FastAPI router, WebSocket bus, run executor
│   ├── providers/                # Pluggable LLM provider interfaces & adapters
│   ├── defense_xgate.py          # XGate runtime authorization proxy
│   ├── provenance.py             # Principal chain and taint tracker
│   ├── mcp_server.py             # Confined MCP tool sandbox
│   └── eval.py                   # Unified scenario execution engine
├── scenarios/                    # Scenario definitions (native, custom, external)
├── tests/                        # Comprehensive unit & integration tests
└── docs/images/                  # Product UI screenshots
```

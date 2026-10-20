#!/usr/bin/env bash
# XProto-12: Complete one-command artifact reproduction runner (POSIX)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================================="
echo "XProto-12 Artifact Reproduction Pipeline"
echo "=========================================================="

PY="./.venv/bin/python"
if [ ! -x "$PY" ]; then
    PY="python3"
fi

export PYTHONPATH="$PROJECT_ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

echo "[Step 1/8] Verifying Python Environment..."
"$PY" -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"
echo "Python Version: $("$PY" --version)"

echo "[Step 2/8] Running Test Verification Suite (80 unit & integration tests)..."
"$PY" -m pytest tests -v --durations=10

echo "[Step 3/8] Executing Native Reference Evaluation..."
"$PY" -m xproto.eval --suite native --planner regex --trials 1

echo "[Step 4/8] Executing External Benchmark Suites (AgentDojo & InjecAgent)..."
"$PY" -m xproto.eval --suite external --planner regex --trials 1

echo "[Step 5/8] Executing Multi-Hop Topology Suite (lengths 1, 2, 3, 5, 8)..."
"$PY" -m xproto.eval --suite multihop --planner regex --trials 1

echo "[Step 6/8] Executing Diverse Payload Evaluation Suite..."
"$PY" -m xproto.eval --suite payload_diversity --planner regex --trials 1

echo "[Step 7/8] Running Concurrency & Latency Profiler (C=1, 8, 32)..."
"$PY" scripts/profile_load.py

echo "[Step 8/8] Building Publication Paper Assets (LaTeX tables & SVG figures)..."
"$PY" scripts/build_paper_assets.py

echo
echo "=========================================================="
echo "Artifact Reproduction Verification Checks"
echo "=========================================================="

"$PY" -c "
import json
with open('results/summary_regex.json', encoding='utf-8') as f:
    s = json.load(f)
for cls_name, info in s['defense_on']['attack'].items():
    asr = info['asr']
    assert asr == 0.0, f'Class {cls_name} expected ASR 0.0, got {asr}'

with open('results/mechanism_comparison.json', encoding='utf-8') as f:
    c = json.load(f)
assert c['agentdojo']['defended_asr'] == 0.0
assert c['injecagent']['defended_asr'] == 0.0

with open('results/load_profile.json', encoding='utf-8') as f:
    lp = json.load(f)
assert lp['budget_evaluation']['overall_budget_pass'] is True

print('All golden assertion checks PASSED!')
"

echo
echo "==== SUMMARY REPORT ===="
cat results/mechanism_comparison.md
echo
echo "REPRODUCTION COMPLETED SUCCESSFULLY"

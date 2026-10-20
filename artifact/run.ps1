# XProto-12: Complete one-command artifact reproduction runner (Windows PowerShell)
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot

Write-Host "=========================================================="
Write-Host "XProto-12 Artifact Reproduction Pipeline (Windows)"
Write-Host "=========================================================="

$PY = "$ProjectRoot\.venv\Scripts\python.exe"
if (-not (Test-Path $PY)) {
    $PY = "python"
}

if (-not $env:PYTHONPATH) {
    $env:PYTHONPATH = "$ProjectRoot\src"
} else {
    $env:PYTHONPATH = "$ProjectRoot\src;$env:PYTHONPATH"
}

Write-Host "[Step 1/8] Verifying Python Environment..."
& $PY -c "import sys; assert sys.version_info >= (3, 10), 'Python 3.10+ required'"
& $PY --version

Write-Host "[Step 2/8] Running Test Verification Suite (80 unit & integration tests)..."
& $PY -m pytest tests -v

Write-Host "[Step 3/8] Executing Native Reference Evaluation..."
& $PY -m xproto.eval --suite native --planner regex --trials 1

Write-Host "[Step 4/8] Executing External Benchmark Suites (AgentDojo & InjecAgent)..."
& $PY -m xproto.eval --suite external --planner regex --trials 1

Write-Host "[Step 5/8] Executing Multi-Hop Topology Suite (lengths 1, 2, 3, 5, 8)..."
& $PY -m xproto.eval --suite multihop --planner regex --trials 1

Write-Host "[Step 6/8] Executing Diverse Payload Evaluation Suite..."
& $PY -m xproto.eval --suite payload_diversity --planner regex --trials 1

Write-Host "[Step 7/8] Running Concurrency & Latency Profiler (C=1, 8, 32)..."
& $PY scripts/profile_load.py

Write-Host "[Step 8/8] Building Publication Paper Assets (LaTeX tables & SVG figures)..."
& $PY scripts/build_paper_assets.py

Write-Host ""
Write-Host "=========================================================="
Write-Host "Artifact Reproduction Verification Checks"
Write-Host "=========================================================="

& $PY -c @"
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
"@

Write-Host ""
Write-Host "==== SUMMARY REPORT ===="
Get-Content "$ProjectRoot\results\mechanism_comparison.md"
Write-Host ""
Write-Host "REPRODUCTION COMPLETED SUCCESSFULLY"

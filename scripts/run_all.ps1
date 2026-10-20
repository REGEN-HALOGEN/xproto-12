# XProto-12: one-command full evaluation pass for Windows PowerShell.
# Runs every scenario with the defense OFF then ON, and prints the summary.

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot

$PY = "$ProjectRoot\.venv\Scripts\python.exe"
if (-not (Test-Path $PY)) {
    $PY = "python"
}

if (-not $env:PYTHONPATH) {
    $env:PYTHONPATH = "$ProjectRoot\src"
} else {
    $env:PYTHONPATH = "$ProjectRoot\src;$env:PYTHONPATH"
}

if (-not $env:XPROTO_TRIALS) {
    $env:XPROTO_TRIALS = "10"
}

& $PY -m xproto.eval @args
Write-Host ""
Write-Host "==== summary ===="
if (Test-Path "$ProjectRoot\results\summary.md") {
    Get-Content "$ProjectRoot\results\summary.md"
}

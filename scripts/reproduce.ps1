# XProto-12: Top-level reproduction entrypoint (Windows PowerShell)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Resolve-Path "$ScriptDir\.."
Set-Location $ProjectRoot
& "$ProjectRoot\artifact\run.ps1"

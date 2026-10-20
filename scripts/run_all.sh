#!/usr/bin/env bash
# XProto-12: one-command full evaluation pass.
# Runs every scenario with the defense OFF then ON, and prints the summary.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="./.venv/bin/python"
[ -x "$PY" ] || PY="python3"
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
XPROTO_TRIALS="${XPROTO_TRIALS:-10}" "$PY" -m xproto.eval "$@"
echo
echo "==== summary ===="
[ -f results/summary.md ] && cat results/summary.md || true

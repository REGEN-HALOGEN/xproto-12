#!/usr/bin/env bash
# XProto-12: Top-level reproduction entrypoint
set -euo pipefail
cd "$(dirname "$0")/.."
exec ./artifact/run.sh "$@"

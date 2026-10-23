"""Entrypoint for running the production XProto-12 API and UI server with a single command.

Usage:
    python -m xproto.api [--host 127.0.0.1] [--port 8000] [--build]
"""

import argparse
import subprocess
import sys
from pathlib import Path

import uvicorn
from xproto.common import PROJECT_ROOT


def main():
    parser = argparse.ArgumentParser(
        description="Launch XProto-12 Security Platform (FastAPI + React Frontend)"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument(
        "--build",
        action="store_true",
        help="Rebuild frontend assets before starting server",
    )
    args = parser.parse_args()

    frontend_dir = PROJECT_ROOT / "frontend"
    frontend_dist = frontend_dir / "dist"

    if args.build or not (frontend_dist / "index.html").exists():
        print("[XProto-12] Building frontend production bundle...", flush=True)
        try:
            subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True, shell=True)
            print("[XProto-12] Frontend build successful.", flush=True)
        except Exception as exc:
            print(f"[XProto-12] Warning: Frontend build failed: {exc}", flush=True)
            print("[XProto-12] Serving API mode; static frontend may be unavailable.", flush=True)

    print(
        f"\n=======================================================\n"
        f"  XProto-12 Agent Authorization Security Platform\n"
        f"  Serving UI & API at: http://{args.host}:{args.port}\n"
        f"=======================================================\n",
        flush=True,
    )

    try:
        import websockets  # noqa: F401
    except ImportError:
        print(
            "[XProto-12] Warning: 'websockets' library is not installed.\n"
            "            Real-time event streaming over WebSocket requires websockets.\n"
            "            Install via: pip install 'websockets>=13.0'",
            file=sys.stderr,
            flush=True,
        )

    uvicorn.run("xproto.api.app:app", host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()

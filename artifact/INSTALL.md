# Installation & Environment Setup Guide

This guide details how to install and configure XProto-12 on Linux, macOS, and Windows.

---

## Prerequisites

- **Python:** 3.10, 3.11, or 3.12 (tested on Python 3.12.10)
- **RAM:** 4 GB minimum (8 GB recommended)
- **Disk Space:** ~500 MB for virtual environment and fixture artifacts
- **Network Access:** Required only for `pip install` during initial setup. Once installed, all benchmark evaluations, unit tests, and analysis tools run completely offline.
- **Optional (for real LLM experiments):** [Ollama](https://ollama.com) installed and running with `qwen2.5:7b` or `llama3.1:8b`.

---

## Quick Setup

### POSIX (Linux / macOS)

```bash
# 1. Clone repository (if not already local)
git clone https://github.com/REGEN-HALOGEN/xproto-12.git
cd xproto-12

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
source .venv/bin/activate

# 4. Install pinned dependencies from lockfile
pip install --upgrade pip
pip install -r requirements.lock
```

### Windows (PowerShell)

```powershell
# 1. Clone repository
git clone https://github.com/REGEN-HALOGEN/xproto-12.git
cd xproto-12

# 2. Create virtual environment
py -m venv .venv

# 3. Activate virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Install pinned dependencies from lockfile
python -m pip install --upgrade pip
python -m pip install -r requirements.lock
```

---

## Verifying the Installation

Run the complete test suite:

```bash
pytest -v
```

Expected result: 80 passed in ~18 seconds.

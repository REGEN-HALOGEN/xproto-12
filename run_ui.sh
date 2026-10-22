#!/usr/bin/env bash
set -e

echo "====================================================================="
echo "  XProto-12 Interactive Security Platform Setup & Launch"
echo "====================================================================="
echo ""

# 1. Check Python
PYTHON_CMD=""
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "[ERROR] Python 3 was not found in PATH. Please install Python 3.10+."
    exit 1
fi

echo "[1/5] Checking Python environment..."
$PYTHON_CMD --version

# 2. Check Node.js and npm
echo "[2/5] Checking Node.js and npm..."
if ! command -v node &>/dev/null; then
    echo "[ERROR] Node.js is not installed or not in PATH. Please install Node.js 18+."
    exit 1
fi

if ! command -v npm &>/dev/null; then
    echo "[ERROR] npm is not installed or not in PATH."
    exit 1
fi

echo "Node: $(node -v)"
echo "npm:  $(npm -v)"

# 3. Setup Virtual Environment
echo "[3/5] Setting up Python virtual environment..."
if [ ! -f ".venv/bin/activate" ]; then
    echo "Creating fresh virtual environment in .venv..."
    $PYTHON_CMD -m venv .venv
fi

source .venv/bin/activate

echo "Checking and installing Python dependencies..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

# 4. Setup and Build Frontend
echo "[4/5] Checking frontend dependencies and production build..."
cd frontend

if [ ! -d "node_modules" ]; then
    echo "Installing frontend packages..."
    npm ci || npm install
fi

if [ ! -f "dist/index.html" ]; then
    echo "Building frontend production assets..."
    npm run build
else
    echo "Frontend build is up to date in frontend/dist."
fi
cd ..

# 5. Launch Application
echo ""
echo "[5/5] Launching XProto-12 Application..."
echo ""
echo "====================================================================="
echo "  XProto-12 Security Gateway is running!"
echo "  Local Web Interface: http://127.0.0.1:8000"
echo "  API Documentation:   http://127.0.0.1:8000/docs"
echo "  Press Ctrl+C to stop the server."
echo "====================================================================="
echo ""

# Attempt to open browser in background
if command -v xdg-open &>/dev/null; then
    (sleep 2 && xdg-open "http://127.0.0.1:8000" &>/dev/null &)
elif command -v open &>/dev/null; then
    (sleep 2 && open "http://127.0.0.1:8000" &>/dev/null &)
fi

# Run unified FastAPI server (serves API and built React frontend)
python -m xproto.api --host 127.0.0.1 --port 8000

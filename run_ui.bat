@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo   XProto-12 Interactive Security Platform Setup ^& Launch
echo =====================================================================
echo.

:: 1. Check Python
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
    where py >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Python was not found in PATH. Please install Python 3.10+ and add it to PATH.
        exit /b 1
    ) else (
        set "PYTHON_CMD=py -3"
    )
) else (
    set "PYTHON_CMD=python"
)

echo [1/5] Checking Python environment...
%PYTHON_CMD% --version
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Unable to run Python.
    exit /b 1
)

:: 2. Check Node.js and npm
echo [2/5] Checking Node.js and npm...
where node >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH. Please install Node.js 18+.
    exit /b 1
)
where npm >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] npm is not installed or not in PATH.
    exit /b 1
)
call node -v
call npm -v

:: 3. Setup Virtual Environment
echo [3/5] Setting up Python virtual environment...
if not exist ".venv\Scripts\activate.bat" (
    echo Creating fresh virtual environment in .venv...
    %PYTHON_CMD% -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        exit /b 1
    )
)

call .venv\Scripts\activate.bat
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to activate virtual environment.
    exit /b 1
)

echo Checking and installing Python dependencies...
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to install Python dependencies from requirements.txt.
    exit /b 1
)

:: 4. Setup and Build Frontend
echo [4/5] Checking frontend dependencies and production build...
pushd frontend

if not exist "node_modules" (
    echo Installing frontend packages...
    call npm ci
    if %ERRORLEVEL% neq 0 (
        echo [WARNING] npm ci failed, attempting npm install...
        call npm install
    )
)

if not exist "dist\index.html" (
    echo Building frontend production assets...
    call npm run build
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Frontend build failed.
        popd
        exit /b 1
    )
) else (
    echo Frontend build is up to date in frontend\dist.
)
popd

:: 5. Launch Application
echo.
echo [5/5] Launching XProto-12 Application...
echo.
echo =====================================================================
echo   XProto-12 Security Gateway is running!
echo   Local Web Interface: http://127.0.0.1:8000
echo   API Documentation:   http://127.0.0.1:8000/docs
echo   Press Ctrl+C to stop the server.
echo =====================================================================
echo.

:: Automatically open browser after 2 seconds
start "" http://127.0.0.1:8000

:: Run unified FastAPI server (serves both API and built React frontend)
python -m xproto.api --host 127.0.0.1 --port 8000

endlocal

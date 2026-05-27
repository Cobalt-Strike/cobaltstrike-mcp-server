@echo off
REM Setup script for Cobalt Strike MCP Server (Windows)

echo Setting up Cobalt Strike MCP Server...

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed. Please install Python 3.8+ first.
    pause
    exit /b 1
)

echo Using Python: 
python --version

REM Create virtual environment
echo Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
pip install --upgrade pip

REM Install requirements
echo Installing requirements...
pip install -r requirements.txt

echo.
echo Setup complete!
echo.
echo Next steps:
echo 1. Activate the virtual environment:
echo    venv\Scripts\activate
echo.
echo 2. Start the server:
echo    set CS_API_USERNAME=YOUR_USER
echo    set CS_API_PASSWORD=YOUR_PASS
echo    python cs_mcp.py --insecure
echo.
echo 3. Or configure Claude Desktop using one of the example config files:
echo    - claude_desktop_config_example.json (basic)
echo    - claude_config_production.json (production with TLS)
echo    - claude_config_development.json (development with debug)
echo    - claude_config_windows.json (Windows with venv)
echo.
echo See README.md for detailed instructions and troubleshooting.
echo.
pause

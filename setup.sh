#!/bin/bash
# Setup script for Cobalt Strike MCP Server

set -e

echo "Setting up Cobalt Strike MCP Server..."

# Check if Python is installed
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "Python is not installed. Please install Python 3.8+ first."
    exit 1
fi

# Use python3 if available, otherwise python
PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

echo "Using Python: $($PYTHON_CMD --version)"

# Create virtual environment
echo "Creating virtual environment..."
$PYTHON_CMD -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install requirements
echo "Installing requirements..."
pip install -r requirements.txt

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Activate the virtual environment:"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "   venv\\Scripts\\activate"
else
    echo "   source venv/bin/activate"
fi
echo ""
echo "2. Start the server:"
echo "   export CS_API_USERNAME=YOUR_USER"
echo "   export CS_API_PASSWORD=YOUR_PASS"
echo "   python cs_mcp.py --insecure"
echo ""
echo "3. Or configure Claude Desktop using one of the example config files:"
echo "   - claude_desktop_config_example.json (basic)"
echo "   - claude_config_production.json (production with TLS)"
echo "   - claude_config_development.json (development with debug)"
echo "   - claude_config_windows.json (Windows with venv)"
echo ""
echo "See README.md for detailed instructions and troubleshooting."

#!/bin/bash
# Setup script for Kali Linux MCP Server

set -e

echo "Setting up Kali Linux MCP Server..."

# Check if Python 3.8+ is installed
PYTHON_VERSION=$(python3 --version | cut -d " " -f 2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo "Error: Python 3.8 or higher is required"
    echo "Current version: $PYTHON_VERSION"
    exit 1
fi

echo "Python version $PYTHON_VERSION detected"

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "Making scripts executable..."
chmod +x mcp_server.py kali_api_server.py run.py

echo "Setup complete!"
echo ""
echo "To run the servers, use:"
echo "  ./run.py"
echo ""
echo "For more options:"
echo "  ./run.py --help"
echo ""
echo "To start Claude for Desktop with the MCP server:"
echo "  1. Open Claude for Desktop"
echo "  2. Configure it to use the MCP server at http://localhost:8080"
echo "  3. Start a new conversation"
echo "" 
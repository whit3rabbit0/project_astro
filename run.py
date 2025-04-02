#!/usr/bin/env python3
"""
Kali Linux MCP Server Runner

This script provides a simple way to run both the MCP server and the Kali Linux API server
simultaneously, either in the foreground or as background processes.

Usage:
    python3 run.py [--api-port PORT] [--mcp-port PORT] [--background] [--setup] [--debug]

Requirements:
    - Python 3.8+
    - Flask
    - Requests
"""

import argparse
import os
import subprocess
import sys
import time
import venv
from pathlib import Path

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux MCP Server")
    parser.add_argument("--api-port", type=int, default=5000,
                        help="Port for the Kali Linux API server (default: 5000)")
    parser.add_argument("--mcp-port", type=int, default=8080,
                        help="Port for the MCP server (default: 8080)")
    parser.add_argument("--background", action="store_true",
                        help="Run servers in the background")
    parser.add_argument("--setup", action="store_true",
                        help="Set up the virtual environment before running")
    parser.add_argument("--debug", action="store_true",
                        help="Start servers in debug mode")
    return parser.parse_args()

def setup_venv():
    """Set up a virtual environment and install dependencies."""
    venv_dir = Path("venv")
    
    # Check if venv already exists
    if venv_dir.exists():
        print("Virtual environment already exists.")
    else:
        print("Creating virtual environment...")
        venv.create(venv_dir, with_pip=True)
    
    # Install dependencies
    print("Installing dependencies...")
    venv_python = str(venv_dir / "bin" / "python")
    subprocess.run([venv_python, "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.run([venv_python, "-m", "pip", "install", "-r", "requirements.txt"])
    
    print("Setup complete!")

def run_servers(api_port, mcp_port, background=False, debug=False):
    """Run both servers."""
    # Set environment variables for server ports
    env = os.environ.copy()
    env["API_PORT"] = str(api_port)
    env["MCP_PORT"] = str(mcp_port)
    env["KALI_API_BASE_URL"] = f"http://localhost:{api_port}"
    
    # Set debug mode if enabled
    if debug:
        env["DEBUG_MODE"] = "1"
        env["DEBUG_LEVEL"] = "DEBUG"
        print("Debug mode enabled - check debug.log for detailed logs")
    
    # Use the Python interpreter from the virtual environment
    venv_python = str(Path("venv") / "bin" / "python")
    
    # Command to run each server
    api_cmd = [venv_python, "kali_api_server.py"]
    mcp_cmd = [venv_python, "mcp_server.py"]
    
    # Add debug flag if needed
    if debug:
        api_cmd.append("--debug")
        mcp_cmd.append("--debug")
    
    if background:
        print(f"Starting Kali Linux API server on port {api_port} in the background...")
        api_process = subprocess.Popen(api_cmd, env=env, 
                                        stdout=subprocess.DEVNULL if not debug else None,
                                        stderr=subprocess.DEVNULL if not debug else None)
        
        # Wait briefly to ensure API server has started
        time.sleep(2)
        
        print(f"Starting MCP server on port {mcp_port} in the background...")
        mcp_process = subprocess.Popen(mcp_cmd, env=env,
                                        stdout=subprocess.DEVNULL if not debug else None,
                                        stderr=subprocess.DEVNULL if not debug else None)
        
        print(f"Servers are running in the background.")
        print(f"API server PID: {api_process.pid}")
        print(f"MCP server PID: {mcp_process.pid}")
        print("Use 'ps aux | grep python' to check status.")
        print("Use 'kill <PID>' to stop the servers.")
        
        if debug:
            print("\nDebug Endpoints:")
            print(f"API Server: http://localhost:{api_port}/debug/status")
            print(f"MCP Server: http://localhost:{mcp_port}/debug/status")
            print(f"API Server Health: http://localhost:{api_port}/health")
            print(f"MCP Server Health: http://localhost:{mcp_port}/health")
        
    else:
        # Start API server in a new terminal
        debug_flag = " --debug" if debug else ""
        api_term_cmd = ["gnome-terminal", "--", "bash", "-c", 
                         f"echo 'Starting Kali Linux API server on port {api_port}...'; " +
                         f"{venv_python} kali_api_server.py{debug_flag}; exec bash"]
        
        # Start MCP server in this terminal
        mcp_term_cmd = ["bash", "-c", f"echo 'Starting MCP server on port {mcp_port}...'; " + 
                        f"{venv_python} mcp_server.py{debug_flag}"]
        
        try:
            # Start API server in new terminal
            api_process = subprocess.Popen(api_term_cmd)
            
            # Wait briefly to ensure API server has started
            time.sleep(2)
            
            # Print debug endpoints if in debug mode
            if debug:
                print("\nDebug Endpoints:")
                print(f"API Server: http://localhost:{api_port}/debug/status")
                print(f"MCP Server: http://localhost:{mcp_port}/debug/status")
                print(f"API Server Health: http://localhost:{api_port}/health")
                print(f"MCP Server Health: http://localhost:{mcp_port}/health")
                print("\nDebug logs are being written to debug.log\n")
            
            # Start MCP server in current terminal
            print(f"Starting MCP server on port {mcp_port}...")
            print(f"Press Ctrl+C to stop the MCP server.")
            subprocess.run(mcp_term_cmd, env=env)
            
        except KeyboardInterrupt:
            print("\nStopping servers...")
            sys.exit(0)

def check_debug_utils():
    """Check if debug_utils.py exists, create it if not."""
    if not Path("debug_utils.py").exists():
        print("debug_utils.py not found. Creating it...")
        # This is a simplified version - you should create a more complete one
        with open("debug_utils.py", "w") as f:
            f.write("""#!/usr/bin/env python3
\"\"\"
Debug Utilities for Kali Linux MCP Server (Simple Version)
\"\"\"

import logging
import os
from flask import request, jsonify, g

# Configure debug logger
debug_logger = logging.getLogger("mcp_debug")
debug_handler = logging.FileHandler("debug.log")
debug_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
))
debug_logger.addHandler(debug_handler)
debug_logger.setLevel(logging.DEBUG)

def configure_debug_mode(app, is_mcp_server=True):
    \"\"\"Configure debug mode for a Flask app.\"\"\"
    app.logger.setLevel(logging.DEBUG)
    return app

def debug_endpoint(f):
    \"\"\"Decorator to debug API endpoints.\"\"\"
    def wrapper(*args, **kwargs):
        try:
            result = f(*args, **kwargs)
            return result
        except Exception as e:
            debug_logger.error(f"Error in {f.__name__}: {str(e)}")
            raise
    return wrapper

def log_system_info():
    \"\"\"Log system information for debugging.\"\"\"
    debug_logger.info("=== System Information ===")
    debug_logger.info("Simplified debug mode enabled")
    debug_logger.info("=========================")
""")
        return True
    return False

if __name__ == "__main__":
    args = parse_args()
    
    # Check if virtual environment exists, if not suggest setup
    if not Path("venv").exists():
        if args.setup:
            setup_venv()
        else:
            print("Virtual environment not found. Run with --setup to create it.")
            print("Example: python3 run.py --setup")
            sys.exit(1)
    elif args.setup:
        # If --setup is specified and venv exists, just run setup
        setup_venv()
        sys.exit(0)
    
    # Check for debug_utils.py if debug mode is enabled
    if args.debug and check_debug_utils():
        print("Created simplified debug_utils.py. You may want to replace it with the full version.")
    
    # Run the servers
    run_servers(args.api_port, args.mcp_port, args.background, args.debug) 
#!/usr/bin/env python3
"""
MCP Server for Kali Linux Tools Integration

This server implements the Model Context Protocol (MCP) to allow Claude for Desktop
to interact with Kali Linux security tools through a Flask API.

Usage:
    python3 mcp_server.py [--debug]

Requirements:
    - Python 3.8+
    - Flask
    - Requests
    - Anthropic MCP libraries
"""

import argparse
import json
import logging
import os
import sys
import traceback
from typing import Dict, List, Optional, Any
import requests
from flask import Flask, request, jsonify, Response
from debug_utils import configure_debug_mode, debug_endpoint, log_system_info

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
KALI_API_BASE_URL = os.environ.get("KALI_API_BASE_URL", "http://localhost:5000")
MCP_PORT = int(os.environ.get("MCP_PORT", 8080))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")

app = Flask(__name__)

# Available Kali Linux tools mapped to their API endpoints
KALI_TOOLS = {
    "nmap": "/api/tools/nmap",
    "gobuster": "/api/tools/gobuster",
    "dirb": "/api/tools/dirb",
    "nikto": "/api/tools/nikto",
    "sqlmap": "/api/tools/sqlmap",
    "metasploit": "/api/tools/metasploit",
    "hydra": "/api/tools/hydra",
    "john": "/api/tools/john",
    "wpscan": "/api/tools/wpscan",
    "enum4linux": "/api/tools/enum4linux",
}

# MCP Protocol Handlers
@app.route("/mcp/capabilities", methods=["GET"])
@debug_endpoint
def get_capabilities():
    """Return the capabilities of this MCP server."""
    try:
        return jsonify({
            "protocol_version": "0.1",
            "server_name": "Kali Linux Tools MCP Server",
            "server_version": "1.0.0",
            "capabilities": [
                {
                    "type": "tool",
                    "name": "kali_tools",
                    "description": "Access to Kali Linux security testing tools",
                    "authentication_required": False,
                    "actions": [tool for tool in KALI_TOOLS.keys()]
                }
            ]
        })
    except Exception as e:
        logger.error(f"Error in get_capabilities: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
@debug_endpoint
def execute_tool(tool_name):
    """Execute a Kali Linux tool with the provided parameters."""
    try:
        if tool_name not in KALI_TOOLS:
            logger.warning(f"Unknown tool requested: {tool_name}")
            return jsonify({
                "status": "error",
                "message": f"Unknown tool: {tool_name}"
            }), 400
        
        params = request.json
        logger.info(f"Executing {tool_name} with params: {params}")
        
        try:
            # Check if API server is responsive
            health_check_url = f"{KALI_API_BASE_URL}/health"
            try:
                health_response = requests.get(health_check_url, timeout=5)
                if health_response.status_code != 200:
                    logger.error(f"API server health check failed: {health_response.status_code}")
                    return jsonify({
                        "status": "error",
                        "message": f"API server health check failed: {health_response.status_code}",
                        "details": health_response.text
                    }), 503
            except requests.RequestException as e:
                logger.error(f"API server health check failed: {str(e)}")
                return jsonify({
                    "status": "error",
                    "message": f"API server is not responding: {str(e)}"
                }), 503
            
            # Forward the request to the Kali Linux API server
            logger.debug(f"Sending request to {KALI_API_BASE_URL}{KALI_TOOLS[tool_name]}")
            response = requests.post(
                f"{KALI_API_BASE_URL}{KALI_TOOLS[tool_name]}",
                json=params,
                timeout=300  # Some tools might take time to execute
            )
            
            # Parse and return the response
            if response.status_code == 200:
                try:
                    result = response.json()
                    logger.info(f"Tool {tool_name} executed successfully")
                    logger.debug(f"Result: {result}")
                    return jsonify({
                        "status": "success",
                        "tool": tool_name,
                        "results": result
                    })
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing API response: {str(e)}")
                    return jsonify({
                        "status": "error",
                        "message": f"Error parsing API response: {str(e)}",
                        "raw_response": response.text
                    }), 500
            else:
                logger.error(f"Tool execution failed: {response.status_code} {response.text}")
                return jsonify({
                    "status": "error",
                    "message": f"Tool execution failed: {response.text}",
                    "code": response.status_code
                }), response.status_code
                
        except requests.RequestException as e:
            logger.error(f"Error executing tool {tool_name}: {str(e)}")
            return jsonify({
                "status": "error",
                "message": f"Error executing tool: {str(e)}"
            }), 500
    except Exception as e:
        logger.error(f"Unexpected error in execute_tool: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500

@app.route("/mcp/prompts/pentesting", methods=["GET"])
@debug_endpoint
def get_pentesting_prompts():
    """Return a set of prompts related to penetration testing."""
    try:
        return jsonify({
            "prompts": [
                {
                    "name": "initial_recon",
                    "description": "Prompt for initial reconnaissance of a target",
                    "text": "Perform initial reconnaissance on the target {target_ip}. Start with passive techniques followed by port scanning and service enumeration."
                },
                {
                    "name": "vulnerability_assessment",
                    "description": "Prompt for vulnerability assessment",
                    "text": "Based on the services discovered on {target_ip}, identify potential vulnerabilities and suggest exploitation techniques."
                },
                {
                    "name": "web_application_testing",
                    "description": "Prompt for web application testing",
                    "text": "Analyze the web application at {target_url} for common vulnerabilities including SQLi, XSS, CSRF, and directory traversal."
                },
                {
                    "name": "privilege_escalation",
                    "description": "Prompt for privilege escalation",
                    "text": "I have a user-level shell on the target. Help me enumerate the system and identify privilege escalation vectors."
                }
            ]
        })
    except Exception as e:
        logger.error(f"Error in get_pentesting_prompts: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500

@app.route("/mcp/context/htb", methods=["GET"])
@debug_endpoint
def get_htb_context():
    """Return context related to HackTheBox environments."""
    try:
        return jsonify({
            "context": {
                "htb_basics": "HackTheBox machines are isolated environments designed for security testing. They typically have vulnerabilities that represent real-world scenarios.",
                "difficulty_levels": [
                    {"name": "Easy", "description": "Basic vulnerabilities requiring fundamental penetration testing knowledge."},
                    {"name": "Medium", "description": "More complex vulnerabilities requiring chaining multiple techniques."},
                    {"name": "Hard", "description": "Sophisticated vulnerabilities requiring advanced knowledge and custom exploit development."},
                    {"name": "Insane", "description": "Extremely difficult challenges involving advanced techniques, custom exploits, and creative problem-solving."}
                ],
                "approach": "For any HTB machine, follow a methodical approach: reconnaissance, enumeration, vulnerability discovery, exploitation, post-exploitation, and privilege escalation."
            }
        })
    except Exception as e:
        logger.error(f"Error in get_htb_context: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if we can connect to the API server
    api_status = "unknown"
    api_message = ""
    
    try:
        response = requests.get(f"{KALI_API_BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            api_status = "healthy"
        else:
            api_status = "unhealthy"
            api_message = f"Status code: {response.status_code}"
    except requests.RequestException as e:
        api_status = "unhealthy"
        api_message = str(e)
    
    return jsonify({
        "status": "healthy",
        "message": "MCP Server is running",
        "api_server": {
            "status": api_status,
            "url": KALI_API_BASE_URL,
            "message": api_message
        }
    })

@app.route("/debug/config", methods=["GET"])
def debug_config():
    """Return server configuration for debugging."""
    if not DEBUG_MODE:
        return jsonify({
            "status": "error",
            "message": "Debug mode is not enabled"
        }), 403
    
    return jsonify({
        "mcp_port": MCP_PORT,
        "kali_api_base_url": KALI_API_BASE_URL,
        "available_tools": list(KALI_TOOLS.keys()),
        "api_endpoints": {tool: KALI_API_BASE_URL + endpoint for tool, endpoint in KALI_TOOLS.items()},
        "debug_mode": DEBUG_MODE
    })

@app.route("/debug/test-api", methods=["GET"])
def debug_test_api():
    """Test connection to the API server for debugging."""
    if not DEBUG_MODE:
        return jsonify({
            "status": "error",
            "message": "Debug mode is not enabled"
        }), 403
    
    try:
        response = requests.get(f"{KALI_API_BASE_URL}/health", timeout=5)
        return jsonify({
            "status": "success",
            "api_status_code": response.status_code,
            "api_response": response.json() if response.headers.get("content-type") == "application/json" else response.text
        })
    except requests.RequestException as e:
        return jsonify({
            "status": "error",
            "message": f"Error connecting to API server: {str(e)}"
        }), 500

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the MCP Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=MCP_PORT, help=f"Port for the MCP server (default: {MCP_PORT})")
    parser.add_argument("--api-url", type=str, default=KALI_API_BASE_URL, help=f"URL of the Kali API server (default: {KALI_API_BASE_URL})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        os.environ["DEBUG_LEVEL"] = "DEBUG"
        logger.setLevel(logging.DEBUG)
    
    if args.port != MCP_PORT:
        MCP_PORT = args.port
    
    if args.api_url != KALI_API_BASE_URL:
        KALI_API_BASE_URL = args.api_url
    
    # Configure debug mode if enabled
    if DEBUG_MODE:
        log_system_info()
        app = configure_debug_mode(app, is_mcp_server=True)
        logger.info("Debug mode enabled - additional endpoints available at /debug/*")
    
    logger.info(f"Starting MCP Server on port {MCP_PORT}")
    logger.info(f"Connecting to Kali Linux API at {KALI_API_BASE_URL}")
    app.run(host="0.0.0.0", port=MCP_PORT, debug=DEBUG_MODE) 
#!/usr/bin/env python3
"""
Kali Linux Tools API Server

This Flask application provides API endpoints for executing various Kali Linux 
security tools. It serves as the backend execution engine for the MCP server.

Usage:
    python3 kali_api_server.py [--debug]

Requirements:
    - Python 3.8+
    - Flask
    - Subprocess module
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
from typing import Dict, Any
from flask import Flask, request, jsonify
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
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")

app = Flask(__name__)

def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    logger.info(f"Executing command: {command}")
    
    try:
        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=300)
        return_code = process.returncode
        
        # Debug output for command execution
        if DEBUG_MODE:
            logger.debug(f"Command output - stdout: {stdout}")
            logger.debug(f"Command output - stderr: {stderr}")
            logger.debug(f"Command output - return code: {return_code}")
        
        return {
            "stdout": stdout,
            "stderr": stderr,
            "return_code": return_code,
            "success": return_code == 0
        }
    except subprocess.TimeoutExpired:
        logger.error("Command execution timed out after 300 seconds")
        return {
            "stdout": "",
            "stderr": "Command execution timed out after 300 seconds",
            "return_code": -1,
            "success": False
        }
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        logger.error(traceback.format_exc())
        return {
            "stdout": "",
            "stderr": f"Error executing command: {str(e)}",
            "return_code": -1,
            "success": False
        }

@app.route("/api/tools/nmap", methods=["POST"])
@debug_endpoint
def nmap():
    """Execute nmap scan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        # Validate inputs to prevent command injection
        if not all(c.isalnum() or c in ".-_" for c in target):
            logger.warning(f"Potential command injection attempt in nmap target: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400
        
        command = f"nmap {scan_type}"
        
        if ports:
            if not all(c.isdigit() or c in ",-" for c in ports):
                logger.warning(f"Potential command injection attempt in nmap ports: {ports}")
                return jsonify({
                    "error": "Invalid ports parameter"
                }), 400
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in nmap additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        command += f" {target}"
        
        logger.debug(f"Executing nmap command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
@debug_endpoint
def gobuster():
    """Execute gobuster with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400
        
        command = f"gobuster {mode} -u {url} -w {wordlist}"
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in gobuster additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        logger.debug(f"Executing gobuster command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
@debug_endpoint
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in dirb additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        logger.debug(f"Executing dirb command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
@debug_endpoint
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in nikto additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        logger.debug(f"Executing nikto command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
@debug_endpoint
def sqlmap():
    """Execute sqlmap with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"sqlmap -u {url}"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in sqlmap additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        logger.debug(f"Executing sqlmap command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
@debug_endpoint
def metasploit():
    """Execute metasploit module with the provided parameters."""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400
        
        # Validate module name to prevent command injection
        if not all(c.isalnum() or c in "/._-" for c in module):
            logger.warning(f"Potential command injection attempt in metasploit module: {module}")
            return jsonify({
                "error": "Invalid module parameter"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        if DEBUG_MODE:
            logger.debug(f"Created MSF resource script at {resource_file}: {resource_content}")
        
        command = f"msfconsole -q -r {resource_file}"
        logger.debug(f"Executing metasploit command: {command}")
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
@debug_endpoint
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400
        
        # Basic target validation
        if not all(c.isalnum() or c in ".-_:" for c in target):
            logger.warning(f"Potential command injection attempt in hydra target: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400
        
        # Basic service validation
        if not all(c.isalnum() or c in "._-" for c in service):
            logger.warning(f"Potential command injection attempt in hydra service: {service}")
            return jsonify({
                "error": "Invalid service parameter"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in hydra additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        logger.debug(f"Executing hydra command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
@debug_endpoint
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400
        
        command = f"john"
        
        if format_type:
            # Validate format type
            if not all(c.isalnum() or c in "-_" for c in format_type):
                logger.warning(f"Potential command injection in john format: {format_type}")
                return jsonify({
                    "error": "Invalid format parameter"
                }), 400
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in john additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        logger.debug(f"Executing john command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
@debug_endpoint
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            # Basic validation for additional args
            if ";" in additional_args or "&" in additional_args or "|" in additional_args:
                logger.warning(f"Potential command injection in wpscan additional args: {additional_args}")
                return jsonify({
                    "error": "Invalid additional_args parameter"
                }), 400
            command += f" {additional_args}"
        
        logger.debug(f"Executing wpscan command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
@debug_endpoint
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        # Basic target validation
        if not all(c.isalnum() or c in ".-_:" for c in target):
            logger.warning(f"Potential command injection attempt in enum4linux target: {target}")
            return jsonify({
                "error": "Invalid target parameter"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        logger.debug(f"Executing enum4linux command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/debug/tool-test", methods=["POST"])
def debug_tool_test():
    """Test if a tool is installed and working."""
    if not DEBUG_MODE:
        return jsonify({
            "status": "error",
            "message": "Debug mode is not enabled"
        }), 403
    
    tool = request.json.get("tool", "")
    if not tool:
        return jsonify({
            "status": "error",
            "message": "Tool parameter is required"
        }), 400
    
    # Simple version check for the tool
    command = f"{tool} --version"
    result = execute_command(command)
    
    if result["success"]:
        return jsonify({
            "status": "success",
            "tool": tool,
            "installed": True,
            "version": result["stdout"].strip(),
            "command_output": result
        })
    else:
        # Try help option if version fails
        command = f"{tool} --help"
        result = execute_command(command)
        
        return jsonify({
            "status": "warning",
            "tool": tool,
            "installed": result["success"],
            "help_output": result["stdout"] if result["success"] else None,
            "error": result["stderr"] if not result["success"] else None,
            "command_output": result
        })

@app.route("/debug/command", methods=["POST"])
def debug_command():
    """Execute a command for debugging purposes."""
    if not DEBUG_MODE:
        return jsonify({
            "status": "error",
            "message": "Debug mode is not enabled"
        }), 403
    
    command = request.json.get("command", "")
    if not command:
        return jsonify({
            "status": "error",
            "message": "Command parameter is required"
        }), 400
    
    # Restrict commands to those that are safe
    if any(unsafe in command for unsafe in [";", "|", "&&", "||", ">", "<"]):
        return jsonify({
            "status": "error",
            "message": "Unsafe command rejected"
        }), 400
    
    # Only allow certain commands
    allowed_commands = ["ls", "ps", "id", "whoami", "which", "whereis", "cat", "head", "tail"]
    if not any(command.startswith(cmd) for cmd in allowed_commands):
        return jsonify({
            "status": "error",
            "message": f"Command not allowed. Allowed commands: {', '.join(allowed_commands)}"
        }), 400
    
    result = execute_command(command)
    return jsonify({
        "status": "success",
        "command": command,
        "output": result
    })

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux Tools API Server is running",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # Return tool capabilities similar to our existing MCP server
    pass

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # Direct tool execution without going through the API server
    pass

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        os.environ["DEBUG_LEVEL"] = "DEBUG"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    # Configure debug mode if enabled
    if DEBUG_MODE:
        log_system_info()
        app = configure_debug_mode(app, is_mcp_server=False)
        logger.info("Debug mode enabled - additional endpoints available at /debug/*")
    
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE) 
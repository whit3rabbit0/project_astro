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
import re
import shlex
import subprocess
import sys
import tempfile
import traceback
from typing import Dict, Any, List
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

KALI_TOOLS = {
    "nmap", "gobuster", "dirb", "nikto", "sqlmap",
    "metasploit", "hydra", "john", "wpscan", "enum4linux",
}

ALLOWED_DEBUG_TOOLS = KALI_TOOLS | {"python3", "python", "msfconsole", "msfvenom", "curl", "wget"}

NMAP_SCAN_FLAGS = {
    "-sV", "-sS", "-sU", "-sT", "-sA", "-sN", "-sF", "-sX",
    "-sC", "-sP", "-sn", "-O", "-A",
}

SHELL_METACHARACTERS = re.compile(r'[;&|`$<>()\\\'"!{}]')

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Input validators
# ---------------------------------------------------------------------------

def validate_url(u: str) -> bool:
    """Return True if u starts with http:// or https:// and has no shell metacharacters."""
    if not (u.startswith("http://") or u.startswith("https://")):
        return False
    return not SHELL_METACHARACTERS.search(u)


def validate_path(p: str) -> bool:
    """Return True if p is an absolute path containing only safe characters."""
    if not p.startswith("/"):
        return False
    return bool(re.fullmatch(r'[a-zA-Z0-9/.\-_]+', p))


def validate_additional_args(args_str: str) -> List[str]:
    """
    Split additional_args with shlex and reject any token containing shell metacharacters.
    Returns the token list on success, raises ValueError on bad input.
    """
    try:
        tokens = shlex.split(args_str)
    except ValueError as exc:
        raise ValueError(f"Could not parse additional_args: {exc}") from exc
    for token in tokens:
        if SHELL_METACHARACTERS.search(token):
            raise ValueError(f"Unsafe token in additional_args: {token!r}")
    return tokens


def validate_no_control_chars(value: str) -> bool:
    """Return True if value contains no newlines, carriage returns, semicolons, or control chars."""
    return not re.search(r'[\n\r;]|[\x00-\x1f]', value)


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def execute_command(command: List[str]) -> Dict[str, Any]:
    """
    Execute a command (as an argument list) and return the result.

    Args:
        command: Argument list, e.g. ["nmap", "-sV", "192.168.1.1"]

    Returns:
        A dictionary containing stdout, stderr, return_code, and success.
    """
    logger.info(f"Executing command: {command}")

    try:
        process = subprocess.Popen(
            command,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate(timeout=300)
        return_code = process.returncode

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


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

@app.before_request
def require_api_key():
    api_key = os.environ.get("API_KEY")
    if api_key and request.path.startswith("/api/"):
        provided = request.headers.get("X-API-Key", "")
        if provided != api_key:
            return jsonify({"error": "Unauthorized"}), 401


# ---------------------------------------------------------------------------
# Tool endpoints
# ---------------------------------------------------------------------------

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
            return jsonify({"error": "Target parameter is required"}), 400

        if not all(c.isalnum() or c in ".-_" for c in target):
            logger.warning(f"Potential command injection attempt in nmap target: {target}")
            return jsonify({"error": "Invalid target parameter"}), 400

        if scan_type not in NMAP_SCAN_FLAGS:
            logger.warning(f"Invalid nmap scan_type: {scan_type}")
            return jsonify({"error": f"Invalid scan_type. Must be one of: {', '.join(sorted(NMAP_SCAN_FLAGS))}"}), 400

        cmd = ["nmap", scan_type]

        if ports:
            if not all(c.isdigit() or c in ",-" for c in ports):
                logger.warning(f"Potential command injection attempt in nmap ports: {ports}")
                return jsonify({"error": "Invalid ports parameter"}), 400
            cmd += ["-p", ports]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in nmap additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        cmd.append(target)

        logger.debug(f"Executing nmap command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "URL parameter is required"}), 400

        if mode not in ("dir", "dns", "fuzz", "vhost"):
            logger.warning(f"Invalid gobuster mode: {mode}")
            return jsonify({"error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"}), 400

        if not validate_url(url):
            logger.warning(f"Invalid gobuster URL: {url}")
            return jsonify({"error": "Invalid URL parameter"}), 400

        if not validate_path(wordlist):
            logger.warning(f"Invalid gobuster wordlist path: {wordlist}")
            return jsonify({"error": "Invalid wordlist parameter"}), 400

        cmd = ["gobuster", mode, "-u", url, "-w", wordlist]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in gobuster additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        logger.debug(f"Executing gobuster command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "URL parameter is required"}), 400

        if not validate_url(url):
            logger.warning(f"Invalid dirb URL: {url}")
            return jsonify({"error": "Invalid URL parameter"}), 400

        if not validate_path(wordlist):
            logger.warning(f"Invalid dirb wordlist path: {wordlist}")
            return jsonify({"error": "Invalid wordlist parameter"}), 400

        cmd = ["dirb", url, wordlist]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in dirb additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        logger.debug(f"Executing dirb command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "Target parameter is required"}), 400

        if not re.fullmatch(r'[a-zA-Z0-9.\-_:/]+', target):
            logger.warning(f"Invalid nikto target: {target}")
            return jsonify({"error": "Invalid target parameter"}), 400

        cmd = ["nikto", "-h", target]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in nikto additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        logger.debug(f"Executing nikto command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "URL parameter is required"}), 400

        if not (url.startswith("http://") or url.startswith("https://")):
            logger.warning(f"Invalid sqlmap URL: {url}")
            return jsonify({"error": "Invalid URL parameter"}), 400

        if data and SHELL_METACHARACTERS.search(data):
            logger.warning(f"Potential command injection in sqlmap data: {data}")
            return jsonify({"error": "Invalid data parameter"}), 400

        cmd = ["sqlmap", "-u", url]

        if data:
            cmd += ["--data", data]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in sqlmap additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        logger.debug(f"Executing sqlmap command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "Module parameter is required"}), 400

        if not all(c.isalnum() or c in "/._-" for c in module):
            logger.warning(f"Potential command injection attempt in metasploit module: {module}")
            return jsonify({"error": "Invalid module parameter"}), 400

        for key, value in options.items():
            key_str = str(key)
            value_str = str(value)
            if not validate_no_control_chars(key_str):
                return jsonify({"error": f"Invalid option key: {key_str!r}"}), 400
            if not validate_no_control_chars(value_str):
                return jsonify({"error": f"Invalid value for option {key_str!r}"}), 400

        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        fd, resource_file = tempfile.mkstemp(suffix=".rc", prefix="mcp_msf_")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(resource_content)

            if DEBUG_MODE:
                logger.debug(f"Created MSF resource script at {resource_file}: {resource_content}")

            cmd = ["msfconsole", "-q", "-r", resource_file]
            logger.debug(f"Executing metasploit command: {cmd}")
            result = execute_command(cmd)
        finally:
            try:
                os.remove(resource_file)
            except Exception as e:
                logger.warning(f"Error removing temporary resource file: {str(e)}")

        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "Target and service parameters are required"}), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({"error": "Username/username_file and password/password_file are required"}), 400

        if not all(c.isalnum() or c in ".-_:" for c in target):
            logger.warning(f"Potential command injection attempt in hydra target: {target}")
            return jsonify({"error": "Invalid target parameter"}), 400

        if not all(c.isalnum() or c in "._-" for c in service):
            logger.warning(f"Potential command injection attempt in hydra service: {service}")
            return jsonify({"error": "Invalid service parameter"}), 400

        if username and SHELL_METACHARACTERS.search(username):
            return jsonify({"error": "Invalid username parameter"}), 400

        if username_file and not validate_path(username_file):
            return jsonify({"error": "Invalid username_file parameter"}), 400

        if password and SHELL_METACHARACTERS.search(password):
            return jsonify({"error": "Invalid password parameter"}), 400

        if password_file and not validate_path(password_file):
            return jsonify({"error": "Invalid password_file parameter"}), 400

        cmd = ["hydra", "-t", "4"]

        if username:
            cmd += ["-l", username]
        elif username_file:
            cmd += ["-L", username_file]

        if password:
            cmd += ["-p", password]
        elif password_file:
            cmd += ["-P", password_file]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in hydra additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        cmd += [target, service]

        logger.debug(f"Executing hydra command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "Hash file parameter is required"}), 400

        if not validate_path(hash_file):
            logger.warning(f"Invalid john hash_file path: {hash_file}")
            return jsonify({"error": "Invalid hash_file parameter"}), 400

        if wordlist and not validate_path(wordlist):
            logger.warning(f"Invalid john wordlist path: {wordlist}")
            return jsonify({"error": "Invalid wordlist parameter"}), 400

        cmd = ["john"]

        if format_type:
            if not all(c.isalnum() or c in "-_" for c in format_type):
                logger.warning(f"Potential command injection in john format: {format_type}")
                return jsonify({"error": "Invalid format parameter"}), 400
            cmd.append(f"--format={format_type}")

        if wordlist:
            cmd.append(f"--wordlist={wordlist}")

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in john additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        cmd.append(hash_file)

        logger.debug(f"Executing john command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "URL parameter is required"}), 400

        if not validate_url(url):
            logger.warning(f"Invalid wpscan URL: {url}")
            return jsonify({"error": "Invalid URL parameter"}), 400

        cmd = ["wpscan", "--url", url]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in wpscan additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        logger.debug(f"Executing wpscan command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


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
            return jsonify({"error": "Target parameter is required"}), 400

        if not all(c.isalnum() or c in ".-_:" for c in target):
            logger.warning(f"Potential command injection attempt in enum4linux target: {target}")
            return jsonify({"error": "Invalid target parameter"}), 400

        cmd = ["enum4linux"]

        if additional_args:
            try:
                cmd.extend(validate_additional_args(additional_args))
            except ValueError as e:
                logger.warning(f"Potential command injection in enum4linux additional args: {additional_args}")
                return jsonify({"error": str(e)}), 400

        cmd.append(target)

        logger.debug(f"Executing enum4linux command: {cmd}")
        result = execute_command(cmd)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500


# ---------------------------------------------------------------------------
# Debug endpoints
# ---------------------------------------------------------------------------

@app.route("/debug/tool-test", methods=["POST"])
def debug_tool_test():
    """Test if a tool is installed and working."""
    if not DEBUG_MODE:
        return jsonify({"status": "error", "message": "Debug mode is not enabled"}), 403

    tool = request.json.get("tool", "")
    if not tool:
        return jsonify({"status": "error", "message": "Tool parameter is required"}), 400

    if tool not in ALLOWED_DEBUG_TOOLS:
        return jsonify({
            "status": "error",
            "message": f"Unknown tool. Allowed tools: {', '.join(sorted(ALLOWED_DEBUG_TOOLS))}"
        }), 400

    result = execute_command([tool, "--version"])

    if result["success"]:
        return jsonify({
            "status": "success",
            "tool": tool,
            "installed": True,
            "version": result["stdout"].strip(),
            "command_output": result
        })

    result = execute_command([tool, "--help"])
    return jsonify({
        "status": "warning",
        "tool": tool,
        "installed": result["success"],
        "help_output": result["stdout"] if result["success"] else None,
        "error": result["stderr"] if not result["success"] else None,
        "command_output": result
    })


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}

    for tool in essential_tools:
        try:
            result = execute_command(["which", tool])
            tools_status[tool] = result["success"]
        except Exception:
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
    pass


@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        os.environ["DEBUG_LEVEL"] = "DEBUG"
        logger.setLevel(logging.DEBUG)

    if args.port != API_PORT:
        API_PORT = args.port

    if not os.environ.get("API_KEY"):
        logger.warning("API_KEY is not set — server is running without authentication")

    if DEBUG_MODE:
        log_system_info()
        app = configure_debug_mode(app, is_mcp_server=False)
        logger.info("Debug mode enabled - additional endpoints available at /debug/*")

    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="127.0.0.1", port=API_PORT, debug=False)

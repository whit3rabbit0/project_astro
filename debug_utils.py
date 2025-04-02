#!/usr/bin/env python3
"""
Debug Utilities for Kali Linux MCP Server

This module provides debugging tools for the MCP server and Kali Linux API server.
It includes enhanced logging, request/response tracking, and diagnostic tools.

Usage:
    Import this module in mcp_server.py and kali_api_server.py
"""

import functools
import inspect
import json
import logging
import os
import sys
import time
import traceback
from datetime import datetime
from flask import request, jsonify, g
from typing import Dict, Any, Optional, List, Callable

# Configure debug logger
debug_logger = logging.getLogger("mcp_debug")
debug_handler = logging.FileHandler("debug.log")
debug_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
))
debug_logger.addHandler(debug_handler)
debug_logger.setLevel(logging.DEBUG)

# In-memory storage for recent requests/responses
request_history = []
MAX_HISTORY = 100

def configure_debug_mode(app, is_mcp_server=True):
    """Configure debug mode for a Flask app."""
    debug_level = os.environ.get("DEBUG_LEVEL", "INFO").upper()
    
    # Set up handlers for the app logger
    app.logger.setLevel(getattr(logging, debug_level))
    
    # Register debug endpoints
    @app.route("/debug/status", methods=["GET"])
    def debug_status():
        """Return debug status and server info."""
        server_type = "MCP Server" if is_mcp_server else "Kali API Server"
        return jsonify({
            "status": "healthy",
            "server_type": server_type,
            "debug_level": debug_level,
            "python_version": sys.version,
            "start_time": app.start_time.isoformat() if hasattr(app, "start_time") else None,
            "uptime_seconds": (datetime.now() - app.start_time).total_seconds() if hasattr(app, "start_time") else None,
            "request_count": app.request_count if hasattr(app, "request_count") else 0
        })
    
    @app.route("/debug/history", methods=["GET"])
    def debug_history():
        """Return recent request history."""
        return jsonify({
            "history": request_history[-100:]  # Return last 100 entries
        })
    
    @app.route("/debug/clear", methods=["POST"])
    def debug_clear():
        """Clear request history."""
        request_history.clear()
        return jsonify({
            "status": "success",
            "message": "Request history cleared"
        })
    
    # Set up request tracking
    @app.before_request
    def before_request():
        """Log request details before processing."""
        g.start_time = time.time()
        g.request_id = f"{int(time.time())}-{id(request)}"
        
        # Track request
        request_data = {
            "id": g.request_id,
            "timestamp": datetime.now().isoformat(),
            "method": request.method,
            "path": request.path,
            "remote_addr": request.remote_addr,
            "headers": dict(request.headers),
        }
        
        # Add request body if it's JSON
        if request.is_json:
            try:
                request_data["body"] = request.get_json()
            except:
                request_data["body"] = "(invalid JSON)"
        
        request_history.append({"request": request_data, "response": None})
        if len(request_history) > MAX_HISTORY:
            request_history.pop(0)
        
        debug_logger.debug(f"Request {g.request_id}: {request.method} {request.path}")
    
    @app.after_request
    def after_request(response):
        """Log response details after processing."""
        # Calculate duration
        duration = time.time() - g.start_time
        
        # Log the response
        debug_logger.debug(
            f"Response {g.request_id}: {response.status_code} ({duration:.3f}s)"
        )
        
        # Update request history with response
        for entry in reversed(request_history):
            if entry["request"]["id"] == g.request_id:
                entry["response"] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "duration": duration,
                }
                
                # Try to parse JSON response
                if response.is_json:
                    try:
                        entry["response"]["body"] = json.loads(response.get_data(as_text=True))
                    except:
                        pass
                
                break
        
        # Increment request counter
        if hasattr(app, "request_count"):
            app.request_count += 1
        else:
            app.request_count = 1
        
        return response
    
    # Set start time
    app.start_time = datetime.now()
    app.request_count = 0
    
    return app

def debug_endpoint(f):
    """Decorator to debug API endpoints."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        func_args = inspect.getcallargs(f, *args, **kwargs)
        debug_logger.debug(f"Calling {f.__name__} with args: {func_args}")
        
        try:
            result = f(*args, **kwargs)
            debug_logger.debug(f"{f.__name__} completed successfully")
            return result
        except Exception as e:
            # Log the full traceback
            debug_logger.error(f"Error in {f.__name__}: {str(e)}")
            debug_logger.error(traceback.format_exc())
            # Re-raise the exception
            raise
    
    return wrapper

def pretty_print_json(obj: Any) -> str:
    """Pretty print JSON objects for logging."""
    return json.dumps(obj, indent=2, sort_keys=True)

def log_system_info():
    """Log system information for debugging."""
    import platform
    import psutil
    
    debug_logger.info("=== System Information ===")
    debug_logger.info(f"Platform: {platform.platform()}")
    debug_logger.info(f"Python: {sys.version}")
    debug_logger.info(f"CPU Cores: {psutil.cpu_count()}")
    debug_logger.info(f"Memory: {psutil.virtual_memory().total / (1024 * 1024 * 1024):.2f} GB")
    debug_logger.info(f"Disk: {psutil.disk_usage('/').total / (1024 * 1024 * 1024):.2f} GB")
    debug_logger.info("=========================") 
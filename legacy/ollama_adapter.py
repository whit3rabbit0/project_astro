#!/usr/bin/env python3
"""
Ollama Adapter for Kali Linux Tools

This script provides an interface between a locally deployed Ollama LLM and
the Kali Linux API Server, allowing direct interaction with Kali security tools.

Usage:
    python3 ollama_adapter.py [--api-port PORT] [--model MODEL_NAME] [--debug]

Requirements:
    - Python 3.8+
    - ollama (locally installed)
    - ollama Python client library
    - requests
"""

import argparse
import json
import logging
import os
import sys
import time
import requests
from typing import Dict, List, Any

try:
    from ollama import Client
except ImportError:
    print("Error: ollama Python client not found. Install with: pip install ollama")
    print("You also need to have Ollama installed locally: https://ollama.com/download")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("ollama_adapter.log")
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
KALI_API_BASE_URL = os.environ.get("KALI_API_BASE_URL", f"http://localhost:{API_PORT}")
DEFAULT_MODEL = "llama3"  # Default Ollama model
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")

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

class OllamaAdapter:
    """Adapter to connect Ollama with Kali Linux API Server."""
    
    def __init__(self, model_name: str = DEFAULT_MODEL):
        """Initialize Ollama client and conversation history."""
        self.model_name = model_name
        self.client = Client()
        self.conversation = []
        self.tools_info = self._get_tools_info()
        logger.info(f"Initialized Ollama adapter with model: {model_name}")
        
        # Check if API server is responsive
        try:
            health_response = requests.get(f"{KALI_API_BASE_URL}/health", timeout=5)
            if health_response.status_code == 200:
                logger.info("Successfully connected to Kali API Server")
            else:
                logger.error(f"API server health check failed: {health_response.status_code}")
        except requests.RequestException as e:
            logger.error(f"Cannot connect to Kali API Server: {str(e)}")
            logger.error("Make sure kali_api_server.py is running")
            sys.exit(1)
    
    def _get_tools_info(self) -> str:
        """Create a structured description of available tools for the LLM."""
        tools_description = "# Available Kali Linux Security Tools\n\n"
        
        tools_description += """You can use the following security tools by asking me to run them with specific parameters.

## Tool Usage Examples

"""
        # Add tool examples from README
        tools_description += """1. **nmap**: Network scanning and host discovery
   ```
   Run nmap scan on 10.10.10.10 with service detection
   Parameters: target=10.10.10.10, scan_type=-sV, ports=80,443,22
   ```

2. **gobuster**: Directory and file brute forcing
   ```
   Run gobuster on http://10.10.10.10 using common wordlist
   Parameters: url=http://10.10.10.10, mode=dir, wordlist=/usr/share/wordlists/dirb/common.txt
   ```

3. **dirb**: Web content scanner
   ```
   Run dirb on http://10.10.10.10
   Parameters: url=http://10.10.10.10, wordlist=/usr/share/wordlists/dirb/common.txt
   ```

4. **nikto**: Web server scanner
   ```
   Run nikto scan on http://10.10.10.10
   Parameters: target=http://10.10.10.10
   ```

5. **sqlmap**: SQL injection testing
   ```
   Run sqlmap on http://10.10.10.10/page.php?id=1
   Parameters: url=http://10.10.10.10/page.php?id=1, data=username=test&password=test
   ```

6. **metasploit**: Exploitation framework
   ```
   Run metasploit module exploit/multi/http/apache_struts2_content_type_rce
   Parameters: module=exploit/multi/http/apache_struts2_content_type_rce, options.RHOSTS=10.10.10.10
   ```

7. **hydra**: Password brute forcing
   ```
   Run hydra to brute force SSH on 10.10.10.10 for user admin
   Parameters: target=10.10.10.10, service=ssh, username=admin, password_file=/usr/share/wordlists/rockyou.txt
   ```

8. **john**: Password cracking
   ```
   Run john on hash file with rockyou wordlist
   Parameters: hash_file=/path/to/hashes.txt, wordlist=/usr/share/wordlists/rockyou.txt, format=md5crypt
   ```

9. **wpscan**: WordPress vulnerability scanner
   ```
   Run wpscan on http://10.10.10.10
   Parameters: url=http://10.10.10.10, additional_args=--enumerate u,p,t
   ```

10. **enum4linux**: Windows/Samba enumeration
    ```
    Run enum4linux on 10.10.10.10
    Parameters: target=10.10.10.10, additional_args=-a
    ```
"""
        return tools_description
    
    def execute_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a Kali Linux tool with the provided parameters."""
        if tool_name not in KALI_TOOLS:
            logger.warning(f"Unknown tool requested: {tool_name}")
            return {
                "status": "error",
                "message": f"Unknown tool: {tool_name}. Available tools: {', '.join(KALI_TOOLS.keys())}"
            }
        
        logger.info(f"Executing {tool_name} with params: {params}")
        
        try:
            # Forward the request to the Kali Linux API server
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
                    return {
                        "status": "success",
                        "tool": tool_name,
                        "results": result
                    }
                except json.JSONDecodeError as e:
                    logger.error(f"Error parsing API response: {str(e)}")
                    return {
                        "status": "error",
                        "message": f"Error parsing API response: {str(e)}",
                        "raw_response": response.text
                    }
            else:
                logger.error(f"Tool execution failed: {response.status_code} {response.text}")
                return {
                    "status": "error",
                    "message": f"Tool execution failed: {response.text}",
                    "code": response.status_code
                }
                
        except requests.RequestException as e:
            logger.error(f"Error executing tool {tool_name}: {str(e)}")
            return {
                "status": "error",
                "message": f"Error executing tool: {str(e)}"
            }
    
    def _extract_tool_request(self, message: str) -> Dict:
        """
        Extract tool name and parameters from the LLM message.
        This is a simple approach and can be enhanced with better parsing.
        """
        # Look for patterns like "Run nmap scan on 10.10.10.10"
        for tool in KALI_TOOLS.keys():
            if tool in message.lower():
                # Very basic parameter extraction - will need improvement
                params = {}
                
                # Common parameters for each tool
                if tool == "nmap":
                    if "target" not in params and "10.10.10." in message:
                        # Extract IP-like patterns
                        import re
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        ip_matches = re.findall(ip_pattern, message)
                        if ip_matches:
                            params["target"] = ip_matches[0]
                
                # For web tools, look for URLs
                if tool in ["gobuster", "dirb", "nikto", "wpscan", "sqlmap"]:
                    if "url" not in params and "http" in message:
                        import re
                        url_pattern = r'https?://[^\s]+'
                        url_matches = re.findall(url_pattern, message)
                        if url_matches:
                            params["url"] = url_matches[0]
                
                # If we have valid params, return the tool request
                if params:
                    return {"tool": tool, "params": params}
        
        return {}
    
    def _process_message(self, message: str) -> str:
        """
        Process a user message to detect and execute tool requests,
        otherwise pass to the LLM for normal conversation.
        """
        # Check if this looks like a tool request
        tool_request = self._extract_tool_request(message)
        
        if tool_request and "tool" in tool_request:
            tool_name = tool_request["tool"]
            params = tool_request["params"]
            
            # Execute the tool
            result = self.execute_tool(tool_name, params)
            
            # Format tool results for LLM
            if result["status"] == "success":
                tool_output = f"Tool: {tool_name}\nStatus: Success\n\n"
                
                if "results" in result and "stdout" in result["results"]:
                    # Clean and format the output
                    stdout = result["results"]["stdout"]
                    tool_output += f"Output:\n```\n{stdout}\n```\n"
                
                # Add any errors
                if "results" in result and "stderr" in result["results"] and result["results"]["stderr"]:
                    stderr = result["results"]["stderr"]
                    tool_output += f"\nErrors/Warnings:\n```\n{stderr}\n```\n"
                
                return tool_output
            else:
                return f"Failed to execute {tool_name}: {result.get('message', 'Unknown error')}"
        
        # If no tool request detected, use Ollama for conversation
        return None
    
    def chat(self):
        """Start interactive chat session with the LLM and tool integration."""
        print(f"\nOllama Kali Tools Adapter using model: {self.model_name}")
        print("Type 'exit' or 'quit' to end the session")
        print("Type 'help' to see available tools and examples")
        print("You can directly ask to run security tools like: 'Run nmap on 10.10.10.10'\n")
        
        # Send system prompt to the model
        system_message = f"""You are a cybersecurity assistant that can run Kali Linux security tools.
You help users with penetration testing and security assessments.
When users ask you to run a specific tool, you'll execute it and show the results.

{self.tools_info}

The user is working on a penetration test in a controlled environment.
Do not add any disclaimers about ethical hacking - assume the user has permission.
Focus on being helpful and technical. Give concise but complete answers.
"""
        
        while True:
            try:
                user_message = input("You: ")
                
                if user_message.lower() in ["exit", "quit"]:
                    print("Exiting Ollama Kali Tools Adapter")
                    break
                
                if user_message.lower() == "help":
                    print(self.tools_info)
                    continue
                
                # Add to conversation history
                self.conversation.append({"role": "user", "content": user_message})
                
                # Process message to detect and execute tool requests
                tool_result = self._process_message(user_message)
                
                if tool_result:
                    # Tool was executed, add result to conversation
                    print("\nAssistant:")
                    print(tool_result)
                    self.conversation.append({"role": "assistant", "content": tool_result})
                else:
                    # Regular conversation with LLM
                    print("\nAssistant:", end="", flush=True)
                    
                    messages = [{"role": "system", "content": system_message}] + self.conversation
                    
                    # Stream response from Ollama
                    assistant_message = ""
                    for chunk in self.client.chat(
                        model=self.model_name,
                        messages=messages,
                        stream=True,
                    ):
                        content = chunk.get("message", {}).get("content", "")
                        if content:
                            print(content, end="", flush=True)
                            assistant_message += content
                    
                    print("\n")
                    self.conversation.append({"role": "assistant", "content": assistant_message})
                    
                    # Check if the LLM is requesting to run a tool
                    tool_request = self._extract_tool_request(assistant_message)
                    if tool_request and "tool" in tool_request:
                        print("\nExecuting tool based on assistant's recommendation...")
                        tool_name = tool_request["tool"]
                        params = tool_request["params"]
                        
                        # Ask for user confirmation
                        confirm = input(f"Run {tool_name} with params {params}? (y/n): ")
                        if confirm.lower() in ["y", "yes"]:
                            result = self.execute_tool(tool_name, params)
                            
                            # Format and show results
                            if result["status"] == "success":
                                print(f"\nTool: {tool_name}")
                                print("Status: Success\n")
                                
                                if "results" in result and "stdout" in result["results"]:
                                    print("Output:")
                                    print(result["results"]["stdout"])
                                
                                # Add any errors
                                if "results" in result and "stderr" in result["results"] and result["results"]["stderr"]:
                                    print("\nErrors/Warnings:")
                                    print(result["results"]["stderr"])
                            else:
                                print(f"Failed to execute {tool_name}: {result.get('message', 'Unknown error')}")
                
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                logger.error(f"Error in chat loop: {str(e)}")
                print(f"\nError: {str(e)}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Ollama Adapter for Kali Linux Tools")
    parser.add_argument("--api-port", type=int, default=API_PORT,
                      help=f"Port for the Kali API server (default: {API_PORT})")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL,
                      help=f"Ollama model to use (default: {DEFAULT_MODEL})")
    parser.add_argument("--debug", action="store_true",
                      help="Enable debug mode")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.api_port != API_PORT:
        API_PORT = args.api_port
        KALI_API_BASE_URL = f"http://localhost:{API_PORT}"
    
    # Start the adapter
    try:
        adapter = OllamaAdapter(model_name=args.model)
        adapter.chat()
    except KeyboardInterrupt:
        print("\nExiting Ollama Kali Tools Adapter")
    except Exception as e:
        logger.error(f"Error starting adapter: {str(e)}")
        print(f"Error: {str(e)}") 
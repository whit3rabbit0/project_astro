# MCP Server for Breaking Shyet

A Model Context Protocol (MCP) server that connects Claude for Desktop with Kali Linux security tools, enabling AI-assisted penetration testing for HackTheBox machines.

## Architecture

This project consists of two main components:

1. **MCP Server** (`mcp_server.py`): Implements the Model Context Protocol to connect Claude for Desktop with the Kali Linux tools API. It provides capabilities, prompts, and context to help Claude understand how to use the Kali tools effectively.

2. **Kali Linux API Server** (`kali_api_server.py`): A Flask application that provides API endpoints for executing various Kali Linux security tools. It handles the actual execution of commands and returns the results to the MCP server.

```
Claude for Desktop ←→ MCP Server ←→ Kali Linux API Server ←→ Kali Linux Tools
```

## Features

- Integration with 10+ popular Kali Linux security tools
- Support for HackTheBox machines ranging from Easy to Insane difficulty
- Pre-defined pentesting prompts for common tasks
- Contextual information about HackTheBox environments
- Secure execution of commands in a controlled environment
- Comprehensive debugging tools for troubleshooting

## Prerequisites

- Kali Linux (or other Linux distribution with security tools installed)
- Python 3.8+
- Claude for Desktop
- The following Python packages (installed automatically in a virtual environment):
  - Flask
  - Requests
  - psutil (for system diagnostics)

## Installation

### Option 1: Using the setup script (Recommended)

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/kali-mcp-server.git
   cd kali-mcp-server
   ```

2. Run the setup script:
   ```
   ./setup.sh
   ```

### Option 2: Manual setup

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/kali-mcp-server.git
   cd kali-mcp-server
   ```

2. Create a virtual environment:
   ```
   python3 -m venv venv
   ```

3. Activate the virtual environment:
   ```
   source venv/bin/activate
   ```

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Make the scripts executable:
   ```
   chmod +x mcp_server.py kali_api_server.py run.py
   ```

### Ensure required Kali Linux tools are installed

Make sure the relevant Kali Linux tools are installed on your system:
```
sudo apt update
sudo apt install nmap gobuster dirb nikto sqlmap metasploit-framework hydra john wpscan enum4linux
```

## Usage

### Using the run.py script (Recommended)

The easiest way to start both servers is using the run.py script:

```
./run.py
```

This will start both the API server and MCP server in separate terminals.

Additional options:
- `--api-port PORT`: Specify the API server port (default: 5000)
- `--mcp-port PORT`: Specify the MCP server port (default: 8080)
- `--background`: Run both servers in the background
- `--setup`: Set up or update the virtual environment
- `--debug`: Enable debug mode with detailed logging and diagnostic endpoints

### Starting servers manually

If you prefer to start the servers manually:

1. Start the Kali Linux API Server:
   ```
   source venv/bin/activate
   python kali_api_server.py
   ```

2. In a new terminal, start the MCP Server:
   ```
   source venv/bin/activate
   python mcp_server.py
   ```

### Connect Claude for Desktop

1. Open Claude for Desktop
2. Configure it to use the MCP server at `http://localhost:8080`
3. Start a new conversation and begin your penetration testing

### Configuring Claude for Desktop (Linux)

If you're using the unofficial Claude Desktop for Linux build:

1. Edit the MCP configuration file:
   ```
   nano ~/.config/Claude/claude_desktop_config.json
   ```

2. Add your MCP server:
   ```json
   {
     "mcp_servers": [
       {
         "name": "Kali Linux Tools",
         "url": "http://localhost:8080",
         "enabled": true
       }
     ]
   }
   ```

3. Save the file and restart Claude Desktop

## Supported Tools

1. **nmap**: Network scanning and host discovery
   ```json
   {
     "target": "10.10.10.10",
     "scan_type": "-sV",
     "ports": "80,443,22",
     "additional_args": "-T4 --open"
   }
   ```

2. **gobuster**: Directory and file brute forcing
   ```json
   {
     "url": "http://10.10.10.10",
     "mode": "dir",
     "wordlist": "/usr/share/wordlists/dirb/common.txt",
     "additional_args": "-x php,txt,html"
   }
   ```

3. **dirb**: Web content scanner
   ```json
   {
     "url": "http://10.10.10.10",
     "wordlist": "/usr/share/wordlists/dirb/common.txt",
     "additional_args": "-r -z 10"
   }
   ```

4. **nikto**: Web server scanner
   ```json
   {
     "target": "http://10.10.10.10",
     "additional_args": "-Tuning 123bx"
   }
   ```

5. **sqlmap**: SQL injection testing
   ```json
   {
     "url": "http://10.10.10.10/page.php?id=1",
     "data": "username=test&password=test",
     "additional_args": "--batch --dbs"
   }
   ```

6. **metasploit**: Exploitation framework
   ```json
   {
     "module": "exploit/multi/http/apache_struts2_content_type_rce",
     "options": {
       "RHOSTS": "10.10.10.10",
       "RPORT": "8080",
       "TARGETURI": "/struts2-showcase/"
     }
   }
   ```

7. **hydra**: Password brute forcing
   ```json
   {
     "target": "10.10.10.10",
     "service": "ssh",
     "username": "admin",
     "password_file": "/usr/share/wordlists/rockyou.txt",
     "additional_args": "-e nsr"
   }
   ```

8. **john**: Password cracking
   ```json
   {
     "hash_file": "/path/to/hashes.txt",
     "wordlist": "/usr/share/wordlists/rockyou.txt",
     "format": "md5crypt",
     "additional_args": "--rules=Jumbo"
   }
   ```

9. **wpscan**: WordPress vulnerability scanner
   ```json
   {
     "url": "http://10.10.10.10",
     "additional_args": "--enumerate u,p,t"
   }
   ```

10. **enum4linux**: Windows/Samba enumeration
    ```json
    {
      "target": "10.10.10.10",
      "additional_args": "-a"
    }
    ```

## Example Workflow for HTB Penetration Testing

1. Start with initial reconnaissance
   - Use Claude to help formulate a plan for approaching the HTB machine
   - Select the "initial_recon" prompt from the MCP server

2. Discover and enumerate services
   - Use nmap to scan for open ports and services
   - Use Claude to help interpret the results

3. Explore identified services
   - For web servers, use gobuster, dirb, nikto, and wpscan
   - For database servers, use sqlmap
   - For Windows/Samba servers, use enum4linux

4. Exploit vulnerabilities
   - Based on Claude's recommendations, use appropriate tools to exploit discovered vulnerabilities
   - Use metasploit when applicable

5. Post-exploitation
   - Privilege escalation
   - Data exfiltration
   - Establish persistence (for training purposes only)

## Troubleshooting

### Debugging Features

If you're experiencing issues, run the servers in debug mode:
```
./run.py --debug
```

This enables:

1. **Detailed Logging**: All operations are logged to `debug.log`
2. **Debug Endpoints**:
   - `http://localhost:8080/debug/status` - MCP server status
   - `http://localhost:5000/debug/status` - API server status
   - `http://localhost:8080/debug/config` - MCP server configuration
   - `http://localhost:5000/debug/tool-test` - Test if tools are working
   - `http://localhost:8080/debug/test-api` - Test MCP-API connection
   - `http://localhost:8080/debug/history` - Request history (last 100 requests)

3. **Health Checks**:
   - `http://localhost:8080/health` - MCP server health check that includes API server status
   - `http://localhost:5000/health` - API server health check that includes tool availability

4. **Command Debugging** (use with caution):
   - `http://localhost:5000/debug/command` - Safe command execution for troubleshooting

All endpoints can be accessed via your browser or using tools like `curl`.

### Dependency Conflicts

If you're experiencing conflicts with system packages:
- Make sure you're using the virtual environment
- Never install packages with `--break-system-packages`
- If you need to recreate the virtual environment: `rm -rf venv && ./setup.sh`

### Server Issues

- If a tool is not working, ensure it's installed and accessible in your PATH
- Check the logs of both servers for error messages
- Verify that Claude for Desktop is properly configured to use the MCP server

## Security Considerations

- This setup should be used in a controlled environment (like HTB) for legal penetration testing only
- Never use these tools against systems without explicit permission
- The API server executes commands directly on your system - use with caution
- Consider running in a VM or container for additional isolation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 

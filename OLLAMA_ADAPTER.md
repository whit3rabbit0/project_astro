# Ollama Adapter for Kali Linux Tools

This adapter enables using locally deployed LLMs via Ollama with the Kali Linux API Server, providing an alternative to Claude for Desktop with similar capabilities.

## Features

- Interactive chat interface with Ollama LLMs
- Direct integration with Kali Linux security tools
- Automatic tool detection in prompts
- Tool parameter extraction from natural language
- Confirmation before executing tools
- Comprehensive logging

## Prerequisites

- Kali Linux (or other Linux distribution with security tools installed)
- Python 3.8+
- [Ollama](https://ollama.com/download) locally installed
- Kali Linux API Server (included in this project)

## Installation

1. Make sure you have Ollama installed on your system:
   ```
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. Install the required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Make sure the Ollama adapter script is executable:
   ```
   chmod +x ollama_adapter.py
   ```

## Usage

### Running the Adapter

First, start the Kali Linux API Server in a separate terminal:

```
./run.py --api-port 5000 --background
```

Then run the Ollama adapter:

```
./ollama_adapter.py
```

### Command Line Options

- `--api-port PORT`: Specify the API server port (default: 5000)
- `--model MODEL_NAME`: Specify the Ollama model to use (default: llama3)
- `--debug`: Enable debug mode with detailed logging

Example with custom model:
```
./ollama_adapter.py --model dolphin-mistral --debug
```

### Available Models

You can use any model available in Ollama. Pull models with:

```
ollama pull llama3
ollama pull mistral
ollama pull dolphin-mistral
```

See the [Ollama model library](https://ollama.com/library) for more models.

## Interactive Commands

In the chat interface:

- Type `exit` or `quit` to end the session
- Type `help` to see available tools and examples
- Ask to run tools directly, e.g., "Run nmap on 10.10.10.10"

## How It Works

1. The adapter connects to both Ollama (for LLM capabilities) and the Kali API Server (for security tools)
2. User messages are analyzed to detect tool requests
3. If a tool request is detected, it's executed through the API server
4. Otherwise, the message is sent to the Ollama LLM for a response
5. The LLM may also suggest running tools, which requires user confirmation

## Tool Integration

The adapter supports all the same security tools as the MCP server:

1. **nmap**: Network scanning and host discovery
2. **gobuster**: Directory and file brute forcing
3. **dirb**: Web content scanner
4. **nikto**: Web server scanner
5. **sqlmap**: SQL injection testing
6. **metasploit**: Exploitation framework
7. **hydra**: Password brute forcing
8. **john**: Password cracking
9. **wpscan**: WordPress vulnerability scanner
10. **enum4linux**: Windows/Samba enumeration

## Example Workflows

### Basic Reconnaissance

```
You: Run nmap on 10.10.10.10
```

### Web Application Testing

```
You: Can you help me test a web application at http://10.10.10.10?
```

### Asking for Security Advice

```
You: What's the best approach for testing SQL injection on a login page?
```

## Troubleshooting

- **Error connecting to API server**: Make sure the Kali API Server is running
- **Ollama model errors**: Check if the specified model is installed with `ollama list`
- **Tool execution failures**: Verify that Kali tools are installed on your system
- **Check logs**: See ollama_adapter.log for detailed error information

## Security Considerations

- This tool executes commands on your system - use in a controlled environment
- Only use for legal penetration testing with permission
- Consider running in a VM or container for additional isolation

## Extending the Adapter

The adapter has a simple design that can be extended:

- Improve parameter extraction in the `_extract_tool_request` method
- Add more sophisticated tool detection
- Implement additional tools by adding them to the `KALI_TOOLS` dictionary
- Enhance the conversation context handling 
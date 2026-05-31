"""Ollama bridge for Project Astro V2.

Rewrite of V1's regex-based tool detection. Uses Ollama's native function
calling (tool_calls) so the LLM decides which tool to invoke and with which
parameters — no brittle regex parsing.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog
from ollama import Client

logger = structlog.get_logger(__name__)

# Canonical parameter schemas for each tool.
_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "nmap_scan": {
        "description": "Run nmap network scanner. Returns structured host/port/service data.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, hostname, or CIDR range"},
                "scan_type": {"type": "string", "description": "Nmap flags (default: -sV)", "default": "-sV"},
                "ports": {"type": "string", "description": "Ports to scan (e.g. '80,443' or '1-1024')"},
                "additional_args": {"type": "string", "description": "Extra nmap flags"},
            },
            "required": ["target"],
        },
    },
    "gobuster_scan": {
        "description": "Run gobuster directory/file/DNS brute-forcer.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "mode": {"type": "string", "description": "Scan mode: dir, dns, vhost", "default": "dir"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "extensions": {"type": "string", "description": "File extensions to test (e.g. 'php,html')"},
                "additional_args": {"type": "string", "description": "Extra gobuster flags"},
            },
            "required": ["url"],
        },
    },
    "dirb_scan": {
        "description": "Run dirb web content scanner.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "additional_args": {"type": "string", "description": "Extra dirb flags"},
            },
            "required": ["url"],
        },
    },
    "nikto_scan": {
        "description": "Run nikto web server vulnerability scanner.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host"},
                "additional_args": {"type": "string", "description": "Extra nikto flags"},
            },
            "required": ["target"],
        },
    },
    "sqlmap_scan": {
        "description": "Run sqlmap SQL injection tester.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with parameter"},
                "data": {"type": "string", "description": "POST data string"},
                "dbs": {"type": "boolean", "description": "Enumerate databases"},
                "tables": {"type": "boolean", "description": "Enumerate tables"},
                "additional_args": {"type": "string", "description": "Extra sqlmap flags"},
            },
            "required": ["url"],
        },
    },
    "metasploit_run": {
        "description": "Run a Metasploit module.",
        "parameters": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Module path (e.g. exploit/multi/handler)"},
                "options": {
                    "type": "object",
                    "description": "Module options (e.g. {RHOSTS: '10.0.0.1', LHOST: '10.0.0.2'})",
                    "additionalProperties": {"type": "string"},
                },
                "additional_args": {"type": "string", "description": "Extra msfconsole flags"},
            },
            "required": ["module"],
        },
    },
    "hydra_attack": {
        "description": "Run hydra password brute-forcer.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "service": {"type": "string", "description": "Service to attack (e.g. ssh, ftp)"},
                "username": {"type": "string", "description": "Single username to test"},
                "username_file": {"type": "string", "description": "Path to username list"},
                "password_file": {"type": "string", "description": "Path to password list"},
                "additional_args": {"type": "string", "description": "Extra hydra flags"},
            },
            "required": ["target", "service"],
        },
    },
    "john_crack": {
        "description": "Run John the Ripper password cracker.",
        "parameters": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string", "description": "Path to hash file"},
                "wordlist": {"type": "string", "description": "Path to wordlist file"},
                "format": {"type": "string", "description": "Hash format (e.g. md5crypt, ntlm)"},
                "additional_args": {"type": "string", "description": "Extra john flags"},
            },
            "required": ["hash_file"],
        },
    },
    "wpscan_scan": {
        "description": "Run WPScan WordPress vulnerability scanner.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target WordPress site URL"},
                "enumerate": {"type": "string", "description": "Enumeration flags (default: u,p,t)"},
                "additional_args": {"type": "string", "description": "Extra wpscan flags"},
            },
            "required": ["url"],
        },
    },
    "enum4linux_scan": {
        "description": "Run enum4linux Windows/Samba enumeration tool.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "additional_args": {"type": "string", "description": "Extra enum4linux flags (default: -a)"},
            },
            "required": ["target"],
        },
    },
}

# Map from MCP tool function name to tool registry key.
_TOOL_REGISTRY_KEY: dict[str, str] = {
    "nmap_scan": "nmap",
    "gobuster_scan": "gobuster",
    "dirb_scan": "dirb",
    "nikto_scan": "nikto",
    "sqlmap_scan": "sqlmap",
    "metasploit_run": "metasploit",
    "hydra_attack": "hydra",
    "john_crack": "john",
    "wpscan_scan": "wpscan",
    "enum4linux_scan": "enum4linux",
}

_SYSTEM_PROMPT = """\
You are a cybersecurity assistant with access to Kali Linux security tools.
You help users with penetration testing and security assessments in controlled
environments. When asked to scan or test a target, use the available tools
directly. Do not add disclaimers about ethical hacking — assume the user
operates within an authorised engagement.
"""


class OllamaBridge:
    """Interactive Ollama chat with native function calling.

    Uses Ollama's tool_calls API so the model decides which security tool to
    invoke. No regex parsing required.
    """

    def __init__(
        self,
        model: str = "llama3",
        executor: Any = None,
        registry: Any = None,
        scope: Any = None,
        engagement: Any = None,
        engagement_id: str | None = None,
    ) -> None:
        self.client = Client()
        self.model = model
        self.executor = executor
        self.registry = registry
        self.scope = scope
        self.engagement = engagement
        self.engagement_id = engagement_id
        self.conversation: list[dict[str, Any]] = []
        self.tools = self._build_tool_definitions()

    # ------------------------------------------------------------------
    # Tool definition building
    # ------------------------------------------------------------------

    def _build_tool_definitions(self) -> list[dict[str, Any]]:
        """Return Ollama-format tool definitions for all 10 security tools."""
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": schema["description"],
                    "parameters": schema["parameters"],
                },
            }
            for name, schema in _TOOL_SCHEMAS.items()
        ]

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _handle_tool_call(self, tool_call: Any) -> dict[str, Any]:
        """Dispatch a tool_call from the LLM to the tool registry."""
        fn_name: str = tool_call.function.name
        params: dict[str, Any] = dict(tool_call.function.arguments or {})

        registry_key = _TOOL_REGISTRY_KEY.get(fn_name)
        if registry_key is None:
            logger.warning("unknown tool called by LLM", tool=fn_name)
            return {"error": f"Unknown tool: {fn_name}"}

        # Scope enforcement
        if self.scope:
            target = params.get("target") or params.get("url") or ""
            if target:
                self.scope.validate_target(target)

        logger.info("executing tool", tool=registry_key, params=params)
        tool = self.registry.get(registry_key)
        result = await tool.execute(self.executor, params)

        if self.engagement and self.engagement_id:
            await self.engagement.record_finding(
                self.engagement_id,
                registry_key,
                params.get("target") or params.get("url") or "",
                params,
                result.raw,
                result.parsed,
            )

        return result.model_dump()

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _print_tools(self) -> None:
        print("\nAvailable tools:")
        for name, schema in _TOOL_SCHEMAS.items():
            print(f"  {name} — {schema['description']}")
        print()

    # ------------------------------------------------------------------
    # Chat loop
    # ------------------------------------------------------------------

    async def chat(self) -> None:
        """Interactive chat loop with native function calling."""
        print(f"\nProject Astro — Ollama Bridge (model: {self.model})")
        print("Type 'exit' to quit, 'help' for available tools\n")

        while True:
            try:
                user_input = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting.")
                break

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                break
            if user_input.lower() == "help":
                self._print_tools()
                continue

            self.conversation.append({"role": "user", "content": user_input})

            response = self.client.chat(
                model=self.model,
                messages=[{"role": "system", "content": _SYSTEM_PROMPT}] + self.conversation,
                tools=self.tools,
            )

            msg = response.message

            if msg.tool_calls:
                for call in msg.tool_calls:
                    print(f"\n[Executing {call.function.name}...]")
                    result = await self._handle_tool_call(call)
                    self.conversation.append(
                        {"role": "assistant", "content": "", "tool_calls": [call]}
                    )
                    self.conversation.append(
                        {"role": "tool", "content": json.dumps(result, default=str)}
                    )

                # Ask the model to interpret the results.
                followup = self.client.chat(
                    model=self.model,
                    messages=[{"role": "system", "content": _SYSTEM_PROMPT}] + self.conversation,
                )
                print(f"\nAssistant: {followup.message.content}\n")
                self.conversation.append(
                    {"role": "assistant", "content": followup.message.content}
                )
            else:
                print(f"\nAssistant: {msg.content}\n")
                self.conversation.append({"role": "assistant", "content": msg.content})

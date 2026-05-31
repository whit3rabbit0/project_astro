"""OpenAI-compatible bridge for Project Astro V2.

Thin adapter that translates OpenAI function-calling format to internal tool
execution. Supports GPT-4, Mistral API, local vLLM instances, and any other
OpenAI-compatible endpoint.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageToolCall

logger = structlog.get_logger(__name__)

# Same registry key mapping as the Ollama bridge.
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

# OpenAI function definitions — kept in sync with Ollama bridge schemas.
_FUNCTION_DEFS: list[dict[str, Any]] = [
    {
        "name": "nmap_scan",
        "description": "Run nmap network scanner. Returns structured host/port/service data.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, hostname, or CIDR range"},
                "scan_type": {"type": "string", "description": "Nmap flags (default: -sV)"},
                "ports": {"type": "string", "description": "Ports to scan (e.g. '80,443')"},
                "additional_args": {"type": "string", "description": "Extra nmap flags"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "gobuster_scan",
        "description": "Run gobuster directory/file/DNS brute-forcer.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "mode": {"type": "string", "description": "Scan mode: dir, dns, vhost"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "extensions": {"type": "string", "description": "File extensions (e.g. php,html)"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "dirb_scan",
        "description": "Run dirb web content scanner.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "nikto_scan",
        "description": "Run nikto web server vulnerability scanner.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or host"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "sqlmap_scan",
        "description": "Run sqlmap SQL injection tester.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target URL with parameter"},
                "data": {"type": "string", "description": "POST data string"},
                "dbs": {"type": "boolean", "description": "Enumerate databases"},
                "tables": {"type": "boolean", "description": "Enumerate tables"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "metasploit_run",
        "description": "Run a Metasploit module.",
        "parameters": {
            "type": "object",
            "properties": {
                "module": {"type": "string", "description": "Module path"},
                "options": {
                    "type": "object",
                    "description": "Module options",
                    "additionalProperties": {"type": "string"},
                },
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["module"],
        },
    },
    {
        "name": "hydra_attack",
        "description": "Run hydra password brute-forcer.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "service": {"type": "string", "description": "Service to attack (e.g. ssh)"},
                "username": {"type": "string", "description": "Single username"},
                "username_file": {"type": "string", "description": "Path to username list"},
                "password_file": {"type": "string", "description": "Path to password list"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["target", "service"],
        },
    },
    {
        "name": "john_crack",
        "description": "Run John the Ripper password cracker.",
        "parameters": {
            "type": "object",
            "properties": {
                "hash_file": {"type": "string", "description": "Path to hash file"},
                "wordlist": {"type": "string", "description": "Path to wordlist"},
                "format": {"type": "string", "description": "Hash format (e.g. md5crypt)"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["hash_file"],
        },
    },
    {
        "name": "wpscan_scan",
        "description": "Run WPScan WordPress vulnerability scanner.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target WordPress URL"},
                "enumerate": {"type": "string", "description": "Enumeration flags (default: u,p,t)"},
                "additional_args": {"type": "string", "description": "Extra flags"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "enum4linux_scan",
        "description": "Run enum4linux Windows/Samba enumeration tool.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target IP or hostname"},
                "additional_args": {"type": "string", "description": "Extra flags (default: -a)"},
            },
            "required": ["target"],
        },
    },
]

_SYSTEM_PROMPT = """\
You are a cybersecurity assistant with access to Kali Linux security tools.
Help users with penetration testing and security assessments in controlled
environments. Use the available tools when asked to scan or test a target.
Do not add disclaimers about ethical hacking — assume an authorised engagement.
"""


class OpenAIBridge:
    """Thin adapter for OpenAI-compatible APIs.

    Supports GPT-4, Mistral API, local vLLM / LM Studio, and any other
    endpoint that accepts the OpenAI chat completions format.
    """

    def __init__(
        self,
        model: str = "gpt-4",
        base_url: str | None = None,
        api_key: str | None = None,
        executor: Any = None,
        registry: Any = None,
        scope: Any = None,
        engagement: Any = None,
        engagement_id: str | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("OPENAI_API_KEY") or "no-key"
        self.client = AsyncOpenAI(base_url=base_url, api_key=resolved_key)
        self.model = model
        self.executor = executor
        self.registry = registry
        self.scope = scope
        self.engagement = engagement
        self.engagement_id = engagement_id
        self.tools = self._build_tool_definitions()

    # ------------------------------------------------------------------
    # Tool definition building
    # ------------------------------------------------------------------

    def _build_tool_definitions(self) -> list[dict[str, Any]]:
        """Return OpenAI-format tool definitions for all 10 security tools."""
        return [
            {"type": "function", "function": fn_def}
            for fn_def in _FUNCTION_DEFS
        ]

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    async def _handle_tool_call(self, tool_call: ChatCompletionMessageToolCall) -> str:
        """Execute an OpenAI tool call and return the result as a JSON string."""
        fn_name = tool_call.function.name
        try:
            params: dict[str, Any] = json.loads(tool_call.function.arguments or "{}")
        except json.JSONDecodeError:
            return json.dumps({"error": "Invalid JSON arguments from model"})

        registry_key = _TOOL_REGISTRY_KEY.get(fn_name)
        if registry_key is None:
            logger.warning("unknown tool called", tool=fn_name)
            return json.dumps({"error": f"Unknown tool: {fn_name}"})

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

        return json.dumps(result.model_dump(), default=str)

    # ------------------------------------------------------------------
    # Chat entry point
    # ------------------------------------------------------------------

    async def chat(
        self,
        message: str,
        conversation: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Send a message and handle tool calls in an agentic loop.

        Args:
            message: The user message to send.
            conversation: Optional prior conversation history (modified in-place
                          and returned so callers can maintain state across calls).

        Returns:
            A dict with keys:
                - ``content``: The assistant's final text response.
                - ``conversation``: The updated conversation history.
                - ``tool_calls_made``: List of tool names that were invoked.
        """
        history: list[dict[str, Any]] = conversation if conversation is not None else []
        history.append({"role": "user", "content": message})
        tool_calls_made: list[str] = []

        messages_with_system = [{"role": "system", "content": _SYSTEM_PROMPT}] + history

        # Agentic loop: keep calling until the model stops requesting tools.
        while True:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages_with_system,
                tools=self.tools,
                tool_choice="auto",
            )

            choice = response.choices[0]
            msg = choice.message

            if not msg.tool_calls:
                # No more tool calls — we have the final response.
                content = msg.content or ""
                history.append({"role": "assistant", "content": content})
                return {
                    "content": content,
                    "conversation": history,
                    "tool_calls_made": tool_calls_made,
                }

            # Append the assistant message with tool_calls to history.
            history.append(msg.model_dump(exclude_unset=True))
            messages_with_system.append(msg.model_dump(exclude_unset=True))

            for call in msg.tool_calls:
                tool_calls_made.append(call.function.name)
                logger.info("tool call requested", tool=call.function.name)
                result_str = await self._handle_tool_call(call)
                tool_msg = {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "content": result_str,
                }
                history.append(tool_msg)
                messages_with_system.append(tool_msg)

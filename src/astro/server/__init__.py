"""Server layer for Project Astro V2.

Public exports:
    AstroConfig      — server configuration model
    load_config      — load config from environment
    mcp              — FastMCP application instance
    initialize_server — wire up server components at startup
    OllamaBridge     — Ollama native function-calling bridge
    OpenAIBridge     — OpenAI-compatible API bridge
"""

from astro.server.config import AstroConfig, load_config

__all__ = [
    "AstroConfig",
    "load_config",
]

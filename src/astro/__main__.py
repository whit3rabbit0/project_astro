"""Project Astro V2 — CLI entry point.

Usage:
    astro serve [options]    Start the MCP server
    astro ollama [options]   Interactive Ollama chat with tool integration
    astro tui [options]      Launch the interactive Terminal UI
    astro version            Print version
"""

from __future__ import annotations

import asyncio

import click


@click.group()
def cli() -> None:
    """Project Astro — Intelligence layer for LLM-driven penetration testing."""


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Server bind address")
@click.option("--port", default=8080, type=int, show_default=True, help="Server listen port")
@click.option(
    "--transport",
    default="streamable-http",
    show_default=True,
    type=click.Choice(["streamable-http", "stdio"]),
    help="MCP transport mode",
)
@click.option("--scope", "scope_config", default=None, help="Path to scope config YAML")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def serve(host: str, port: int, transport: str, scope_config: str | None, debug: bool) -> None:
    """Start the MCP server."""
    import os
    os.environ["ASTRO_HOST"] = host
    os.environ["ASTRO_PORT"] = str(port)

    from astro.observability.logging import setup_logging
    from astro.server.config import load_config

    setup_logging(debug=debug)

    config = load_config()
    config.host = host
    config.port = port
    config.transport = transport
    if scope_config:
        config.scope_config_path = scope_config
    config.debug = debug

    from astro.server.mcp_server import initialize_server, mcp
    asyncio.run(initialize_server(config))

    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport="streamable-http")


@cli.command()
@click.option("--model", default="llama3", show_default=True, help="Ollama model name")
@click.option("--scope", "scope_config", default=None, help="Path to scope config YAML")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def ollama(model: str, scope_config: str | None, debug: bool) -> None:
    """Start interactive Ollama chat with tool integration."""
    from astro.core import ScopeEnforcer, ToolExecutor
    from astro.observability.logging import setup_logging
    from astro.server.ollama_bridge import OllamaBridge
    from astro.tools import create_default_registry

    setup_logging(debug=debug)

    executor = ToolExecutor()
    registry = create_default_registry()
    scope = ScopeEnforcer(scope_config) if scope_config else None

    bridge = OllamaBridge(
        model=model,
        executor=executor,
        registry=registry,
        scope=scope,
    )
    asyncio.run(bridge.chat())


@cli.command()
@click.option("--target", default="", help="Initial target IP/URL")
@click.option("--scope", "scope_config", default=None, help="Path to scope config YAML")
@click.option("--engagement", "engagement_name", default=None, help="Auto-create engagement with this name")
@click.option("--debug", is_flag=True, help="Enable debug logging")
def tui(target: str, scope_config: str | None, engagement_name: str | None, debug: bool) -> None:
    """Launch the interactive Terminal UI."""
    from astro.core import EngagementManager, ScopeEnforcer, ToolExecutor
    from astro.intel.methodology import MethodologyTracker
    from astro.tools import create_default_registry
    from astro.tui.app import AstroApp

    try:
        from astro.observability.logging import setup_logging
        setup_logging(debug=debug)
    except ImportError:
        pass

    executor = ToolExecutor()
    registry = create_default_registry()
    scope = ScopeEnforcer(scope_config) if scope_config else None
    methodology = MethodologyTracker()
    engagement = EngagementManager()

    async def _run() -> None:
        await engagement.initialize()
        app = AstroApp(
            executor=executor,
            registry=registry,
            scope=scope,
            engagement=engagement,
            methodology=methodology,
        )
        if target:
            app.current_target = target
        if engagement_name:
            app.current_engagement_id = await engagement.create_engagement(engagement_name)
            app.sub_title = f"v2.0.0  |  engagement: {engagement_name}"
        await app.run_async()

    asyncio.run(_run())


@cli.command()
def version() -> None:
    """Show version information."""
    from astro import __version__

    click.echo(f"Project Astro v{__version__}")


def main() -> None:
    """Package entry point (registered as 'astro' in pyproject.toml)."""
    cli()


if __name__ == "__main__":
    main()

"""Server configuration for Project Astro V2."""

from __future__ import annotations

import os

from pydantic import BaseModel, Field


class AstroConfig(BaseModel):
    """Top-level server configuration.

    All fields can be overridden via environment variables.
    """

    host: str = Field(default="127.0.0.1", description="Server bind address")
    port: int = Field(default=8080, ge=1, le=65535, description="Server listen port")
    transport: str = Field(
        default="streamable-http",
        description="MCP transport: 'streamable-http' or 'stdio'",
    )
    scope_config_path: str | None = Field(
        default=None, description="Path to scope enforcement YAML config"
    )
    debug: bool = Field(default=False, description="Enable verbose debug logging")
    db_path: str = Field(
        default="~/.astro/engagements.db",
        description="Path to SQLite engagement database",
    )
    api_key: str | None = Field(
        default=None,
        description="API key for server authentication (optional)",
    )

    # -- OIDC / OAuth2 -------------------------------------------------------
    oidc_issuer_url: str | None = Field(
        default=None,
        description="OIDC issuer URL (e.g. https://accounts.google.com)",
    )
    oidc_client_id: str | None = Field(
        default=None,
        description="OAuth2 client ID registered with the OIDC provider",
    )
    oidc_audience: str | None = Field(
        default=None,
        description="Expected 'aud' claim in JWTs",
    )
    oidc_required_roles: list[str] = Field(
        default_factory=list,
        description="Roles the user must possess (comma-separated via env var)",
    )


def load_config() -> AstroConfig:
    """Load configuration from environment variables and defaults.

    Environment variables:
        ASTRO_HOST           — bind address (default: 127.0.0.1)
        ASTRO_PORT           — listen port (default: 8080)
        ASTRO_TRANSPORT      — 'streamable-http' or 'stdio' (default: streamable-http)
        ASTRO_SCOPE_CONFIG   — path to scope YAML (default: unset)
        ASTRO_DEBUG          — '1'/'true'/'yes' to enable debug (default: false)
        ASTRO_DB_PATH        — SQLite DB path (default: ~/.astro/engagements.db)
        API_KEY              — server API key (default: unset)
        ASTRO_OIDC_ISSUER    — OIDC issuer URL (default: unset)
        ASTRO_OIDC_CLIENT_ID — OAuth2 client ID (default: unset)
        ASTRO_OIDC_AUDIENCE  — expected JWT audience (default: unset)
        ASTRO_OIDC_ROLES     — comma-separated required roles (default: unset)
    """
    debug_raw = os.environ.get("ASTRO_DEBUG", "0").lower()
    debug = debug_raw in ("1", "true", "yes", "y")

    # Parse comma-separated roles, stripping whitespace and empty entries
    roles_raw = os.environ.get("ASTRO_OIDC_ROLES", "")
    oidc_roles = [r.strip() for r in roles_raw.split(",") if r.strip()]

    return AstroConfig(
        host=os.environ.get("ASTRO_HOST", "127.0.0.1"),
        port=int(os.environ.get("ASTRO_PORT", "8080")),
        transport=os.environ.get("ASTRO_TRANSPORT", "streamable-http"),
        scope_config_path=os.environ.get("ASTRO_SCOPE_CONFIG") or None,
        debug=debug,
        db_path=os.environ.get("ASTRO_DB_PATH", "~/.astro/engagements.db"),
        api_key=os.environ.get("API_KEY") or None,
        oidc_issuer_url=os.environ.get("ASTRO_OIDC_ISSUER") or None,
        oidc_client_id=os.environ.get("ASTRO_OIDC_CLIENT_ID") or None,
        oidc_audience=os.environ.get("ASTRO_OIDC_AUDIENCE") or None,
        oidc_required_roles=oidc_roles,
    )

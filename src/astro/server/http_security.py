"""Security boundary for Astro's streamable-HTTP transport.

The MCP SDK exposes an ASGI application, but Project Astro owns its API-key and
OIDC policy. This module keeps that policy outside individual MCP tools so the
same authentication decision protects tools, resources, prompts, and any batch
endpoints registered on the server.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Any, Awaitable, Callable, Protocol

ASGIReceive = Callable[[], Awaitable[dict[str, Any]]]
ASGISend = Callable[[dict[str, Any]], Awaitable[None]]
ASGIApp = Callable[[dict[str, Any], ASGIReceive, ASGISend], Awaitable[None]]


class AuthResultLike(Protocol):
    authenticated: bool


class AuthManagerLike(Protocol):
    @property
    def auth_mode(self) -> str:
        ...

    async def authenticate(
        self,
        api_key: str | None = None,
        bearer_token: str | None = None,
    ) -> AuthResultLike:
        ...


def is_loopback_host(host: str) -> bool:
    """Return whether a bind host is unambiguously loopback-only."""
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_http_startup(config: Any) -> None:
    """Refuse unauthenticated HTTP on a non-loopback bind address.

    Stdio does not expose a network listener and remains usable without auth.
    Loopback HTTP is allowed for local development. Any other HTTP bind must
    configure at least one real authentication method.
    """
    if getattr(config, "transport", "streamable-http") == "stdio":
        return
    if is_loopback_host(getattr(config, "host", "127.0.0.1")):
        return
    if getattr(config, "api_key", None) or getattr(config, "oidc_issuer_url", None):
        return
    raise RuntimeError(
        "Refusing to start unauthenticated MCP HTTP on a non-loopback address. "
        "Set API_KEY or ASTRO_OIDC_ISSUER, bind to 127.0.0.1/::1, or use stdio."
    )


def _decode_headers(scope: dict[str, Any]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", []):
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        headers[name] = value
    return headers


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


async def _send_json(send: ASGISend, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if status == 401:
        headers.append((b"www-authenticate", b'Bearer realm="astro"'))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


class AuthenticatedMCPApp:
    """ASGI wrapper that authenticates every MCP HTTP request.

    The health endpoint is intentionally public and reveals only readiness.
    Lifespan and non-HTTP scopes pass through unchanged to preserve the MCP
    SDK's session-manager lifecycle.
    """

    def __init__(
        self,
        app: ASGIApp,
        auth: AuthManagerLike,
        health_path: str = "/health",
    ) -> None:
        self._app = app
        self._auth = auth
        self._health_path = health_path

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: ASGIReceive,
        send: ASGISend,
    ) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        if scope.get("path") == self._health_path:
            await _send_json(send, 200, {"status": "ok"})
            return

        if self._auth.auth_mode == "none":
            await self._app(scope, receive, send)
            return

        headers = _decode_headers(scope)
        try:
            result = await self._auth.authenticate(
                api_key=headers.get("x-api-key"),
                bearer_token=_bearer_token(headers.get("authorization")),
            )
        except Exception:
            # Authentication backends must fail closed. Detailed errors stay in
            # server logs rather than leaking provider details to the client.
            await _send_json(send, 401, {"error": "unauthorized"})
            return

        if not result.authenticated:
            await _send_json(send, 401, {"error": "unauthorized"})
            return

        state = scope.setdefault("state", {})
        state["astro_auth"] = result
        await self._app(scope, receive, send)

from __future__ import annotations

import asyncio

from types import SimpleNamespace
from typing import Any

import pytest

from astro.server.http_security import (
    AuthenticatedMCPApp,
    is_loopback_host,
    validate_http_startup,
)


class _Result:
    def __init__(self, authenticated: bool) -> None:
        self.authenticated = authenticated


class _FakeAuth:
    def __init__(self, expected_key: str | None = "secret", mode: str = "api_key") -> None:
        self.expected_key = expected_key
        self.auth_mode = mode
        self.calls: list[tuple[str | None, str | None]] = []

    async def authenticate(
        self,
        api_key: str | None = None,
        bearer_token: str | None = None,
    ) -> _Result:
        self.calls.append((api_key, bearer_token))
        return _Result(api_key == self.expected_key)


class _RaisingAuth(_FakeAuth):
    async def authenticate(
        self,
        api_key: str | None = None,
        bearer_token: str | None = None,
    ) -> _Result:
        raise ValueError("malformed credential")


async def _downstream(scope: dict[str, Any], receive: Any, send: Any) -> None:
    await send({"type": "http.response.start", "status": 204, "headers": []})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


async def _request(
    app: Any,
    *,
    path: str = "/mcp",
    headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    header_pairs = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": header_pairs,
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8080),
    }

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    await app(scope, receive, send)
    return messages


@pytest.mark.parametrize("host", ["127.0.0.1", "127.2.3.4", "::1", "[::1]", "localhost"])
def test_loopback_hosts_are_recognized(host: str) -> None:
    assert is_loopback_host(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.2", "astro.internal"])
def test_non_loopback_hosts_are_rejected(host: str) -> None:
    assert not is_loopback_host(host)


def test_non_loopback_http_requires_authentication() -> None:
    config = SimpleNamespace(
        transport="streamable-http",
        host="0.0.0.0",
        api_key=None,
        oidc_issuer_url=None,
    )
    with pytest.raises(RuntimeError, match="Refusing to start unauthenticated MCP HTTP"):
        validate_http_startup(config)


def test_non_loopback_http_allows_api_key() -> None:
    config = SimpleNamespace(
        transport="streamable-http",
        host="0.0.0.0",
        api_key="secret",
        oidc_issuer_url=None,
    )
    validate_http_startup(config)


def test_stdio_does_not_require_network_authentication() -> None:
    config = SimpleNamespace(
        transport="stdio",
        host="0.0.0.0",
        api_key=None,
        oidc_issuer_url=None,
    )
    validate_http_startup(config)


def test_http_request_without_credentials_is_rejected() -> None:
    app = AuthenticatedMCPApp(_downstream, _FakeAuth())
    messages = asyncio.run(_request(app))
    assert messages[0]["status"] == 401


def test_http_request_with_wrong_credentials_is_rejected() -> None:
    app = AuthenticatedMCPApp(_downstream, _FakeAuth())
    messages = asyncio.run(_request(app, headers={"X-API-Key": "wrong"}))
    assert messages[0]["status"] == 401


def test_http_request_with_valid_api_key_reaches_mcp_app() -> None:
    auth = _FakeAuth()
    app = AuthenticatedMCPApp(_downstream, auth)
    messages = asyncio.run(_request(app, headers={"X-API-Key": "secret"}))
    assert messages[0]["status"] == 204
    assert auth.calls == [("secret", None)]


def test_bearer_token_is_forwarded_to_auth_manager() -> None:
    auth = _FakeAuth(expected_key=None)
    app = AuthenticatedMCPApp(_downstream, auth)
    asyncio.run(_request(app, headers={"Authorization": "Bearer token-value"}))
    assert auth.calls == [(None, "token-value")]


def test_malformed_bearer_token_fails_closed() -> None:
    app = AuthenticatedMCPApp(_downstream, _RaisingAuth())
    messages = asyncio.run(
        _request(app, headers={"Authorization": "Bearer malformed"})
    )
    assert messages[0]["status"] == 401


def test_health_endpoint_is_public_and_minimal() -> None:
    auth = _FakeAuth()
    app = AuthenticatedMCPApp(_downstream, auth)
    messages = asyncio.run(_request(app, path="/health"))
    assert messages[0]["status"] == 200
    assert auth.calls == []


def test_no_auth_mode_passes_through() -> None:
    auth = _FakeAuth(mode="none")
    app = AuthenticatedMCPApp(_downstream, auth)
    messages = asyncio.run(_request(app))
    assert messages[0]["status"] == 204
    assert auth.calls == []

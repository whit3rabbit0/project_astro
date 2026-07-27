# MCP HTTP security

Project Astro treats its streamable-HTTP transport as a remote execution boundary.

## Startup policy

- `stdio` may run without network authentication because it does not create a network listener.
- HTTP bound to `127.0.0.0/8`, `::1`, or `localhost` may run without authentication for local development.
- HTTP bound to any other address refuses to start unless `API_KEY` or `ASTRO_OIDC_ISSUER` is configured.

The Docker Compose configurations bind the published host port to loopback and require `API_KEY`:

```bash
export API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

## Request authentication

Every MCP HTTP request, including tools, resources, prompts, and batch operations, passes through the authentication boundary before reaching FastMCP.

API-key clients must send:

```text
X-API-Key: <configured API_KEY>
```

OIDC clients must send:

```text
Authorization: Bearer <token>
```

Missing, malformed, or invalid credentials receive `401 Unauthorized`. Authentication backend errors fail closed.

`GET /health` is intentionally public and returns only a minimal readiness response. It does not expose tool, scope, engagement, or authentication details.

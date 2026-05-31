"""OIDC/OAuth2 authentication for Project Astro V2.

Supports OpenID Connect discovery, JWT token validation, and role-based
access control for team environments.  Crypto signature verification is
deferred to the optional ``PyJWT`` library -- when it is not installed the
token's base64 payload is decoded and non-crypto claims (issuer, audience,
expiration) are still validated, with a warning logged.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Any

import httpx
import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AuthenticationError(Exception):
    """Raised when authentication fails for any reason."""


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class OIDCConfig(BaseModel):
    """Configuration required to validate tokens against an OIDC provider."""

    issuer_url: str = Field(
        ...,
        description="OIDC issuer URL, e.g. 'https://accounts.google.com'",
    )
    client_id: str = Field(
        ...,
        description="OAuth2 client ID registered with the provider",
    )
    audience: str = Field(
        ...,
        description="Expected 'aud' claim in JWTs",
    )
    required_roles: list[str] = Field(
        default_factory=list,
        description="Roles the user must possess (empty = no role check)",
    )


class UserInfo(BaseModel):
    """Authenticated user identity extracted from a JWT."""

    sub: str = Field(..., description="Subject identifier")
    email: str = Field(default="", description="Email address")
    name: str = Field(default="", description="Display name")
    roles: list[str] = Field(
        default_factory=list,
        description="Roles extracted from token claims",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64_decode_segment(segment: str) -> bytes:
    """Decode a Base64url-encoded JWT segment, adding padding as needed."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def _decode_jwt_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode a JWT without verifying its signature.

    Returns (header, payload) as dicts.  Raises ``AuthenticationError`` if
    the token cannot be parsed.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationError("Malformed JWT: expected 3 dot-separated segments")

    try:
        header = json.loads(_b64_decode_segment(parts[0]))
        payload = json.loads(_b64_decode_segment(parts[1]))
    except (json.JSONDecodeError, Exception) as exc:
        raise AuthenticationError(f"Failed to decode JWT payload: {exc}") from exc

    return header, payload


def extract_bearer_token(authorization: str | None) -> str | None:
    """Extract the Bearer token from an ``Authorization`` header value.

    Returns ``None`` if the header is missing or does not use the Bearer
    scheme.
    """
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1]


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------


class OIDCAuthenticator:
    """Validates JWTs against an OIDC provider.

    Usage::

        authenticator = OIDCAuthenticator(config)
        await authenticator.initialize()      # fetch discovery + JWKS
        user = await authenticator.authenticate(token)
    """

    def __init__(self, config: OIDCConfig) -> None:
        self._config = config
        self._discovery: dict[str, Any] = {}
        self._jwks: dict[str, Any] = {}
        self._initialized = False
        self._http_client: httpx.AsyncClient | None = None

    # -- lifecycle -----------------------------------------------------------

    async def initialize(self) -> None:
        """Fetch the OIDC discovery document and JWKS from the provider."""
        issuer = self._config.issuer_url.rstrip("/")
        discovery_url = f"{issuer}/.well-known/openid-configuration"

        self._http_client = httpx.AsyncClient(timeout=15.0)

        logger.info("oidc_discovery_start", url=discovery_url)
        try:
            resp = await self._http_client.get(discovery_url)
            resp.raise_for_status()
            self._discovery = resp.json()
        except httpx.HTTPError as exc:
            raise AuthenticationError(
                f"Failed to fetch OIDC discovery document from {discovery_url}: {exc}"
            ) from exc

        jwks_uri = self._discovery.get("jwks_uri")
        if not jwks_uri:
            raise AuthenticationError(
                "OIDC discovery document missing 'jwks_uri'"
            )

        logger.info("oidc_jwks_fetch", url=jwks_uri)
        try:
            resp = await self._http_client.get(jwks_uri)
            resp.raise_for_status()
            self._jwks = resp.json()
        except httpx.HTTPError as exc:
            raise AuthenticationError(
                f"Failed to fetch JWKS from {jwks_uri}: {exc}"
            ) from exc

        self._initialized = True
        logger.info(
            "oidc_initialized",
            issuer=issuer,
            jwks_keys=len(self._jwks.get("keys", [])),
        )

    async def close(self) -> None:
        """Release the underlying HTTP client."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    # -- authentication ------------------------------------------------------

    async def authenticate(self, token: str) -> UserInfo:
        """Validate a JWT and return the authenticated user.

        Raises ``AuthenticationError`` on any validation failure.
        """
        if not self._initialized:
            raise AuthenticationError("OIDCAuthenticator has not been initialized")

        header, payload = _decode_jwt_unverified(token)

        self._validate_claims(payload)
        self._verify_signature(token, header)

        user = self._extract_user(payload)
        self._check_roles(user)

        logger.info("oidc_auth_success", sub=user.sub, email=user.email)
        return user

    # -- internal validation -------------------------------------------------

    def _validate_claims(self, payload: dict[str, Any]) -> None:
        """Validate standard JWT claims: iss, aud, exp, iat."""
        # Issuer
        expected_issuer = self._config.issuer_url.rstrip("/")
        token_issuer = (payload.get("iss") or "").rstrip("/")
        if token_issuer != expected_issuer:
            raise AuthenticationError(
                f"Issuer mismatch: expected '{expected_issuer}', got '{token_issuer}'"
            )

        # Audience -- can be a string or a list
        aud = payload.get("aud")
        if isinstance(aud, str):
            aud_list = [aud]
        elif isinstance(aud, list):
            aud_list = aud
        else:
            raise AuthenticationError("Token missing 'aud' claim")

        if self._config.audience not in aud_list:
            raise AuthenticationError(
                f"Audience mismatch: expected '{self._config.audience}' "
                f"in {aud_list}"
            )

        # Expiration
        exp = payload.get("exp")
        if exp is None:
            raise AuthenticationError("Token missing 'exp' claim")
        try:
            exp_ts = float(exp)
        except (TypeError, ValueError) as exc:
            raise AuthenticationError(f"Invalid 'exp' claim: {exc}") from exc

        now = time.time()
        # Allow 30 seconds of clock skew
        if now > exp_ts + 30:
            raise AuthenticationError("Token has expired")

        # Not-before (optional)
        nbf = payload.get("nbf")
        if nbf is not None:
            try:
                nbf_ts = float(nbf)
            except (TypeError, ValueError):
                nbf_ts = 0.0
            if now < nbf_ts - 30:
                raise AuthenticationError("Token is not yet valid (nbf)")

    def _verify_signature(
        self,
        token: str,
        header: dict[str, Any],
    ) -> None:
        """Verify the JWT cryptographic signature.

        If ``PyJWT`` (``jwt``) is installed, full RS256/RS384/RS512/ES256
        verification is performed using the provider's JWKS.  Otherwise a
        warning is logged and signature verification is skipped.
        """
        try:
            import jwt as pyjwt  # type: ignore[import-untyped]
            from jwt import PyJWKClient  # type: ignore[import-untyped]
        except ImportError:
            raise AuthenticationError(
                "PyJWT is not installed -- JWT signature verification "
                "cannot be performed.  Install 'PyJWT[crypto]' to enable "
                "OIDC authentication."
            )

        kid = header.get("kid")
        alg = header.get("alg", "RS256")

        # Build a PyJWKClient from the already-fetched JWKS
        jwks_uri = self._discovery.get("jwks_uri", "")
        try:
            jwk_client = PyJWKClient(jwks_uri)
            signing_key = jwk_client.get_signing_key_from_jwt(token)
            pyjwt.decode(
                token,
                signing_key.key,
                algorithms=[alg],
                audience=self._config.audience,
                issuer=self._config.issuer_url.rstrip("/"),
                options={"verify_exp": True},
            )
            logger.debug("oidc_signature_verified", kid=kid, alg=alg)
        except Exception as exc:
            raise AuthenticationError(
                f"JWT signature verification failed: {exc}"
            ) from exc

    def _extract_user(self, payload: dict[str, Any]) -> UserInfo:
        """Build a ``UserInfo`` from JWT claims."""
        sub = payload.get("sub")
        if not sub:
            raise AuthenticationError("Token missing 'sub' claim")

        # Roles can appear in various claims depending on the IdP
        roles: list[str] = []
        # Keycloak puts roles in realm_access.roles
        realm_access = payload.get("realm_access")
        if isinstance(realm_access, dict):
            roles.extend(realm_access.get("roles", []))
        # Some providers use a top-level "roles" claim
        top_roles = payload.get("roles")
        if isinstance(top_roles, list):
            roles.extend(top_roles)
        # Azure AD uses "groups" or "wids"
        groups = payload.get("groups")
        if isinstance(groups, list):
            roles.extend(groups)

        return UserInfo(
            sub=sub,
            email=payload.get("email", ""),
            name=payload.get("name", ""),
            roles=list(set(roles)),  # deduplicate
        )

    def _check_roles(self, user: UserInfo) -> None:
        """Ensure the user possesses all required roles."""
        required = self._config.required_roles
        if not required:
            return
        missing = set(required) - set(user.roles)
        if missing:
            raise AuthenticationError(
                f"User '{user.sub}' missing required roles: {sorted(missing)}"
            )

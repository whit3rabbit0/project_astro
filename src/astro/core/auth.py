"""Unified authentication for Project Astro V2.

Supports three modes (selected automatically based on configuration):

1. **No auth** -- if neither API key nor OIDC is configured, all requests
   are allowed.  This is the default for local development.
2. **API key** -- simple shared-secret via the ``API_KEY`` env var.
3. **OIDC/OAuth2** -- JWT validation against an OpenID Connect provider.
"""

from __future__ import annotations

import hmac
import os
import time as _time
from collections import deque
from typing import Optional

import structlog
from pydantic import BaseModel, Field

from astro.core.oidc import (
    AuthenticationError,
    OIDCAuthenticator,
    OIDCConfig,
    UserInfo,
    extract_bearer_token,
)

logger = structlog.get_logger(__name__)

# Re-export for convenience
__all__ = [
    "AuthenticationError",
    "AuthManager",
    "AuthResult",
    "UserInfo",
    "extract_bearer_token",
    "get_api_key",
    "verify_api_key",
]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AuthResult(BaseModel):
    """Outcome of an authentication attempt."""

    authenticated: bool = Field(..., description="Whether authentication succeeded")
    method: str = Field(
        ...,
        description="Auth method used: 'api_key', 'oidc', or 'none'",
    )
    user: UserInfo | None = Field(
        default=None,
        description="Authenticated user info (only for OIDC)",
    )


# ---------------------------------------------------------------------------
# Legacy helpers (preserved for backward compatibility)
# ---------------------------------------------------------------------------


def get_api_key() -> Optional[str]:
    return os.environ.get("API_KEY")


def verify_api_key(provided: Optional[str]) -> bool:
    """Return True if provided matches API_KEY env var, or if API_KEY is not set."""
    configured = get_api_key()
    if not configured:
        return True
    if not provided:
        return False
    return hmac.compare_digest(provided, configured)


# ---------------------------------------------------------------------------
# Unified AuthManager
# ---------------------------------------------------------------------------


class AuthManager:
    """Unified authentication -- supports API key, OIDC, or no auth.

    Initialization flow::

        from astro.server.config import AstroConfig, load_config

        config = load_config()
        auth = AuthManager(config)
        await auth.initialize()

        result = await auth.authenticate(
            api_key=request_api_key,
            bearer_token=extract_bearer_token(authorization_header),
        )
        if not result.authenticated:
            raise PermissionError("Not authenticated")
    """

    # Rate limiting constants
    _RATE_LIMIT_MAX_FAILURES = 10
    _RATE_LIMIT_WINDOW_SECONDS = 60

    def __init__(self, config: object) -> None:
        # Accept AstroConfig (or any object with the required attributes) to
        # avoid a circular import with astro.server.config.
        self._api_key: str | None = getattr(config, "api_key", None)

        # Build OIDC config if the issuer URL is present
        issuer = getattr(config, "oidc_issuer_url", None)
        if issuer:
            self._oidc_config: OIDCConfig | None = OIDCConfig(
                issuer_url=issuer,
                client_id=getattr(config, "oidc_client_id", ""),
                audience=getattr(config, "oidc_audience", ""),
                required_roles=getattr(config, "oidc_required_roles", []),
            )
        else:
            self._oidc_config = None

        self._oidc: OIDCAuthenticator | None = None
        self._initialized = False

        # Rate limiting: track timestamps of failed auth attempts
        self._failed_attempts: deque[float] = deque()

    @property
    def auth_mode(self) -> str:
        """Return a human-readable description of the active auth mode."""
        if self._oidc_config and self._api_key:
            return "oidc+api_key"
        if self._oidc_config:
            return "oidc"
        if self._api_key:
            return "api_key"
        return "none"

    # -- lifecycle -----------------------------------------------------------

    async def initialize(self) -> None:
        """Initialize the OIDC authenticator if configured."""
        if self._oidc_config:
            self._oidc = OIDCAuthenticator(self._oidc_config)
            await self._oidc.initialize()
            logger.info("auth_manager_oidc_ready", issuer=self._oidc_config.issuer_url)

        logger.info("auth_manager_initialized", mode=self.auth_mode)
        self._initialized = True

    async def close(self) -> None:
        """Release resources held by the authenticator."""
        if self._oidc:
            await self._oidc.close()

    # -- authentication ------------------------------------------------------

    def _record_failure(self) -> None:
        """Record a failed authentication attempt for rate limiting."""
        self._failed_attempts.append(_time.time())

    def _is_rate_limited(self) -> bool:
        """Check if authentication attempts are currently rate limited."""
        now = _time.time()
        cutoff = now - self._RATE_LIMIT_WINDOW_SECONDS

        # Evict expired entries from the front of the deque
        while self._failed_attempts and self._failed_attempts[0] < cutoff:
            self._failed_attempts.popleft()

        return len(self._failed_attempts) >= self._RATE_LIMIT_MAX_FAILURES

    async def authenticate(
        self,
        api_key: str | None = None,
        bearer_token: str | None = None,
    ) -> AuthResult:
        """Authenticate a request using the best available method.

        Evaluation order:

        1. If a Bearer token is provided **and** OIDC is configured, validate
           the JWT.
        2. If an API key is provided **and** an API key is configured, compare
           them.
        3. If neither auth method is configured, allow the request (no-auth
           mode).
        4. Otherwise, reject.
        """
        # -- Rate limiting ----------------------------------------------------
        if self._is_rate_limited():
            logger.warning("auth_rate_limited")
            raise AuthenticationError(
                "Too many failed authentication attempts. Please try again later."
            )

        # -- OIDC path -------------------------------------------------------
        if bearer_token and self._oidc:
            try:
                user = await self._oidc.authenticate(bearer_token)
                return AuthResult(authenticated=True, method="oidc", user=user)
            except AuthenticationError:
                self._record_failure()
                logger.warning("auth_oidc_failed", reason="token validation failed")
                return AuthResult(authenticated=False, method="oidc")

        # -- API key path -----------------------------------------------------
        if self._api_key:
            if api_key and hmac.compare_digest(api_key, self._api_key):
                return AuthResult(authenticated=True, method="api_key")
            # If we reach here, either no api_key was provided or it was wrong.
            # Either way, authentication fails when an API key is configured.
            if api_key:
                self._record_failure()
                logger.warning("auth_api_key_failed")
            else:
                self._record_failure()
            return AuthResult(authenticated=False, method="api_key")

        # -- OIDC required but no token provided ------------------------------
        if self._oidc and not bearer_token:
            self._record_failure()
            return AuthResult(authenticated=False, method="oidc")

        # -- No auth configured -----------------------------------------------
        return AuthResult(authenticated=True, method="none")

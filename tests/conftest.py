"""
Shared Test Configuration

This module holds the fixtures and Hypothesis profiles shared by the whole suite. The default test
run needs no appliance, no credential and no network: the ``credential`` fixture builds a synthetic
credential, and ``credential_source`` injects it where production would read the caller's
``Authorization`` header.

``POWERPACK_MCP_ENV_FILE`` is pointed at a path that does not exist, so a real
``/opt/em7/services/powerpack-mcp/powerpack-mcp.env`` on a developer's machine cannot influence
results.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from hypothesis import HealthCheck, settings
from pydantic import SecretStr

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential, username_from_authorization

# Hypothesis profiles shared by every test module. In both, shrinking stays enabled and
# `derandomize` is never set, because a fixed seed defeats the point of generative testing; the
# seed is reported on failure so any failing case is reproducible.
settings.register_profile("dev", max_examples=50, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("ci", max_examples=500, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))

if TYPE_CHECKING:
    from collections.abc import Callable

# Environment prefixes the autouse fixture below clears; it is only as good as this list. Without
# `ENABLE_`, a leaked `ENABLE_DB_TOOLS=false` would change which tool sets register, so a test of
# the default-on posture would pass on one machine and fail on another.
#
# Known gap: `MAX_REQUEST_` does not match `MAX_CONCURRENT_REQUESTS`, so that variable is not
# cleared.
_CONFIG_ENV_PREFIXES = (
    "ENABLE_",
    "LCE_",
    "LISTEN_",
    "LOG_LEVEL",
    "MAX_REQUEST_",
    "POWERPACK_MCP_",
)


@pytest.fixture(autouse=True)
def _isolate_config_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Isolate every test from the host environment and from any real env file.

    Autouse, because a leaked configuration variable could make a test that should fail pass, and
    the failure would then only appear on a machine that did not have it set.
    """
    for key in list(os.environ):
        if key.startswith(_CONFIG_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("POWERPACK_MCP_ENV_FILE", str(tmp_path / "absent.env"))


@pytest.fixture
def anyio_backend() -> str:
    """Run async tests on asyncio only.

    `anyio`'s pytest plugin arrives transitively with `httpx`, so no extra dev dependency is needed.
    Trio is not exercised because the service runs under uvicorn on asyncio.
    """
    return "asyncio"


@pytest.fixture
def credential_value() -> str:
    """Return a synthetic credential value. Not a real credential, and not a real password.

    Basic-shaped so tests exercise the username derivation: base64 of ``testuser:testpass``.
    """
    return "Basic dGVzdHVzZXI6dGVzdHBhc3M="


@pytest.fixture
def config() -> Config:
    """Return a valid `Config` built directly, bypassing the environment.

    Every key has a default and no credential is configured, so this is simply `Config()`.
    """
    return Config()


@pytest.fixture
def credential(credential_value: str) -> LceCredential:
    """Return a request-scoped `LceCredential`, as `credentials.extract_from_scope` would build it.

    Built through the real parse so the fixture cannot drift from production behaviour.
    """
    return LceCredential(SecretStr(credential_value), username_from_authorization(credential_value))


@pytest.fixture
def credential_source(credential: LceCredential) -> Callable[[], LceCredential]:
    """Return the injected `ToolContext.credential_source` for tests.

    Ignores the scope and returns the synthetic credential, so tool tests can call tool functions
    directly, outside any HTTP context. Injection keeps the production path strict: making a missing
    credential non-fatal outside an HTTP context would add a runtime path that tolerates absence
    and is not reliably test-only.
    """

    def _source() -> LceCredential:
        return credential

    return _source

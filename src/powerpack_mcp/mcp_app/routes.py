"""
Health Route

This module provides ``/health``, the only route the service exposes besides the MCP transport
mount. There is no debug, metrics or documentation endpoint.

``/health`` is the only anonymously reachable route, and the nginx location rules mark it public.
There is no ``/ready`` route: with no configured credential a readiness probe has nothing to
authenticate with, so LCE reachability surfaces as an ``lce_unreachable`` error on a real tool
call instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request


__all__ = ["HEALTH_PATH", "health"]

HEALTH_PATH: Final[str] = "/health"


async def health(request: Request) -> JSONResponse:
    """Report process liveness. Never contacts LCE.

    Because the route is public, it discloses nothing beyond liveness: no version, configuration,
    uptime or dependency status. A version string would tell an unauthenticated caller which
    release to look up vulnerabilities for.
    """
    del request
    return JSONResponse({"status": "ok"})

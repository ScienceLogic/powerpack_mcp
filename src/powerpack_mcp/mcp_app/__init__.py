"""
MCP Application Package

This module re-exports the inbound MCP application: the composition root that uvicorn and
``main`` call, the ``/health`` route, the correlation-id ``ContextVar`` and middleware, and the
logging filter and formatter that other components use.
"""

from __future__ import annotations

from powerpack_mcp.mcp_app.app import (
    MCP_MOUNT_PATH,
    build_mcp_server,
    create_app,
    global_error_handler,
    lifespan_for,
    register_tools,
    start_up,
)
from powerpack_mcp.mcp_app.correlation import (
    CORRELATION_ID,
    FORWARDED_ACTOR_HEADERS,
    CorrelationIdMiddleware,
    current_correlation_id,
    forwarded_actor,
    mint_correlation_id,
    sanitize_correlation_id,
)
from powerpack_mcp.mcp_app.logging_setup import (
    SECRET_FIELD_DENYLIST,
    CorrelationIdFilter,
    SlConfigExtraFormatter,
    configure_logging,
)
from powerpack_mcp.mcp_app.routes import HEALTH_PATH, health

__all__ = [
    "CORRELATION_ID",
    "FORWARDED_ACTOR_HEADERS",
    "HEALTH_PATH",
    "MCP_MOUNT_PATH",
    "SECRET_FIELD_DENYLIST",
    "CorrelationIdFilter",
    "CorrelationIdMiddleware",
    "SlConfigExtraFormatter",
    "build_mcp_server",
    "configure_logging",
    "create_app",
    "current_correlation_id",
    "forwarded_actor",
    "global_error_handler",
    "health",
    "lifespan_for",
    "mint_correlation_id",
    "register_tools",
    "sanitize_correlation_id",
    "start_up",
]

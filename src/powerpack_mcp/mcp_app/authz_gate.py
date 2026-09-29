"""
Authorization Gate

This module decides whether a caller may run a tool. ``hook_source`` answers what the caller may
do, ``authz``'s ``required_hooks`` says what the tool needs, and ``AuthorizationGate`` compares
them and refuses a call that falls short.

The gate is a FastMCP middleware rather than a decorator because tools reach the server through
more than one decorator and one bare registration, so dispatch is the only place every call
converges, and a newly added tool cannot omit the check. FastMCP's ``on_call_tool`` receives the
already-parsed ``CallToolRequestParams``, so the tool name costs nothing to read here, unlike in
ASGI middleware.

Two checks deliberately live elsewhere:

- The job-ownership check runs in the tool, not here. This hook sees the raw JSON arguments while
  the tool sees them after pydantic validation, so re-parsing ``proc_id`` here could check one job
  while the tool reads another. An AST test asserts the tool's call site exists.
- ``ENABLE_DB_WRITE_TOOLS`` is consumed only by ``tool_sets`` at registration, so a write tool does
  not exist when the flag is off and a runtime re-check here could never fire. Registration bounds
  whether a tool is offered; this module bounds who may call it.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from fastmcp.server.middleware import Middleware
from fastmcp.tools.base import ToolResult

from powerpack_mcp.authz import TOOL_REGISTRY, ToolTransport
from powerpack_mcp.errors import (
    AuthorizationDenied,
    LogEvent,
    PowerPackMcpError,
    build_error_payload,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    import mcp.types as mt
    from fastmcp.server.middleware import CallNext, MiddlewareContext

    from powerpack_mcp.credentials import LceCredential
    from powerpack_mcp.hook_source import HookCache

__all__ = ["ActorUnresolvable", "AuthorizationGate", "ToolNotMapped", "is_gated"]

logger = logging.getLogger(__name__)


class ActorUnresolvable(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """The request carried a usable credential but no resolvable account id.

    It deliberately has no ``ErrorType`` member, so ``build_error_payload`` renders it as
    ``internal_error``, as ``DbToolNotRegistered`` does: no caller can trigger it in a correct
    deployment. nginx sets ``X-User-ID`` from its own ``auth_request`` subrequest, so reaching here
    means a platform upgrade dropped the nginx fragment's include line, or someone called the
    loopback listener directly. Telling the caller to ask for a hook would not help them.

    It still refuses and is still logged as an authorization event. An unattributable request
    cannot be authorized, and a burst of these is what a dropped include line looks like from the
    inside.
    """

    tool_name: str

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"no resolvable account id for a call to {tool_name}")


class ToolNotMapped(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """A tool is inside the gated scope but carries no ``required_hooks``.

    Rendered as ``internal_error`` for the same reason as ``DbToolNotRegistered``: it is a
    mis-registration on our side. It is a separate type from ``ActorUnresolvable`` so the log's
    ``reason`` field tells "our mapping is incomplete" apart from "our perimeter is
    misconfigured".

    ``authz``'s import-time check makes this unreachable today. It is kept because an absent
    mapping must refuse as a behaviour, not only as a startup assertion, and because widening
    ``is_gated`` past the SQL tools would reach tools with no mapping; this makes that change fail
    closed instead of silently allowing. A test exercises it directly.
    """

    tool_name: str

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"{tool_name} is gated but has no required_hooks mapping")


def is_gated(tool_name: str) -> bool:
    """Return whether the gate covers ``tool_name``, derived from the registry, never listed.

    The gate covers exactly the SQL tools. ``authz``'s import-time check guarantees every SQL tool
    carries a mapping and no other tool does, so "is it gated" and "does it have required hooks"
    cannot disagree.

    A tool absent from the registry is not gated, and that is correct rather than a hole. Tools
    outside the registry reach SL1 with the caller's own credential, so SL1 refuses them itself: a
    restricted account gets 403 from REST and ``RESTRICTED_ACCESS`` from GraphQL. Widening the
    gate means adding registry rows; read ``authz``'s docstring first.

    :param tool_name: The MCP tool name.
    :return: ``True`` if the tool's registry entry uses the SQL transport.
    """
    entry = TOOL_REGISTRY.get(tool_name)
    return entry is not None and entry.transport is ToolTransport.SQL


class AuthorizationGate(Middleware):
    """Refuse a gated tool call whose caller lacks the hooks it requires.

    The gate refuses by returning a payload, never by raising. FastMCP's ``mask_error_details``
    defaults to false, so an exception escaping this hook would show its message to the caller
    unfiltered, and this middleware sits outside ``sl1_tool_boundary``, so nothing downstream
    would sanitise it. ``ToolResult(structured_content=...)`` is byte-identical to what a tool
    returning a dict produces, so a client parses one envelope shape whichever side refused.

    A denial makes no transport call of any kind: ``call_next`` is not invoked, so a refused caller
    cannot use the gate to probe which devices or jobs exist. That also keeps the deny path cheap
    enough not to need its own rate limit.
    """

    def __init__(
        self,
        *,
        cache: HookCache,
        credential_source: Callable[[], LceCredential],
        gated: Callable[[str], bool] = is_gated,
    ) -> None:
        """Create the gate.

        The gate is process-scoped and a credential is request-scoped, so it holds no credential,
        only a source that looks one up per request.

        :param cache: The per-account hook cache.
        :param credential_source: Zero-argument callable returning the current request's
            credential. Tests substitute one that never touches HTTP.
        :param gated: Predicate selecting the gated tools. Injected so a test can widen or narrow
            the scope without a real registry.
        """
        self._cache = cache
        self._credential_source = credential_source
        self._gated = gated

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Decide, then dispatch or refuse."""
        tool_name = context.message.name
        if not self._gated(tool_name):
            return await call_next(context)
        try:
            await self._authorize(tool_name)
        except PowerPackMcpError as exc:
            return self._refuse(tool_name, exc)
        return await call_next(context)

    async def _authorize(self, tool_name: str) -> None:
        """Raise a ``PowerPackMcpError`` unless the caller holds every required hook.

        Every failure here raises, and ``hook_source`` never returns a default, so no branch turns
        an unresolved hook set into permission. Writing this check backwards would be the most
        dangerous mistake in the module.

        :raises ToolNotMapped: If the gated tool has no ``required_hooks``.
        :raises ActorUnresolvable: If the request has no resolvable account id.
        :raises AuthorizationDenied: If the caller lacks a required hook.
        """
        entry = TOOL_REGISTRY[tool_name]
        required = entry.required_hooks
        if not required:
            raise ToolNotMapped(tool_name)

        credential = self._credential_source()
        # Imported here, not at module scope: ``sl1_db_pipeline`` reaches back into ``mcp_app``
        # for ``forwarded_actor``, so a module-level import type-checks cleanly and then fails at
        # collection when a test imports that module first (see ``create_app``).
        from powerpack_mcp.tools.sl1_db_pipeline import actor_user_id

        account_id = actor_user_id()
        if account_id is None:
            raise ActorUnresolvable(tool_name)

        granted = await self._cache.hooks_for_account(account_id, credential)
        if not required <= granted:
            # Report the required set, never the granted one. The missing subset is not computed,
            # because naming it would disclose, by difference, part of what the caller holds.
            raise AuthorizationDenied(tool_name, required)

    def _refuse(self, tool_name: str, exc: PowerPackMcpError) -> ToolResult:
        """Log the refusal and build the caller-facing envelope.

        The record is keyed on ``event`` so monitoring matches the token rather than the message,
        and carries the tool and its required hooks. It never carries a credential or the caller's
        granted set, which is a named person's entitlement profile. ``RedactingFilter`` matches
        attribute names, so a ``granted_hooks`` extra would pass through untouched; the safe rule
        is never to attach it.

        :return: The error envelope as a ``ToolResult``.
        """
        entry = TOOL_REGISTRY.get(tool_name)
        required = sorted(entry.required_hooks) if entry is not None else []
        logger.warning(
            "Refused a tool call: the caller does not hold the required access hooks.",
            extra={
                "event": str(LogEvent.AUTHORIZATION_DENIED),
                "tool": tool_name,
                "required_hooks": required,
                "reason": type(exc).__name__,
            },
        )
        return ToolResult(structured_content=build_error_payload(exc))

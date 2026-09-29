"""
SL1 Tool Boundary and Passthrough Audit

This module provides ``sl1_tool_boundary``, the decorator every SL1 platform tool carries, and
``audit_passthrough``, which records each passthrough call for the audit trail.

This is a separate boundary from ``tools.pipeline.tool_boundary`` because that decorator reads
``descriptor.path_template`` and branches on the LCE exception classes. The caller-facing payload
is still built only by ``build_error_payload``, so it has one definition; what differs is the log
fields and the audit record. The two boundaries can drift in their logging, so
``test_sl1_tools.py`` pins the fields both must carry.
"""

from __future__ import annotations

import logging
import time
from functools import wraps
from typing import TYPE_CHECKING, Any, ParamSpec, Protocol

from powerpack_mcp.errors import LogEvent, PowerPackMcpError, ValidationBlocked, build_error_payload

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from powerpack_mcp.config import Config
    from powerpack_mcp.credentials import LceCredential
    from powerpack_mcp.lce_client.client import LceClient
    from powerpack_mcp.sl1_client import Sl1Client
    from powerpack_mcp.tools.sl1_descriptors import (
        GraphQlDescriptor,
        Sl1OperationDescriptor,
    )

logger = logging.getLogger(__name__)

__all__ = ["NamedDescriptor", "Sl1ToolContext", "audit_passthrough", "sl1_tool_boundary"]

_P = ParamSpec("_P")


class NamedDescriptor(Protocol):
    """Anything carrying a ``tool_name``.

    ``sl1_tool_boundary`` reads only ``tool_name`` and branches on ``PowerPackMcpError``, which the
    database errors (``DbError``, ``DbQueryTimeout``, ``DbUnreachable``) also derive from. So the
    database tools reuse this boundary instead of adding a third copy of the same logging fields.
    A ``Protocol`` rather than a union of the concrete descriptor classes, so a new descriptor type
    needs no edit here.
    """

    @property
    def tool_name(self) -> str: ...


class Sl1ToolContext:
    """What every SL1 tool needs: the injected clients, the configuration, a credential factory.

    Mirrors ``tools.pipeline.ToolContext``. ``credential_source`` is a callable because this object
    is process-scoped and a credential is request-scoped; injecting it means the default test run
    needs no real credential.

    ``lce_client`` is not a second SL1 transport. ``sl1_align_dynamic_apps_to_device`` and its
    unalign sibling must resolve a Dynamic App identifier to its 32-hex guid through LCE before
    they can issue the SL1 GraphQL mutation, because ``alignDynamicApplicationsToDevice`` accepts
    guids only. This is the same ``LceClient`` instance the LCE tools use, so no new pool,
    connection budget or credential path is created.

    :ivar client: The shared SL1 client.
    :ivar config: The service configuration.
    :ivar credential_source: Returns the current caller's credential.
    :ivar lce_client: The shared LCE client, for identifier resolution.
    """

    __slots__ = ("client", "config", "credential_source", "lce_client")

    def __init__(
        self,
        client: Sl1Client,
        config: Config,
        credential_source: Callable[[], LceCredential],
        lce_client: LceClient,
    ) -> None:
        self.client = client
        self.config = config
        self.credential_source = credential_source
        self.lce_client = lce_client


def _actor() -> str | None:
    """Return the forwarded caller identity for the audit record's ``actor`` field.

    This delegates to the private ``tools.pipeline._current_actor`` rather than reimplementing the
    lookup. Its resolution order (the credential's username, then nginx's ``X-User-ID``, then
    omitted) is subtle, and a naive version that sanitised the username like a correlation id would
    record a different fake principal for every email-form login. An audit trail should have one
    implementation of "who is calling".
    """
    from powerpack_mcp.tools.pipeline import _current_actor

    return _current_actor()


def audit_passthrough(
    descriptor: Sl1OperationDescriptor | GraphQlDescriptor,
    *,
    method: str,
    path: str,
    outcome: str,
) -> None:
    """Emit the audit record for one passthrough call.

    Passthroughs are the REST and GraphQL tools that send arbitrary caller-supplied operations,
    bounded only by SL1's own authorization; ``is_passthrough`` on the descriptor marks them.

    Call this on every outcome, including validation rejection. An audit log that records only
    successful passthroughs is useless against someone probing paths, because the rejected calls
    are the interesting ones.

    The record carries no credential: method, path, actor and outcome only. ``path`` is
    caller-supplied and is recorded here because reconstructing what was called is the point of
    the trail; it is kept out of error messages returned to the caller.

    :param descriptor: The passthrough tool's descriptor.
    :param method: The HTTP method.
    :param path: The requested path.
    :param outcome: What happened, for example ``invoked`` or ``rejected_method``.
    """
    logger.info(
        "SL1 passthrough invoked.",
        extra={
            "event": LogEvent.SL1_PASSTHROUGH_INVOKED,
            "tool": descriptor.tool_name,
            "sl1_method": method,
            "sl1_path": path,
            "actor": _actor(),
            "outcome": outcome,
        },
    )


def sl1_tool_boundary(
    descriptor: NamedDescriptor,
) -> Callable[
    [Callable[_P, Awaitable[dict[str, Any] | list[Any]]]], Callable[_P, Awaitable[object]]
]:
    """Translate SL1 failures into the caller-facing payload, exactly once.

    Each invocation emits one INFO record carrying ``tool``, ``outcome`` and ``duration_ms``,
    matching the declared log schema so the LCE and SL1 boundaries do not diverge.

    Payload bodies are never logged, and neither are arguments, for any tool. Tools whose
    descriptor sets ``carries_secret_input`` must not log their arguments; an allowlist of loggable
    parameters would need per-tool maintenance and fail as silent secret disclosure, so no
    arguments are logged at all.

    :param descriptor: The descriptor of the wrapped tool.
    :return: The decorator.
    """

    def decorate(
        func: Callable[_P, Awaitable[dict[str, Any] | list[Any]]],
    ) -> Callable[_P, Awaitable[object]]:
        @wraps(func)
        async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> object:
            started = time.monotonic()
            try:
                result = await func(*args, **kwargs)
            except ValidationBlocked as exc:
                logger.warning(
                    "Request blocked before reaching SL1.",
                    extra={
                        "event": LogEvent.VALIDATION_BLOCKED,
                        "tool": descriptor.tool_name,
                        "outcome": "validation_blocked",
                        "finding_count": len(exc.findings),
                        "finding_codes": sorted({str(f.rule) for f in exc.findings}),
                        "duration_ms": round((time.monotonic() - started) * 1000, 3),
                    },
                )
                return build_error_payload(exc)
            except PowerPackMcpError as exc:
                # One clause for the whole hierarchy. The type distinction the caller needs is made
                # by ``build_error_payload``; duplicating the branch here would give two texts that
                # can disagree.
                logger.warning(
                    "SL1 tool call failed.",
                    extra={
                        # ``ValidationBlocked`` cannot reach here (the clause above catches it), so
                        # this is unconditional.
                        "event": LogEvent.UNHANDLED_EXCEPTION,
                        "tool": descriptor.tool_name,
                        "outcome": type(exc).__name__,
                        "duration_ms": round((time.monotonic() - started) * 1000, 3),
                    },
                )
                return build_error_payload(exc)
            logger.info(
                "SL1 tool call completed.",
                extra={
                    "tool": descriptor.tool_name,
                    "outcome": "success",
                    "duration_ms": round((time.monotonic() - started) * 1000, 3),
                },
            )
            return result

        return wrapper

    return decorate

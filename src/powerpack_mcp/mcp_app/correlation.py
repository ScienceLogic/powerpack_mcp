"""
Correlation Identifier Handling

This module adopts, mints and propagates the correlation id that ties a request's log records
together, and reads the caller identity nginx forwards for audit records.

The id travels only in a ``ContextVar``; no function signature carries it. An explicit parameter
would have to be added to pure helpers such as ``validate_payload``, ``build_filter_params`` and
``drop_empty``, and every property-test strategy for them would have to generate an id it does
not care about.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar
from typing import TYPE_CHECKING, Final

from fastmcp.server.middleware import Middleware

if TYPE_CHECKING:
    import mcp.types as mt
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools.base import ToolResult
    from starlette.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "CORRELATION_HEADERS",
    "CORRELATION_ID",
    "FORWARDED_ACTOR_HEADERS",
    "MAX_CORRELATION_ID_LENGTH",
    "CorrelationIdMiddleware",
    "ToolCallCorrelationMiddleware",
    "current_correlation_id",
    "forwarded_actor",
    "identity_or_none",
    "mint_correlation_id",
    "sanitize_correlation_id",
]

MAX_CORRELATION_ID_LENGTH: Final[int] = 128

_CORRELATION_ID_RE: Final[re.Pattern[str]] = re.compile(
    rf"^[A-Za-z0-9._-]{{1,{MAX_CORRELATION_ID_LENGTH}}}$"
)

# Adoption order. Lower-cased because ASGI delivers header names lower-cased as bytes.
CORRELATION_HEADERS: Final[tuple[bytes, ...]] = (b"x-request-id", b"x-correlation-id")

# The caller identity nginx forwards. nginx's ``auth_request`` calls ``auth_user.em7``, then
# ``auth_request_set $user_id $upstream_http_x_user_id`` forwards it as ``X-User-ID``.
#
# This tuple must stay a single entry; widening it is a security regression. Headers nginx does
# not set, such as ``x-remote-user``, ``x-forwarded-user`` or ``x-authenticated-user``, pass the
# client's own value straight through, so a caller sending ``X-Remote-User: admin`` would be
# attributed as ``admin``. The identity must be set by nginx, never trusted from the client. The
# nginx fragment also clears those three names as defence in depth, but the primary control is
# here.
FORWARDED_ACTOR_HEADERS: Final[tuple[bytes, ...]] = (b"x-user-id",)

# Outside a request there is still a correlation id, because every log record must carry one,
# including those emitted at startup and shutdown.
_STARTUP_CORRELATION_ID: Final[str] = "startup"

CORRELATION_ID: ContextVar[str] = ContextVar("correlation_id", default=_STARTUP_CORRELATION_ID)


def mint_correlation_id() -> str:
    """Mint a fresh identifier: a UUID4 hex string, which satisfies the character rule by
    construction.
    """
    return uuid.uuid4().hex


def sanitize_correlation_id(value: str | None) -> str:
    """Return a correlation identifier that is always valid, whatever arrived on the wire.

    The output always matches ``[A-Za-z0-9._-]{1,128}``, for every input including ``None`` and the
    empty string. The function never raises, never returns an empty string, and is idempotent on
    its own output. A property test over arbitrary strings (newlines, control characters,
    megabyte-long inputs) verifies this.

    An invalid inbound value is discarded and replaced, never repaired and never rejected.
    Stripping bad characters would let a caller influence the id's content, and failing a request
    over a malformed observability header is worse than ignoring it.

    The character rule is a security rule: this value lands in every log record for the request,
    so a newline would let a caller forge log lines and unbounded length would let a caller flood
    the journal.

    :param value: The inbound header value, or ``None`` if absent.
    :return: ``value`` if valid, otherwise a freshly minted id.
    """
    if value is None:
        return mint_correlation_id()
    # ``fullmatch``, not ``match``. In Python's ``re``, ``$`` also matches just before a trailing
    # newline, so ``match("0\n")`` succeeds and would return the value with its newline intact,
    # letting ``X-Request-ID: 0\n<forged record>`` put a forged line into the log.
    # ``[A-Za-z0-9._-]`` cannot consume ``\n``, so ``fullmatch`` rejects it. The ``ci`` Hypothesis
    # profile (500 examples) exercises this; the ``dev`` profile's 50 may not generate it.
    if _CORRELATION_ID_RE.fullmatch(value):
        return value
    return mint_correlation_id()


def current_correlation_id() -> str:
    """Read the current identifier. Used by the logging filter, never by pure code."""
    return CORRELATION_ID.get()


def _header(scope: Scope, names: tuple[bytes, ...]) -> str | None:
    """Return the first present header value from ``names``, decoded leniently.

    Decoding cannot raise: bytes that are not valid UTF-8 yield replacement characters, which
    ``sanitize_correlation_id`` then discards. This function must stay total, because a failure
    inside the outermost middleware is not caught by the global error handler.
    """
    raw: list[tuple[bytes, bytes]] = scope.get("headers", [])
    for name in names:
        for key, value in raw:
            if key == name:
                return value.decode("utf-8", errors="replace")
    return None


def forwarded_actor(scope: Scope) -> str | None:
    """Read the caller identity nginx forwards, for audit records.

    Sanitised with the same rule as the correlation id, because it reaches log records by the same
    path and carries the same log-injection risk.

    This is attribution, not authorization: it says who nginx believed the caller to be, and
    nothing is decided on it.

    :param scope: The ASGI scope.
    :return: The identity, or ``None`` when absent or unsafe to log.
    """
    return identity_or_none(_header(scope, FORWARDED_ACTOR_HEADERS))


def identity_or_none(value: str | None) -> str | None:
    """Return ``value`` if it is safe to put in a log record, otherwise ``None``.

    The counterpart to ``sanitize_correlation_id``. Both enforce the same ``[A-Za-z0-9._-]{1,128}``
    shape, because both feed log records, but they differ in what they do with a rejected value:

    * ``sanitize_correlation_id`` mints a replacement, which is right for a correlation id: one
      must always exist, and a fabricated id correlates nothing but misleads nobody.
    * This function returns ``None``, which is right for an identity: a fabricated value looks
      like a real principal, so ``actor`` must be either true or missing, never invented.

    Use this for anything that names a caller. Routing an identity through the minting function
    would turn every email-form login (which contains ``@``) into a different fake principal on
    every call.
    """
    if value is None:
        return None
    # ``fullmatch`` for the same reason as in ``sanitize_correlation_id``: ``$`` would admit a
    # trailing newline, putting a forged line break into an ``actor`` field.
    return value if _CORRELATION_ID_RE.fullmatch(value) else None


class CorrelationIdMiddleware:
    """Establish the correlation identifier before anything that could fail.

    Outermost in the ASGI chain, so the global error handler runs inside this scope and its ERROR
    record carries the id. The response to an unhandled error must be a generic
    ``internal_error``, and the id is what keeps it diagnosable: a caller quotes it and an operator
    finds the real cause in the log.

    A failure inside this middleware is not caught by the global error handler. That gap is
    bounded, because the only work here is reading headers and calling the total function
    ``sanitize_correlation_id``.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] not in {"http", "websocket"}:
            await self._app(scope, receive, send)
            return
        correlation_id = sanitize_correlation_id(_header(scope, CORRELATION_HEADERS))
        token = CORRELATION_ID.set(correlation_id)
        try:
            await self._app(scope, receive, send)
        finally:
            # Reset rather than leave set: the ContextVar is per request, and concurrent requests
            # must not observe each other's value.
            CORRELATION_ID.reset(token)


class ToolCallCorrelationMiddleware(Middleware):
    """Mint a fresh correlation identifier per tool call.

    The session-task context capture described on ``RequestDeadlineMiddleware`` strands this value
    too. ``CorrelationIdMiddleware`` mints a fresh id when no ``x-request-id`` or
    ``x-correlation-id`` header is present, and the nginx fragment sets neither, so without this
    class every tool call in a session would carry the id of the request that created the session.
    A caller would quote an id and the operator would find the whole session rather than the
    failing call. For this transport, each tool call deserves its own id.

    The trade-off is a real loss: a per-call id keeps no link back to the session that issued it,
    because there is no per-call inbound header to honour. Telling two calls apart is worth more
    than grouping by session, since the failing call is what an operator is looking for.

    It always dispatches, for the same reason ``RequestDeadlineMiddleware`` does.
    """

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Replace the ambient identifier, captured or otherwise, with one minted now.

        ``mint_correlation_id`` rather than ``sanitize_correlation_id``: there is no wire value to
        sanitise here, and minting is what ``sanitize_correlation_id(None)`` would do anyway.
        """
        token = CORRELATION_ID.set(mint_correlation_id())
        try:
            return await call_next(context)
        finally:
            CORRELATION_ID.reset(token)

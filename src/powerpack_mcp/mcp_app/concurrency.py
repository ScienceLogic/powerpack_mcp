"""
Inbound Concurrency Gate and Request Deadline

This module bounds how many tool requests are in flight and how long each may run. The response
shaping passes cost about 46 MiB of RSS per in-flight maximum-size request (the parsed object
graph is about 3.1x the wire bytes, plus a non-mutating copy alive at the same time), and the
body and validation guards run before the outbound call, so a request waiting on the outbound
pool already holds its parsed payload. Without an inbound bound, ``MemoryMax=512M`` is breached
at about 8 concurrent maximum-size requests, fewer than the outbound pool's 10 connections.

Design constraints:

- uvicorn's ``limit_concurrency`` is not used. It counts open TCP connections, including idle
  keep-alive ones, so with long-lived streamable-HTTP sessions it would 503 an idle session
  without bounding memory, and it answers with a ``text/plain`` body and no ``event``-keyed log.
- The gate is ASGI middleware, not a tool-pipeline guard, because the memory is spent at parse
  time; a guard inside the pipeline would acquire the slot after the cost was paid.
- Only POST is gated. GET opens long-lived streams (nginx allows ``proxy_read_timeout 3600s``)
  and GET and DELETE carry no body, so gating them would let idle streams take every slot and
  starve the POSTs the gate protects. Every non-exempt POST is still bounded.
- The gate's deadline is a backstop. Outbound calls bound themselves to finish
  ``OUTBOUND_DEADLINE_MARGIN_SECONDS`` earlier, because once a streamed response has started the
  gate's cancellation cannot send the caller anything, whereas the tool's own error can.
"""

from __future__ import annotations

import asyncio
import logging
import time
from contextvars import ContextVar
from typing import TYPE_CHECKING

from fastmcp.server.middleware import Middleware

from powerpack_mcp.config import OUTBOUND_DEADLINE_MARGIN_SECONDS
from powerpack_mcp.errors import (
    CONCURRENCY_LIMITED_PAYLOAD,
    REQUEST_DEADLINE_EXCEEDED_PAYLOAD,
    LogEvent,
)
from powerpack_mcp.mcp_app.routes import HEALTH_PATH

if TYPE_CHECKING:
    import mcp.types as mt
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools.base import ToolResult
    from starlette.types import ASGIApp, Message, Receive, Scope, Send

__all__ = [
    "EXEMPT_PATHS",
    "OUTBOUND_DEADLINE_MARGIN_SECONDS",
    "REQUEST_DEADLINE",
    "ConcurrencyGateMiddleware",
    "RequestDeadlineMiddleware",
    "outbound_budget_seconds",
    "remaining_deadline_seconds",
]

logger = logging.getLogger(__name__)

# Absolute ``time.monotonic()`` instant at which the current request's deadline expires, or
# ``None`` outside a gated request.
#
# A contextvar rather than a parameter, because the gate is middleware and ``db_client`` sits
# several frames below it; threading the value through would change every signature in between.
# ``time.monotonic()`` rather than the loop clock, because the consumer converts it to a MariaDB
# ``max_statement_time`` and it must be meaningful off the event loop.
REQUEST_DEADLINE: ContextVar[float | None] = ContextVar("request_deadline", default=None)


def remaining_deadline_seconds() -> float | None:
    """Return the seconds left on the request deadline, or ``None`` if none is in force.

    Returns ``0.0`` rather than a negative number once the deadline has passed. MariaDB accepts a
    negative ``max_statement_time`` and reads it as no limit, which would turn an expired deadline
    into an unbounded query, so this clamps rather than trusting the arithmetic.

    Call this on the event loop, not in a worker thread: ``loop.run_in_executor`` does not copy
    the calling context, so capture the value before submitting work and pass it in, as
    ``db_client`` does.
    """
    deadline = REQUEST_DEADLINE.get()
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


# ``OUTBOUND_DEADLINE_MARGIN_SECONDS`` lives in ``config`` and is re-exported here: the read-timeout
# validator needs it to refuse a deadline the margin would consume, and ``config`` cannot import
# this module.


def outbound_budget_seconds() -> float | None:
    """Return how long an outbound call may take, or ``None`` if no deadline is in force.

    This is the request deadline's remainder less ``OUTBOUND_DEADLINE_MARGIN_SECONDS``, floored at
    ``0.0``. ``0.0`` means there is no time left to spend: a caller refuses rather than sending a
    request that cannot finish before the gate cancels it.

    Like ``remaining_deadline_seconds``, call this on the event loop, not in a worker thread.
    """
    remaining = remaining_deadline_seconds()
    if remaining is None:
        return None
    return max(0.0, remaining - OUTBOUND_DEADLINE_MARGIN_SECONDS)


# The gate must never throttle the liveness probe. systemd and appliance monitoring read
# ``/health``, so a 503 there could restart a service that is merely busy, turning a capacity
# condition into an outage.
#
# This is an exemption list rather than "gate only paths under ``/mcp``" on purpose: with an
# exemption list, any route added later is gated by default, which is the fail-closed direction.
EXEMPT_PATHS: frozenset[str] = frozenset({HEALTH_PATH})

_SERVICE_UNAVAILABLE = 503
_GATEWAY_TIMEOUT = 504


class ConcurrencyGateMiddleware:
    """Bound concurrent tool invocations, rejecting the excess with a parseable 503.

    Register this with ``app.add_middleware``, not by wrapping the app. Starlette composes
    ``ServerErrorMiddleware -> user middleware -> ExceptionMiddleware -> router`` and the generic
    ``Exception`` handler installs into ``ServerErrorMiddleware``, so middleware added this way
    sits inside the error handler, inside ``CorrelationIdMiddleware``, and before any body is
    read. An outer ASGI wrapper would sit outside the exception handler.

    The semaphore is created per instance and never awaited with a timeout: a caller that would
    have to wait is rejected immediately rather than queued, because queueing is what holds memory.
    """

    def __init__(self, app: ASGIApp, limit: int, deadline_seconds: float) -> None:
        """Create the gate.

        :param app: The downstream ASGI application.
        :param limit: Maximum concurrent gated requests.
        :param deadline_seconds: Total time a gated request may hold its slot. Required, with no
            default, so a call site cannot omit it and silently get no bound.
        """
        self._app = app
        self._limit = limit
        self._semaphore = asyncio.Semaphore(limit)
        self._deadline_seconds = deadline_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("path") in EXEMPT_PATHS
            or scope.get("method") != "POST"
        ):
            # Non-HTTP scopes (lifespan), the exempt paths and non-POST methods pass through
            # ungated; the module docstring explains why only POST is gated.
            #
            # ``scope.get("method")``, not ``scope["method"]``: ASGI guarantees the key on an HTTP
            # scope, but a synthetic scope without it must pass through rather than raise
            # ``KeyError`` here, where the error handler sits outside this frame.
            await self._app(scope, receive, send)
            return

        if self._semaphore.locked():
            await self._reject(send)
            return

        # ``locked()`` then acquiring is not a race: asyncio runs this coroutine to its next await
        # without interruption, and acquiring an available semaphore does not yield.
        async with self._semaphore:
            # The deadline wraps the whole downstream call inside the semaphore, so it bounds
            # exactly what the slot holds.
            #
            # A read timeout is not enough. httpx's ``read`` timeout is a per-chunk allowance, not
            # a total deadline: with a 0.5 s read timeout, 15 chunks 0.2 s apart complete in 3.03 s
            # with no ``ReadTimeout``. A slow-drip backend could hold a slot indefinitely, and a
            # handful of such responses would take every slot.
            #
            # The bound covers parse, validation, the outbound call and shaping, not just the
            # outbound leg, so it includes local work rather than adding to it; ``mcp_app.app``
            # explains how the value is chosen. The deadline is published as an absolute instant so
            # work below derives its own bound from the remainder without double-counting.
            #
            # This is the backstop, not the only bound. Every outbound call also bounds its own
            # total time by ``outbound_budget_seconds()``, which ends
            # ``OUTBOUND_DEADLINE_MARGIN_SECONDS`` before this one, so a slow backend surfaces as
            # the tool's own structured error rather than as this cancellation. The inner bound sits
            # strictly inside this one because cancelling here cannot produce a reply once a
            # streamed response has started; see that constant for the reasoning.
            started = False

            async def tracking_send(message: Message) -> None:
                nonlocal started
                if message["type"] == "http.response.start":
                    started = True
                await send(message)

            token = REQUEST_DEADLINE.set(time.monotonic() + self._deadline_seconds)
            try:
                async with asyncio.timeout(self._deadline_seconds):
                    await self._app(scope, receive, tracking_send)
            except TimeoutError:
                # The downstream call has been cancelled. The slot is released when this block
                # exits, after at most one small 504 write.
                self._log_deadline_exceeded(response_started=started)
                if not started:
                    # Nothing is on the wire yet, so the caller can still be told what happened.
                    await self._send_deadline_exceeded(send)
                # Otherwise there is no clean error envelope: the response's bytes are on the wire
                # and the client sees a truncated response, which is still better than a slot held
                # indefinitely. A 504 now would violate the ASGI protocol with a second
                # ``http.response.start``.
            finally:
                # Reset even though each request usually gets a fresh context: the middleware
                # makes no assumption about its caller, and a leaked deadline would silently bound
                # the next piece of work on this context.
                REQUEST_DEADLINE.reset(token)

    def _log_deadline_exceeded(self, *, response_started: bool) -> None:
        """Log that a request was aborted at the deadline.

        Without this record an operator sees a truncated or absent response and nothing to tell
        "the backend was slow" from "the backend failed". It is distinct from
        ``CONCURRENCY_LIMITED``, which means the bound was hit; this means one request held its
        slot to the limit, which is what produces the other, so an operator seeing only rejections
        would tune the wrong setting.

        ``response_started`` says whether the caller got a 504 (``False``) or a truncated response
        (``True``).
        """
        logger.warning(
            "Aborted a request at the inbound deadline.",
            extra={
                "event": LogEvent.REQUEST_DEADLINE_EXCEEDED,
                "deadline_seconds": self._deadline_seconds,
                "response_started": response_started,
            },
        )

    async def _send_deadline_exceeded(self, send: Send) -> None:
        """Send the standard error envelope as a 504, for a request aborted before it responded.

        The ``request_deadline_exceeded`` type rather than ``internal_error``, because the advice is
        to retry, perhaps with a narrower query, not to report a bug.
        """
        await _send_json(send, _GATEWAY_TIMEOUT, REQUEST_DEADLINE_EXCEEDED_PAYLOAD, [])

    async def _reject(self, send: Send) -> None:
        """Send the standard error envelope as a 503, and log an ``event``-keyed record.

        The body uses the service's error envelope with the ``concurrency_limited`` type, so
        clients parse it like any other error, unlike uvicorn's bare ``text/plain``. The message
        advises a retry rather than a bug report, which is why ``internal_error`` is not reused.
        """
        logger.warning(
            "Rejected a request at the inbound concurrency bound.",
            extra={"event": LogEvent.CONCURRENCY_LIMITED, "concurrency_limit": self._limit},
        )
        await _send_json(
            send,
            _SERVICE_UNAVAILABLE,
            CONCURRENCY_LIMITED_PAYLOAD,
            # Advisory only: there is no queue, so no precise wait can be given.
            [(b"retry-after", b"1")],
        )


async def _send_json(
    send: Send,
    status: int,
    payload: dict[str, dict[str, object]],
    extra_headers: list[tuple[bytes, bytes]],
) -> None:
    """Send ``payload`` as a complete JSON response with an exact ``content-length``."""
    import json

    body = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                *extra_headers,
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class RequestDeadlineMiddleware(Middleware):
    """Re-arm the request deadline for each tool call.

    ``ConcurrencyGateMiddleware`` sets ``REQUEST_DEADLINE`` once per ASGI call, which is right for
    the slot it bounds but wrong for a tool call. Stateful streamable HTTP runs one long-lived task
    per session (``mcp.server.streamable_http_manager``'s ``task_group.start(run_server)``), and
    anyio copies the calling context into that task. The task therefore keeps the absolute
    deadline of the request that created the session, and once it expires every later tool call
    reads a remainder of ``0.0``, so ``db_client._refuse_if_deadline_spent`` refuses every
    database tool for the rest of the session before issuing a statement. The gate's own
    ``reset(token)`` cannot fix this, because it restores the middleware's context, not the copy
    the session task holds.

    This does not replace the ASGI deadline and must not. That one bounds how long a request holds
    a slot, and the shutdown budget depends on it; this adds the per-invocation bound that
    ``outbound_budget_seconds`` reads for ``Sl1Client``, ``LceClient`` and ``db_client``.

    It always dispatches: it sets a contextvar and calls ``call_next`` unconditionally, so placing
    it ahead of ``AuthorizationGate`` cannot leave a tool call ungated. A test asserts this.
    """

    def __init__(self, deadline_seconds: float) -> None:
        """Create the middleware.

        :param deadline_seconds: ``LCE_READ_TIMEOUT_SECONDS``, the value the ASGI gate also uses.
            Passed as a primitive so the middleware is testable without a configuration model.
        """
        self._deadline_seconds = deadline_seconds

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        """Replace whatever deadline the ambient context holds with one armed now."""
        token = REQUEST_DEADLINE.set(time.monotonic() + self._deadline_seconds)
        try:
            return await call_next(context)
        finally:
            # Reset so the ambient context is left as found. This cannot undo the session task's
            # captured copy; that is why the deadline is re-armed on every call.
            REQUEST_DEADLINE.reset(token)

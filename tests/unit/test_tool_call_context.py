"""
Per-Tool-Call Context Tests

This module tests that the request deadline and correlation ID are armed afresh for every tool
call, rather than inherited from the request that created the MCP session.

Stateful streamable HTTP spawns one long-lived task per MCP session
(``mcp.server.streamable_http_manager``, ``task_group.start(run_server)``), and anyio copies the
calling context into it. Without per-call arming, every later tool call reads the first request's
absolute ``time.monotonic()`` deadline, and ``db_client._refuse_if_deadline_spent`` refuses every
DB-touching tool once ``LCE_READ_TIMEOUT_SECONDS`` have passed.

Each fix assertion has a control that reproduces the defect with the middleware absent, so the
test measures the fix rather than the harness. The ASGI gate's own deadline is guarded by
``test_concurrency.py::TestRequestDeadline::test_the_constructor_requires_a_deadline``.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import anyio
import pytest
from fastmcp import Client, FastMCP
from fastmcp.server.middleware import Middleware
from mcp.types import TextContent

if TYPE_CHECKING:
    import mcp.types as mt
    from anyio.abc import TaskStatus
    from fastmcp.client.client import CallToolResult
    from fastmcp.server.middleware import CallNext, MiddlewareContext
    from fastmcp.tools.base import ToolResult

    from powerpack_mcp.config import Config

from powerpack_mcp.mcp_app.concurrency import (
    REQUEST_DEADLINE,
    RequestDeadlineMiddleware,
    remaining_deadline_seconds,
)
from powerpack_mcp.mcp_app.correlation import (
    CORRELATION_ID,
    ToolCallCorrelationMiddleware,
    current_correlation_id,
)

# A deadline long enough that any remainder the tool observes is unambiguously "freshly armed"
# rather than a rounding artefact of an expired one.
_DEADLINE = 30.0

# How far in the past the simulated captured instant sits. Any positive value reproduces the
# defect; five seconds is simply legible in a failure message.
_EXPIRED_BY = 5.0


def _observing_server(*middleware: Middleware) -> FastMCP:
    """A server whose single tool reports the context it actually observes.

    Returns a delimited string rather than a dict so the assertion does not depend on how fastmcp
    happens to structure a mapping return value.
    """
    server: FastMCP = FastMCP(name="context-probe", middleware=list(middleware))

    @server.tool
    def observe() -> str:
        remaining = remaining_deadline_seconds()
        rendered = "none" if remaining is None else f"{remaining:.3f}"
        return f"{rendered}|{current_correlation_id()}"

    @server.tool
    def explode() -> str:
        raise RuntimeError("deliberate")

    return server


def _armed() -> tuple[ToolCallCorrelationMiddleware, RequestDeadlineMiddleware]:
    """The two arming middlewares, in the order `build_mcp_server` registers them."""
    return (ToolCallCorrelationMiddleware(), RequestDeadlineMiddleware(_DEADLINE))


def _reported(result: CallToolResult) -> tuple[str, str]:
    """Split the probe tool's ``remaining|correlation`` payload.

    The `isinstance` narrowing is not ceremony: ``content`` is a union of block types and only
    `TextContent` carries ``text``, so an unexpected block shape must fail as a wrong *type* rather
    than as an attribute error inside an assertion.
    """
    block = result.content[0]
    assert isinstance(block, TextContent), f"expected a text block, got {type(block).__name__}"
    remaining, correlation = block.text.split("|", 1)
    return remaining, correlation


async def _observe(server: FastMCP) -> tuple[str, str]:
    async with Client(server) as client:
        result = await client.call_tool("observe", {})
    return _reported(result)


class TestTheDeadlineIsArmedPerCall:
    """The primary assertion, with the control that makes it discriminating."""

    @pytest.mark.anyio
    async def test_an_expired_ambient_deadline_is_replaced_for_the_call(self) -> None:
        """The fix: a captured, expired instant does not reach the tool."""
        REQUEST_DEADLINE.set(time.monotonic() - _EXPIRED_BY)
        assert remaining_deadline_seconds() == 0.0, "the simulated capture must start expired"

        remaining, _ = await _observe(_observing_server(*_armed()))

        assert remaining != "none"
        assert float(remaining) > 0.0
        # Armed from scratch, so it must be within the granted budget rather than merely positive.
        assert float(remaining) <= _DEADLINE

    @pytest.mark.anyio
    async def test_without_the_middleware_the_tool_sees_the_expired_instant(self) -> None:
        """The control: the original defect reproduced.

        Same ambient state, middleware removed: the tool observes ``0.0``. This proves the test
        above is measuring the fix and not the harness.
        """
        REQUEST_DEADLINE.set(time.monotonic() - _EXPIRED_BY)

        remaining, _ = await _observe(_observing_server())

        assert remaining == "0.000"

    @pytest.mark.anyio
    async def test_every_call_is_armed_afresh_not_merely_the_first(self) -> None:
        """The failure persisted across every call in a session, so one call is not enough.

        Both calls share one `Client`, i.e. one MCP session -- which is the condition under which
        the defect appears at all.
        """
        REQUEST_DEADLINE.set(time.monotonic() - _EXPIRED_BY)
        server = _observing_server(*_armed())

        async with Client(server) as client:
            first = await client.call_tool("observe", {})
            await anyio.sleep(0.01)
            second = await client.call_tool("observe", {})

        for result in (first, second):
            remaining, _ = _reported(result)
            assert float(remaining) > 0.0


class TestTheAmbientContextIsLeftAsFound:
    """Both middlewares reset, so they cannot bound or mislabel the *next* piece of work."""

    @pytest.mark.anyio
    async def test_the_deadline_is_restored_after_a_successful_call(self) -> None:
        sentinel = time.monotonic() - _EXPIRED_BY
        REQUEST_DEADLINE.set(sentinel)

        await _observe(_observing_server(*_armed()))

        assert REQUEST_DEADLINE.get() == sentinel

    @pytest.mark.anyio
    async def test_the_deadline_is_restored_when_the_tool_raises(self) -> None:
        """A `finally`, not a trailing statement: a raising tool must not leak an armed
        deadline.
        """
        sentinel = time.monotonic() - _EXPIRED_BY
        REQUEST_DEADLINE.set(sentinel)
        server = _observing_server(*_armed())

        async with Client(server) as client:
            result = await client.call_tool("explode", {}, raise_on_error=False)
        assert result.is_error, "the control: the tool really did fail"

        assert REQUEST_DEADLINE.get() == sentinel


class TestTheCorrelationIdIsMintedPerCall:
    """The sibling half: a repeated identifier across calls is what made the defect visible."""

    @pytest.mark.anyio
    async def test_a_captured_identifier_does_not_reach_the_tool(self) -> None:
        CORRELATION_ID.set("capturedsessionid")

        _, correlation = await _observe(_observing_server(*_armed()))

        assert correlation != "capturedsessionid"

    @pytest.mark.anyio
    async def test_without_the_middleware_the_captured_identifier_reaches_the_tool(self) -> None:
        """The control: without the middleware, every call reports the same captured id."""
        CORRELATION_ID.set("capturedsessionid")

        _, correlation = await _observe(_observing_server())

        assert correlation == "capturedsessionid"

    @pytest.mark.anyio
    async def test_two_calls_in_one_session_get_different_identifiers(self) -> None:
        """The whole point: an operator can tell the failing call from its neighbours."""
        CORRELATION_ID.set("capturedsessionid")
        server = _observing_server(*_armed())

        async with Client(server) as client:
            first = await client.call_tool("observe", {})
            second = await client.call_tool("observe", {})

        _, left = _reported(first)
        _, right = _reported(second)
        assert left != right
        assert "capturedsessionid" not in {left, right}


class TestPlacingThemOutsideTheGateCannotUngateAnything:
    """The arming middlewares run ahead of `AuthorizationGate`; this checks that is safe.

    The gate refuses by not calling ``call_next``. Anything placed outside it must therefore always
    dispatch, or it could swallow a call before the gate decided, silently bypassing
    authorization.
    """

    @pytest.mark.anyio
    async def test_a_middleware_behind_them_still_runs(self) -> None:
        """Asserted by execution, because `app.py`'s comment claims it in prose."""
        seen: list[str] = []

        class Recorder(Middleware):
            async def on_call_tool(
                self,
                context: MiddlewareContext[mt.CallToolRequestParams],
                call_next: CallNext[mt.CallToolRequestParams, ToolResult],
            ) -> ToolResult:
                seen.append(context.message.name)
                return await call_next(context)

        REQUEST_DEADLINE.set(time.monotonic() - _EXPIRED_BY)
        await _observe(_observing_server(*_armed(), Recorder()))

        assert seen == ["observe"], "a middleware behind the arming pair did not run"

    def test_the_built_server_arms_context_before_the_authorization_gate(
        self, config: Config
    ) -> None:
        """The wiring itself, not a reconstruction of it.

        Guards the ordering: if someone moves `AuthorizationGate` back to index 0, its
        SL1 hook fetch silently returns to running on the captured deadline.
        """
        from powerpack_mcp.lce_client import LceClient
        from powerpack_mcp.mcp_app.app import build_mcp_server
        from powerpack_mcp.mcp_app.authz_gate import AuthorizationGate
        from powerpack_mcp.sl1_client import Sl1Client

        server = build_mcp_server(config, LceClient(config), Sl1Client(config))
        registered = [type(m) for m in server.middleware]

        assert registered.index(ToolCallCorrelationMiddleware) < registered.index(
            RequestDeadlineMiddleware
        )
        assert registered.index(RequestDeadlineMiddleware) < registered.index(AuthorizationGate)


class TestTheCapturedContextMechanism:
    """Pins the anyio behaviour the fix exists to defeat. Not a test of our code.

    Without this, a future refactor could revert to an ASGI-only deadline and every test above
    would still pass, because they exercise the middleware directly, not the transport that
    strands it.
    """

    @pytest.mark.anyio
    async def test_a_task_spawned_inside_a_request_keeps_the_captured_deadline(self) -> None:
        """The reset restores the setter's context and cannot reach the spawned task's copy."""
        observed: list[float | None] = []

        async def session_task(*, task_status: TaskStatus[None]) -> None:
            task_status.started()
            await anyio.sleep(0.02)
            observed.append(REQUEST_DEADLINE.get())

        # The task group is created outside the "request", exactly as the session manager's is
        # created at app startup.
        armed = time.monotonic() + _DEADLINE

        async with anyio.create_task_group() as task_group:
            token = REQUEST_DEADLINE.set(armed)
            await task_group.start(session_task)
            REQUEST_DEADLINE.reset(token)

            assert REQUEST_DEADLINE.get() is None, "the setter's own context is restored"

        assert observed == [armed], "the spawned task still holds the captured instant"

"""
Concurrency Gate Tests

This module tests ``mcp_app.concurrency``, the inbound gate that bounds concurrent tool calls and
applies a per-request deadline. It covers the rejection shape, the 503 status, the
``concurrency_limited`` record, the ``/health`` exemption and the POST-only method scope.

The invariant "at most N tool calls are in flight" is not tested by execution, because stateful
concurrency tests are a known source of flakiness. Saturation is made deterministic by
pre-acquiring the semaphore. The deadline is covered by a property-based test over timing
schedules, since ``httpx``'s read timeout is a per-chunk allowance, not a total-request deadline,
and no example table would expose that. The property asserts boundedness, not precise timing.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from powerpack_mcp.config import (
    MAX_CONCURRENT_REQUESTS_CEILING,
    MIN_CONCURRENT_REQUESTS,
    Config,
)
from powerpack_mcp.errors import LogEvent
from powerpack_mcp.mcp_app.concurrency import EXEMPT_PATHS, ConcurrencyGateMiddleware
from powerpack_mcp.mcp_app.routes import HEALTH_PATH

if TYPE_CHECKING:
    from starlette.types import Receive, Scope, Send

# ``deadline_seconds`` is a required constructor parameter, because a default would leave a
# construction silently unbounded. This value is far larger than anything these tests do: they
# exercise the semaphore, not the deadline, and a deadline that could fire here would make them
# flaky. ``TestRequestDeadline`` tests the deadline with a small value on purpose.
NEVER_FIRES = 3600.0

_SERVICE_UNAVAILABLE = 503


class _RecordingApp:
    """A downstream ASGI app that records every scope it is handed."""

    def __init__(self) -> None:
        self.calls: list[Scope] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        del receive
        self.calls.append(scope)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})


async def _noop_receive() -> dict[str, Any]:  # pragma: no cover - never awaited in these tests
    return {"type": "http.request"}


def _collector() -> tuple[list[dict[str, Any]], Send]:
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    return sent, send  # type: ignore[return-value]


def _http_scope(path: str = "/mcp") -> dict[str, Any]:
    return {"type": "http", "path": path, "method": "POST", "headers": []}


class TestPassThrough:
    @pytest.mark.anyio
    async def test_a_request_below_the_bound_reaches_the_application(self) -> None:
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=2, deadline_seconds=NEVER_FIRES)
        _sent, send = _collector()
        await gate(_http_scope(), _noop_receive, send)  # type: ignore[arg-type]
        assert len(app.calls) == 1

    @pytest.mark.anyio
    async def test_non_http_scopes_pass_through_ungated(self) -> None:
        """A lifespan scope has no path and must never be gated."""
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        _sent, send = _collector()
        await gate({"type": "lifespan"}, _noop_receive, send)  # type: ignore[arg-type]
        assert len(app.calls) == 1

    @pytest.mark.anyio
    async def test_the_semaphore_is_released_after_each_request(self) -> None:
        """Sequential requests beyond the bound must all succeed -- the bound is on *concurrent*
        requests, not a quota.
        """
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        for _ in range(5):
            _sent, send = _collector()
            await gate(_http_scope(), _noop_receive, send)  # type: ignore[arg-type]
        assert len(app.calls) == 5


class TestRejection:
    """What a caller gets when the bound is hit, which uvicorn's own limiter gets wrong."""

    @staticmethod
    async def _saturated_rejection() -> tuple[list[dict[str, Any]], _RecordingApp]:
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        # Pre-acquire so saturation is deterministic, not a race.
        await gate._semaphore.acquire()
        sent, send = _collector()
        await gate(_http_scope(), _noop_receive, send)  # type: ignore[arg-type]
        return sent, app

    @pytest.mark.anyio
    async def test_the_excess_request_never_reaches_the_application(self) -> None:
        _sent, app = await self._saturated_rejection()
        assert app.calls == [], "a rejected request must not reach the application"

    @pytest.mark.anyio
    async def test_the_status_is_503(self) -> None:
        sent, _app = await self._saturated_rejection()
        assert sent[0]["status"] == _SERVICE_UNAVAILABLE

    @pytest.mark.anyio
    async def test_the_body_is_the_standard_json_envelope(self) -> None:
        """uvicorn's ``limit_concurrency`` returns ``text/plain`` "Service Unavailable", which a
        programmatic client cannot parse. This must be the project's own JSON envelope.
        """
        sent, _app = await self._saturated_rejection()
        headers = dict(sent[0]["headers"])
        assert headers[b"content-type"] == b"application/json"
        payload = json.loads(sent[1]["body"])
        assert payload["error"]["type"] == "concurrency_limited"

    @pytest.mark.anyio
    async def test_the_message_advises_retry_not_bug_reporting(self) -> None:
        """``internal_error`` is not reused because its message says to report a bug, not retry."""
        sent, _app = await self._saturated_rejection()
        message = json.loads(sent[1]["body"])["error"]["message"]
        assert "retry" in message.lower()
        assert "report" not in message.lower()

    @pytest.mark.anyio
    async def test_content_length_matches_the_body(self) -> None:
        sent, _app = await self._saturated_rejection()
        headers = dict(sent[0]["headers"])
        assert int(headers[b"content-length"]) == len(sent[1]["body"])

    @pytest.mark.anyio
    async def test_an_event_keyed_record_is_emitted(self, caplog: pytest.LogCaptureFixture) -> None:
        """uvicorn's limiter replaces the application, so no ``event``-keyed record is emitted.

        Monitoring keys on ``event``, never on message text.
        """
        with caplog.at_level(logging.WARNING):
            await self._saturated_rejection()
        events = [getattr(r, "event", None) for r in caplog.records]
        assert LogEvent.CONCURRENCY_LIMITED in events

    @pytest.mark.anyio
    async def test_the_record_carries_the_configured_limit(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """So an operator can tell whether the bound is simply too low for real traffic."""
        with caplog.at_level(logging.WARNING):
            await self._saturated_rejection()
        record = next(
            r for r in caplog.records if getattr(r, "event", None) == LogEvent.CONCURRENCY_LIMITED
        )
        assert getattr(record, "concurrency_limit", None) == 1


class TestProbeExemption:
    """A 503 from the liveness probe could make systemd restart a service that is merely busy,
    turning a capacity condition into an outage.
    """

    def test_health_is_the_only_exempt_path(self) -> None:
        """``/health`` is the only probe; there is no ``/ready``."""
        assert {HEALTH_PATH} == EXEMPT_PATHS

    @pytest.mark.anyio
    @pytest.mark.parametrize("path", [HEALTH_PATH])
    async def test_probes_pass_through_even_when_saturated(self, path: str) -> None:
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        await gate._semaphore.acquire()
        _sent, send = _collector()
        await gate(_http_scope(path), _noop_receive, send)  # type: ignore[arg-type]
        assert len(app.calls) == 1, f"{path} must never be throttled"

    @pytest.mark.anyio
    async def test_a_tool_path_is_still_rejected_when_saturated(self) -> None:
        """The exemption must be narrow: only the ``/health`` probe, not everything."""
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        await gate._semaphore.acquire()
        sent, send = _collector()
        await gate(_http_scope("/mcp"), _noop_receive, send)  # type: ignore[arg-type]
        assert app.calls == []
        assert sent[0]["status"] == _SERVICE_UNAVAILABLE


class TestConfigIntegration:
    """The bound is an operator-tunable, validated ``Config`` key."""

    def test_default_is_six(self) -> None:
        """Below the measured breach point of about 7.6 requests against ``MemoryMax=512M``."""
        assert Config().MAX_CONCURRENT_REQUESTS == 6

    @pytest.mark.parametrize("value", [MIN_CONCURRENT_REQUESTS, 6, MAX_CONCURRENT_REQUESTS_CEILING])
    def test_the_valid_range_is_accepted(self, value: int) -> None:
        assert value == Config(MAX_CONCURRENT_REQUESTS=value).MAX_CONCURRENT_REQUESTS

    @pytest.mark.parametrize(
        "value", [0, -1, MAX_CONCURRENT_REQUESTS_CEILING + 1, MAX_CONCURRENT_REQUESTS_CEILING * 10]
    )
    def test_out_of_range_fails_startup_rather_than_being_clamped(self, value: int) -> None:
        """A silently clamped bound would be a misconfiguration an operator never learns about."""
        from pydantic import ValidationError

        from powerpack_mcp.errors import ConfigurationError

        with pytest.raises((ValidationError, ConfigurationError, ValueError)):
            Config(MAX_CONCURRENT_REQUESTS=value)

    def test_the_gate_is_registered_with_the_configured_limit(self) -> None:
        """The wiring, not just the value: `create_app` must pass the `Config` key through."""
        from powerpack_mcp.mcp_app import create_app

        app = create_app(Config(MAX_CONCURRENT_REQUESTS=3))
        assert app is not None


class TestMethodScope:
    """Only POST is gated.

    Holding a slot for every method starves the gate: long-lived streamable-HTTP GET streams, which
    the nginx fragment gives ``proxy_read_timeout 3600s``, would consume every slot and each POST
    would get a 503.
    """

    @staticmethod
    def _scope(method: str, path: str = "/mcp") -> dict[str, Any]:
        return {"type": "http", "path": path, "method": method, "headers": []}

    @pytest.mark.anyio
    @pytest.mark.parametrize("method", ["GET", "DELETE", "HEAD", "OPTIONS"])
    async def test_a_bodyless_method_passes_through_even_when_saturated(self, method: str) -> None:
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        await gate._semaphore.acquire()
        _sent, send = _collector()
        await gate(self._scope(method), _noop_receive, send)  # type: ignore[arg-type]
        assert len(app.calls) == 1, f"{method} carries no body, so it must not be gated"

    @pytest.mark.anyio
    async def test_post_is_still_rejected_when_saturated(self) -> None:
        """The other half: narrowing the gate must not disable it."""
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        await gate._semaphore.acquire()
        sent, send = _collector()
        await gate(self._scope("POST"), _noop_receive, send)  # type: ignore[arg-type]
        assert app.calls == []
        assert sent[0]["status"] == _SERVICE_UNAVAILABLE

    @pytest.mark.anyio
    async def test_idle_streams_no_longer_starve_a_post(self) -> None:
        """The starvation scenario end to end, at the real default bound of 6.

        Six concurrent GET streams must not stop a seventh request, a POST, from being admitted.
        """
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=6, deadline_seconds=NEVER_FIRES)
        for _ in range(6):
            _sent, send = _collector()
            await gate(self._scope("GET"), _noop_receive, send)  # type: ignore[arg-type]
        sent, send = _collector()
        await gate(self._scope("POST"), _noop_receive, send)  # type: ignore[arg-type]
        assert len(app.calls) == 7, "the POST must reach the application, not be 503'd"
        assert sent[0]["status"] == 200

    @pytest.mark.anyio
    async def test_a_scope_without_a_method_passes_through_rather_than_raising(self) -> None:
        """`scope.get`, not `scope["method"]`.

        ASGI guarantees the key on an HTTP scope, but a `KeyError` raised *inside* middleware sits
        outside `ServerErrorMiddleware`'s frame, so it would surface as a bare 500 with no
        `unhandled_exception` record. Failing open on a malformed scope is the lesser evil, and it
        is asserted rather than left to chance.
        """
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        _sent, send = _collector()
        await gate(  # type: ignore[arg-type]
            {"type": "http", "path": "/mcp", "headers": []}, _noop_receive, send
        )
        assert len(app.calls) == 1


class _SlowApp:
    """A downstream ASGI app that takes ``delay`` seconds before responding.

    A stub rather than a loopback server, so the suite needs no network and does not flake on a
    loaded CI host. The ``httpx`` timeout behaviour that motivated the deadline was found with a
    real loopback server; what needs pinning per commit is the gate's own behaviour.
    """

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.completed = False

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        del scope, receive
        await asyncio.sleep(self.delay)
        self.completed = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})


def _post_scope(path: str = "/mcp") -> dict[str, Any]:
    return {"type": "http", "method": "POST", "path": path}


class TestRequestDeadline:
    """The per-request deadline that releases a slot held by a slow downstream call."""

    @pytest.mark.anyio
    async def test_a_slow_request_does_not_hold_its_slot_indefinitely(self) -> None:
        """A read timeout could not deliver this.

        ``httpx``'s read timeout is a per-chunk allowance: at 0.5s against 0.2s gaps, a response
        completed in 3.03s without raising. The slot was held for as long as the backend took, and
        six such requests fill the whole gate.
        """
        app = _SlowApp(delay=10.0)
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=0.05)
        _, send = _collector()

        await gate(_post_scope(), _noop_receive, send)  # type: ignore[arg-type]

        assert app.completed is False, "the downstream call should have been cancelled"

    @pytest.mark.anyio
    async def test_the_slot_is_released_so_a_later_request_is_admitted(self) -> None:
        """The slot must come back, not merely the slow call fail.

        A gate that timed out the request but leaked the slot would pass a weaker test and still
        be broken.
        """
        slow = _SlowApp(delay=10.0)
        gate = ConcurrencyGateMiddleware(slow, limit=1, deadline_seconds=0.05)
        _, send = _collector()
        await gate(_post_scope(), _noop_receive, send)

        # Same gate, same single slot: this can only succeed if the slot came back.
        fast = _RecordingApp()
        gate._app = fast  # substituting downstream to reuse the one slot
        sent, send2 = _collector()
        await gate(_post_scope(), _noop_receive, send2)  # type: ignore[arg-type]

        assert len(fast.calls) == 1
        assert sent[0]["status"] == 200, "the slot was not released by the deadline"

    @pytest.mark.anyio
    async def test_it_emits_the_deadline_event(self, caplog: pytest.LogCaptureFixture) -> None:
        """Without this record the failure is invisible to monitoring, which keys on ``event``."""
        app = _SlowApp(delay=10.0)
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=0.05)
        _, send = _collector()

        with caplog.at_level(logging.WARNING):
            await gate(_post_scope(), _noop_receive, send)  # type: ignore[arg-type]

        events = [r for r in caplog.records if getattr(r, "event", None)]
        actual = [getattr(r, "event") for r in events]  # noqa: B009
        assert actual == [LogEvent.REQUEST_DEADLINE_EXCEEDED]
        assert events[0].deadline_seconds == 0.05  # type: ignore[attr-defined]

    @pytest.mark.anyio
    async def test_the_deadline_event_is_not_the_concurrency_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """They demand opposite operator responses, so conflating them would mislead."""
        app = _SlowApp(delay=10.0)
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=0.05)
        _, send = _collector()

        with caplog.at_level(logging.WARNING):
            await gate(_post_scope(), _noop_receive, send)  # type: ignore[arg-type]

        emitted = {getattr(r, "event", None) for r in caplog.records}
        assert LogEvent.CONCURRENCY_LIMITED not in emitted

    @pytest.mark.anyio
    async def test_a_fast_request_is_untouched(self) -> None:
        """The deadline must be invisible in the normal case."""
        app = _RecordingApp()
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=NEVER_FIRES)
        sent, send = _collector()

        await gate(_post_scope(), _noop_receive, send)  # type: ignore[arg-type]

        assert sent[0]["status"] == 200
        assert len(app.calls) == 1

    @pytest.mark.anyio
    async def test_the_constructor_requires_a_deadline(self) -> None:
        """No default, so an omission fails loudly rather than silently leaving the guard off."""
        with pytest.raises(TypeError, match="deadline_seconds"):
            ConcurrencyGateMiddleware(_RecordingApp(), limit=1)  # type: ignore[call-arg]


class TestDeadlineRespectsTheGatesOwnFilter:
    """The deadline applies only to requests the gate itself admits.

    The streamable-HTTP GET handler opens long-lived streams that the nginx fragment provisions
    ``proxy_read_timeout 3600s`` for, and a deadline on those would sever every session. The
    deadline reuses the gate's POST-only filter, and these tests stop the two drifting apart.
    """

    @pytest.mark.anyio
    @pytest.mark.parametrize("method", ["GET", "DELETE"])
    async def test_a_long_lived_non_post_stream_outlives_the_deadline(self, method: str) -> None:
        app = _SlowApp(delay=0.2)
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=0.01)
        sent, send = _collector()

        await gate(  # type: ignore[arg-type]
            {"type": "http", "method": method, "path": "/mcp"}, _noop_receive, send
        )

        assert app.completed is True, f"{method} must not be bounded by the deadline"
        assert sent[0]["status"] == 200

    @pytest.mark.anyio
    async def test_the_exempt_health_path_outlives_the_deadline(self) -> None:
        """Throttling or aborting the liveness probe turns a capacity condition into an outage."""
        app = _SlowApp(delay=0.2)
        gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=0.01)
        sent, send = _collector()

        await gate({"type": "http", "method": "POST", "path": HEALTH_PATH}, _noop_receive, send)

        assert app.completed is True
        assert sent[0]["status"] == 200


class TestDeadlineHoldTimeProperty:
    """Property test over timing schedules, the input space where the missing deadline hid.

    A hand-picked example table does not explore response timing, so Hypothesis generates
    schedules instead.
    """

    @given(
        deadline=st.floats(min_value=0.02, max_value=0.06),
        overrun=st.floats(min_value=2.0, max_value=20.0),
    )
    @settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_hold_time_never_exceeds_the_deadline(self, deadline: float, overrun: float) -> None:
        """For any deadline and any downstream duration, the slot is held at most the deadline
        (plus scheduling slack).
        """

        async def scenario() -> float:
            app = _SlowApp(delay=deadline * overrun)
            gate = ConcurrencyGateMiddleware(app, limit=1, deadline_seconds=deadline)
            _, send = _collector()
            start = time.monotonic()
            await gate(_post_scope(), _noop_receive, send)  # type: ignore[arg-type]
            return time.monotonic() - start

        held = asyncio.run(scenario())
        # A generous margin: this asserts boundedness, not the event loop's wake-up precision. An
        # unbounded hold would be ``deadline * overrun``.
        assert held < deadline + 0.5, f"held {held:.3f}s against a {deadline:.3f}s deadline"

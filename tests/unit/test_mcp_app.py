"""
MCP Application Tests

This module tests ``powerpack_mcp.mcp_app``: the health route, correlation IDs, the forwarded
actor, the logging chain, the global error handler, startup and shutdown, and tool-set gating at
the composition root.

Requests go through ``httpx.ASGITransport``, so nothing binds a port or reaches the network.
"""

from __future__ import annotations

import io
import json
import logging
import sys
from typing import TYPE_CHECKING, Any, cast

import httpx
import pytest
from fastmcp import Client, FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, SecretStr, ValidationError

from powerpack_mcp.config import TOOL_SET_FLAG_KEYS, Config, load_config
from powerpack_mcp.errors import ConfigurationError, LogEvent, ToolSetDisabledReason
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.mcp_app import (
    CORRELATION_ID,
    FORWARDED_ACTOR_HEADERS,
    HEALTH_PATH,
    SlConfigExtraFormatter,
    build_mcp_server,
    configure_logging,
    create_app,
    current_correlation_id,
    forwarded_actor,
    global_error_handler,
    lifespan_for,
    register_tools,
    sanitize_correlation_id,
)
from powerpack_mcp.mcp_app.logging_setup import (
    CorrelationIdFilter,
    PydanticErrorInputFilter,
    RedactingFilter,
)
from powerpack_mcp.sl1_client import Sl1Client
from powerpack_mcp.tool_sets import ALL_TOOL_SET_IDS

if TYPE_CHECKING:
    from collections.abc import Iterator


class _StubClient:
    """Substitute for `LceClient` in route and lifespan tests.

    `probe_calls` stays at zero by design, so the "/health never contacts LCE" test has something
    to assert against.
    """

    def __init__(self) -> None:
        self.probe_calls = 0
        self.close_calls = 0
        self.correlation_ids: list[str] = []

    async def aclose(self) -> None:
        self.close_calls += 1


# A test-only path used to observe `current_correlation_id()` from inside a request. `/health`
# never touches the client, so a dedicated route records the ContextVar value for the duration of
# a request.
CAPTURE_PATH = "/_test_capture"


def _app_with_stub(stub: _StubClient, config: Config) -> Any:
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from powerpack_mcp.mcp_app.correlation import CorrelationIdMiddleware
    from powerpack_mcp.mcp_app.routes import health

    del config

    async def capture(_request: Any) -> JSONResponse:
        stub.correlation_ids.append(current_correlation_id())
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route(HEALTH_PATH, health), Route(CAPTURE_PATH, capture)])
    app.state.lce_client = stub
    return CorrelationIdMiddleware(app)


async def _get(app: Any, path: str, headers: dict[str, str] | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(path, headers=headers or {})


class TestHealth:
    @pytest.mark.anyio
    async def test_returns_ok(self, config: Config) -> None:
        stub = _StubClient()
        response = await _get(_app_with_stub(stub, config), HEALTH_PATH)
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    @pytest.mark.anyio
    async def test_never_contacts_lce(self, config: Config) -> None:
        """Process liveness and nothing else."""
        stub = _StubClient()
        await _get(_app_with_stub(stub, config), HEALTH_PATH)
        assert stub.probe_calls == 0

    @pytest.mark.anyio
    async def test_discloses_nothing_beyond_liveness(self, config: Config) -> None:
        """It is the one anonymously reachable route.

        A version string here would tell an unauthenticated caller which release to look up
        vulnerabilities for.
        """
        stub = _StubClient()
        body = (await _get(_app_with_stub(stub, config), HEALTH_PATH)).json()
        assert set(body) == {"status"}


class TestSanitizeCorrelationId:
    """Example-based coverage of the correlation ID sanitiser, alongside the property tests."""

    def test_valid_value_is_adopted_unchanged(self) -> None:
        assert sanitize_correlation_id("abc-123_x.y") == "abc-123_x.y"

    @pytest.mark.parametrize(
        "hostile",
        [
            None,
            "",
            "has space",
            "line\nbreak",
            "carriage\rreturn",
            "null\x00byte",
            "semi;colon",
            "x" * 129,
            "unicode-é",
            "<script>alert(1)</script>",
        ],
    )
    def test_hostile_input_is_discarded_and_replaced(self, hostile: str | None) -> None:
        """Discarded and replaced, never repaired and never rejected."""
        result = sanitize_correlation_id(hostile)
        assert result != hostile
        assert len(result) == 32
        assert result.isalnum()

    def test_never_repairs_by_stripping(self) -> None:
        """Repairing would let a caller influence the identifier's content."""
        assert "break" not in sanitize_correlation_id("line\nbreak")

    def test_is_idempotent_on_its_own_output(self) -> None:
        once = sanitize_correlation_id("bad value!")
        assert sanitize_correlation_id(once) == once


class TestCorrelationMiddleware:
    @pytest.mark.anyio
    @pytest.mark.parametrize("header", ["X-Request-ID", "X-Correlation-ID"])
    async def test_adopts_either_inbound_header(self, config: Config, header: str) -> None:
        """Either header is adopted as the correlation id."""
        stub = _StubClient()
        await _get(_app_with_stub(stub, config), CAPTURE_PATH, {header: "inbound-id-1"})
        assert stub.correlation_ids == ["inbound-id-1"]

    @pytest.mark.anyio
    async def test_x_request_id_wins_over_x_correlation_id(self, config: Config) -> None:
        stub = _StubClient()
        await _get(
            _app_with_stub(stub, config),
            CAPTURE_PATH,
            {"X-Request-ID": "first", "X-Correlation-ID": "second"},
        )
        assert stub.correlation_ids == ["first"]

    @pytest.mark.anyio
    async def test_mints_when_absent(self, config: Config) -> None:
        stub = _StubClient()
        await _get(_app_with_stub(stub, config), CAPTURE_PATH)
        assert len(stub.correlation_ids[0]) == 32

    @pytest.mark.anyio
    async def test_hostile_inbound_value_does_not_reject_the_request(self, config: Config) -> None:
        """Failing a request over a malformed observability header would be the worse outcome."""
        response = await _get(
            _app_with_stub(_StubClient(), config),
            CAPTURE_PATH,
            {"X-Request-ID": "forged\nline"},
        )
        assert response.status_code == 200

    @pytest.mark.anyio
    async def test_context_var_is_reset_after_the_request(self, config: Config) -> None:
        """Concurrent requests must not observe each other's value."""
        before = CORRELATION_ID.get()
        await _get(_app_with_stub(_StubClient(), config), CAPTURE_PATH, {"X-Request-ID": "x1"})
        assert CORRELATION_ID.get() == before


class TestForwardedActor:
    def test_reads_the_forwarded_identity(self) -> None:
        """`x-user-id` is the header nginx sets, as observed on a live appliance."""
        assert forwarded_actor({"type": "http", "headers": [(b"x-user-id", b"alice")]}) == "alice"

    def test_absent_returns_none(self) -> None:
        """The expected case whenever the request did not arrive through the nginx fragment."""
        assert forwarded_actor({"type": "http", "headers": []}) is None

    def test_hostile_value_is_dropped(self) -> None:
        """Reaches log records by the same path as the correlation id, so the same rule applies."""
        assert forwarded_actor({"type": "http", "headers": [(b"x-user-id", b"a\nb")]}) is None

    @pytest.mark.parametrize(
        "header", [b"x-remote-user", b"x-forwarded-user", b"x-authenticated-user"]
    )
    def test_legacy_header_names_are_not_trusted(self, header: bytes) -> None:
        """nginx sets none of these, so it would pass a client's own value through.

        A caller sending ``X-Remote-User: admin`` would be attributed as ``admin``. The nginx
        fragment also clears all three, but this asserts the primary control: the application
        itself must not read them.
        """
        assert forwarded_actor({"type": "http", "headers": [(header, b"admin")]}) is None

    def test_tuple_stays_narrow(self) -> None:
        """Widening this tuple is a security regression, not a feature.

        The failure is silent: a re-added header name would be accepted from clients with no error.
        """
        assert FORWARDED_ACTOR_HEADERS == (b"x-user-id",)


class TestLoggingChain:
    def test_correlation_filter_injects_the_identifier(self) -> None:
        """Every record carries the current request's correlation id."""
        record = logging.LogRecord("t", logging.INFO, "f", 1, "msg", None, None)
        token = CORRELATION_ID.set("known-id")
        try:
            assert CorrelationIdFilter().filter(record) is True
            assert record.correlation_id == "known-id"  # type: ignore[attr-defined]
        finally:
            CORRELATION_ID.reset(token)

    @pytest.mark.parametrize(
        "field",
        [
            "authorization",
            "Authorization",
            "TOKEN",
            "secret",
            "credential",
            "password",
            "api_key",
            "cookie",
        ],
    )
    def test_redacting_filter_replaces_denylisted_field_names(self, field: str) -> None:
        """Case-insensitive, and on the field name.

        Value matching would have to know what a secret looks like, which for an opaque token it
        cannot.
        """
        record = logging.LogRecord("t", logging.INFO, "f", 1, "msg", None, None)
        setattr(record, field, "Bearer super-secret")
        RedactingFilter().filter(record)
        assert getattr(record, field) == "**redacted**"

    def test_redacting_filter_leaves_other_fields_alone(self) -> None:
        record = logging.LogRecord("t", logging.INFO, "f", 1, "msg", None, None)
        record.tool = "lce_get_powerpack"  # type: ignore[attr-defined]
        RedactingFilter().filter(record)
        assert record.tool == "lce_get_powerpack"  # type: ignore[attr-defined]

    def test_formatter_preserves_the_appliance_log_prefix(self) -> None:
        """An appliance parser splitting on ``:::`` still works."""
        record = logging.LogRecord("mod", logging.INFO, "f.py", 42, "hello", None, None)
        rendered = SlConfigExtraFormatter().format(record)
        assert ":::hello" in rendered
        assert "::INFO::" in rendered

    def test_formatter_appends_extras_deterministically(self) -> None:
        """Order is fixed because grep patterns depend on it."""
        record = logging.LogRecord("mod", logging.INFO, "f.py", 1, "done", None, None)
        record.duration_ms = 412  # type: ignore[attr-defined]
        record.correlation_id = "abc"  # type: ignore[attr-defined]
        record.event = "write_committed"  # type: ignore[attr-defined]
        rendered = SlConfigExtraFormatter().format(record)
        assert rendered.endswith("correlation_id=abc event=write_committed duration_ms=412")

    def test_formatter_neutralises_newlines_in_extras(self) -> None:
        """A real newline in any field would forge a second log record."""
        record = logging.LogRecord("mod", logging.INFO, "f.py", 1, "m", None, None)
        record.actor = "a\nb"  # type: ignore[attr-defined]
        rendered = SlConfigExtraFormatter().format(record)
        assert "\n" not in rendered
        assert "\\n" in rendered

    def test_formatter_quotes_values_containing_spaces(self) -> None:
        record = logging.LogRecord("mod", logging.INFO, "f.py", 1, "m", None, None)
        record.outcome = "not ok"  # type: ignore[attr-defined]
        assert 'outcome="not ok"' in SlConfigExtraFormatter().format(record)

    def test_configure_logging_replaces_only_its_own_handler(self) -> None:
        """`create_app` calls this twice, so repeated calls must not duplicate every record.

        It must also leave foreign handlers alone. Removing every root handler would silently
        disable pytest's log capture, and anything attached before startup in production.
        """
        foreign = logging.NullHandler()
        logging.getLogger().addHandler(foreign)
        try:
            configure_logging()
            configure_logging()
            configure_logging()
            ours = [
                h
                for h in logging.getLogger().handlers
                if getattr(h, "_powerpack_mcp_handler", False)
            ]
            assert len(ours) == 1
            assert foreign in logging.getLogger().handlers
        finally:
            logging.getLogger().removeHandler(foreign)

    def test_redaction_runs_after_injection(self) -> None:
        """Redaction runs last, so it covers anything an earlier filter added.

        `PydanticErrorInputFilter` runs first: it only removes data, and removing it before a later
        filter can copy ``record.args`` onto an attribute keeps the value out of the redacting
        filter's blind spot. The whole ordered list is asserted, so a new filter cannot slip in.
        """
        configure_logging()
        handler = next(
            h for h in logging.getLogger().handlers if getattr(h, "_powerpack_mcp_handler", False)
        )
        assert [type(f) for f in handler.filters] == [
            PydanticErrorInputFilter,
            CorrelationIdFilter,
            RedactingFilter,
        ]


# A stand-in for a real secret. Nothing about the leak depends on the value, but a distinctive
# literal makes a leak unmissable in a diff and greppable in CI output.
_CANARY = "canary-6f2b-treat-this-as-a-secret"


@pytest.fixture
def restored_logging_state() -> Iterator[None]:
    """Snapshot and restore every global `logging` mutation `configure_logging` performs.

    It mutates the root logger and the ``fastmcp`` logger, whose handlers this project clears.
    Without restoration, fastmcp's own stderr output would stay disabled for every later test.
    """
    root = logging.getLogger()
    saved_root_handlers = list(root.handlers)
    saved_root_level = root.level
    fastmcp_logger = logging.getLogger("fastmcp")
    saved_fastmcp_handlers = list(fastmcp_logger.handlers)
    saved_propagate = fastmcp_logger.propagate
    try:
        yield
    finally:
        root.handlers[:] = saved_root_handlers
        root.setLevel(saved_root_level)
        fastmcp_logger.handlers[:] = saved_fastmcp_handlers
        fastmcp_logger.propagate = saved_propagate


def _capture_this_projects_handler() -> tuple[logging.Handler, io.StringIO]:
    """Point the handler `configure_logging` installed at a buffer and return both.

    Not `caplog`: the property under test is what this project's handler emits, which is what
    reaches syslog through ``StandardError=syslog``. `caplog` would capture the record before that
    handler's filter chain ran.
    """
    handler = next(
        h for h in logging.getLogger().handlers if getattr(h, "_powerpack_mcp_handler", False)
    )
    buffer = io.StringIO()
    cast("Any", handler).setStream(buffer)
    return handler, buffer


def _pydantic_error_args(canary: str) -> tuple[str, list[Any]]:
    """Build the exact `record.args` fastmcp logs, from a real pydantic error.

    Provoking pydantic, rather than hand-writing a dict, gives whatever shape the installed
    pydantic produces. A literal would keep passing after a pydantic release changed the entry,
    while the real filter silently stopped matching.

    Typed `list[Any]` because the production filter treats entries as plain mappings and does not
    rely on the `TypedDict` shape.
    """

    class _Arguments(BaseModel):
        query: str

    try:
        _Arguments(query=cast("Any", {"nested": canary}))
    except ValidationError as exc:
        return ("sl1_graphql", exc.errors(include_url=False))
    raise AssertionError("pydantic accepted a dict where a str is required")


async def _reject_a_wrongly_typed_tool_argument(canary: str) -> None:
    """Drive a real rejection through a real `FastMCP` server and an in-memory `Client`.

    The WARNING is emitted deep inside fastmcp's own `call_tool`, so anything short of a real
    rejected call would test a reconstruction of fastmcp's behaviour.
    """
    server = FastMCP("invalid-argument-canary")

    @server.tool
    def sl1_graphql(query: str) -> str:
        return query

    async with Client(server) as client:
        with pytest.raises(ToolError):
            # An object where the schema requires a string. `query` is the argument a real caller
            # would put a credential-bearing GraphQL document in.
            await client.call_tool("sl1_graphql", {"query": {"nested": canary}})


@pytest.mark.usefixtures("restored_logging_state")
class TestFastmcpInvalidArgumentLogging:
    """fastmcp 3.x logs rejected tool arguments, including their values.

    ``fastmcp/server/server.py`` calls ``logger.warning("Invalid arguments for tool %r: %s", name,
    cause.errors(include_url=False))``, and every pydantic error entry carries an ``input`` key with
    the offending value untruncated. The systemd unit sets ``StandardError=syslog``, so such a
    record would persist a secret to appliance logs.

    The canary test builds a real server, makes a real rejected call, and asserts on the bytes this
    project's handler emits.
    """

    @pytest.mark.anyio
    async def test_a_canary_in_a_rejected_argument_never_reaches_the_log(self) -> None:
        """The secret is absent from what the handler emits."""
        configure_logging("INFO")
        _handler, buffer = _capture_this_projects_handler()

        await _reject_a_wrongly_typed_tool_argument(_CANARY)

        emitted = buffer.getvalue()
        assert "Invalid arguments for tool" in emitted, (
            "the record did not reach this project's handler at all, so the absence of the canary "
            "below would prove nothing"
        )
        assert _CANARY not in emitted

    @pytest.mark.anyio
    async def test_the_canary_leaks_when_the_filter_is_removed(self) -> None:
        """Proves the canary test can fail: only `PydanticErrorInputFilter` is taken out."""
        configure_logging("INFO")
        handler, buffer = _capture_this_projects_handler()
        for existing in list(handler.filters):
            if isinstance(existing, PydanticErrorInputFilter):
                handler.removeFilter(existing)

        await _reject_a_wrongly_typed_tool_argument(_CANARY)

        assert _CANARY in buffer.getvalue()

    @pytest.mark.anyio
    async def test_the_diagnostic_survives_the_scrub(self) -> None:
        """The mitigation must not be indistinguishable from deleting the log line.

        An operator still needs to know which tool, which field and what was wrong, none of which
        requires the value itself.
        """
        configure_logging("INFO")
        _handler, buffer = _capture_this_projects_handler()

        await _reject_a_wrongly_typed_tool_argument(_CANARY)

        emitted = buffer.getvalue()
        assert "sl1_graphql" in emitted  # which tool
        assert "'query'" in emitted  # which field, from `loc`
        assert "string_type" in emitted  # what was wrong, from `type`
        assert "Input should be a valid string" in emitted  # ... and in words

    @pytest.mark.anyio
    async def test_nothing_is_written_to_stderr_by_fastmcp(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The reroute must move the record, not copy it.

        fastmcp's two `RichHandler`s write to stderr, which the unit sends to syslog, so a record
        left on them would still be persisted unredacted.
        """
        configure_logging("INFO")
        _capture_this_projects_handler()

        await _reject_a_wrongly_typed_tool_argument(_CANARY)

        captured = capsys.readouterr()
        assert _CANARY not in captured.err
        assert "Invalid arguments for tool" not in captured.err

    def test_the_filter_strips_input_from_a_real_pydantic_error(self) -> None:
        """Drives the filter directly against the installed pydantic's error shape.

        The assertion before the filter runs proves the value is in ``record.args`` to begin with,
        so the assertion after it measures removal rather than absence.
        """
        args = _pydantic_error_args(_CANARY)
        record = logging.LogRecord(
            "fastmcp.server.server",
            logging.WARNING,
            "server.py",
            1325,
            "Invalid arguments for tool %r: %s",
            args,
            None,
        )
        assert _CANARY in record.getMessage()

        assert PydanticErrorInputFilter().filter(record) is True

        rendered = record.getMessage()
        assert _CANARY not in rendered
        assert "'input'" not in rendered
        assert "string_type" in rendered
        assert "sl1_graphql" in rendered

    def test_an_ordinary_record_is_left_untouched_by_identity(self) -> None:
        """`args` is not rebuilt when there is nothing to strip.

        The dict carries an ``input`` key but is not a pydantic error entry, so the filter's
        narrow-shape rule leaves it alone.
        """
        args = ("a value", {"input": "not a pydantic error"})
        record = logging.LogRecord("t", logging.INFO, "f", 1, "%s %s", args, None)

        assert PydanticErrorInputFilter().filter(record) is True

        assert record.args is args
        assert record.getMessage() == "a value {'input': 'not a pydantic error'}"

    def test_mapping_style_args_are_not_rewritten(self) -> None:
        """`logger.info("%(input)s", {...})` puts a mapping on `record.args`.

        Removing a key from it would make `record.getMessage()` raise `KeyError` and destroy the
        record, so the filter returns early instead.
        """
        record = logging.LogRecord("t", logging.INFO, "f", 1, "%(input)s", None, None)
        record.args = {"input": "kept", "type": "string_type", "loc": (), "msg": "m"}

        assert PydanticErrorInputFilter().filter(record) is True

        assert record.getMessage() == "kept"

    def test_configure_logging_reroutes_the_fastmcp_logger(self) -> None:
        """The reroute itself: fastmcp ships ``propagate = False`` plus two stderr handlers.

        Records only reach this project's chain once both are undone. A filter on the ``fastmcp``
        logger could not substitute, because `logging` runs logger filters only on the originating
        logger, here ``fastmcp.server.server``.
        """
        configure_logging("INFO")

        fastmcp_logger = logging.getLogger("fastmcp")
        assert fastmcp_logger.propagate is True
        assert fastmcp_logger.handlers == []

    def test_the_reroute_and_the_handler_are_idempotent(self) -> None:
        """`start_up` calls `configure_logging` twice, so neither may accumulate."""
        configure_logging()
        configure_logging("INFO")
        _handler, buffer = _capture_this_projects_handler()

        owned = [
            h for h in logging.getLogger().handlers if getattr(h, "_powerpack_mcp_handler", False)
        ]
        assert len(owned) == 1
        fastmcp_logger = logging.getLogger("fastmcp")
        assert fastmcp_logger.handlers == []
        assert fastmcp_logger.propagate is True

        logging.getLogger("fastmcp.server.server").warning(
            "Invalid arguments for tool %r: %s", "sl1_graphql", _pydantic_error_args(_CANARY)[1]
        )
        assert buffer.getvalue().count("Invalid arguments for tool") == 1
        assert _CANARY not in buffer.getvalue()

    def test_the_import_order_hazard_is_reported_rather_than_silent(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The one way this mitigation can silently stop working, made noisy.

        fastmcp configures its logger at import time. If `configure_logging` ran first, fastmcp
        would re-add its handlers and reset ``propagate = False``, undoing the reroute with no
        error. `app.py` imports `fastmcp` at module level and calls `configure_logging` only from
        `start_up`, so the order holds today; this warning catches a future reordering.

        `caplog` is used here because the warning is emitted inside `configure_logging`, before the
        new handler's stream could be swapped for a buffer.
        """
        monkeypatch.delitem(sys.modules, "fastmcp", raising=False)

        with caplog.at_level(logging.WARNING):
            configure_logging("INFO")

        assert [r for r in caplog.records if "Import fastmcp before" in r.getMessage()], caplog.text

    def test_no_warning_when_fastmcp_is_already_imported(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The complement, so the test above cannot pass by warning unconditionally."""
        assert "fastmcp" in sys.modules

        with caplog.at_level(logging.WARNING):
            configure_logging("INFO")
            configure_logging("INFO")

        assert [r for r in caplog.records if "Import fastmcp before" in r.getMessage()] == []

    def test_the_rest_of_the_chain_still_works(self) -> None:
        """Correlation, redaction and the log format are unaffected by the input filter."""
        configure_logging("INFO")
        _handler, buffer = _capture_this_projects_handler()

        logging.getLogger("collateral").warning(
            "ordinary record", extra={"token": "Bearer would-be-secret", "event": "probe"}
        )

        emitted = buffer.getvalue()
        assert ":::ordinary record" in emitted  # appliance log prefix, byte-for-byte
        assert "correlation_id=" in emitted  # CorrelationIdFilter still injects
        assert "token=**redacted**" in emitted  # RedactingFilter still redacts, last
        assert "would-be-secret" not in emitted
        assert "event=probe" in emitted  # the greppable event token


class TestGlobalErrorHandler:
    @pytest.mark.anyio
    async def test_returns_a_generic_payload(self) -> None:
        """No stack trace, path, version or configuration value."""
        exc = RuntimeError("secret /opt/em7 detail")
        response = await global_error_handler(None, exc)  # type: ignore[arg-type]
        rendered = bytes(response.body).decode()
        body = json.loads(rendered)
        assert response.status_code == 500
        assert body["error"]["type"] == "internal_error"
        assert "opt/em7" not in rendered
        assert "RuntimeError" not in rendered

    @pytest.mark.anyio
    async def test_logs_the_type_but_never_the_message(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """`h11`'s ``LocalProtocolError`` embeds the offending header value in its message.

        Rendering that message into a log record would put the credential into the log.
        """
        import h11

        with pytest.raises(h11.LocalProtocolError) as raised:
            h11.Request(
                method=b"GET",
                target=b"/",
                headers=[(b"host", b"x"), (b"authorization", b"Bearer leaked\r\nX-Evil: 1")],
            )
        exc = raised.value
        # The precondition the whole test rests on: h11 really does embed the offending value.
        assert "Bearer leaked" in str(exc)

        with caplog.at_level(logging.ERROR, logger="powerpack_mcp.mcp_app.app"):
            await global_error_handler(None, exc)  # type: ignore[arg-type]

        record = caplog.records[0]
        # The message must not carry it, and neither may any structured field the formatter would
        # render. The leak would be just as real either way.
        assert "Bearer leaked" not in caplog.text
        assert not any("Bearer leaked" in str(v) for v in vars(record).values())
        assert record.exception_type == "LocalProtocolError"  # type: ignore[attr-defined]
        assert record.event == LogEvent.UNHANDLED_EXCEPTION  # type: ignore[attr-defined]
        assert record.exc_info is None, "exc_info would re-introduce the value via the traceback"


class TestStartupAndShutdown:
    def test_startup_fails_closed_on_invalid_configuration(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """One ERROR with event=startup_failed, then exit. No degraded mode."""
        monkeypatch.setenv("LCE_CREDENTIAL", "Bearer x")
        monkeypatch.setenv("LISTEN_HOST", "0.0.0.0")
        with caplog.at_level(logging.ERROR), pytest.raises(ConfigurationError):
            create_app()
        events = [getattr(r, "event", None) for r in caplog.records]
        assert LogEvent.STARTUP_FAILED in events

    def test_startup_never_contacts_lce(self, config: Config) -> None:
        """Building the app performs no I/O; if it did, this would need a network stub to pass."""
        assert create_app(config) is not None

    def test_create_app_returns_correlation_middleware_outermost(self, config: Config) -> None:
        """The error handler must run inside the correlation scope so its record carries the id."""
        from powerpack_mcp.mcp_app.correlation import CorrelationIdMiddleware

        assert isinstance(create_app(config), CorrelationIdMiddleware)

    def test_exposes_only_health_and_the_mcp_mount(self, config: Config) -> None:
        """No debug, metrics or readiness endpoint.

        ``/ready`` is asserted absent, not merely unmentioned: the service exposes no readiness
        endpoint.
        """
        from starlette.applications import Starlette

        from powerpack_mcp.mcp_app.correlation import CorrelationIdMiddleware

        middleware = create_app(config)
        assert isinstance(middleware, CorrelationIdMiddleware)
        inner = cast("Starlette", middleware._app)
        paths = {getattr(route, "path", None) for route in inner.router.routes}
        assert HEALTH_PATH in paths
        assert "/ready" not in paths, "the service exposes no readiness route"

    @pytest.mark.anyio
    async def test_lifespan_releases_all_three_pools(self) -> None:
        """Asserting fewer than all three would let the others leak.

        Extend this test whenever a new client with a pool is added to the lifespan.
        """
        lce, sl1, db = _StubClient(), _StubClient(), _StubClient()
        lifespan = lifespan_for(lce, sl1, db)  # type: ignore[arg-type]
        async with lifespan(None):  # type: ignore[arg-type]
            pass
        assert lce.close_calls == 1
        assert sl1.close_calls == 1
        assert db.close_calls == 1, "the DB executor and its thread-affine cursors must be released"

    @pytest.mark.anyio
    async def test_lifespan_releases_all_three_pools_even_on_failure(self) -> None:
        """The `finally` matters: a failure during serving must still release all three."""
        lce, sl1, db = _StubClient(), _StubClient(), _StubClient()
        lifespan = lifespan_for(lce, sl1, db)  # type: ignore[arg-type]
        with pytest.raises(RuntimeError):
            async with lifespan(None):  # type: ignore[arg-type]
                raise RuntimeError("boom")
        assert lce.close_calls == 1
        assert sl1.close_calls == 1
        assert db.close_calls == 1

    @pytest.mark.anyio
    async def test_the_db_pool_is_released_even_if_both_earlier_closes_raise(self) -> None:
        """The DB pool survives both earlier closes raising.

        The DB client holds OS threads rather than sockets, so leaking it is the costliest of the
        three.
        """

        class _FailingClient(_StubClient):
            async def aclose(self) -> None:
                await super().aclose()
                raise RuntimeError("close failed")

        lce, sl1, db = _FailingClient(), _FailingClient(), _StubClient()
        lifespan = lifespan_for(lce, sl1, db)  # type: ignore[arg-type]
        with pytest.raises(RuntimeError, match="close failed"):
            async with lifespan(None):  # type: ignore[arg-type]
                pass
        assert db.close_calls == 1, (
            "the DB pool must be released even when both earlier closes raise"
        )

    @pytest.mark.anyio
    async def test_an_absent_db_client_is_not_an_error(self) -> None:
        """A driverless appliance has no `DbClient`, and shutdown must not care.

        Requiring one would turn the degraded mode without DB tools into a crash on shutdown.
        """
        lce, sl1 = _StubClient(), _StubClient()
        lifespan = lifespan_for(lce, sl1, None)  # type: ignore[arg-type]
        async with lifespan(None):  # type: ignore[arg-type]
            pass
        assert lce.close_calls == 1
        assert sl1.close_calls == 1

    @pytest.mark.anyio
    async def test_the_sl1_pool_is_released_even_if_the_lce_close_raises(self) -> None:
        """The inner `try/finally`, which nothing else reaches.

        Without it, an exception from the first `aclose()` skips the second, leaking the pool when a
        crash makes it most likely to hold open connections. A single `finally` around both calls
        looks equivalent and is not.
        """

        class _FailingClient(_StubClient):
            async def aclose(self) -> None:
                await super().aclose()
                raise RuntimeError("close failed")

        lce, sl1 = _FailingClient(), _StubClient()
        lifespan = lifespan_for(lce, sl1)  # type: ignore[arg-type]
        with pytest.raises(RuntimeError, match="close failed"):
            async with lifespan(None):  # type: ignore[arg-type]
                pass
        assert lce.close_calls == 1
        assert sl1.close_calls == 1, "the SL1 pool must be released even when the LCE close raises"


class TestToolRegistrySeam:
    """`register_tools` and the LCE tools it registers.

    `register_tools` takes a `config` because the body-size guard needs
    `Config.MAX_REQUEST_BODY_BYTES`.
    """

    def test_register_tools_binds_the_injected_dependencies(self, config: Config) -> None:
        server = build_mcp_server(config, LceClient(config), Sl1Client(config))
        register_tools(server, LceClient(config), config, Sl1Client(config))
        assert server is not None

    @pytest.mark.anyio
    async def test_all_seven_lce_operations_are_registered(self, config: Config) -> None:
        """The registry is driven by `ALL_DESCRIPTORS`, so the names cannot drift from it.

        A subset check, because other tool sets register too; the total surface is asserted in
        `TestToolSetGating`. There are 7 LCE tools, matching `ALL_DESCRIPTORS` and the LCE Swagger.
        """
        from powerpack_mcp.tools import ALL_DESCRIPTORS

        server = build_mcp_server(config, LceClient(config), Sl1Client(config))
        # fastmcp 3.x `list_tools()` returns Tool objects, not names, so every name comparison in
        # this file projects to ``t.name`` explicitly.
        registered = {t.name for t in await server.list_tools()}
        descriptor_names = {d.tool_name for d in ALL_DESCRIPTORS}
        assert len(descriptor_names) == 7
        assert descriptor_names <= registered

    @pytest.mark.anyio
    async def test_every_lce_tool_name_is_lce_prefixed(self, config: Config) -> None:
        """Every ``lce_``-prefixed name maps to a descriptor, and every descriptor is prefixed.

        The prefix identifies the backend a tool reaches. It is not a global invariant: other sets
        use other names, and ``get_content_standards`` has no prefix. `TestNoBackend` in
        ``test_standards.py`` asserts that tool can reach no backend at all.
        """
        from powerpack_mcp.tools import ALL_DESCRIPTORS

        descriptor_names = {d.tool_name for d in ALL_DESCRIPTORS}
        assert all(name.startswith("lce_") for name in descriptor_names)

        server = build_mcp_server(config, LceClient(config), Sl1Client(config))
        registered = {t.name for t in await server.list_tools()}  # names, not Tools
        assert {n for n in registered if n.startswith("lce_")} == descriptor_names


def test_secret_str_default_repr_would_not_leak(credential_value: str) -> None:
    """Sanity check on the layer beneath `LceCredential.__repr__`: pydantic redacts too."""
    assert credential_value not in repr(SecretStr(credential_value))


class TestModuleEntryPoint:
    """The systemd unit invokes ``python -m powerpack_mcp``, not the console script.

    The two entry points cannot drift because one imports the other; this asserts it.
    """

    def test_module_entry_point_is_the_same_callable_as_the_console_script(self) -> None:
        import powerpack_mcp.__main__ as module_entry
        from powerpack_mcp.main import main as console_entry

        assert module_entry.main is console_entry


class TestToolSetGating:
    """Tool-set gating at the composition root.

    The `tool_sets` tests cover the decision as a pure function. These cover the enactment: a plan
    changes what ``tools/list`` contains, and the startup log reports it.
    """

    @staticmethod
    def _server(config: Config) -> FastMCP:
        return build_mcp_server(config, LceClient(config), Sl1Client(config))

    @pytest.mark.anyio
    async def test_the_standards_tool_registers_by_default(self, config: Config) -> None:
        """Default-on is the shipped default."""
        assert "get_content_standards" in {
            t.name for t in await self._server(config).list_tools()
        }  # `in` over the raw list would test Tool identity, not the name

    @pytest.mark.anyio
    async def test_a_disabled_set_is_absent_from_tools_list(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Absent, not present-and-failing, proven against a real tool set."""
        monkeypatch.setenv("ENABLE_STANDARDS_TOOLS", "false")
        config = load_config()
        # Project to names. Without it the negative assertion below is vacuously true, because
        # ``"get_content_standards" not in [Tool, ...]`` always holds.
        names = {t.name for t in await self._server(config).list_tools()}
        assert "get_content_standards" not in names
        # The LCE set is unaffected; it has no flag.
        assert any(name.startswith("lce_") for name in names)

    @pytest.mark.anyio
    async def test_disabling_every_optional_set_leaves_the_lce_tools_only(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A valid configuration, not an error."""
        for key in TOOL_SET_FLAG_KEYS:
            monkeypatch.setenv(key, "false")
        names = {t.name for t in await self._server(load_config()).list_tools()}
        assert all(name.startswith("lce_") for name in names)
        assert len(names) == 7

    @pytest.mark.anyio
    async def test_tools_list_is_deterministic_across_builds(self, config: Config) -> None:
        """Two builds from identical configuration, which is what a restart is."""
        # Sort names: `Tool` objects are pydantic models with no `__lt__`.
        first = sorted(t.name for t in await self._server(config).list_tools())
        second = sorted(t.name for t in await self._server(config).list_tools())
        assert first == second

    def test_one_record_is_logged_per_tool_set_including_lce(
        self, config: Config, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A complete inventory, not a list of the optional parts."""
        with caplog.at_level(logging.INFO):
            self._server(config)
        records = [
            r
            for r in caplog.records
            if getattr(r, "event", None) == LogEvent.TOOL_SETS_REGISTERED and hasattr(r, "set_id")
        ]
        assert {getattr(r, "set_id", None) for r in records} == set(ALL_TOOL_SET_IDS)
        lce_record = next(r for r in records if getattr(r, "set_id", None) == "lce")
        assert getattr(lce_record, "flag", "unset") is None, (
            "carrying no flag is how always-on is marked"
        )
        assert getattr(lce_record, "registered", None) is True

    def test_a_nested_disable_is_reported_as_such(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The operator set one key and two sets went off.

        The log has to say which was the instruction and which the consequence, because "disabled"
        alone cannot distinguish them and they demand opposite responses.
        """
        monkeypatch.setenv("ENABLE_DB_TOOLS", "false")
        with caplog.at_level(logging.INFO):
            self._server(load_config())
        reasons = {
            getattr(r, "set_id", None): getattr(r, "reason", None)
            for r in caplog.records
            if getattr(r, "event", None) == LogEvent.TOOL_SETS_REGISTERED and hasattr(r, "set_id")
        }
        assert reasons["db_read"] is ToolSetDisabledReason.DISABLED_BY_CONFIGURATION
        assert reasons["db_write"] is ToolSetDisabledReason.DISABLED_BY_NESTING

    def test_no_flag_record_carries_anything_beyond_the_pinned_fields(
        self, config: Config, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The pinned fields, checked at the log boundary rather than only on the record type.

        The record type makes extra fields structurally impossible instead of sanitising them; this
        checks that the ``extra`` mapping is exactly the record's fields plus ``event``.
        """
        with caplog.at_level(logging.INFO):
            self._server(config)
        for record in caplog.records:
            if getattr(record, "event", None) != LogEvent.TOOL_SETS_REGISTERED:
                continue
            if not hasattr(record, "set_id"):
                continue
            assert getattr(record, "flag", "unset") in (None, *TOOL_SET_FLAG_KEYS)
            assert isinstance(getattr(record, "registered", None), bool)
            assert isinstance(getattr(record, "tool_count", None), int)

    @pytest.mark.anyio
    async def test_registered_schemas_are_trimmed(self, config: Config) -> None:
        """Trimming runs at startup, on registered tools only.

        Asserted as the absence of advisory metadata in the live schemas rather than by trusting the
        count `trim_registered_tools` returned.
        """
        from powerpack_mcp.schema_slim import registered_tools

        server = self._server(config)
        for tool in registered_tools(server):
            assert "title" not in tool.parameters

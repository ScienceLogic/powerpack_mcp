"""
DB Client Tests

This module tests ``powerpack_mcp.db_client`` without an appliance. The platform modules are
absent here by design (``mysqlclient`` is not a dependency, and ``sl_mysql`` lives in
``/opt/em7``), so the tests inject a fake ``_Platform``. The interesting cases are the failure
ones, above all the connection rule: errno 1969 keeps the connection, everything else discards it.

A fake cursor does not perform MySQLdb's ``sql % args`` interpolation, so the silent-empty result
that a stray ``%`` can cause is invisible here; that guard lives in ``sql.Statement.__post_init__``
and is tested against the rendered statement. Real query behaviour and the true connection state
after cancellation can only be verified on an appliance.
"""

from __future__ import annotations

import asyncio
import re
import sys
import threading
import time
import types
from typing import TYPE_CHECKING, Any

import pytest

from powerpack_mcp import db_client as dbc
from powerpack_mcp.errors import (
    DbDeadlineExceeded,
    DbError,
    DbQueryTimeout,
    DbUnreachable,
    LogEvent,
)
from powerpack_mcp.mcp_app.concurrency import REQUEST_DEADLINE
from powerpack_mcp.mcp_app.correlation import CORRELATION_ID
from powerpack_mcp.sql import Statement

if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeOperationalError(Exception):
    """Stands in for ``MySQLdb.OperationalError``; errno lives in ``args[0]`` as it really does."""


class _FakeInterfaceError(Exception):
    """Stands in for ``MySQLdb.InterfaceError``."""


class _FakeCursor:
    # The platform cursor has both attributes, so the fake carries them. ``db_client`` reads them
    # through ``getattr`` with a default, because a write that has already committed must not then
    # die on an ``AttributeError``; ``test_absent_cursor_attributes_degrade_rather_than_raise``
    # covers the fallback.
    rowcount = 1
    lastrowid = 0

    def __init__(self, raises: BaseException | None = None) -> None:
        self.statements: list[tuple[str, object]] = []
        self.closed = False
        self._raises = raises

    def execute(self, query: str, args: object = None) -> object:
        self.statements.append((query, args))
        # The SET SESSION preamble must always succeed; only the real query fails, otherwise a test
        # could pass by failing at the wrong statement.
        if self._raises is not None and not query.startswith("SET SESSION"):
            raise self._raises
        return None

    def fetchall(self) -> tuple[tuple[object, ...], ...]:
        return ((1, "row"),)

    def close(self) -> None:
        self.closed = True


class _CursorFactory:
    """Hands out one cursor per call and records them, so per-thread affinity is observable."""

    def __init__(self, raises: BaseException | None = None, fail_open: bool = False) -> None:
        self.created: list[_FakeCursor] = []
        self._raises = raises
        self._fail_open = fail_open
        self._lock = threading.Lock()

    def __call__(self) -> Any:  # stands in for the platform's cursor type
        if self._fail_open:
            raise RuntimeError("connect failed: user=clientdbuser password=hunter2")
        cursor = _FakeCursor(self._raises)
        with self._lock:
            self.created.append(cursor)
        return cursor


@pytest.fixture(autouse=True)
def _reset_platform_cache() -> Iterator[None]:
    """``_load_platform`` caches module-globally; leaking it across tests would hide failures."""
    dbc._platform = None
    dbc._platform_error = None
    yield
    dbc._platform = None
    dbc._platform_error = None


def _install(factory: _CursorFactory) -> None:
    dbc._platform = dbc._Platform(
        local_db=factory,
        operational_error=_FakeOperationalError,
        interface_error=_FakeInterfaceError,
    )


class TestDbWorkerCount:
    """``db_threads = min(MAX_CONCURRENT_REQUESTS, 30)``, derived rather than chosen."""

    def test_it_tracks_the_inbound_slot_count(self) -> None:
        assert dbc.db_worker_count(6) == 6
        assert dbc.db_worker_count(1) == 1

    def test_it_is_capped_by_the_measured_connection_cache_ceiling(self) -> None:
        # Config's own ceiling for MAX_CONCURRENT_REQUESTS is 64, so this cap bites. The platform's
        # connection cache is ``LRUCache(maxsize=30)``.
        assert dbc.db_worker_count(64) == dbc.CONNECTION_CACHE_CEILING == 30

    def test_a_non_positive_slot_count_is_refused(self) -> None:
        with pytest.raises(ValueError, match=">= 1"):
            dbc.db_worker_count(0)

    def test_the_client_reports_the_derived_count(self) -> None:
        client = dbc.DbClient(max_concurrent_requests=4)
        assert client.worker_count == 4


class TestStatementTimeout:
    """The remaining request budget becomes a server-side statement timeout."""

    def test_no_deadline_means_no_session_timeout(self) -> None:
        assert dbc.DbClient._statement_timeout(None) is None

    def test_a_remaining_budget_is_passed_through(self) -> None:
        assert dbc.DbClient._statement_timeout(12.5) == 12.5

    def test_zero_is_still_clamped_as_a_boundary_guard(self) -> None:
        # MariaDB reads max_statement_time = 0 as no limit, so a zero budget would become an
        # unbounded query. ``fetch_all`` and ``run_unit`` now refuse a spent deadline before the
        # submit (see ``TestSpentDeadlineRefusal``), so this is not reachable through them; the
        # clamp stays as a boundary guard in case a future call site reaches it directly.
        clamped = dbc.DbClient._statement_timeout(0.0)
        assert clamped == dbc.MIN_STATEMENT_TIME_SECONDS
        assert clamped is not None
        assert clamped > 0


@pytest.mark.anyio
class TestSpentDeadlineRefusal:
    """A spent deadline is refused, never issued as a 1 ms query.

    A 1 ms query produces a ``db_query_timeout`` record with ``statement_timeout_seconds=0.001``.
    Every part of that record is true and the whole of it misleads: nothing was slow, and its
    advice to narrow the query cannot help.
    """

    def test_no_deadline_never_refuses(self) -> None:
        """An absent deadline means no limit, not a 1 ms clamp.

        ``remaining_deadline_seconds`` returns ``None``, and ``_statement_timeout`` maps that to no
        limit. Refusing here would break the health check.
        """
        assert dbc.DbClient._refuse_if_deadline_spent(None) is None

    def test_a_positive_remainder_never_refuses(self) -> None:
        assert dbc.DbClient._refuse_if_deadline_spent(5.0) is None
        # Positive but below the floor still proceeds: there is no "worth attempting" threshold.
        assert dbc.DbClient._refuse_if_deadline_spent(dbc.MIN_STATEMENT_TIME_SECONDS / 2) is None

    def test_a_spent_deadline_carries_the_measured_remainder(self) -> None:
        with pytest.raises(DbDeadlineExceeded) as caught:
            dbc.DbClient._refuse_if_deadline_spent(0.0)
        assert caught.value.remaining_seconds == 0.0

    async def test_not_one_statement_is_issued(self) -> None:
        """Nothing must be sent at all.

        A clearer message on a doomed 1 ms query would still occupy a worker and a connection and
        still leave MariaDB to kill it.
        """
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        token = REQUEST_DEADLINE.set(time.monotonic() - 1.0)
        try:
            with pytest.raises(DbDeadlineExceeded):
                await client.fetch_all(Statement("SELECT 1"))
        finally:
            REQUEST_DEADLINE.reset(token)
        assert factory.created == []
        await client.aclose()

    async def test_run_unit_refuses_symmetrically(self) -> None:
        """The read and write paths must not diverge, which is why ``_execute`` is shared."""
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        token = REQUEST_DEADLINE.set(time.monotonic() - 1.0)
        try:
            with pytest.raises(DbDeadlineExceeded):
                await client.run_unit(Statement("SELECT 1"))
        finally:
            REQUEST_DEADLINE.reset(token)
        assert factory.created == []
        await client.aclose()

    async def test_the_event_is_its_own_key_and_not_db_query_timeout(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The refusal has its own event key, distinct from ``db_query_timeout``.

        ``db_query_timeout`` means the server stopped a running query; this means none was issued.
        An operator keying on the former would tune the statement timeout, which is the wrong knob.
        """
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        token = REQUEST_DEADLINE.set(time.monotonic() - 1.0)
        try:
            with caplog.at_level("INFO"), pytest.raises(DbDeadlineExceeded):
                await client.fetch_all(Statement("SELECT 1"))
        finally:
            REQUEST_DEADLINE.reset(token)
        events = [r.__dict__.get("event") for r in caplog.records]
        assert str(LogEvent.DB_DEADLINE_EXCEEDED) in events
        assert str(LogEvent.DB_QUERY_TIMEOUT) not in events
        await client.aclose()


@pytest.mark.anyio
class TestCorrelationIdReachesTheWorker:
    """Records emitted from the DB worker must carry the request's correlation id.

    ``run_in_executor`` does not copy the calling context, so without an explicit copy every record
    from inside ``_execute`` reports ``correlation_id=startup``, the ``ContextVar`` default, even
    mid-request. That reads as a lost request context when only the log record is wrong.
    """

    async def test_the_worker_thread_sees_the_requests_correlation_id(self) -> None:
        observed: list[str] = []

        class _ObservingFactory(_CursorFactory):
            def __call__(self) -> Any:  # matches the platform cursor type
                cursor = _FakeCursor()
                original = cursor.execute

                def recording(query: str, args: object = None) -> object:
                    # Runs in the executor thread, which is the point of the assertion.
                    observed.append(CORRELATION_ID.get())
                    return original(query, args)

                cursor.execute = recording  # type: ignore[method-assign]
                with self._lock:
                    self.created.append(cursor)
                return cursor

        factory = _ObservingFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        token = CORRELATION_ID.set("regressionid")
        try:
            await client.fetch_all(Statement("SELECT 1"))
        finally:
            CORRELATION_ID.reset(token)
        await client.aclose()
        assert observed, "the fake cursor never executed, so nothing was measured"
        assert observed == ["regressionid"] * len(observed)
        # The context default, asserted explicitly so a regression names itself.
        assert "startup" not in observed


class TestErrnoExtraction:
    def test_the_errno_is_read_from_args_zero(self) -> None:
        assert dbc._errno_of(_FakeOperationalError(1969, "interrupted")) == 1969

    @pytest.mark.parametrize(
        "exc", [_FakeOperationalError(), _FakeOperationalError("not an int"), RuntimeError()]
    )
    def test_an_unrecognisable_shape_yields_none(self, exc: BaseException) -> None:
        # Asymmetric on purpose: None falls through to the discard branch. Mistaking a broken
        # connection for a timeout would keep it; the reverse merely wastes a healthy one.
        assert dbc._errno_of(exc) is None


@pytest.mark.anyio
class TestFetchAll:
    async def test_rows_are_returned_and_the_statement_is_executed(self) -> None:
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=2)
        rows = await client.fetch_all(Statement("SELECT a FROM t WHERE b = %s", ("x",)))
        assert rows == ((1, "row"),)
        (cursor,) = factory.created
        assert ("SELECT a FROM t WHERE b = %s", ("x",)) in cursor.statements
        await client.aclose()

    async def test_an_empty_param_tuple_is_passed_as_none_not_as_an_empty_tuple(self) -> None:
        # ``params or None``: MySQLdb only %-interpolates when args is not None, so None skips the
        # mechanism entirely rather than relying on Statement's guard alone.
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.fetch_all(Statement("SELECT 1"))
        (cursor,) = factory.created
        assert ("SELECT 1", None) in cursor.statements
        await client.aclose()

    async def test_a_deadline_produces_a_set_session_statement_timeout(self) -> None:
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        token = REQUEST_DEADLINE.set(time.monotonic() + 5.0)
        try:
            await client.fetch_all(Statement("SELECT 1"))
        finally:
            REQUEST_DEADLINE.reset(token)
        (cursor,) = factory.created
        preamble = [s for s in cursor.statements if s[0].startswith("SET SESSION")]
        assert len(preamble) == 1
        assert preamble[0][0] == "SET SESSION max_statement_time = %s"
        args = preamble[0][1]
        assert isinstance(args, tuple)
        assert 0 < float(args[0]) <= 5.0
        await client.aclose()

    async def test_no_deadline_means_no_preamble(self) -> None:
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.fetch_all(Statement("SELECT 1"))
        (cursor,) = factory.created
        assert not [s for s in cursor.statements if s[0].startswith("SET SESSION")]
        await client.aclose()

    async def test_errno_1969_raises_db_query_timeout_and_keeps_the_connection(self) -> None:
        """Errno 1969 keeps the connection, and getting this backwards is the easy mistake.

        The server ended the query and drained its result, so the connection is clean and
        immediately reusable (measured, not assumed). Discarding here would throw away a healthy
        connection on every slow query.
        """
        factory = _CursorFactory(raises=_FakeOperationalError(1969, "max_statement_time exceeded"))
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbQueryTimeout):
            await client.fetch_all(Statement("SELECT 1"))
        (cursor,) = factory.created
        assert cursor.closed is False
        await client.aclose()

    async def test_any_other_operational_error_discards_the_connection(self) -> None:
        """Nothing says the connection is in a known state, so it goes."""
        factory = _CursorFactory(raises=_FakeOperationalError(2006, "server has gone away"))
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbError):
            await client.fetch_all(Statement("SELECT 1"))
        (cursor,) = factory.created
        assert cursor.closed is True
        await client.aclose()

    async def test_an_interface_error_discards_the_connection(self) -> None:
        factory = _CursorFactory(raises=_FakeInterfaceError("connection closed"))
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbError):
            await client.fetch_all(Statement("SELECT 1"))
        (cursor,) = factory.created
        assert cursor.closed is True
        await client.aclose()

    async def test_a_driver_error_message_never_reaches_the_caller(self) -> None:
        """No connection parameter or secret appears in any caller-facing text."""
        factory = _CursorFactory(
            raises=_FakeOperationalError(2006, "Access denied for clientdbuser using password YES")
        )
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbError) as exc:
            await client.fetch_all(Statement("SELECT 1"))
        rendered = str(exc.value)
        assert "clientdbuser" not in rendered
        assert "password" not in rendered
        await client.aclose()

    async def test_a_failure_to_open_a_connection_hides_the_driver_message(self) -> None:
        _install(_CursorFactory(fail_open=True))
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbUnreachable) as exc:
            await client.fetch_all(Statement("SELECT 1"))
        assert "hunter2" not in str(exc.value)
        assert "clientdbuser" not in str(exc.value)
        await client.aclose()

    async def test_a_cursor_is_reused_within_a_thread(self) -> None:
        """Connections are thread-affine: one worker means one connection across many calls."""
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        for _ in range(4):
            await client.fetch_all(Statement("SELECT 1"))
        assert len(factory.created) == 1
        await client.aclose()

    async def test_a_discarded_connection_is_replaced_on_the_next_call(self) -> None:
        factory = _CursorFactory(raises=_FakeInterfaceError("gone"))
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        for _ in range(2):
            with pytest.raises(DbError):
                await client.fetch_all(Statement("SELECT 1"))
        # Two attempts, two connections: the first was discarded rather than reused.
        assert len(factory.created) == 2
        assert all(c.closed for c in factory.created)
        await client.aclose()

    async def test_cancellation_emits_the_leak_event_and_reraises(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Cancellation emits the event that distinguishes a leak from a slow query.

        The two events differ because one is recovered and the other is not. Collapsing this into
        ``db_query_timeout`` would lose the only signal that a thread and a connection are still
        busy after the slot was released.
        """
        started = threading.Event()
        release = threading.Event()

        class _BlockingFactory(_CursorFactory):
            def __call__(self) -> Any:  # matches the platform cursor type
                cursor = _FakeCursor()
                original = cursor.execute

                def blocking(query: str, args: object = None) -> object:
                    started.set()
                    release.wait(timeout=5)
                    return original(query, args)

                cursor.execute = blocking  # type: ignore[method-assign]
                self.created.append(cursor)
                return cursor

        _install(_BlockingFactory())
        client = dbc.DbClient(max_concurrent_requests=1)
        with caplog.at_level("WARNING"):
            task = asyncio.create_task(client.fetch_all(Statement("SELECT 1")))
            await asyncio.to_thread(started.wait, 5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        release.set()
        events = [r.__dict__.get("event") for r in caplog.records]
        assert str(LogEvent.DB_AWAIT_ABANDONED) in events
        assert str(LogEvent.DB_QUERY_TIMEOUT) not in events
        await client.aclose()

    async def test_a_closed_client_refuses_further_work(self) -> None:
        _install(_CursorFactory())
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.aclose()
        with pytest.raises(DbUnreachable):
            await client.fetch_all(Statement("SELECT 1"))

    async def test_a_non_statement_argument_is_refused(self) -> None:
        _install(_CursorFactory())
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(TypeError, match=re.escape("sql.Statement")):
            await client.fetch_all("SELECT 1")
        await client.aclose()


class TestPlatformLoading:
    def test_a_missing_platform_raises_db_unreachable_naming_no_path(self) -> None:
        # Normally unreachable, because the DB tool sets are disabled at startup with
        # PREREQUISITE_MISSING. This is the fail-closed path for when they are not.
        with pytest.raises(DbUnreachable) as exc:
            dbc._load_platform()
        message = str(exc.value)
        assert "/opt/em7" not in message
        assert dbc.platform_import_error() is not None

    def test_the_failure_is_remembered_rather_than_retried_per_call(self) -> None:
        with pytest.raises(DbUnreachable):
            dbc._load_platform()
        first = dbc.platform_import_error()
        with pytest.raises(DbUnreachable):
            dbc._load_platform()
        assert dbc.platform_import_error() == first

    def test_platform_import_error_is_none_before_any_attempt(self) -> None:
        assert dbc.platform_import_error() is None


class TestPlatformAvailableGatesRegistration:
    """Why registration must not gate on ``platform_import_error()``.

    An ``import sl_mysql`` failure must disable the DB tool sets with ``PREREQUISITE_MISSING``.
    Registration runs before any tool call, and ``platform_import_error()`` reports a cached
    outcome, so at that moment it is ``None`` and indistinguishable from success. Gating on it would
    register the SQL tools on a driverless appliance, where they would fail at first use instead of
    being withheld with a stated reason.
    """

    def test_the_cached_reader_cannot_tell_absent_from_untried(self) -> None:
        """Both facts asserted together, because either one alone reads as harmless."""
        assert dbc.platform_import_error() is None  # nothing has been tried yet
        assert dbc.platform_available() is False  # and yet the driver is genuinely absent

    def test_it_reports_false_and_records_a_reason_when_the_driver_is_absent(self) -> None:
        assert dbc.platform_available() is False
        assert dbc.platform_import_error() is not None

    def test_it_reports_true_when_the_platform_loads(self) -> None:
        """The appliance path, injected rather than skipped: registration depends on this half."""
        dbc._platform = dbc._Platform(
            local_db=_CursorFactory(),
            operational_error=_FakeOperationalError,
            interface_error=_FakeInterfaceError,
        )
        assert dbc.platform_available() is True

    def test_it_never_raises_so_startup_cannot_be_stopped_by_it(self) -> None:
        """Degrade, do not crash: this is called from the composition root at startup."""
        assert dbc.platform_available() in (True, False)

    def test_it_opens_no_connection(self) -> None:
        """Startup contacts no backend.

        ``_load_platform`` resolves ``local_db`` and stores it; calling it is what would connect.
        The injected factory records its calls, so this is observed rather than argued.
        """
        factory = _CursorFactory()
        dbc._platform = dbc._Platform(
            local_db=factory,
            operational_error=_FakeOperationalError,
            interface_error=_FakeInterfaceError,
        )
        assert dbc.platform_available() is True
        assert factory.created == []


class TestPlatformLoadingSucceeds:
    """The success path, exercised by injecting fake platform modules into ``sys.modules``.

    This is where the four symbols are wired. A transposition, such as ``interface_error`` bound to
    ``OperationalError``, would silently invert the keep-or-discard decision for errno 1969, and no
    other test here would notice because they inject ``_Platform`` ready-made.
    """

    def test_it_binds_the_four_symbols_from_the_platform_modules(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake_mysqldb = types.ModuleType("MySQLdb")
        fake_mysqldb.OperationalError = _FakeOperationalError  # type: ignore[attr-defined]
        fake_mysqldb.InterfaceError = _FakeInterfaceError  # type: ignore[attr-defined]

        sentinel = _CursorFactory()
        fake_silo = types.ModuleType("sl_mysql.silo_cursor")
        fake_silo.local_db = sentinel  # type: ignore[attr-defined]
        fake_pkg = types.ModuleType("sl_mysql")
        fake_pkg.silo_cursor = fake_silo  # type: ignore[attr-defined]

        monkeypatch.setitem(sys.modules, "MySQLdb", fake_mysqldb)
        monkeypatch.setitem(sys.modules, "sl_mysql", fake_pkg)
        monkeypatch.setitem(sys.modules, "sl_mysql.silo_cursor", fake_silo)

        platform = dbc._load_platform()
        assert platform.local_db is sentinel
        assert platform.operational_error is _FakeOperationalError
        assert platform.interface_error is _FakeInterfaceError
        # Resolved once, not per call.
        assert dbc._load_platform() is platform
        assert dbc.platform_import_error() is None


@pytest.mark.anyio
class TestDiscardIsBestEffort:
    async def test_a_cursor_that_fails_to_close_does_not_mask_the_original_error(self) -> None:
        """We are already on an error path and the connection is being abandoned regardless.

        A raise from ``close()`` here would replace ``DbError``, which the caller needs, with a
        driver exception whose message must not propagate.
        """

        class _UncloseableCursor(_FakeCursor):
            def close(self) -> None:
                raise _FakeInterfaceError("close failed for clientdbuser")

        class _UncloseableFactory(_CursorFactory):
            def __call__(self) -> Any:  # matches the platform cursor type
                cursor = _UncloseableCursor(_FakeInterfaceError("gone"))
                self.created.append(cursor)
                return cursor

        _install(_UncloseableFactory())
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbError) as exc:
            await client.fetch_all(Statement("SELECT 1"))
        assert "clientdbuser" not in str(exc.value)
        await client.aclose()


class TestDiscardIsIdempotent:
    def test_discarding_with_no_connection_open_is_a_no_op(self) -> None:
        """The guard is unreachable through ``fetch_all`` and is kept deliberately.

        ``_discard`` is only called after ``_cursor`` succeeded, so a cursor is always present on
        that path. The guard makes discard idempotent: shutdown, retry and error paths may all drop
        a connection, and a second discard raising ``AttributeError`` would turn cleanup into a
        new failure.
        """
        client = dbc.DbClient(max_concurrent_requests=1)
        client._discard()
        client._discard()
        assert getattr(client._thread_state, "cursor", None) is None


@pytest.mark.anyio
class TestNoCredentialSurvivesADiscard:
    """A discarded connection leaves no decrypted credential reachable.

    The platform's ``sl_connex.connect_cache`` keys its ``LRUCache`` on a tuple containing the
    plaintext DB password. This service never populates that cache, but it does hold the object
    ``local_db()`` hands back, and a discard is the moment an abandoned connection could be left
    referenced. Value-level redaction is no answer, because the credential would be in the key.
    """

    async def test_the_thread_state_holds_nothing_after_a_discard(self) -> None:
        """The direct assertion: no connection object is reachable from our own state."""
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.fetch_all(Statement("SELECT 1"))
        assert factory.created, "expected a cursor to have been created"

        client._discard()
        assert getattr(client._thread_state, "cursor", None) is None
        # Asserted over ``vars()``, not just the one attribute, so stashing the connection under a
        # second name would still fail.
        leaked = {k: v for k, v in vars(client._thread_state).items() if v is not None}
        assert not leaked, f"thread state still references objects after a discard: {leaked}"

    async def test_no_credential_material_appears_in_the_clients_own_repr(self) -> None:
        """``DbClient``'s repr must not walk the platform cursor it holds.

        The platform cache is never touched (asserted in ``test_source_invariants.py``), but if the
        repr walked the cursor, a diagnostic log line would carry whatever the driver exposes. A
        repr can leak the cached password without anyone intending it.
        """
        _install(_CursorFactory())
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.fetch_all(Statement("SELECT 1"))
        rendered = repr(client)
        for forbidden in ("passwd", "password", "hunter2", "clientdbuser"):
            assert forbidden not in rendered.lower(), (
                f"{forbidden!r} reachable through repr(DbClient)"
            )
        client._discard()
        assert "passwd" not in repr(client).lower()

    async def test_a_discard_on_the_error_path_leaves_nothing_either(self) -> None:
        """The error path is where ``_discard`` actually runs, after a non-1969 failure.

        It is also where an abandoned connection is most likely to be left referenced.
        """
        _install(_CursorFactory(raises=_FakeOperationalError(2013, "connection lost")))
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbError):
            await client.fetch_all(Statement("SELECT 1"))
        assert getattr(client._thread_state, "cursor", None) is None
        leaked = {k: v for k, v in vars(client._thread_state).items() if v is not None}
        assert not leaked, f"error-path discard left state behind: {leaked}"


@pytest.mark.anyio
class TestRunUnit:
    """The write path.

    ``run_unit`` exists because two ``local_db()`` handles do not share session state, so
    ``SET @ct`` and ``LAST_INSERT_ID()`` must run on one connection. A fake cursor has no session,
    so no test below proves that session state carries; that needs an appliance. What they prove is
    the mechanism: one cursor is used for the whole sequence, in order.
    """

    async def test_every_statement_runs_on_one_cursor_in_order(self) -> None:
        """One connection, with sequence order preserved."""
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=4)
        results = await client.run_unit(
            Statement("SET @ct := %s", (7,)),
            Statement("UPDATE t SET c = COALESCE(@ct, c) WHERE a = %s", ("x",)),
            Statement("SELECT c FROM t WHERE a = %s", ("x",)),
        )
        assert len(results) == 3
        # One cursor for three statements. More than one would mean more than one connection,
        # which is the failure this method exists to prevent.
        assert len(factory.created) == 1
        (cursor,) = factory.created
        issued = [q for q, _ in cursor.statements if not q.startswith("SET SESSION")]
        assert issued == [
            "SET @ct := %s",
            "UPDATE t SET c = COALESCE(@ct, c) WHERE a = %s",
            "SELECT c FROM t WHERE a = %s",
        ]
        await client.aclose()

    async def test_statements_are_sent_singly_never_as_one_script(self) -> None:
        """A multi-statement script would be accepted, and it is still not sent.

        A script would put several statements' text through one ``Statement``, and the ``%``
        interpolation hazard scales with statement text. So no issued statement may contain an
        internal ``;``.
        """
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.run_unit(Statement("INSERT INTO t VALUES (%s)", (1,)), Statement("SELECT 1"))
        (cursor,) = factory.created
        for query, _ in cursor.statements:
            assert ";" not in query.rstrip(";")
        await client.aclose()

    async def test_lastrowid_and_rowcount_are_reported_per_statement(self) -> None:
        """What lets ``sl1_simulate_event`` skip a ``SELECT LAST_INSERT_ID()``."""

        class _InsertCursor(_FakeCursor):
            rowcount = 1
            lastrowid = 90210

        def _factory() -> Any:  # stands in for the platform's cursor type
            return _InsertCursor()

        dbc._platform = dbc._Platform(
            local_db=_factory,
            operational_error=_FakeOperationalError,
            interface_error=_FakeInterfaceError,
        )
        client = dbc.DbClient(max_concurrent_requests=1)
        (result,) = await client.run_unit(
            Statement("INSERT INTO master_events.x VALUES (%s)", (1,))
        )
        assert result.lastrowid == 90210
        assert result.rowcount == 1
        assert result.rows == ((1, "row"),)
        await client.aclose()

    async def test_absent_cursor_attributes_degrade_rather_than_raise(self) -> None:
        """A driver without ``lastrowid`` must not raise after a write has committed.

        ``@@autocommit = 1``, so by the time these attributes are read the statement is already
        durable. Raising would report a failure for a write that succeeded, which is worse than
        returning a useless but honest ``-1``/``0``.
        """

        class _BareCursor:
            def __init__(self) -> None:
                self.statements: list[tuple[str, object]] = []

            def execute(self, query: str, args: object = None) -> object:
                self.statements.append((query, args))
                return None

            def fetchall(self) -> tuple[tuple[object, ...], ...]:
                return ()

            def close(self) -> None:
                return None

        def _bare_factory() -> Any:  # stands in for the platform's cursor type
            return _BareCursor()

        dbc._platform = dbc._Platform(
            local_db=_bare_factory,
            operational_error=_FakeOperationalError,
            interface_error=_FakeInterfaceError,
        )
        client = dbc.DbClient(max_concurrent_requests=1)
        (result,) = await client.run_unit(Statement("UPDATE t SET a = %s", (1,)))
        assert result.rowcount == -1
        assert result.lastrowid == 0
        assert result.rows == ()
        await client.aclose()

    async def test_a_deadline_bounds_each_statement_in_the_unit(self) -> None:
        """The statement timeout is applied per statement, from the remainder captured once.

        So a unit of N statements can outlive that remainder by up to a factor of N. That limitation
        is recorded in ``run_unit``'s docstring, and this pins the behaviour so a change to it is
        deliberate: two statements, two preambles.
        """
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        token = REQUEST_DEADLINE.set(time.monotonic() + 5.0)
        try:
            await client.run_unit(Statement("SELECT 1"), Statement("SELECT 2"))
        finally:
            REQUEST_DEADLINE.reset(token)
        (cursor,) = factory.created
        preambles = [s for s in cursor.statements if s[0].startswith("SET SESSION")]
        assert len(preambles) == 2
        await client.aclose()

    async def test_a_mid_unit_failure_leaves_earlier_statements_applied(self) -> None:
        """A mid-unit failure does not undo earlier statements.

        There is no transaction, so a failure at statement 2 leaves statement 1 applied. "Nothing
        happened" is the wrong thing for a caller to infer from a ``run_unit`` exception, and a
        refactor that made the method look atomic would break here.
        """

        class _FailSecondCursor(_FakeCursor):
            def execute(self, query: str, args: object = None) -> object:
                super().execute(query, args)
                issued = [q for q, _ in self.statements if not q.startswith("SET SESSION")]
                if len(issued) == 2:
                    raise _FakeOperationalError(2006, "server has gone away")
                return None

        created: list[_FailSecondCursor] = []

        def _factory() -> Any:
            cursor = _FailSecondCursor()
            created.append(cursor)
            return cursor

        dbc._platform = dbc._Platform(
            local_db=_factory,
            operational_error=_FakeOperationalError,
            interface_error=_FakeInterfaceError,
        )
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbError):
            await client.run_unit(
                Statement("INSERT INTO t VALUES (%s)", (1,)),
                Statement("UPDATE t SET a = %s", (2,)),
            )
        (cursor,) = created
        issued = [q for q, _ in cursor.statements if not q.startswith("SET SESSION")]
        assert issued[0] == "INSERT INTO t VALUES (%s)"
        assert len(issued) == 2
        await client.aclose()

    async def test_a_non_statement_is_refused_before_any_execution(self) -> None:
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(TypeError, match=re.escape("run_unit requires sql.Statement")):
            await client.run_unit(Statement("SELECT 1"), "SELECT 2")
        # Nothing ran: validation happens before dispatch, so a bad argument cannot leave a
        # half-applied unit behind.
        assert factory.created == []
        await client.aclose()

    async def test_an_empty_unit_is_refused(self) -> None:
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(ValueError, match="at least one statement"):
            await client.run_unit()
        await client.aclose()

    async def test_a_closed_client_refuses_a_unit(self) -> None:
        factory = _CursorFactory()
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        await client.aclose()
        with pytest.raises(DbUnreachable):
            await client.run_unit(Statement("SELECT 1"))

    async def test_errno_1969_in_a_unit_raises_db_query_timeout(self) -> None:
        """The classification is shared with ``fetch_all`` through ``_run_one``.

        If the two paths classified errno 1969 differently, one would discard a healthy connection
        on every slow query.
        """
        factory = _CursorFactory(raises=_FakeOperationalError(1969, "max_statement_time exceeded"))
        _install(factory)
        client = dbc.DbClient(max_concurrent_requests=1)
        with pytest.raises(DbQueryTimeout):
            await client.run_unit(Statement("SELECT SLEEP(9)"))
        (cursor,) = factory.created
        assert not cursor.closed  # errno 1969 keeps the connection
        await client.aclose()

    async def test_an_abandoned_unit_records_the_leak_event(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The leak event matters more for a unit than for a read.

        An abandoned unit may already have committed some of its statements, so the record is the
        only thing that makes a partial write visible. It is distinct from ``db_query_timeout``,
        which is recovered.
        """

        class _BlockingCursor(_FakeCursor):
            def execute(self, query: str, args: object = None) -> object:
                super().execute(query, args)
                if not query.startswith("SET SESSION"):
                    time.sleep(0.30)
                return None

        def _factory() -> Any:
            return _BlockingCursor()

        dbc._platform = dbc._Platform(
            local_db=_factory,
            operational_error=_FakeOperationalError,
            interface_error=_FakeInterfaceError,
        )
        client = dbc.DbClient(max_concurrent_requests=1)
        with caplog.at_level("WARNING"):
            task = asyncio.ensure_future(client.run_unit(Statement("SELECT 1")))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        events = [r.__dict__.get("event") for r in caplog.records]
        assert str(LogEvent.DB_AWAIT_ABANDONED) in events
        await client.aclose()

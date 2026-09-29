"""
Appliance Database Client

This module provides ``DbClient``, the service's only blocking I/O. A MySQLdb cursor call is a
synchronous C-extension call, so run on the event loop one slow query would stall the whole
service, including ``/health``, which systemd and appliance monitoring read.

Three bounds work as a set; each alone leaves one of thread, query or connection unbounded:

- A dedicated executor of ``min(MAX_CONCURRENT_REQUESTS, 30)`` threads. Connections are
  per thread, so this also bounds connections; nothing else client-side does.
- A server-side ``max_statement_time`` per statement. ``asyncio.timeout`` bounds the await, not
  the query (a 0.30 s deadline fired while the blocking call ran its full 2.0 s), so this is the
  only real bound. The platform default is 3600 s.
- Disposal of a suspect connection. A query the server ended leaves the connection clean, so only
  other failures discard it.

Each worker thread holds one connection from ``local_db()``. The platform's
``@cache_connections`` is not used: ``local_db()`` is not on its cached path, and where it applies
it shares one connection per credential tuple while ``MySQLdb.threadsafety`` is 1. A thread is
keyed by nothing a caller controls, so this is not a per-caller or per-credential cache. The
platform's cache key holds the plaintext DB password; nothing here may log, ``repr`` or return
``sl_connex.connect_cache._cache``, and this module never populates it.

Writes run through ``run_unit``, which pins a statement sequence to one session because the write
statements share session state; see its docstring. There is no transaction: the platform
connection runs with ``@@autocommit = 1``, and disabling that on a platform-owned connection would
change behaviour for everything else it serves. A partially applied write is therefore reachable,
so every control (``ENABLE_DB_WRITE_TOOLS``, parameterisation, the audit record) runs before the
statement; nothing here can undo a write.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from powerpack_mcp.errors import (
    DbDeadlineExceeded,
    DbError,
    DbQueryTimeout,
    DbUnreachable,
    LogEvent,
)
from powerpack_mcp.mcp_app.concurrency import remaining_deadline_seconds

if TYPE_CHECKING:
    from collections.abc import Callable

    from sl_mysql.silo_cursor import Row, silo_cursor

__all__ = [
    "CONNECTION_CACHE_CEILING",
    "MAX_STATEMENT_TIME_EXCEEDED",
    "MIN_STATEMENT_TIME_SECONDS",
    "DbClient",
    "StatementResult",
    "db_worker_count",
    "platform_available",
    "platform_import_error",
]

logger = logging.getLogger(__name__)

# MariaDB's errno for ``max_statement_time`` expiry. Observed rather than documented:
# ``SET SESSION max_statement_time=0.5`` then ``SELECT SLEEP(3)`` raised
# ``OperationalError(1969, 'Query execution was interrupted (max_statement_time exceeded)')`` after
# 0.50 s on MariaDB 10.11.16.
MAX_STATEMENT_TIME_EXCEEDED: Final[int] = 1969

# ``LRUCache(maxsize=30)``, the platform connection cache's size, read from the live module. Used
# only as the ceiling on worker threads. ``Config`` allows ``MAX_CONCURRENT_REQUESTS`` up to 64,
# so this cap can bite.
CONNECTION_CACHE_CEILING: Final[int] = 30

# Floor for the statement timeout. MariaDB reads ``max_statement_time = 0`` as no limit, so a zero
# value would turn an expired deadline into an unbounded query. Guarded here as well as in
# ``remaining_deadline_seconds`` because this is the last point before the value reaches the server.
MIN_STATEMENT_TIME_SECONDS: Final[float] = 0.001


def db_worker_count(max_concurrent_requests: int) -> int:
    """Return the database worker pool size: ``min(MAX_CONCURRENT_REQUESTS, 30)``.

    Threads equal inbound slots so requests are rejected at the gate rather than queueing invisibly
    inside the executor, where they would hold memory. The value is derived rather than a literal so
    tuning ``MAX_CONCURRENT_REQUESTS`` cannot silently decouple the two.

    :param max_concurrent_requests: The inbound concurrency limit.
    :return: The worker count, capped at ``CONNECTION_CACHE_CEILING``.
    :raises ValueError: If ``max_concurrent_requests`` is less than 1.
    """
    if max_concurrent_requests < 1:
        raise ValueError(f"max_concurrent_requests must be >= 1, got {max_concurrent_requests}")
    return min(max_concurrent_requests, CONNECTION_CACHE_CEILING)


@dataclass(frozen=True, slots=True)
class StatementResult:
    """One statement's outcome inside a ``run_unit`` sequence.

    ``rowcount`` and ``lastrowid`` come from the platform cursor; both were confirmed present on the
    running platform. ``lastrowid`` lets ``sl1_simulate_event`` report its new event id without a
    second ``SELECT LAST_INSERT_ID()``, one fewer statement in a unit that cannot be rolled back.

    If either attribute is absent they default to ``-1`` and ``0``, so a driver difference yields a
    useless but safe value rather than an ``AttributeError`` after a write has committed.

    :ivar rows: The rows the statement returned.
    :ivar rowcount: The cursor's ``rowcount``.
    :ivar lastrowid: The cursor's ``lastrowid``.
    """

    rows: tuple[Row, ...]
    rowcount: int
    lastrowid: int


@dataclass(frozen=True, slots=True)
class _Platform:
    """The platform symbols this module uses, resolved once. See ``typings/`` for the stubs."""

    local_db: Callable[[], silo_cursor]
    operational_error: type[BaseException]
    interface_error: type[BaseException]


_platform: _Platform | None = None
_platform_error: str | None = None
_platform_lock = threading.Lock()


def _load_platform() -> _Platform:
    """Import the platform DB modules once, or raise ``DbUnreachable``.

    An absent driver is a startup condition: the DB tool sets are disabled with
    ``ToolSetDisabledReason.PREREQUISITE_MISSING`` and never registered, so normally no caller
    reaches here. This handles the abnormal case, and fails closed. The import is guarded because
    ``sl_mysql`` needs ``libem7`` at import time, so the failure is an exception during import.

    :raises DbUnreachable: If the platform modules cannot be imported, now or on an earlier call.
    """
    global _platform, _platform_error  # module-level resolve-once cache
    with _platform_lock:
        if _platform is not None:
            return _platform
        if _platform_error is not None:
            raise DbUnreachable(_platform_error)
        try:
            # Deferred deliberately: these must not fail at module import.
            import MySQLdb
            from sl_mysql.silo_cursor import local_db
        except Exception as exc:  # noqa: BLE001 - any import-time platform failure is the same story
            # The exception's own text is deliberately discarded: a platform import error can name
            # filesystem paths, and credential material travels readily in this area. The type
            # name alone is diagnostic enough.
            _platform_error = f"platform database modules unavailable ({type(exc).__name__})"
            raise DbUnreachable(_platform_error) from None
        _platform = _Platform(
            local_db=local_db,
            operational_error=MySQLdb.OperationalError,
            interface_error=MySQLdb.InterfaceError,
        )
        return _platform


def platform_import_error() -> str | None:
    """Return the recorded import failure, or ``None`` before any attempt or on success.

    This is a cache read and cannot gate registration, because the import happens lazily; use
    :func:`platform_available`.
    """
    return _platform_error


def platform_available() -> bool:
    """Attempt the platform import now and report whether it succeeded.

    Registration must use this, not ``platform_import_error()``. That returns the cached outcome of
    an import ``_load_platform`` performs lazily, so before any tool call it is ``None``, which is
    indistinguishable from success; gating on it would register the SQL tools on a driverless
    appliance and let them fail at first use instead of being withheld with a stated reason.

    This opens no connection and contacts no database: ``_load_platform`` only resolves
    ``local_db`` and two exception types. The result is fixed for the life of the process, so
    registration stays deterministic.

    :return: ``True`` if the platform database modules are importable.
    """
    try:
        _load_platform()
    except DbUnreachable:
        return False
    return True


def _errno_of(exc: BaseException) -> int | None:
    """Return the MySQLdb errno from ``args[0]``, or ``None`` if the exception is not shaped so.

    Defensive because mistakes are asymmetric: mistaking 1969 for a generic failure discards a
    healthy connection, but mistaking a generic failure for 1969 would keep a broken one, so an
    unrecognisable shape must fall through to the discard branch.
    """
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return args[0]
    return None


class DbClient:
    """Thread-affine, bounded access to the appliance database.

    Not a connection pool: each worker thread reuses its own connection, and the platform's
    connection cache is never touched. Constructing a ``DbClient`` opens no connection.

    :param max_concurrent_requests: The inbound concurrency limit, which sizes the worker pool.
    """

    def __init__(self, max_concurrent_requests: int) -> None:
        self._workers = db_worker_count(max_concurrent_requests)
        self._executor = ThreadPoolExecutor(max_workers=self._workers, thread_name_prefix="pmcp-db")
        self._thread_state = threading.local()
        self._closed = False

    @property
    def worker_count(self) -> int:
        """The worker pool size, which is also the maximum number of connections."""
        return self._workers

    async def fetch_all(self, statement: object) -> tuple[Row, ...]:
        """Run a ``sql.Statement`` off the event loop and return every row.

        ``statement`` is typed ``object`` and duck-checked rather than importing
        ``powerpack_mcp.sql``, so ``sql`` has no dependency on this module and its property tests
        need no appliance.

        :param statement: A ``sql.Statement``.
        :return: Every row the statement returned.
        :raises DbDeadlineExceeded: If the request deadline is already spent.
        :raises DbQueryTimeout: If the server stopped the statement at ``max_statement_time``.
        :raises DbError: If the database failed the statement.
        :raises DbUnreachable: If the client is closed or no connection could be opened.
        """
        sql = getattr(statement, "sql", None)
        params = getattr(statement, "params", None)
        if not isinstance(sql, str) or not isinstance(params, tuple):
            raise TypeError("fetch_all requires a sql.Statement")
        if self._closed:
            raise DbUnreachable("db_client is closed")

        # Capture the remainder here, on the event loop, and pass it in as an argument. The submit
        # below also copies the context, but the statement bound is a correctness property, so it
        # comes from an argument that a future change to how work is submitted cannot silently
        # drop. A worker that saw ``None`` would run the query unbounded until the platform's
        # 3600 s default.
        remaining = remaining_deadline_seconds()
        self._refuse_if_deadline_spent(remaining)
        loop = asyncio.get_running_loop()
        try:
            # Submit through a copy of the calling context, so records emitted from the worker carry
            # the request's ``correlation_id`` instead of the ``startup`` default.
            context = contextvars.copy_context()
            # A zero-argument closure rather than ``context.run, self._execute, ...``, because
            # ``run_in_executor`` types its extras as bare ``*args`` and pyright rejects binding
            # ``Context.run`` there.
            return await loop.run_in_executor(
                self._executor, lambda: context.run(self._execute, sql, params, remaining)
            )
        except asyncio.CancelledError:
            # Our await was abandoned by the deadline or a client disconnect, but the worker thread
            # and its connection are still executing. The inbound slot is already released, so
            # nothing else would show why capacity is missing; the statement timeout bounds it and
            # this record makes it visible. Distinct from ``db_query_timeout`` on purpose: that one
            # is recovered, this one is a leak.
            logger.warning(
                "A DB query's caller went away while the query was still running.",
                extra={
                    "event": str(LogEvent.DB_AWAIT_ABANDONED),
                    "statement_timeout_seconds": remaining,
                },
            )
            raise

    async def run_unit(self, *statements: object) -> tuple[StatementResult, ...]:
        """Run several ``sql.Statement`` objects on one connection, in order.

        This is the write path. The write tools' statements share session state (``SET @ct``,
        ``LAST_INSERT_ID()``), two ``local_db()`` handles do not share a session, and consecutive
        ``fetch_all`` calls may land on different workers. Straddling sessions would turn
        ``COALESCE(@ct, class_type)`` into a silent no-op ``UPDATE`` whose success check still
        passes. Statements are sent one ``execute()`` at a time, never as a multi-statement script,
        so less statement text passes through each parameterised call.

        Not atomic. With ``@@autocommit = 1`` each statement commits before the next runs, so a
        failure part-way leaves earlier statements applied with no rollback; for example,
        ``sl1_create_device_class``'s ``INSERT ... SELECT`` can succeed while the alignment
        ``UPDATE`` after it fails. Put the statement whose failure is cheapest first, and never
        treat a raise from here as "nothing happened".

        :param statements: The ``sql.Statement`` objects to run.
        :return: One ``StatementResult`` per statement, in order, so a caller can read
            ``lastrowid`` from an ``INSERT`` and rows from a following ``SELECT``.
        :raises ValueError: If no statements are given.
        :raises DbDeadlineExceeded: If the request deadline is already spent.
        :raises DbQueryTimeout: If the server stopped a statement at ``max_statement_time``.
        :raises DbError: If the database failed a statement.
        :raises DbUnreachable: If the client is closed or no connection could be opened.
        """
        prepared: list[tuple[str, tuple[object, ...]]] = []
        for statement in statements:
            sql = getattr(statement, "sql", None)
            params = getattr(statement, "params", None)
            if not isinstance(sql, str) or not isinstance(params, tuple):
                raise TypeError("run_unit requires sql.Statement values")
            prepared.append((sql, params))
        if not prepared:
            raise ValueError("run_unit requires at least one statement")
        if self._closed:
            raise DbUnreachable("db_client is closed")

        # As in ``fetch_all``: read the remainder on the event loop, and refuse a spent deadline
        # before a connection or worker is occupied.
        remaining = remaining_deadline_seconds()
        self._refuse_if_deadline_spent(remaining)
        loop = asyncio.get_running_loop()
        try:
            # As in ``fetch_all``: carry the request's context into the worker.
            context = contextvars.copy_context()
            # A distinct name rather than rebinding ``statements``: the parameter's declared type is
            # ``tuple[object, ...]``, which does not match what ``_execute_unit`` requires, and mypy
            # rejects the rebind.
            unit = tuple(prepared)
            return await loop.run_in_executor(
                self._executor, lambda: context.run(self._execute_unit, unit, remaining)
            )
        except asyncio.CancelledError:
            # The same leak event as ``fetch_all``, and worse here: an abandoned unit may already
            # have committed some of its statements.
            logger.warning(
                "A DB unit's caller went away while the unit was still running.",
                extra={
                    "event": str(LogEvent.DB_AWAIT_ABANDONED),
                    "statement_timeout_seconds": remaining,
                },
            )
            raise

    def _execute_unit(
        self, prepared: tuple[tuple[str, tuple[object, ...]], ...], remaining: float | None
    ) -> tuple[StatementResult, ...]:
        """Run ``run_unit``'s statements synchronously, on one thread and so one connection."""
        platform = _load_platform()
        cursor = self._cursor(platform)
        timeout = self._statement_timeout(remaining)
        results: list[StatementResult] = []
        for sql, params in prepared:
            # The bound is applied per statement using the deadline captured once before dispatch,
            # so each statement gets the caller's full remainder and a unit of N statements can run
            # up to N times that remainder on the server. The caller's await is still bounded by its
            # own ``asyncio`` deadline; those are different bounds.
            self._run_one(platform, cursor, sql, params, timeout)
            results.append(
                StatementResult(
                    rows=cursor.fetchall(),
                    rowcount=int(getattr(cursor, "rowcount", -1)),
                    lastrowid=int(getattr(cursor, "lastrowid", 0)),
                )
            )
        return tuple(results)

    def _execute(
        self, sql: str, params: tuple[object, ...], remaining: float | None
    ) -> tuple[Row, ...]:
        """Run one statement synchronously on a worker thread and return its rows."""
        platform = _load_platform()
        cursor = self._cursor(platform)
        timeout = self._statement_timeout(remaining)
        self._run_one(platform, cursor, sql, params, timeout)
        return cursor.fetchall()

    def _run_one(
        self,
        platform: _Platform,
        cursor: silo_cursor,
        sql: str,
        params: tuple[object, ...],
        timeout: float | None,
    ) -> None:
        """Execute one statement with its server-side timeout, discarding a suspect connection.

        Shared by ``fetch_all`` and ``run_unit`` so error classification cannot diverge between
        the read and write paths, where errno 1969 would discard a healthy connection on one path
        and keep it on the other.

        :raises DbQueryTimeout: If the server stopped the statement at ``max_statement_time``.
        :raises DbError: For any other operational or interface error.
        """
        try:
            if timeout is not None:
                # Set per call, not once per connection: a thread-affine connection outlives many
                # calls with different remaining budgets, so a value set at acquisition would bound
                # later queries by an earlier caller's deadline.
                cursor.execute("SET SESSION max_statement_time = %s", (timeout,))
            # ``params or None`` is deliberate. MySQLdb applies ``sql % args`` whenever ``args`` is
            # not None, so an empty tuple would enable %-formatting for a statement that needs
            # none. ``sql.Statement`` already forbids a literal '%', so this is a second layer.
            cursor.execute(sql, params or None)
        except platform.operational_error as exc:
            if _errno_of(exc) == MAX_STATEMENT_TIME_EXCEEDED:
                # The connection is kept. The server ended the query and drained its result, and a
                # ``SELECT 1+1`` on the same connection succeeded immediately afterwards, so
                # discarding here would throw away a healthy connection on every slow query.
                logger.info(
                    "A DB query was stopped by the server statement timeout.",
                    extra={
                        "event": str(LogEvent.DB_QUERY_TIMEOUT),
                        "statement_timeout_seconds": timeout,
                    },
                )
                raise DbQueryTimeout(timeout if timeout is not None else 0.0) from None
            self._discard()
            raise DbError("the database failed the request") from None
        except platform.interface_error:
            self._discard()
            raise DbError("the database connection failed") from None

    def _cursor(self, platform: _Platform) -> silo_cursor:
        """Return this thread's cursor, creating it on first use.

        Obtained through ``local_db()``, never by building connection parameters here. ``Config``
        has no database host, port, user or password, so ``host="localhost"`` cannot be supplied by
        accident; it would silently switch the transport off the TCP:7706 path.

        :raises DbUnreachable: If no connection could be opened.
        """
        existing: silo_cursor | None = getattr(self._thread_state, "cursor", None)
        if existing is not None:
            return existing
        try:
            cursor = platform.local_db()
        except Exception as exc:  # noqa: BLE001 - the driver's own message must not propagate
            raise DbUnreachable(
                f"could not open a database connection ({type(exc).__name__})"
            ) from None
        self._thread_state.cursor = cursor
        return cursor

    def _discard(self) -> None:
        """Drop this thread's connection so the next call reconnects.

        ``local_db()`` returns a cursor that holds the connection, so closing a cursor per query
        would defeat per-thread reuse. One cursor per thread, closed here and in ``aclose``, meets
        the intent that every cursor is closed without inventing an unverified way to make cursors
        from the connection.

        A failure to close is swallowed: this is already an error path, the connection is being
        abandoned regardless, and the driver's message must not escape.
        """
        cursor: silo_cursor | None = getattr(self._thread_state, "cursor", None)
        self._thread_state.cursor = None
        if cursor is None:
            return
        with contextlib.suppress(Exception):  # see the docstring
            cursor.close()

    @staticmethod
    def _refuse_if_deadline_spent(remaining: float | None) -> None:
        """Refuse before a worker or connection is occupied when the deadline is already spent.

        ``remaining_deadline_seconds`` clamps at ``0.0``, so exactly zero means the deadline has
        passed. Without this check, ``_statement_timeout`` would floor it to
        ``MIN_STATEMENT_TIME_SECONDS`` and issue the statement with a 1 ms budget, MariaDB would
        kill it with errno 1969, and the caller would get a ``DbQueryTimeout`` advising a narrower
        query when nothing was slow.

        The test is ``> 0.0``, with no invented threshold: a positive but tiny remainder still goes
        to the floor, because a minimum "worth attempting" budget would be policy this layer has no
        basis for.

        ``None`` returns early: it means no deadline is in force (health checks, startup work), and
        refusing it would break those paths.

        This raises on the event loop, so the record carries the request's ``correlation_id``
        rather than a worker-thread default.

        :raises DbDeadlineExceeded: If ``remaining`` is zero.
        """
        if remaining is None or remaining > 0.0:
            return
        logger.info(
            "Refused a DB statement: the request deadline was spent before it could be issued.",
            extra={
                "event": str(LogEvent.DB_DEADLINE_EXCEEDED),
                "remaining_deadline_seconds": remaining,
            },
        )
        raise DbDeadlineExceeded(remaining)

    @staticmethod
    def _statement_timeout(remaining: float | None) -> float | None:
        """Clamp the deadline remainder into a value MariaDB treats as a limit.

        ``None`` means no inbound deadline is in force (health checks, startup work), so the
        statement runs under the platform's own 3600 s default.

        ``_refuse_if_deadline_spent`` rejects an expired deadline before submission, so this only
        floors a positive remainder. Do not remove the floor: MariaDB reads
        ``max_statement_time = 0`` as no limit, so it stops a sub-millisecond budget becoming an
        unbounded query.
        """
        if remaining is None:
            return None
        return max(MIN_STATEMENT_TIME_SECONDS, remaining)

    async def aclose(self) -> None:
        """Stop accepting work and let in-flight queries finish.

        ``cancel_futures=False`` because an in-flight write is never cancelled: some writes'
        idempotency cannot be established, so abandoning them part-way is worse than finishing.
        ``wait=False`` keeps shutdown off the event loop; each thread finishes its current
        statement, which the statement timeout already bounds.
        """
        self._closed = True
        self._executor.shutdown(wait=False, cancel_futures=False)

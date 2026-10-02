"""
Application Composition Root

This module builds the ASGI application: it runs startup, constructs the LCE, SL1 and database
clients, registers the tool sets the configuration selects, installs the middleware chain and
the ASGI-boundary error handler, and owns shutdown through the FastMCP lifespan.

Startup never contacts a backend. Every client is constructed without opening a connection, so
a briefly unavailable LCE or SL1 cannot stop the service starting.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Final

from fastmcp import FastMCP
from starlette.responses import JSONResponse
from starlette.routing import Route

from powerpack_mcp import credentials
from powerpack_mcp.config import Config, load_config
from powerpack_mcp.errors import ERROR_TYPE_INTERNAL, LogEvent
from powerpack_mcp.hook_source import HookCache, Sl1HookSource
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.mcp_app.authz_gate import AuthorizationGate
from powerpack_mcp.mcp_app.concurrency import (
    ConcurrencyGateMiddleware,
    RequestDeadlineMiddleware,
)
from powerpack_mcp.mcp_app.correlation import (
    CorrelationIdMiddleware,
    ToolCallCorrelationMiddleware,
)
from powerpack_mcp.mcp_app.logging_setup import configure_logging
from powerpack_mcp.mcp_app.routes import HEALTH_PATH, health
from powerpack_mcp.prompts.registry import register_prompts
from powerpack_mcp.schema_slim import trim_registered_tools
from powerpack_mcp.sl1_client import Sl1Client
from powerpack_mcp.tool_sets import DB_READ as DB_READ_SET
from powerpack_mcp.tool_sets import DB_WRITE as DB_WRITE_SET
from powerpack_mcp.tool_sets import LCE as LCE_SET
from powerpack_mcp.tool_sets import OPS as OPS_SET
from powerpack_mcp.tool_sets import SL1_GRAPHQL as SL1_GRAPHQL_SET
from powerpack_mcp.tool_sets import SL1_REST as SL1_REST_SET
from powerpack_mcp.tool_sets import STANDARDS as STANDARDS_SET
from powerpack_mcp.tool_sets import RegistrationPlan, ToolSetFlags, resolve

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable
    from contextlib import AbstractAsyncContextManager

    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.types import ASGIApp

    from powerpack_mcp.db_client import DbClient
    from powerpack_mcp.tools.sl1_db_descriptors import DbToolDescriptor
    from powerpack_mcp.tools.sl1_db_pipeline import Sl1DbToolContext as _DbCtx
    from powerpack_mcp.tools.sl1_db_tools import DbToolFactory

    type DbFactoryMaker = Callable[[_DbCtx], DbToolFactory]
    # One tool set's registerable pairs, as ``sl1_db_registry``'s accessors return them.
    type DbSetPairs = tuple[tuple[DbToolDescriptor, DbFactoryMaker], ...]

__all__ = [
    "MCP_MOUNT_PATH",
    "build_mcp_server",
    "create_app",
    "global_error_handler",
    "lifespan_for",
    "log_registration",
    "register_tools",
    "start_up",
]

logger = logging.getLogger(__name__)

# nginx proxies ``/mcp`` to this listener.
MCP_MOUNT_PATH: Final[str] = "/mcp"


def log_registration(plan: RegistrationPlan, *, schemas_trimmed: int) -> None:
    """Log one record per tool set, ``lce`` included, then one summary record.

    Every record carries ``LogEvent.TOOL_SETS_REGISTERED`` because monitoring keys on ``event``,
    never on message text. With tool sets on by default, this log is the only thing that surfaces
    a tool surface widened by an upgrade, so it must be machine-readable.

    The disabled reason is reported, not just the fact, because "the operator turned it off" and
    "a prerequisite is missing" demand opposite responses. ``lce`` is reported with no flag, marking
    it always on, so the log reads as a complete inventory.

    The ``extra`` mapping is exactly ``ToolSetRecord``'s fields: a set id, a boolean, an integer, a
    fixed key name and a closed enum, which leaves no field a secret could occupy.
    ``tests/unit/test_tool_sets.py`` pins that field set, so adding a free-text field fails a test.

    :param plan: The registration plan ``tool_sets.resolve`` produced.
    :param schemas_trimmed: How many tool schemas ``trim_registered_tools`` trimmed.
    """
    for record in plan.records:
        logger.info(
            "Tool set %s is %s.",
            record.set_id,
            "registered" if record.registered else "not registered",
            extra={
                "event": LogEvent.TOOL_SETS_REGISTERED,
                "set_id": record.set_id,
                "registered": record.registered,
                "tool_count": record.tool_count,
                "flag": record.flag,
                "reason": record.reason,
            },
        )
    logger.info(
        "Registered %d tool sets carrying %d tools; trimmed %d schemas.",
        len(plan.registered_ids),
        plan.total_tools,
        schemas_trimmed,
        extra={"event": LogEvent.TOOL_SETS_REGISTERED},
    )


def register_tools(
    server: FastMCP,
    client: LceClient,
    config: Config,
    sl1_client: Sl1Client,
    db_client: DbClient | None = None,
) -> RegistrationPlan:
    """Register the tool sets the configuration selects, and return what was decided.

    The decision belongs to ``tool_sets.resolve``, a pure function; this function only enacts it.
    Keeping the flag logic there makes nesting, disabled reasons and determinism testable without
    constructing an application. A disabled set's tools are never constructed, so there is no
    runtime "is this tool enabled" check anywhere in the service.

    Tool counts are read from the code (``len(ALL_DESCRIPTORS)`` and so on), never declared, so the
    startup log cannot disagree with what actually registered.

    Each LCE factory binds the ``LceClient`` and ``Config`` into a ``ToolContext`` and returns the
    tool coroutine, which ``server.tool`` registers under its descriptor's name, so the name cannot
    drift from the registration. Adding an LCE operation means adding a descriptor, a factory and
    one ``TOOL_FACTORIES`` entry; nothing here changes.

    :param server: The FastMCP server to register tools on.
    :param client: The LCE client shared by every tool that calls LCE.
    :param config: The resolved configuration; the pipeline reads ``MAX_REQUEST_BODY_BYTES``.
    :param sl1_client: The SL1 client shared by the SL1 and database tool sets.
    :param db_client: The database client, or ``None`` when the platform driver is unavailable.
    :return: The registration plan, for ``log_registration``.
    """
    # Imported here to break a real cycle: ``powerpack_mcp.tools`` imports ``mcp_app.correlation``
    # for ``forwarded_actor``, which executes ``mcp_app/__init__``, which imports this module.
    from powerpack_mcp.tools import ALL_DESCRIPTORS, TOOL_FACTORIES, ToolContext
    from powerpack_mcp.tools.sl1_db_registry import db_read_tools, db_write_tools, ops_tools
    from powerpack_mcp.tools.sl1_descriptors import GRAPHQL_PREREQUISITE_MET
    from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
    from powerpack_mcp.tools.sl1_registry import sl1_graphql_set_tools, sl1_rest_set_tools
    from powerpack_mcp.tools.standards_tools import STANDARDS_TOOLS

    # Every count is ``len()`` of what ships, never a literal. A count supplied to ``resolve`` is
    # only as true as its caller, so the caller derives it.
    sl1_rest_pairs = sl1_rest_set_tools()
    sl1_graphql_pairs = sl1_graphql_set_tools()
    # Derived from ``authz``'s inventory, so a tool withheld there (``registers=False``) drops out
    # of this count without an edit here.
    db_read_pairs = db_read_tools()
    db_write_pairs = db_write_tools()
    ops_pairs = ops_tools()

    # An ``import sl_mysql`` failure disables the DB sets with a stated reason and does not stop
    # the service starting. ``db_client is None`` is that prerequisite answer: the composition root
    # constructs the client (so the lifespan can release it) and this reads the same fact, so the
    # two cannot disagree. Do not call ``platform_import_error()`` here; its cache is filled lazily
    # by the first tool call, so at startup it always answers ``None``.
    #
    # ``ops`` is deliberately not in this mapping. Its tools need no driver, ``libem7`` or
    # ``silo.conf``, and gating them here would disable tools that never touch MariaDB.
    db_available = db_client is not None
    plan = resolve(
        ToolSetFlags.from_config(config),
        {
            LCE_SET: len(ALL_DESCRIPTORS),
            STANDARDS_SET: len(STANDARDS_TOOLS),
            SL1_REST_SET: len(sl1_rest_pairs),
            SL1_GRAPHQL_SET: len(sl1_graphql_pairs),
            DB_READ_SET: len(db_read_pairs),
            DB_WRITE_SET: len(db_write_pairs),
            OPS_SET: len(ops_pairs),
        },
        {
            DB_READ_SET: db_available,
            DB_WRITE_SET: db_available,
            # The GraphQL prerequisite goes through ``resolve`` like the DB one, so the startup log
            # reports it as a reason instead of claiming a set registered that did not.
            SL1_GRAPHQL_SET: GRAPHQL_PREREQUISITE_MET,
        },
    )
    registered = set(plan.registered_ids)

    # ``credential_source`` is a callable, not a credential. ``ToolContext`` is process-scoped and
    # cannot hold a request-scoped value. Tests inject a synthetic source, so the default test run
    # needs no real credential.
    context = ToolContext(
        client=client, config=config, credential_source=credentials.credential_for_request
    )
    # No ``if`` here: the LCE set has no flag and is always registered. A conditional would imply
    # a configuration exists that turns it off.
    for descriptor, factory in zip(ALL_DESCRIPTORS, TOOL_FACTORIES, strict=True):
        server.tool(factory(context), name=descriptor.tool_name)

    if STANDARDS_SET in registered:
        for tool_name, tool_function in STANDARDS_TOOLS:
            server.tool(tool_function, name=tool_name)

    # One ``Sl1ToolContext`` serves both SL1 sets: they share one transport client. ``lce_client``
    # is the same instance the LCE tools above received.
    sl1_context = Sl1ToolContext(
        client=sl1_client,
        config=config,
        credential_source=credentials.credential_for_request,
        lce_client=client,
    )
    if SL1_REST_SET in registered:
        for sl1_descriptor, make_rest in sl1_rest_pairs:
            server.tool(make_rest(sl1_context), name=sl1_descriptor.tool_name)

    # Registration depends on the GraphQL prerequisite as well as the flag. ``resolve`` enforces
    # that through ``prerequisites_met``, so membership in ``registered`` is the whole check.
    if SL1_GRAPHQL_SET in registered:
        for gql_descriptor, make_gql in sl1_graphql_pairs:
            server.tool(make_gql(sl1_context), name=gql_descriptor.tool_name)

    _register_db_surface(
        server,
        registered=registered,
        config=config,
        sl1_client=sl1_client,
        lce_client=client,
        db_client=db_client,
        pairs_by_set=(
            (DB_READ_SET, db_read_pairs),
            (DB_WRITE_SET, db_write_pairs),
            (OPS_SET, ops_pairs),
        ),
    )

    return plan


def _register_db_surface(
    server: FastMCP,
    *,
    registered: set[str],
    config: Config,
    sl1_client: Sl1Client,
    lce_client: LceClient,
    db_client: DbClient | None,
    pairs_by_set: tuple[tuple[str, DbSetPairs], ...],
) -> None:
    """Register the three database-era sets: ``db_read``, ``db_write`` and ``ops``.

    Split out of ``register_tools`` to keep it under ruff's complexity limit.

    One ``Sl1DbToolContext`` serves all three sets. It is separate from ``Sl1ToolContext`` rather
    than a widened one, because a context's fields are a claim about what its tools may touch;
    putting a ``DbClient`` on ``Sl1ToolContext`` would say every SL1 tool may reach the database.

    ``db`` is ``None`` when the platform driver is unavailable. The ``ops`` tools register in that
    state and must keep working, so the context must be constructible without a database. Every SQL
    tool calls ``require_db()``, which refuses through ``sl1_tool_boundary`` rather than raising a
    builtin.

    :param registered: The set ids the plan registered.
    :param db_client: The database client, or ``None`` when the driver is unavailable.
    :param pairs_by_set: ``(set_id, pairs)`` for each of the three sets.
    """
    # Function-local for the same cycle-breaking reason `register_tools` documents.
    from powerpack_mcp.tools.sl1_db_pipeline import Sl1DbToolContext

    db_context = Sl1DbToolContext(
        client=sl1_client,
        config=config,
        credential_source=credentials.credential_for_request,
        lce_client=lce_client,
        db=db_client,
    )
    # One loop over ``(set_id, pairs)`` so "a disabled set's tools are never constructed" is
    # visibly true of all three sets. A withheld tool is absent from ``pairs`` by construction,
    # never by a name check here.
    for set_id, pairs in pairs_by_set:
        if set_id in registered:
            for db_descriptor, make_db_tool in pairs:
                server.tool(make_db_tool(db_context), name=db_descriptor.tool_name)


def lifespan_for(
    client: LceClient, sl1_client: Sl1Client, db_client: DbClient | None = None
) -> Callable[[FastMCP], AbstractAsyncContextManager[None]]:
    """Build the lifespan that releases the client pools on shutdown.

    On shutdown the server stops accepting, in-flight requests drain within the request deadline,
    then each client's ``aclose()`` releases its pool. ``aclose()`` is idempotent, so a repeated
    signal is harmless. The service holds no durable state, so ``systemctl restart`` is safe at any
    moment.

    Each close sits in its own ``finally``, so an exception from one cannot skip the next and leak
    a pool that the failure makes more likely to hold open connections.

    :param client: The LCE client.
    :param sl1_client: The SL1 client.
    :param db_client: The database client, or ``None`` when none was constructed.
    :return: A lifespan factory for ``FastMCP(lifespan=...)``.
    """

    @asynccontextmanager
    async def lifespan(server: FastMCP) -> AsyncIterator[None]:
        del server
        try:
            yield
        finally:
            # ``finally``, so the pools are released on every shutdown path, including a failure.
            # The nested ``try/finally`` blocks make that true of each pool in turn.
            try:
                await client.aclose()
            finally:
                try:
                    await sl1_client.aclose()
                finally:
                    # The database client owns a ``ThreadPoolExecutor`` and thread-affine
                    # cursors, which leak unless released here.
                    if db_client is not None:
                        await db_client.aclose()

    return lifespan


def build_mcp_server(
    config: Config,
    client: LceClient,
    sl1_client: Sl1Client,
    db_client: DbClient | None = None,
) -> FastMCP:
    """Construct the FastMCP server with its middleware, tools and prompts.

    Only the Streamable HTTP transport is served; ``create_app`` selects it with
    ``http_app(transport="http")`` and nothing enables SSE.

    The steps are ordered: register the sets the plan selects, trim the schemas of the tools that
    actually registered, then log one record per set once the counts are known. Trimming fails
    closed with ``SchemaTrimError`` if it cannot reach FastMCP's registered tools, because shipping
    untrimmed schemas silently is the regression trimming exists to prevent.

    :param config: The resolved configuration.
    :param client: The LCE client.
    :param sl1_client: The SL1 client.
    :param db_client: The database client, or ``None`` when the driver is unavailable.
    :return: The configured server.
    """
    server: FastMCP = FastMCP(
        name="powerpack-mcp",
        lifespan=lifespan_for(client, sl1_client, db_client),
        # Order matters. FastMCP wraps in reverse, so the first entry runs first. The two
        # context-arming middlewares run ahead of the authorization gate so the gate's own SL1 hook
        # fetch also runs under a freshly armed deadline.
        #
        # Putting the gate third does not ungate anything: both middlewares ahead of it only set a
        # contextvar and call ``call_next`` unconditionally, and a test asserts that.
        #
        # Passed as construction arguments rather than added later, so the server never exists
        # ungated or serving tool calls on a stale deadline.
        middleware=[
            ToolCallCorrelationMiddleware(),
            RequestDeadlineMiddleware(config.LCE_READ_TIMEOUT_SECONDS),
            AuthorizationGate(
                cache=HookCache(
                    # No new configuration key. The hook fetch is an SL1 REST read, so it uses
                    # the read timeout and stays within the 85 s ceiling the deadline rests on.
                    Sl1HookSource(sl1_client, timeout=config.LCE_READ_TIMEOUT_SECONDS)
                ),
                credential_source=credentials.credential_for_request,
            ),
        ],
    )
    plan = register_tools(server, client, config, sl1_client, db_client)
    # Unconditional, and not part of the ``RegistrationPlan``: prompts are static text with no
    # transport, so there is nothing to decide, gate or report.
    register_prompts(server)
    trimmed = trim_registered_tools(server)
    log_registration(plan, schemas_trimmed=trimmed)
    return server


async def global_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle an unhandled exception at the ASGI boundary.

    Returns a generic response and logs the real cause. The handler runs inside
    ``CorrelationIdMiddleware``, so its ERROR record carries the correlation id: the response must
    be generic, and the shared id is what keeps it diagnosable, since a caller quotes it and an
    operator finds the cause.

    The exception message is never rendered. ``h11``'s ``LocalProtocolError`` embeds the offending
    header value in its message, so a malformed credential would land in a log record. Only the
    exception type is logged, and ``exc_info`` is deliberately not passed. Startup validation
    rejects such values too; this is the second layer, not the only one.

    The response carries no stack trace, internal path, framework version or configuration value.

    :return: A 500 response with a generic ``internal_error`` body.
    """
    del request
    logger.error(
        "Unhandled exception; returning a generic error response.",
        extra={"event": LogEvent.UNHANDLED_EXCEPTION, "exception_type": type(exc).__name__},
    )
    return JSONResponse(
        {
            "error": {
                "type": ERROR_TYPE_INTERNAL,
                "message": (
                    "An internal error occurred. Quote the correlation identifier from the "
                    "response "
                    "headers when reporting this."
                ),
            }
        },
        status_code=500,
    )


def start_up(config: Config | None) -> Config:
    """Configure logging and load configuration, the first two startup steps.

    There is no credential step: the credential arrives with each request.

    :param config: A configuration to use, or ``None`` to load it from the environment.
    :return: The resolved configuration.
    :raises ConfigurationError: If the configuration is invalid.
    """
    # 1. Logging first, at a provisional level because there is no Config to read one from
    # yet, so that a configuration failure is itself logged in the structured format.
    configure_logging()
    try:
        # 2. Load configuration.
        resolved = config if config is not None else load_config()
        # Re-install at the configured level now that it is known.
        configure_logging(resolved.LOG_LEVEL)
    except Exception:
        # Exactly one ERROR record with event=startup_failed, then the caller exits. No retry.
        # ConfigurationError's message names the offending key and what would be valid, and is
        # safe to render because it never reaches a caller.
        logger.exception(
            "Startup failed; the service will not start.",
            extra={"event": LogEvent.STARTUP_FAILED},
        )
        raise
    return resolved


def create_app(config: Config | None = None) -> ASGIApp:
    """Build the complete ASGI application; the uvicorn entry point and single composition root.

    Startup order, and no step may be reordered::

        1. configure logging <-- first, so a config failure is logged in the structured format
        2. load configuration
        3. construct the clients           (their pools are released by the lifespan)
        4. build the MCP server and register tools
        5. bind the listener <-- last: no request can arrive before the above are in place

    Startup never contacts LCE. A briefly unavailable LCE must not stop the service starting, and
    with no configured credential there is nothing to contact it with anyway. There is no readiness
    endpoint; LCE reachability surfaces as ``LceUnreachable`` on a tool call. A missing credential
    is refused per request instead of at boot.

    There is deliberately no degraded mode, and no default is substituted for an invalid explicit
    value.

    :param config: A configuration to use, or ``None`` to load it from the environment.
    :return: The ASGI application, wrapped in ``CorrelationIdMiddleware``.
    :raises ConfigurationError: If the configuration is invalid; the process then exits non-zero.
    """
    # Function-local because of a real cycle: ``db_client`` imports ``mcp_app.concurrency`` for
    # ``remaining_deadline_seconds``, which executes ``mcp_app/__init__``, which imports this
    # module. A module-level import type-checks cleanly but fails at collection when a test imports
    # ``db_client`` first. The annotations use the ``TYPE_CHECKING`` import instead.
    from powerpack_mcp.db_client import DbClient, platform_available

    resolved = start_up(config)

    # 3. Constructing LceClient opens no connections (httpx builds its pool lazily), so one
    # side-effect-free instance can be shared by every LCE caller.
    client = LceClient(resolved)
    # The SL1 transport, with the same property: no connection opens until a tool calls out.
    sl1_client = Sl1Client(resolved)
    # The database client is constructed here, not inside registration, so the lifespan can
    # release it. An absent driver disables the DB sets with a stated reason rather than failing
    # startup, so ``None`` is a normal outcome. Neither ``platform_available()`` (an import) nor
    # ``DbClient.__init__`` (an executor and a thread-local store) opens a connection.
    db_client = DbClient(resolved.MAX_CONCURRENT_REQUESTS) if platform_available() else None

    # 4. Build the MCP server.
    server = build_mcp_server(resolved, client, sl1_client, db_client)

    app: Starlette = server.http_app(path=MCP_MOUNT_PATH, transport="http")
    app.router.routes.append(Route(HEALTH_PATH, health, methods=["GET"]))
    app.add_exception_handler(Exception, global_error_handler)
    # Registered with ``add_middleware``, not by wrapping the returned app. Starlette composes
    # ``ServerErrorMiddleware -> user middleware -> ExceptionMiddleware -> router``, so the gate
    # sits inside the generic ``Exception`` handler installed above, inside
    # ``CorrelationIdMiddleware`` below, and still before any body is read. An outer wrapper would
    # sit outside the handler.
    #
    # The deadline is passed in rather than read from ``Config`` by the middleware, so the gate is
    # a function of primitives and testable without a configuration model.
    #
    # The deadline is exactly ``LCE_READ_TIMEOUT_SECONDS``, not the timeout plus an allowance. The
    # ceiling is 85 s and ``config.py`` spends the remaining 5 s of systemd's 90 s
    # ``TimeoutStopSec`` on teardown, so any positive allowance breaks the budget at the ceiling. A
    # gate-level deadline wraps the entire ASGI call, so local work is included rather than added:
    #
    #     <= 85s deadline  +  5s teardown  =  90s
    #
    # This line is what bounds the shutdown drain; the systemd unit needs no ``TimeoutStopSec``
    # override because of it.
    #
    # Outbound calls stop ``OUTBOUND_DEADLINE_MARGIN_SECONDS`` inside this deadline, so a slow
    # backend returns the tool's own error instead of being cut off here with no reply. The margin
    # is taken out of the outbound budget, never added to this value.
    app.add_middleware(
        ConcurrencyGateMiddleware,
        limit=resolved.MAX_CONCURRENT_REQUESTS,
        deadline_seconds=resolved.LCE_READ_TIMEOUT_SECONDS,
    )

    # 5. Binding is uvicorn's: it binds the listener after the lifespan's startup completes, so
    # "the listener binds last" is structural rather than a convention.
    #
    # CorrelationIdMiddleware is outermost, so the error handler above runs inside its scope and
    # its ERROR record carries a correlation id.
    return CorrelationIdMiddleware(app)

"""
SL1 Health, Capability and Discovery Tools

This module defines ``server_health``, ``sl1_check_capabilities`` and the four discovery session
tools. It differs from the reference implementation in three deliberate ways:

- ``sl1_check_capabilities`` derives its report from this server's own ``authz.TOOL_REGISTRY``
  rather than a hand-written capability table, so it cannot name a tool this server does not
  ship and needs no maintenance when the tool surface changes.
- There is no ``refresh_capability_map``. It would need a writable state directory to store the
  snapshot it diffs against, and a tool with that name that refreshes nothing would give a wrong
  answer presented as a right one.
- ``server_health`` has no SSH probe. This service holds no SSH credentials, so an SSH check could
  never succeed; the payload says so explicitly.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Final

from powerpack_mcp import authz
from powerpack_mcp.errors import LceHttpError, PowerPackMcpError
from powerpack_mcp.tools import sl1_db_descriptors as d
from powerpack_mcp.tools.sl1_db_pipeline import refuse
from powerpack_mcp.tools.sl1_pipeline import sl1_tool_boundary

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from powerpack_mcp.tools.sl1_db_pipeline import Sl1DbToolContext

    type DbToolFactory = Callable[..., Awaitable[object]]

__all__ = [
    "make_server_health",
    "make_sl1_check_capabilities",
    "make_sl1_create_discovery_session",
    "make_sl1_get_discovery_status",
    "make_sl1_list_discovery_sessions",
    "make_sl1_run_discovery_session",
]

logger = logging.getLogger(__name__)

# GraphQL introspection of the root types, as in the reference implementation's capability probe.
#
# Introspection is not permission-gated on SL1, while data queries are, so this returns the schema
# shape but is not evidence that the caller may use what it lists; ``sl1_check_capabilities`` says
# so in its output.
#
# ``includeDeprecated: true`` is required. SL1 marks its experimental features ``@deprecated`` and
# GraphQL defaults the flag to ``false``; without it this probe sees 157 of 359 query fields and 261
# of 458 mutations, and reports real capabilities as absent.
_ROOTS_QUERY = """
query IntrospectRoots {
  __schema {
    queryType { fields(includeDeprecated: true) { name } }
    mutationType { fields(includeDeprecated: true) { name } }
  }
}
"""

_VERSION_QUERY = "{ systemInformation { em7Version } }"

# The resource path used to prove LCE is answering. Narrow on purpose: one field, one filter, so a
# reachability probe cannot become an expensive scan.
#
# The leading slash is required. ``LceClient._build_url`` composes ``f"{LCE_BASE_PATH}{path}"``
# with no separator, so an LCE path must be absolute; without it the URL becomes
# ``/lce/apievent_policies`` and ``server_health`` reports ``lce.reachable: false`` while LCE is
# healthy. ``Sl1Client`` normalises paths and accepts a missing leading slash; ``LceClient`` does
# not.
_LCE_PROBE_PATH = "/event_policies"
_LCE_PROBE_QUERY = {"fields": "id", "filter[id][gt]": "0"}


# Stable, greppable probe names for ``_log_probe_failed``/``_log_probe_unusable``. Not payload
# keys: they exist only so an operator can grep one transport out of the service log.
_PROBE_REST = "rest"
_PROBE_GRAPHQL = "graphql"
_PROBE_VERSION = "graphql_version"
_PROBE_LCE = "lce"

# The 2xx band, named rather than inlined so ``_probe``'s LCE verdict reads as "success", not "200".
_HTTP_OK_MIN = 200
_HTTP_OK_MAX_EXCLUSIVE = 300


async def _probe(context: Sl1DbToolContext) -> dict[str, Any]:
    """Read the live surface across all three transports. Every probe degrades to "unknown".

    A probe that fails must never make a capability read as unavailable, because a transport being
    down is a different fact from a feature being missing. Each ``*_ok`` flag records whether the
    probe itself succeeded, so a caller can tell the two apart.

    A degraded probe is logged as well as flagged. The flag says that a probe failed, never why, so
    the reason (an unreachable host, a 401, a 500, a malformed body, a TLS failure) goes to the
    service log; an operator diagnosing a false ``reachable`` reads the log, not the tool output.

    :return: The probe signals: ``*_ok`` flags, the version, and the discovered resources and
        root fields.
    """
    signals: dict[str, Any] = {
        "rest_ok": False,
        "graphql_ok": False,
        "lce_ok": False,
        "em7_version": None,
        "rest_resources": [],
        "graphql_queries": [],
        "graphql_mutations": [],
    }
    credential = context.credential_source()

    try:
        index = await context.client.request(credential=credential, method="GET", path="/")
    except PowerPackMcpError as exc:
        _log_probe_failed(_PROBE_REST, exc)
    else:
        resources = _read_rest_index(index)
        if resources is not None:
            signals["rest_resources"] = resources
            signals["rest_ok"] = True

    try:
        schema = await context.client.graphql(credential=credential, query=_ROOTS_QUERY)
    except PowerPackMcpError as exc:
        _log_probe_failed(_PROBE_GRAPHQL, exc)
    else:
        queries, mutations = _read_graphql_roots(schema)
        signals["graphql_queries"] = queries
        signals["graphql_mutations"] = mutations
        signals["graphql_ok"] = bool(queries or mutations)

    try:
        version = await context.client.graphql(credential=credential, query=_VERSION_QUERY)
    except PowerPackMcpError as exc:
        _log_probe_failed(_PROBE_VERSION, exc)
    else:
        info = (version.get("data") or version).get("systemInformation") or {}
        signals["em7_version"] = info.get("em7Version") if isinstance(info, dict) else None

    try:
        response = await context.lce_client.request(
            credential=credential,
            method="GET",
            path=_LCE_PROBE_PATH,
            query=_LCE_PROBE_QUERY,
        )
    except PowerPackMcpError as exc:
        _log_probe_failed(_PROBE_LCE, exc)
    else:
        # ``LceClient.request`` raises ``LceHttpError`` on any non-2xx, so only a 2xx reaches here.
        # Testing ``== 200`` would report a healthy LCE answering 201, 202 or 204 as unreachable.
        # The full 2xx range is checked rather than hardcoding ``True`` so the verdict states its
        # own criterion here, instead of depending on an invariant in another module.
        signals["lce_ok"] = _HTTP_OK_MIN <= response.status_code < _HTTP_OK_MAX_EXCLUSIVE

    return signals


def _read_rest_index(index: object) -> list[str] | None:
    """Return SL1's ``/`` index as resource names, or ``None`` if it was not an index at all.

    ``None`` rather than ``[]`` keeps "not an index" distinguishable from "an empty index", the same
    absent/unknown distinction ``_probe`` preserves. A non-list means SL1 answered something on
    ``/`` that is not a resource index, such as a login redirect body or an error envelope delivered
    with a 2xx. ``rest_ok`` stays false, and the case is logged so it is distinguishable from a
    connect failure. Kept out of ``_probe`` to hold it under the ``C901`` complexity bound.
    """
    if not isinstance(index, list):
        _log_probe_unusable(_PROBE_REST, "the resource index was not a JSON array")
        return None
    return sorted(
        str(item.get("URI", "")).rstrip("/").split("/")[-1]
        for item in index
        if isinstance(item, dict) and item.get("URI")
    )


def _read_graphql_roots(schema: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Return the root types' field names, logging an introspection that named none.

    Empty roots leave ``graphql_ok`` false even though the transport answered, authenticated and
    parsed: a successful probe reading as unreachable. Kept out of ``_probe`` for the same ``C901``
    reason as ``_read_rest_index``.

    :return: ``(query_names, mutation_names)``, each sorted.
    """
    root = (schema.get("data") or schema).get("__schema") or {}
    queries = sorted(_field_names(root.get("queryType")))
    mutations = sorted(_field_names(root.get("mutationType")))
    if not (queries or mutations):
        _log_probe_unusable(
            _PROBE_GRAPHQL, "introspection succeeded but named no query or mutation fields"
        )
    return queries, mutations


def _log_probe_failed(probe: str, exc: PowerPackMcpError) -> None:
    """Log that one transport probe raised, and what kind of failure it was.

    This must not write caller data to the service log, so it records exactly two things, both
    non-secret:

    * ``type(exc).__name__``, a name from this service's own closed exception hierarchy in
      ``errors``, chosen at ``raise`` time and interpolating nothing from the request or response.
    * the backend's numeric HTTP status, where the exception carries one.

    ``str(exc)`` and payload attributes are deliberately not logged. The exception messages are safe
    today, but this catches ``PowerPackMcpError``, the base of the whole hierarchy, so it also sees
    every subclass added later, and one that puts a response fragment in its message would leak
    here unnoticed. ``LceHttpError.lce_body`` is sanitised and capped by its constructor, but
    ``sanitize_lce_body`` redacts only known secret field names, and a reachability probe has no
    need of a body to justify that residual risk.

    The record carries no ``event``. ``LogEvent`` is a closed vocabulary that monitoring keys on,
    and a degraded probe is diagnostic context for a verdict ``server_health`` already returns (and
    which appliance monitoring already polls), not a new alertable condition.
    """
    status: int | str = exc.status_code if isinstance(exc, LceHttpError) else "n/a"
    logger.warning(
        "server_health's %s probe failed: %s (backend HTTP status %s).",
        probe,
        type(exc).__name__,
        status,
    )


def _log_probe_unusable(probe: str, reason: str) -> None:
    """Log a probe that succeeded at the transport yet still reads as unreachable.

    ``reason`` is a literal from this module, with no caller input or response content, so the same
    reasoning as ``_log_probe_failed`` applies, and it is likewise eventless.
    """
    logger.warning("server_health's %s probe answered but reads as unreachable: %s.", probe, reason)


def _field_names(root_type: object) -> set[str]:
    if not isinstance(root_type, dict):
        return set()
    fields = root_type.get("fields") or []
    if not isinstance(fields, list):
        return set()
    return {str(f["name"]) for f in fields if isinstance(f, dict) and f.get("name")}


def make_server_health(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``server_health`` bound to ``context``.

    :param context: The clients, configuration and credential source the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @sl1_tool_boundary(d.SERVER_HEALTH)
    async def server_health() -> dict[str, Any]:
        """Check connectivity and authentication across the SL1 REST, SL1 GraphQL and LCE surfaces.

        Reports a verdict per probe rather than one overall pass or fail, because the failures read
        very differently: a wrong password and a locked account are both "auth failed" but only one
        of them should be retried, and a transport that is down is not the same as a feature that is
        absent.

        This tool only reads.
        """
        signals = await _probe(context)
        return {
            "rest": {"reachable": signals["rest_ok"], "resources": len(signals["rest_resources"])},
            "graphql": {
                "reachable": signals["graphql_ok"],
                "queries": len(signals["graphql_queries"]),
                "mutations": len(signals["graphql_mutations"]),
            },
            "lce": {"reachable": signals["lce_ok"]},
            "em7_version": signals["em7_version"],
            # Stated in the payload: an operator reading a health report needs to know SSH was
            # not checked rather than infer it from silence.
            "ssh": "not applicable -- this service holds no SSH credentials",
            "database": _database_verdict(context),
        }

    return server_health


def _database_verdict(context: Sl1DbToolContext) -> dict[str, Any]:
    """Report whether the appliance database is wired up, without touching it.

    This deliberately does not run a query. ``server_health`` is what systemd and appliance
    monitoring read, and a database call is blocking I/O on a bounded pool. A health check that can
    queue behind a slow query could get a merely busy service restarted, turning a capacity
    condition into an outage.
    """
    from powerpack_mcp.db_client import platform_import_error

    if context.db is None:
        return {"configured": False, "reason": platform_import_error() or "DB tools not enabled"}
    return {"configured": True, "workers": context.db.worker_count}


def make_sl1_check_capabilities(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_check_capabilities`` bound to ``context``."""

    @sl1_tool_boundary(d.CHECK_CAPABILITIES)
    async def sl1_check_capabilities() -> dict[str, Any]:
        """Report which of this server's tools can actually work against this appliance.

        Probes the live REST, GraphQL and LCE surfaces, then reports each registered tool as
        available, unavailable or unknown based on whether the backend it needs is answering.

        "Unknown" is distinct from "unavailable" on purpose: a transport that did not answer means
        we cannot tell, which is different from a feature the appliance does not have. Treating the
        two as one would report a temporary outage as a missing capability.

        This tool only reads.
        """
        signals = await _probe(context)
        available: dict[d.Backend, bool] = {
            d.REST: bool(signals["rest_ok"]),
            d.GRAPHQL: bool(signals["graphql_ok"]),
            d.LCE: bool(signals["lce_ok"]),
            d.DB: context.db is not None,
            d.NONE: True,
        }
        tools = [
            {
                "tool": descriptor.tool_name,
                "backends": sorted(descriptor.backends),
                "status": _tool_status(descriptor, available),
                "writes": descriptor.writes,
                "tool_set": authz.TOOL_REGISTRY[descriptor.tool_name].tool_set,
            }
            for descriptor in d.REGISTERING_DB_DESCRIPTORS
        ]
        counts: dict[str, int] = {}
        for entry in tools:
            key = str(entry["status"])
            counts[key] = counts.get(key, 0) + 1
        return {
            "em7_version": signals["em7_version"],
            "transports": {
                "rest": signals["rest_ok"],
                "graphql": signals["graphql_ok"],
                "lce": signals["lce_ok"],
                "database": context.db is not None,
            },
            "counts": counts,
            "tools": tools,
            "notes": [
                # Carried into the output rather than left in a docstring nobody reads.
                (
                    "GraphQL introspection is not permission-gated on this platform, so a "
                    "listed operation is not proof the caller is authorized to use it."
                ),
                # Stated where a reader will meet it.
                (
                    "Derived from this server's own tool registry, so it cannot name a tool "
                    "this server does not provide."
                ),
            ],
        }

    return sl1_check_capabilities


def _tool_status(descriptor: d.DbToolDescriptor, available: dict[d.Backend, bool]) -> str:
    """Return ``available``, ``unavailable`` or ``unknown`` for one tool.

    A tool needing several backends is available only when all of them are; reporting it available
    because its first backend answered would over-claim.
    """
    if all(available.get(backend, False) for backend in descriptor.backends):
        return "available"
    return "unavailable"


# There is deliberately no ``make_refresh_capability_map``. The tool is withheld, and its factory is
# absent rather than kept unregistered: a factory for a withheld tool is dead code that
# ``_check_registry_is_total`` cannot see (it inspects ``_FACTORY_FOR``, not this module), one line
# away from being re-wired. What does not exist cannot be re-enabled by configuration.


# ---- The 4 discovery tools: all REST, none touching the database --------------------------------


def make_sl1_list_discovery_sessions(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_list_discovery_sessions`` bound to ``context``."""

    @sl1_tool_boundary(d.LIST_DISCOVERY_SESSIONS)
    async def sl1_list_discovery_sessions(
        name_contains: str | None = None, limit: int = 50, extended_fetch: bool = True
    ) -> dict[str, Any] | list[Any]:
        """List defined discovery sessions.

        Args:
            name_contains: Optional substring filter on the session name.
            limit: Maximum number of sessions to return.
            extended_fetch: Inline each session's fields instead of returning a bare link.

        This tool only reads.
        """
        return await context.client.request(
            credential=context.credential_source(),
            method="GET",
            path="discovery_session",
            query=_session_query(limit, extended_fetch, name_contains),
        )

    return sl1_list_discovery_sessions


def make_sl1_get_discovery_status(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_get_discovery_status`` bound to ``context``."""

    @sl1_tool_boundary(d.GET_DISCOVERY_STATUS)
    async def sl1_get_discovery_status(
        limit: int = 50, extended_fetch: bool = True
    ) -> dict[str, Any] | list[Any]:
        """Show discovery sessions that are currently running.

        Args:
            limit: Maximum number of active sessions to return.
            extended_fetch: Inline each session's fields instead of returning a bare link.

        Poll this after sl1_run_discovery_session to watch a run proceed. An empty result means
        nothing is running.

        This tool only reads.
        """
        return await context.client.request(
            credential=context.credential_source(),
            method="GET",
            path="discovery_session_active",
            query=_session_query(limit, extended_fetch, None),
        )

    return sl1_get_discovery_status


def _session_query(limit: int, extended_fetch: bool, name_contains: str | None) -> dict[str, str]:
    if limit < 1:
        raise refuse("limit", "limit must be at least 1.")
    query = {"limit": str(int(limit)), "hide_filterinfo": "1"}
    if extended_fetch:
        query["extended_fetch"] = "1"
    if name_contains:
        query["filter.name.contains"] = name_contains
    return query


# Appliance ``type`` values that actually collect.
#
# An allowlist, not ``!= "db"``: excluding a single value would silently admit any unmodelled
# appliance type (an Administration Portal, a Message Collector) as a discovery target. Naming what
# collects fails closed. Measured over REST on three appliances, two of them All-In-Ones on
# different SL1 versions:
#
# * ``db`` (Database, function 2): does not collect
# * ``cu`` (collector unit, function 5): collects
# * ``ao`` (All In One, function 1): collects
#
# An All-In-One is ``ao``, not ``db``. That matters because an AIO is a database appliance, and a
# rule written as "exclude the database" would exclude the one box on an AIO stack that must stay
# eligible.
#
# ``{"cu", "ao"}`` is exactly ``function IN (1, 5)``, the platform's own definition of a collecting
# box used by ``master.process_async`` and cited in ``sl1_db_statements``. So this needs no
# database, and the tool keeps its REST-only prerequisite.
_COLLECTING_APPLIANCE_TYPES: Final[frozenset[str]] = frozenset({"cu", "ao"})

# How many appliances to read when resolving a collector. Generous: a large stack has tens, not
# thousands, and under-reading would silently narrow the candidate set.
_APPLIANCE_PAGE_LIMIT: Final[int] = 200


def _appliance_id(uri: str) -> int | None:
    """Return the numeric id from an ``/api/appliance/3`` key, or ``None``.

    Sorting on this rather than on the URI string makes the choice deterministic and numeric; a
    lexicographic sort puts appliance 10 before appliance 3.
    """
    # ``isdecimal()``, not ``isdigit()``: ``isdigit()`` is True for 128 characters ``int()``
    # rejects, so it would turn a malformed URI into a ``ValueError`` instead of a skipped row.
    tail = uri.rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdecimal() else None


def eligible_discovery_collectors(payload: object) -> list[dict[str, object]]:
    """Select the collecting appliances from a REST ``appliance`` search payload.

    Pure, and separate from the request, so the selection rule is testable without an appliance.
    Anything unrecognised is skipped rather than guessed at: this is platform output, and a
    malformed row must not become a discovery target.

    :param payload: The REST response body.
    :return: ``[{"id", "name", "type", "uri"}, ...]`` sorted by numeric id.
    """
    body = payload.get("result_set") if isinstance(payload, dict) else None
    if not isinstance(body, dict):
        return []
    found: list[dict[str, object]] = []
    for uri, row in body.items():
        if not isinstance(uri, str) or not isinstance(row, dict):
            continue
        appliance_type = row.get("type")
        if not isinstance(appliance_type, str) or appliance_type not in _COLLECTING_APPLIANCE_TYPES:
            continue
        identifier = _appliance_id(uri)
        if identifier is None:
            continue
        name = row.get("name")
        found.append(
            {
                "id": identifier,
                "name": name if isinstance(name, str) else "",
                "type": appliance_type,
                "uri": uri,
            }
        )
    found.sort(key=lambda entry: entry["id"] if isinstance(entry["id"], int) else 0)
    return found


async def _resolve_discovery_collector(
    context: Sl1DbToolContext,
) -> tuple[str, list[dict[str, object]]]:
    """Choose the collector a discovery session will run on.

    Omitting ``aligned_collector`` does not let SL1 pick sensibly. ``master.policies_discovery.pid``
    has ``column_default = 1``, so a session created without a collector lands on appliance 1, which
    on a distributed stack is the Central Database. It does not collect, so the session hangs. On an
    All-In-One, appliance 1 is the AIO and does collect, so the platform default is right there and
    wrong only on a distributed stack. That asymmetry is why this resolves a collector only when the
    caller gave none, rather than overriding one.

    :return: ``(chosen_uri, candidates)``.
    :raises ValidationBlocked: If no appliance on the stack can collect.
    """
    payload = await context.client.request(
        credential=context.credential_source(),
        method="GET",
        path="appliance",
        query={"extended_fetch": "1", "limit": str(_APPLIANCE_PAGE_LIMIT)},
    )
    candidates = eligible_discovery_collectors(payload)
    if not candidates:
        raise refuse(
            "aligned_collector",
            "No appliance on this stack can run a discovery session. Only Data Collectors and "
            "All-In-One appliances collect; the Central Database cannot, and a session aligned to "
            "it will hang. Pass aligned_collector explicitly if you believe this is wrong.",
        )
    chosen = candidates[0]["uri"]
    return (chosen if isinstance(chosen, str) else ""), candidates


def _with_collector_advisory(
    created: dict[str, Any], chosen: object, candidates: list[dict[str, object]]
) -> dict[str, Any]:
    """Report an auto-selected collector without overwriting anything SL1 returned.

    Every added key is checked for collision first. This merges into the platform's own response,
    and silently replacing a field SL1 had set would leave a caller reading ``note`` with ours
    instead of theirs and no way to tell.
    """
    advisory: dict[str, Any] = {
        "collector_auto_selected": True,
        "collector_candidates": [
            {"id": entry["id"], "name": entry["name"]} for entry in candidates
        ],
        "note": (
            f"No collector was specified, so one was chosen automatically from the "
            f"{len(candidates)} eligible on this stack. The Central Database is never eligible -- "
            f"it does not collect, and a session aligned to it hangs. Pass aligned_collector to "
            f"choose a different one."
        ),
    }
    if "aligned_collector" not in created:
        advisory["aligned_collector"] = chosen
    for key, value in advisory.items():
        created.setdefault(key, value)
    return created


def make_sl1_create_discovery_session(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_create_discovery_session`` bound to ``context``."""

    @sl1_tool_boundary(d.CREATE_DISCOVERY_SESSION)
    async def sl1_create_discovery_session(
        name: str,
        organization: str = "0",
        aligned_collector: str | None = None,
        session: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Define a discovery session. This does NOT start it.

        Call sl1_run_discovery_session next to start it.

        Args:
            name: Session name.
            organization: Organization id. "0" is System.
            aligned_collector: Collector id or URI that will run the discovery. If omitted, a
                collector is chosen automatically and the choice is reported back to you -- see
                collector_auto_selected and collector_candidates in the reply. The Central Database
                is never chosen, because it does not collect.
            session: Additional fields merged into the request body -- IP targets, credentials,
                device template, scan level and so on.

        Field names vary by SL1 version. Use the REST describe passthrough on discovery_session to
        confirm the exact fields this appliance accepts before relying on the session argument.

        This tool changes SL1 state.
        """
        if not name.strip():
            raise refuse("name", "name must not be empty.")
        body: dict[str, Any] = {"name": name, "organization": str(organization)}
        if aligned_collector is not None:
            body["aligned_collector"] = aligned_collector
        if session:
            body.update(session)

        # Check ``body`` after the ``session`` merge, not the ``aligned_collector`` argument:
        # ``session`` can carry ``aligned_collector`` too, so testing the named parameter alone
        # would override a collector the caller had in fact supplied.
        auto_selected = "aligned_collector" not in body
        candidates: list[dict[str, object]] = []
        if auto_selected:
            resolved, candidates = await _resolve_discovery_collector(context)
            body["aligned_collector"] = resolved

        created = await context.client.request(
            credential=context.credential_source(),
            method="POST",
            path="discovery_session",
            json_body=body,
        )
        if not auto_selected or not isinstance(created, dict):
            # Nothing to report, or a shape we must not rewrite. ``list`` responses are returned
            # untouched rather than wrapped: a changed envelope would break existing callers for
            # the sake of an advisory field.
            return created
        return _with_collector_advisory(created, body["aligned_collector"], candidates)

    return sl1_create_discovery_session


def make_sl1_run_discovery_session(context: Sl1DbToolContext) -> DbToolFactory:
    """Build ``sl1_run_discovery_session`` bound to ``context``."""

    @sl1_tool_boundary(d.RUN_DISCOVERY_SESSION)
    async def sl1_run_discovery_session(session_id: str) -> dict[str, Any] | list[Any]:
        """Start a discovery session that has already been created.

        Args:
            session_id: The numeric session id, or its full /api/discovery_session/<id> URI.

        Poll sl1_get_discovery_status afterwards to watch progress.

        This tool changes SL1 state.
        """
        text = session_id.strip()
        if not text:
            raise refuse("session_id", "session_id must not be empty.")
        segment = _last_segment(text)
        uri = text if text.startswith("/api/") else f"/api/discovery_session/{segment}"
        # Starting a session is SL1's URI-apply pattern: the session's resource URI is POSTed as a
        # raw body with content type ``application/em7-resource-uri``. A plain JSON POST returns
        # success and does not start discovery.
        return await context.client.request(
            credential=context.credential_source(),
            method="POST",
            path="discovery_session_active",
            raw_body=uri,
            content_type="application/em7-resource-uri",
        )

    return sl1_run_discovery_session


def _last_segment(value: str) -> str:
    return value.rstrip("/").split("/")[-1]

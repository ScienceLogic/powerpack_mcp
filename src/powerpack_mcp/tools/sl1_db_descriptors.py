"""
SL1 Platform Tool Descriptors

This module describes each SL1 platform tool as data: the clients it needs, its summary, the SQL
statements it issues, and any GraphQL document. Which tools exist and whether they touch SQL
come from ``authz.TOOL_REGISTRY``; this module adds only the per-tool client wiring. Transport
inferred from a tool's name has repeatedly been wrong, so ``_check_against_registry`` checks the
two against each other at import.

A tool here may issue a sequence of SQL statements, a REST call, a GraphQL document, or several
transports at once, so ``backends`` is a set:

- ``server_health`` probes REST, GraphQL and LCE, and ``sl1_check_capabilities`` probes the same
  three. The reference implementation's SSH probe is not ported: per-call credentials were removed
  service-wide, so that branch could never run. It was not dropped as a security measure.
- Every SQL tool except ``sl1_fetch_collection_output`` resolves a device or class through REST
  before issuing SQL, so it needs both ``sl1_client`` and ``db_client``. The fetch tool takes a job
  id an earlier call returned, so it needs the database alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from powerpack_mcp.authz import TOOL_REGISTRY, ToolTransport

__all__ = [
    "ALL_DB_DESCRIPTORS",
    "DB_DESCRIPTORS_BY_NAME",
    "REGISTERING_DB_DESCRIPTORS",
    "SQL_DESCRIPTORS",
    "Backend",
    "DbToolDescriptor",
]


class Backend(str):
    """A client a tool needs at runtime.

    A plain ``str`` subclass rather than an enum, because the set of backends is open and the
    values are only compared for membership, never branched on exhaustively. An enum would make
    each new client a change to a widely imported type for no checking benefit.
    """

    __slots__ = ()


# The clients these tools draw on. There is deliberately no ``SSH`` constant: this service uses
# no SSH, and a named constant would imply otherwise.
DB: Final[Backend] = Backend("db_client")
REST: Final[Backend] = Backend("sl1_client.rest")
GRAPHQL: Final[Backend] = Backend("sl1_client.graphql")
LCE: Final[Backend] = Backend("lce_client")
NONE: Final[Backend] = Backend("none")


@dataclass(frozen=True, slots=True)
class DbToolDescriptor:
    """One SL1 platform tool, described as data.

    :ivar tool_name: The MCP tool name.
    :ivar backends: Every client the tool needs. A set, because several tools use more than one.
    :ivar summary: Human-facing summary, kept here so the schema-size tests measure text that is
        reviewable in one place.
    :ivar writes: ``True`` when the tool changes SL1 state. Always taken from the registry by
        ``_d``, never passed in, so the write gate and the descriptor cannot drift apart.
    :ivar statements: Names of the SQL statements the tool issues, in order; the builders live in
        ``sl1_db_statements``. Empty for every non-SQL tool.
    :ivar source_symbol: The reference-implementation symbol this row was derived from, so a
        reviewer can diff intent against the original.
    :ivar document: The GraphQL document, verbatim from the reference implementation. Empty for
        every non-GraphQL tool.
    :ivar root_field: The key to read out of ``data``. Not derivable from ``tool_name``; for
        example ``sl1_set_device_class`` reads ``updateDevice``.
    """

    tool_name: str
    backends: frozenset[Backend]
    summary: str
    writes: bool
    statements: tuple[str, ...] = ()
    source_symbol: str = ""
    document: str = ""
    root_field: str = ""


def _d(
    name: str,
    backends: frozenset[Backend],
    summary: str,
    *,
    statements: tuple[str, ...] = (),
    source_symbol: str = "",
    document: str = "",
    root_field: str = "",
) -> DbToolDescriptor:
    """Build a descriptor, taking ``writes`` from the registry rather than an argument.

    The ``ENABLE_DB_WRITE_TOOLS`` gate reads the registry's copy. A second hand-maintained copy here
    could drift, leaving a tool described as read-only gated as a write, or worse, the reverse.

    :raises KeyError: If ``name`` is not in the registry.
    """
    entry = TOOL_REGISTRY[name]  # KeyError here means the descriptor names a tool nobody registered
    return DbToolDescriptor(
        tool_name=name,
        backends=backends,
        summary=summary,
        writes=entry.writes,
        statements=statements,
        source_symbol=source_symbol,
        document=document,
        root_field=root_field,
    )


# ---- GraphQL documents, verbatim from the reference implementation's ``device_classes.py`` ------
#
# Two were re-wrapped to fit the line-length limit, which is safe because GraphQL is
# whitespace-insensitive. No field, argument or operation name was changed.

_CREATE_ICON = (
    "mutation CreateIcon($name: String!, $svg: String!) "
    "{ createIcon(name: $name, svg: $svg) { id name size dateCreated } }"
)

_LIST_ICONS = """
query ListIcons($first: Int, $contains: String) {
  icons(first: $first, search: { name: { contains: $contains } }) {
    edges { node { id name size } }
  }
}
"""

_SET_CLASS_ICON = (
    "mutation SetDeviceClassIcon($deviceClassId: ID!, $iconId: ID) "
    "{ setDeviceClassIcon(deviceClassId: $deviceClassId, iconId: $iconId) { id } }"
)

# Read after the icon mutation, because the mutation's own return can be stale.
_READ_CLASS = """
query ($id: ID!) {
  deviceClass(id: $id) {
    id class description virtualType hasIcon icon { id name } deviceCategory { id name }
  }
}
"""

_SET_DEVICE_CLASS = """
mutation SetDeviceClassOfDevice($id: ID!, $deviceClass: ID!) {
  updateDevice(id: $id, deviceClass: $deviceClass) {
    id name deviceClass { id class description hasIcon icon { name } }
  }
}
"""

# Exposed so ``sl1_class_tools`` can issue the confirming read without re-declaring the document.
READ_DEVICE_CLASS_DOCUMENT: Final[str] = _READ_CLASS


# ---- SQL tools ---------------------------------------------------------------------------------
#
# All but one carry ``REST`` as well as ``DB``: each resolves a device or class through
# ``sl1_client`` before issuing any SQL, so with ``db_client`` alone it would fail at its first
# argument. ``FETCH_COLLECTION_OUTPUT`` is the exception; its only argument is a job id an earlier
# call returned.

SIMULATE_EVENT: Final = _d(
    "sl1_simulate_event",
    frozenset({DB, REST}),
    "Insert a synthetic active event on a device, bypassing SL1's event engine. No policy "
    "matching, no correlation and no auto-clear run -- use sl1_inject_alert to exercise those. "
    "Clear the result with sl1_clear_event.",
    statements=("insert_active_event",),
    source_symbol="tools/events.py::sl1_simulate_event",
)

GET_COMPONENT_TREE: Final = _d(
    "sl1_get_component_tree",
    frozenset({DB, REST}),
    "Walk the DCM component tree beneath a root device (read-only), reporting counts by state and "
    "class and the discovering Dynamic Applications. The root is resolved through REST with the "
    "caller's credential; components outside the root's organization are only counted, as "
    "withheld.",
    statements=("read_root_summary", "read_component_map"),
    source_symbol="tools/collection.py::sl1_get_component_tree",
)

CREATE_DEVICE_CLASS: Final = _d(
    "sl1_create_device_class",
    frozenset({DB, REST}),
    "Create an SL1 device class by direct database insert -- there is no create API. The category "
    "must resolve to a real device category or nothing is inserted.",
    statements=("insert_device_class", "read_device_class_by_guid"),
    source_symbol="tools/device_classes.py::sl1_create_device_class",
)

UPDATE_DEVICE_CLASS: Final = _d(
    "sl1_update_device_class",
    frozenset({DB, REST}),
    "Update fields on an existing device class, keyed by GUID. Only arguments actually supplied "
    "are changed; an unresolvable category is left alone rather than nulled.",
    statements=("update_device_class", "read_device_class_by_guid"),
    source_symbol="tools/device_classes.py::sl1_update_device_class",
)

ALIGN_DYNAMIC_APP_TO_DEVICE_CLASS: Final = _d(
    "sl1_align_dynamic_app_to_device_class",
    frozenset({DB, REST}),
    "Align a Dynamic Application to a component device class, or unalign it with device_class='0'.",
    statements=("resolve_class_type", "align_dynamic_app", "read_dynamic_app_alignment"),
    source_symbol="tools/device_classes.py::_align_da_to_class",
)

GET_DEVICE_CLASS_ALIGNMENT: Final = _d(
    "sl1_get_device_class_alignment",
    frozenset({DB, REST}),
    "Show which Dynamic Applications are aligned to a component device class (read-only).",
    statements=("resolve_class_type", "read_class_alignment", "read_aligned_dynamic_apps"),
    source_symbol="tools/device_classes.py::sl1_get_device_class_alignment",
)

RUN_DYNAMIC_COLLECTION: Final = _d(
    "sl1_run_dynamic_collection",
    frozenset({DB, REST}),
    "Queue a Dynamic Application collection on one device now, in debug mode, and return a "
    "receipt. It does NOT wait, so the output comes from "
    "sl1_fetch_collection_output. The same thing the Device Tools lightning bolt does.",
    statements=(
        "resolve_device_collector",
        "dispatch_dynamic_collection",
        "last_insert_id",
        "record_device_tool_run",
        "read_collection_output",
        "read_collection_job",
    ),
    source_symbol="tools/sl1_db_tools.py::sl1_run_dynamic_collection",
)

FETCH_COLLECTION_OUTPUT: Final = _d(
    "sl1_fetch_collection_output",
    frozenset({DB}),
    "Poll the output of a collection started by sl1_run_dynamic_collection, resuming after a "
    "row id. Every collection outlives its dispatch call, so this is the normal "
    "second half of the pair rather than an exception for slow ones.",
    statements=("read_collection_output", "read_collection_job"),
    source_symbol="tools/sl1_db_tools.py::sl1_fetch_collection_output",
)

SQL_DESCRIPTORS: Final[tuple[DbToolDescriptor, ...]] = (
    SIMULATE_EVENT,
    GET_COMPONENT_TREE,
    CREATE_DEVICE_CLASS,
    UPDATE_DEVICE_CLASS,
    ALIGN_DYNAMIC_APP_TO_DEVICE_CLASS,
    GET_DEVICE_CLASS_ALIGNMENT,
    RUN_DYNAMIC_COLLECTION,
    FETCH_COLLECTION_OUTPUT,
)

# ---- REST tools ---------------------------------------------------------------------------------

CLEAR_EVENT: Final = _d(
    "sl1_clear_event",
    frozenset({REST}),
    "Clear an active event through the supported REST path, moving it to events_cleared exactly as "
    "a real resolution would.",
    source_symbol="tools/events.py::sl1_clear_event",
)

INJECT_ALERT: Final = _d(
    "sl1_inject_alert",
    frozenset({REST}),
    "Inject an alert into SL1's real event pipeline, so policy matching, deduplication, masking, "
    "correlation and auto-clear all run. An event appears only if an enabled policy matches with "
    "source=API -- no match is itself a useful diagnostic.",
    source_symbol="tools/events.py::sl1_inject_alert",
)

GET_RECENT_EVENTS: Final = _d(
    "sl1_get_recent_events",
    frozenset({REST}),
    "Read back recent active events, newest first, with optional device, severity-floor and source "
    "filters. Reports when the scan window filled, so older matches are not silently omitted.",
    source_symbol="tools/events.py::sl1_get_recent_events",
)

GET_COLLECTED_VALUES: Final = _d(
    "sl1_get_collected_values",
    frozenset({REST}),
    "Read what SL1 stored for a device's aligned Dynamic Applications, through the supported "
    "config_data and performance_data paths rather than direct database reads.",
    source_symbol="tools/collection.py::sl1_get_collected_values",
)

LIST_DISCOVERY_SESSIONS: Final = _d(
    "sl1_list_discovery_sessions",
    frozenset({REST}),
    "List discovery sessions, optionally filtered by a substring of the session name.",
    source_symbol="tools/discovery.py::sl1_list_discovery_sessions",
)

GET_DISCOVERY_STATUS: Final = _d(
    "sl1_get_discovery_status",
    frozenset({REST}),
    "Report the status of recent discovery runs.",
    source_symbol="tools/discovery.py::sl1_get_discovery_status",
)

CREATE_DISCOVERY_SESSION: Final = _d(
    "sl1_create_discovery_session",
    frozenset({REST}),
    "Create a discovery session against an organization, optionally aligned to a collector.",
    source_symbol="tools/discovery.py::sl1_create_discovery_session",
)

RUN_DISCOVERY_SESSION: Final = _d(
    "sl1_run_discovery_session",
    frozenset({REST}),
    "Start a previously created discovery session.",
    source_symbol="tools/discovery.py::sl1_run_discovery_session",
)

REST_DESCRIPTORS: Final[tuple[DbToolDescriptor, ...]] = (
    CLEAR_EVENT,
    INJECT_ALERT,
    GET_RECENT_EVENTS,
    GET_COLLECTED_VALUES,
    LIST_DISCOVERY_SESSIONS,
    GET_DISCOVERY_STATUS,
    CREATE_DISCOVERY_SESSION,
    RUN_DISCOVERY_SESSION,
)

# ---- GraphQL tools ------------------------------------------------------------------------------
#
# The icon and reclass tools, which the reference implementation reaches through AP2 GraphQL rather
# than SQL.

CREATE_ICON: Final = _d(
    "sl1_create_icon",
    frozenset({GRAPHQL}),
    "Create a reusable SVG icon. Assign it to a device class with sl1_set_device_class_icon -- one "
    "icon can serve many classes.",
    source_symbol="tools/device_classes.py::sl1_create_icon",
    document=_CREATE_ICON,
    root_field="createIcon",
)

LIST_ICONS: Final = _d(
    "sl1_list_icons",
    frozenset({GRAPHQL}),
    "List existing SVG icons so one can be reused rather than recreated.",
    source_symbol="tools/device_classes.py::sl1_list_icons",
    document=_LIST_ICONS,
    root_field="icons",
)

SET_DEVICE_CLASS_ICON: Final = _d(
    "sl1_set_device_class_icon",
    frozenset({GRAPHQL}),
    "Assign an SVG icon to a device class, or clear it. Re-reads the class to confirm, because the "
    "mutation's own return can be stale.",
    source_symbol="tools/device_classes.py::sl1_set_device_class_icon",
    document=_SET_CLASS_ICON,
    root_field="setDeviceClassIcon",
)

SET_DEVICE_CLASS: Final = _d(
    "sl1_set_device_class",
    frozenset({GRAPHQL}),
    "Reclass a device to a given device class. The device inherits the class's icon automatically.",
    source_symbol="tools/device_classes.py::sl1_set_device_class",
    document=_SET_DEVICE_CLASS,
    root_field="updateDevice",
)

GRAPHQL_DESCRIPTORS: Final[tuple[DbToolDescriptor, ...]] = (
    CREATE_ICON,
    LIST_ICONS,
    SET_DEVICE_CLASS_ICON,
    SET_DEVICE_CLASS,
)

# ---- Multi-transport tools, and the withheld tools -----------------------------------------------
#
# Each of these probes several transports in one call; ``backends`` lists what it actually needs.

SERVER_HEALTH: Final = _d(
    "server_health",
    frozenset({REST, GRAPHQL, LCE}),
    "Connectivity and authentication check across REST, GraphQL and LCE, reporting a raw status "
    "plus a verdict per probe -- a wrong password and an account lockout read very differently "
    "despite both being 'auth failed'.",
    source_symbol="tools/ops.py::server_health",
)

CHECK_CAPABILITIES: Final = _d(
    "sl1_check_capabilities",
    frozenset({REST, GRAPHQL, LCE}),
    "Probe which SL1 capabilities this appliance actually exposes, so a tool that would fail on "
    "this version can be identified before it is called.",
    source_symbol="tools/capability.py::sl1_check_capabilities",
)

# Deliberately not registered. The diff its name promises needs a persisted snapshot, and so a
# writable state directory (systemd ``StateDirectory=``, RPM ownership, SELinux context) that this
# deployment does not have. Withheld rather than shipped with a payload disclaiming the diff,
# because a caller reads the name first. Kept as data so the exclusion stays reviewable.
REFRESH_CAPABILITY_MAP: Final = _d(
    "refresh_capability_map",
    frozenset({REST, GRAPHQL}),
    "Withheld. Would re-probe the capability map and report what changed since the last snapshot, "
    "but this deployment has nowhere to persist a snapshot.",
    source_symbol="tools/capability.py::refresh_capability_map",
)

# Deliberately not registered: MCP's own ``tools/list`` already answers this, and porting it would
# mean reading private FastMCP internals. Kept as data so the exclusion stays reviewable.
LIST_CAPABILITIES: Final = _d(
    "list_capabilities",
    frozenset({NONE}),
    "Withheld. Enumerates this server's own tools; superseded by MCP's tools/list.",
    source_symbol="tools/capability.py::list_capabilities",
)

MULTI_DESCRIPTORS: Final[tuple[DbToolDescriptor, ...]] = (
    SERVER_HEALTH,
    CHECK_CAPABILITIES,
    REFRESH_CAPABILITY_MAP,
)

# Every descriptor, registering or not: the same inventory ``authz._ENTRIES`` holds.
ALL_DB_DESCRIPTORS: Final[tuple[DbToolDescriptor, ...]] = (
    *SQL_DESCRIPTORS,
    *REST_DESCRIPTORS,
    *GRAPHQL_DESCRIPTORS,
    *MULTI_DESCRIPTORS,
    LIST_CAPABILITIES,
)

# The descriptors that register, derived from the registry's ``registers`` flag rather than the
# groupings above, which are for reading only. Moving a tool between groups must not change
# whether it registers.
REGISTERING_DB_DESCRIPTORS: Final[tuple[DbToolDescriptor, ...]] = tuple(
    d for d in ALL_DB_DESCRIPTORS if TOOL_REGISTRY[d.tool_name].registers
)

DB_DESCRIPTORS_BY_NAME: Final[dict[str, DbToolDescriptor]] = {
    d.tool_name: d for d in ALL_DB_DESCRIPTORS
}


def _check_against_registry() -> None:
    """Fail at import if this module and the registry disagree.

    A descriptor for an unregistered tool is already caught by ``_d``. This checks the other ways
    they can diverge:

    - A registry row with no descriptor.
    - A ``DB``/``SQL`` mismatch. Only SQL tools may be gated on the database, and the gate reads
      the registry while the wiring reads ``backends``. A mismatch leaves a tool gated on a
      prerequisite it does not need, or reaching for a client that may be absent.
    - Statements on a non-SQL tool, or none on a SQL tool.

    It runs at import rather than as a test, because a test can be skipped and an import cannot.

    :raises AssertionError: If the two disagree.
    """
    described = {d.tool_name for d in ALL_DB_DESCRIPTORS}
    missing = set(TOOL_REGISTRY) - described
    if missing:
        raise AssertionError(f"registry rows with no descriptor: {sorted(missing)}")

    for descriptor in ALL_DB_DESCRIPTORS:
        entry = TOOL_REGISTRY[descriptor.tool_name]
        needs_db = DB in descriptor.backends
        is_sql = entry.transport is ToolTransport.SQL
        if needs_db != is_sql:
            raise AssertionError(
                f"{descriptor.tool_name}: backends say needs_db={needs_db} but the registry says "
                f"transport={entry.transport.value}. Only SQL tools may be DB-gated."
            )
        if bool(descriptor.statements) != is_sql:
            raise AssertionError(
                f"{descriptor.tool_name}: has statements={bool(descriptor.statements)} but "
                f"transport={entry.transport.value}; only SQL tools issue statements."
            )


_check_against_registry()

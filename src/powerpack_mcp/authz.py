"""
Tool Registry and Authorization Mapping

This module is the inventory of the SL1 platform tools that live outside the LCE surface. For
each tool it records how the tool reaches SL1 (``transport``), whether it writes, which tool
set's flag gates it, whether it registers at all, and which SL1 access hooks a caller must hold
before it may run. ``mcp_app.authz_gate`` enforces those hooks, resolving each caller's hooks from
their own forwarded credential through ``GET /api/account/_self/access_hooks`` (see
``hook_source``).

Constraints a maintainer must keep:

- A tool absent from the registry is refused. There is no wildcard, no fallback and no "allow if
  unmapped" branch.
- Only SQL tools carry hook mappings. MariaDB enforces the service database user's grants, not SL1
  hooks, so nothing downstream catches a mapping error and an over-permissive entry fails
  silently. This mapping is the only specification of correct access for these tools.
- Hook ids are SL1's ``hook_id`` primary key from ``master_access.hooks``, never the mutable
  ``name`` display column.
- ``transport`` is used only to tell SQL tools from the rest. SQL tools are gated on the database
  prerequisite (driver, ``libem7`` and ``silo.conf``); every other tool must not be, or a missing
  driver would disable tools that never use it.
- Refusal has not been verified against a live restricted account for
  ``sl1_get_component_tree`` or ``sl1_run_dynamic_collection``, because the only restricted
  account available held every candidate hook. A passing test suite is not evidence that they
  refuse.

Tools are grouped into three tool sets:

- ``db_read``: the SQL reads.
- ``db_write``: the SQL writes.
- ``ops``: every other tool in this registry.

``db_read`` and ``db_write`` therefore mean exactly "needs MariaDB". Two tools are inventoried but
withheld with ``registers=False``: ``refresh_capability_map``, which cannot report the diff its
name promises without a writable state directory, and ``list_capabilities``, which duplicates
MCP's own ``tools/list``. ``_check_set_assignment`` validates the whole registry at import.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from powerpack_mcp.errors import LogEvent, PowerPackMcpError

__all__ = [
    "DB_READ_SET",
    "DB_TOOL_COUNT",
    "DB_WRITE_SET",
    "OPS_SET",
    "REGISTERED_TOOL_COUNT",
    "REGISTRY_TOOL_SETS",
    "SQL_TOOL_COUNT",
    "TOOL_REGISTRY",
    "WRITE_TOOL_COUNT",
    "DbToolNotRegistered",
    "ToolTransport",
    "registry_entry",
    "sql_tool_names",
    "tool_names_for_set",
    "write_tool_names",
]

logger = logging.getLogger(__name__)

# The tool-set identifiers this registry populates. Spelled out rather than imported from
# ``tool_sets`` to avoid the import edge; a test asserts the values match.
DB_READ_SET: Final[str] = "db_read"
DB_WRITE_SET: Final[str] = "db_write"
OPS_SET: Final[str] = "ops"


# ==================================================================================================
# SL1 hook ids. Every value exists in ``master_access.hooks``. They are constants rather than
# inline literals so a typo at a use site fails at import instead of naming a hook nobody holds.
#
# A constant protects the reference, not the value, so each one notes where its mapping comes
# from. ``master_access.entity_access`` (SL1's own operation-to-hook table) is the strongest
# evidence; a ``ValidatePageAH`` call site in the SL1 UI is the next best; anything else is marked
# inferred. None of these mappings has been confirmed by an observed 403.
# ==================================================================================================

# ``entity_access.event.view_hook``: reading an event.
_HOOK_EVT_VIEW: Final[str] = "EVT_VIEW"
# ``entity_access.event.rem_hook``: clearing an event.
_HOOK_EVT_CLEAR: Final[str] = "EVT_CLEAR"
# ``entity_access.device.view_hook``.
_HOOK_DEV_VIEW: Final[str] = "DEV_VIEW"
# ``entity_access.ent_device_class.view_hook``.
_HOOK_DEV_CLASS_VIEW: Final[str] = "DEV_CLASS_VIEW"
# ``ValidatePageAH('DEV_COMPONENT_REG_PAGE')`` in ``registry_device_component.inc``, the SL1 UI's
# reader of ``master_dev.component_dev_map``. Not in ``entity_access``, so the mapping to this
# operation is inferred.
_HOOK_DEV_COMPONENT_REG_PAGE: Final[str] = "DEV_COMPONENT_REG_PAGE"
# ``entity_access.device_class`` maps add, remove, view and edit all to this one hook, so it cannot
# separate create from update from delete: granting create also grants delete. SL1 has no
# ``DEV_CLASS_ADD`` hook.
_HOOK_SYS_CUSTOM_DEV_CLASS_PAGE: Final[str] = "SYS_CUSTOM_DEV_CLASS_PAGE"
# ``entity_access.dynamic_app.edit_hook``. SL1 documents this hook for the Classic UI and REST API
# and ``DYN_APP_EDIT`` for AP2/GraphQL; ``entity_access`` names only this one, and the SQL here is
# what the Classic UI page runs.
_HOOK_SYS_DYN_APP_EDIT: Final[str] = "SYS_DYN_APP_EDIT"
# ``entity_access.dynamic_app.view_hook``; also checked in ``admin_dynamic_app.inc``.
_HOOK_SYS_DYN_APP_MANAGEMENT: Final[str] = "SYS_DYN_APP_MANAGEMENT"
# ``ValidatePageAH('DEV_TOOLS_RUN')`` guards the Device Toolbox page and ``device_tools_log.inc``,
# whose only query is the same ``proc_remote_logs`` read the fetch tool performs, so the mapping
# for that read is verified. For running a collection it is inferred.
#
# This is a page-level hook and does not grant the individual toolbox tools: SL1 checks each tool
# separately, first ``DEV_TOOLS_RUN_<label>`` and then a per-tool additional hook. Those sub-hook
# names are built at runtime from a label list, so searching the SL1 source for a literal
# ``DEV_TOOLS_RUN_<X>`` finds nothing. Do not describe this hook's blast radius beyond "page level".
_HOOK_DEV_TOOLS_RUN: Final[str] = "DEV_TOOLS_RUN"
# SL1 declares this as the additional hook for toolbox ``tool_id 20`` in
# ``functions_device_tools.inc``. The label list SL1 uses for the first check stops at index 11, so
# ``DEV_TOOLS_RUN_<label>`` does not exist for tool 20, and this hook is the platform's effective
# gate. This service is deliberately stricter and also requires ``DEV_TOOLS_RUN``, because this
# view hook gates a write: queueing an arbitrary-argument command onto a collector.
_HOOK_DEV_COLLECTIONS_VIEW: Final[str] = "DEV_COLLECTIONS_VIEW"


class ToolTransport(StrEnum):
    """How a tool reaches SL1.

    Transport is recorded explicitly per tool, and the SQL tool count is computed from it rather
    than stated. A transport inferred from a tool's name or description is easy to get wrong, and a
    wrong one passes type checks and mocked tests while calling an endpoint that does not exist.
    """

    SQL = "sql"
    REST = "rest"
    GRAPHQL = "graphql"

    # More than one transport in a single call, for example a health check that probes REST,
    # GraphQL and LCE.
    MULTI = "multi"

    # No transport at all: purely local introspection that never leaves the process.
    LOCAL = "local"


@dataclass(frozen=True, slots=True)
class ToolRegistryEntry:
    """One tool in the registry.

    :ivar name: The MCP tool name.
    :ivar transport: How the tool reaches SL1.
    :ivar writes: Whether the tool changes SL1 state.
    :ivar tool_set: The tool set whose flag gates this tool. Implied by ``transport`` and
        ``writes`` for SQL tools, and ``ops`` for everything else.
    :ivar registers: ``False`` for a tool that is inventoried but withheld from the MCP surface.
    :ivar required_hooks: The ``hook_id`` values SL1 must grant the caller before this tool may
        run. A set because one operation can require several hooks at once. Non-empty for every
        SQL tool and empty for every other tool; ``_check_set_assignment`` enforces this.
    """

    name: str
    transport: ToolTransport
    writes: bool
    tool_set: str = OPS_SET
    registers: bool = True
    required_hooks: frozenset[str] = frozenset()


def _entry(
    name: str,
    transport: ToolTransport,
    *,
    writes: bool = False,
    tool_set: str = OPS_SET,
    registers: bool = True,
    required_hooks: frozenset[str] = frozenset(),
) -> ToolRegistryEntry:
    return ToolRegistryEntry(
        name=name,
        transport=transport,
        writes=writes,
        tool_set=tool_set,
        registers=registers,
        required_hooks=required_hooks,
    )


_ENTRIES: Final[tuple[ToolRegistryEntry, ...]] = (
    # ---- Event, component and device-class tools ------------------------------------------------
    #
    # SL1 offers no hook for creating an event: ``entity_access.event.add_hook`` is ``FALSE`` and
    # no SL1 UI path inserts into ``events_active``. This pair is therefore reasoned rather than
    # looked up: a caller who may fabricate an event should be able to see it (``EVT_VIEW``) and to
    # clear it (``EVT_CLEAR``). The main write control here is ``ENABLE_DB_WRITE_TOOLS``.
    _entry(
        "sl1_simulate_event",
        ToolTransport.SQL,
        writes=True,
        tool_set=DB_WRITE_SET,
        required_hooks=frozenset({_HOOK_EVT_VIEW, _HOOK_EVT_CLEAR}),
    ),
    # Uses SL1's supported REST endpoint (``DELETE event/{id}``), not a direct SQL write, so it
    # needs no database.
    _entry("sl1_clear_event", ToolTransport.REST, writes=True),
    # Reads ``master_dev.component_dev_map`` joined to ``legend_device`` and
    # ``legend_device_vanished``, plus ``master.definitions_dev_classes`` for the class label,
    # hence three hooks. Refusal is not verified against a live restricted account.
    _entry(
        "sl1_get_component_tree",
        ToolTransport.SQL,
        tool_set=DB_READ_SET,
        required_hooks=frozenset(
            {_HOOK_DEV_VIEW, _HOOK_DEV_CLASS_VIEW, _HOOK_DEV_COMPONENT_REG_PAGE}
        ),
    ),
    # Create and update share one hook, and no hook can separate them. When ``ppguid`` is given as
    # a PowerPack name these tools also read ``master.powerpack`` to resolve it. That read is
    # deliberately not hook-checked: ``SYS_POWERPACK_REG_PAGE`` would have to be required on every
    # call, refusing callers who never reference a PowerPack, and it discloses only the GUID for a
    # name the caller supplied.
    _entry(
        "sl1_create_device_class",
        ToolTransport.SQL,
        writes=True,
        tool_set=DB_WRITE_SET,
        required_hooks=frozenset({_HOOK_SYS_CUSTOM_DEV_CLASS_PAGE}),
    ),
    _entry(
        "sl1_update_device_class",
        ToolTransport.SQL,
        writes=True,
        tool_set=DB_WRITE_SET,
        required_hooks=frozenset({_HOOK_SYS_CUSTOM_DEV_CLASS_PAGE}),
    ),
    # ``SYS_DYN_APP_ADDREM`` is a separate hook, so this does not imply add or remove. Unaligning
    # (``class_type = 0``) is the same ``UPDATE``, so the edit hook covers both directions.
    _entry(
        "sl1_align_dynamic_app_to_device_class",
        ToolTransport.SQL,
        writes=True,
        tool_set=DB_WRITE_SET,
        required_hooks=frozenset({_HOOK_SYS_DYN_APP_EDIT, _HOOK_DEV_CLASS_VIEW}),
    ),
    _entry(
        "sl1_get_device_class_alignment",
        ToolTransport.SQL,
        tool_set=DB_READ_SET,
        required_hooks=frozenset({_HOOK_DEV_CLASS_VIEW, _HOOK_SYS_DYN_APP_MANAGEMENT}),
    ),
    # ---- Device collection ----------------------------------------------------------------------
    #
    # Recreates the SL1 UI's Device Tools "run collection" action (``device_tools_run.inc``,
    # ``$tool_id == 20``) over the same stored procedure. These are DB tools rather than LCE tools
    # so they can be switched off: they inherit ``ENABLE_DB_WRITE_TOOLS`` under ``ENABLE_DB_TOOLS``,
    # while LCE tools are always registered.
    #
    # SL1 gates the dispatch on ``toolbox_get_tools_validate_access($tool_id)``, whose effective
    # check is ``DEV_COLLECTIONS_VIEW`` alone. Requiring ``DEV_TOOLS_RUN`` as well is a deliberate
    # strengthening. Refusal is not verified against a live restricted account.
    _entry(
        "sl1_run_dynamic_collection",
        ToolTransport.SQL,
        writes=True,
        tool_set=DB_WRITE_SET,
        required_hooks=frozenset({_HOOK_DEV_TOOLS_RUN, _HOOK_DEV_COLLECTIONS_VIEW}),
    ),
    # ``device_tools_log.inc`` checks ``DEV_TOOLS_RUN`` and then runs this same
    # ``proc_remote_logs`` read, so this is the hook SL1 itself puts on it.
    #
    # The hook alone is not sufficient. SL1's own viewer does no ownership check, so any holder of
    # ``DEV_TOOLS_RUN`` could read any collection's output by iterating ids. ``mcp_app.authz_gate``
    # adds an ownership check on top. Do not remove it, or the ``proc == 125 AND Xtype == 20``
    # scope filter, to "match platform behaviour".
    _entry(
        "sl1_fetch_collection_output",
        ToolTransport.SQL,
        tool_set=DB_READ_SET,
        required_hooks=frozenset({_HOOK_DEV_TOOLS_RUN}),
    ),
    # ---- Event and icon tools that do not use SQL -----------------------------------------------
    #
    # These must not be gated on the database prerequisite: a missing driver would otherwise
    # disable GraphQL tools that need no driver, no ``libem7`` and no ``silo.conf``.
    _entry("sl1_inject_alert", ToolTransport.REST, writes=True),
    _entry("sl1_get_recent_events", ToolTransport.REST),
    _entry("sl1_get_collected_values", ToolTransport.REST),
    _entry("sl1_create_icon", ToolTransport.GRAPHQL, writes=True),
    _entry("sl1_list_icons", ToolTransport.GRAPHQL),
    _entry("sl1_set_device_class_icon", ToolTransport.GRAPHQL, writes=True),
    _entry("sl1_set_device_class", ToolTransport.GRAPHQL, writes=True),
    # ---- Health, discovery and capability tools -------------------------------------------------
    #
    # ``server_health`` probes REST, GraphQL and LCE in one call.
    _entry("server_health", ToolTransport.MULTI),
    _entry("sl1_list_discovery_sessions", ToolTransport.REST),
    _entry("sl1_get_discovery_status", ToolTransport.REST),
    _entry("sl1_create_discovery_session", ToolTransport.REST, writes=True),
    _entry("sl1_run_discovery_session", ToolTransport.REST, writes=True),
    # Probes REST, GraphQL and LCE.
    _entry("sl1_check_capabilities", ToolTransport.MULTI),
    # Withheld. It would need a writable state directory to report the diff between calls that its
    # name promises. It is withheld rather than shipped with a disclaimer in its payload, because a
    # caller chooses a tool by its name before reading any payload.
    _entry("refresh_capability_map", ToolTransport.MULTI, registers=False),
    # Withheld. MCP's own ``tools/list`` already answers the same question, and describing this
    # service's surface would mean reading private FastMCP internals.
    _entry("list_capabilities", ToolTransport.LOCAL, registers=False),
)

# Name-keyed registry. A tool absent from it is refused.
#
# It covers only the tools in ``_ENTRIES``, and the authorization gate applies to the SQL tools
# among them. Widening the gate to other tools would need rows this registry does not have, so
# revisit where the mapping lives before doing that.
TOOL_REGISTRY: Final[dict[str, ToolRegistryEntry]] = {e.name: e for e in _ENTRIES}

# Every tool in the registry, registering or not.
DB_TOOL_COUNT: Final[int] = len(_ENTRIES)

# The tools that register. Derived rather than written down, so it cannot drift from the entries;
# ``tests/unit/test_registration_surface.py`` checks it against a real server.
REGISTERED_TOOL_COUNT: Final[int] = sum(1 for e in _ENTRIES if e.registers)

# Computed from ``transport`` so it cannot disagree with it.
SQL_TOOL_COUNT: Final[int] = sum(1 for e in _ENTRIES if e.transport is ToolTransport.SQL)

WRITE_TOOL_COUNT: Final[int] = sum(1 for e in _ENTRIES if e.writes)


class DbToolNotRegistered(PowerPackMcpError):  # noqa: N818 - house naming of the hierarchy
    """Raised when a tool name is not in the registry, or is withheld.

    This has no ``ErrorType`` of its own. Tools are registered from this same registry, so a caller
    cannot trigger it; reaching it means the service mis-registered a tool. The caller therefore
    sees ``internal_error`` from ``build_error_payload``'s fallback, while the exception type and
    the logged ``event`` identify the cause.

    :param tool_name: The tool name that was looked up.
    """

    tool_name: str

    def __init__(self, tool_name: str) -> None:
        self.tool_name = tool_name
        super().__init__(f"tool {tool_name!r} is not in the tool registry")


def registry_entry(tool_name: str) -> ToolRegistryEntry:
    """Return the registry entry for a tool, refusing unknown and withheld tools.

    A withheld tool (``registers=False``) is refused for the same reason as an unknown one: being in
    the inventory is not permission to run. There is no wildcard and no fallback.

    This function has no callers in ``src/`` today, because every registered tool comes from this
    registry. Do not delete it as dead code: it is the only implementation of the deny-by-default
    lookup, of its logged refusal and of the only ``raise DbToolNotRegistered``. An AST check in
    ``tests/unit/test_source_invariants.py`` fails if it disappears.

    :param tool_name: The MCP tool name to look up.
    :return: The tool's registry entry.
    :raises DbToolNotRegistered: If the tool is not in the registry or is withheld.
    """
    entry = TOOL_REGISTRY.get(tool_name)
    if entry is None or not entry.registers:
        # Keyed on ``event`` for monitoring, and carries no credential.
        logger.warning(
            "Refused a tool that is not in the tool registry.",
            extra={
                "event": str(LogEvent.VALIDATION_BLOCKED),
                "tool_name": tool_name,
                "withheld": entry is not None,
            },
        )
        raise DbToolNotRegistered(tool_name)
    return entry


def sql_tool_names() -> frozenset[str]:
    """Return the names of the tools that may be gated on the database prerequisite.

    Derived from ``transport`` on every call, so it cannot drift from the registry.

    :return: The names of every SQL tool.
    """
    return frozenset(e.name for e in _ENTRIES if e.transport is ToolTransport.SQL)


def write_tool_names() -> frozenset[str]:
    """Return the names of the tools that require ``ENABLE_DB_WRITE_TOOLS``.

    :return: The names of every tool that writes.
    """
    return frozenset(e.name for e in _ENTRIES if e.writes)


# The tool sets this registry populates, in the same order as ``tool_sets``.
REGISTRY_TOOL_SETS: Final[tuple[str, ...]] = (DB_READ_SET, DB_WRITE_SET, OPS_SET)


def tool_names_for_set(set_id: str) -> tuple[str, ...]:
    """Return every registering tool in a tool set, in registry order.

    Order comes from the single ``_ENTRIES`` tuple rather than per-set lists, so a tool cannot be
    registered twice or lost when it moves between sets. Withheld tools are excluded.

    :param set_id: A tool-set identifier such as ``db_read``.
    :return: The tool names, in registration order.
    """
    return tuple(e.name for e in _ENTRIES if e.tool_set == set_id and e.registers)


def _check_set_assignment() -> None:
    """Validate every registry entry at import time.

    Each of these mistakes would be silent at runtime, so they fail the import instead:

    1. A non-SQL tool in a DB set. A missing ``mysqlclient`` driver disables the DB sets, which
       would take down a tool that needs no database.
    2. A SQL tool outside the DB sets. It would register without the database prerequisite being
       checked and fail on first use.
    3. A write tool in ``db_read``. It would escape ``ENABLE_DB_WRITE_TOOLS``, one of the two write
       controls alongside ``required_hooks``.
    4. A SQL tool with no ``required_hooks``, or a non-SQL tool with some. A new SQL tool cannot be
       added without a hook mapping, and hooks on a non-SQL tool would imply a check that nothing
       enforces.
    5. A blank or space-padded hook id.

    An unknown tool-set identifier is also rejected, because a typo would create a set that nothing
    registers. Every clause can fail; keep it that way, so coverage shows any check that cannot.

    :raises AssertionError: If any entry breaks one of the rules above.
    """
    for entry in _ENTRIES:
        if entry.tool_set not in REGISTRY_TOOL_SETS:
            raise AssertionError(
                f"{entry.name}: tool_set {entry.tool_set!r} is not one of {REGISTRY_TOOL_SETS}"
            )
        in_db_set = entry.tool_set in (DB_READ_SET, DB_WRITE_SET)
        is_sql = entry.transport is ToolTransport.SQL
        if in_db_set != is_sql:
            raise AssertionError(
                f"{entry.name}: tool_set={entry.tool_set!r} but transport="
                f"{entry.transport.value!r}. Only SQL tools may be in a DB set, and every SQL tool "
                "must be in one."
            )
        if entry.writes and entry.tool_set == DB_READ_SET:
            raise AssertionError(
                f"{entry.name}: a write tool cannot sit in {DB_READ_SET!r} -- it would escape "
                "ENABLE_DB_WRITE_TOOLS, which is one of the two write controls."
            )
        if bool(entry.required_hooks) != is_sql:
            raise AssertionError(
                f"{entry.name}: transport={entry.transport.value!r} but "
                f"required_hooks={sorted(entry.required_hooks)!r}. Every SQL tool must carry a "
                "non-empty hook mapping, so a new DB tool cannot bypass the authorization gate, "
                "and no non-SQL tool may carry one."
            )
        if any(not h or h != h.strip() for h in entry.required_hooks):
            raise AssertionError(
                f"{entry.name}: required_hooks holds a blank or space-padded hook id. A lenient "
                "value is how an 'allow if unmapped' branch reappears without anyone writing one."
            )


_check_set_assignment()

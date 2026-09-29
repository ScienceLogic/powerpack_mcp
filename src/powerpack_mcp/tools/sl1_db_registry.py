"""
SL1 Platform Tool Registry

This module pairs each SL1 platform tool descriptor with the factory that builds it, and groups
the tools by tool set. Pairing is keyed by name, never by position: two tuples zipped in matching
order would register every tool under the wrong name after a transposition, and
``zip(..., strict=True)`` catches only a length difference.

Two tools deliberately have no factory: ``list_capabilities`` and ``refresh_capability_map`` are
inventoried but withheld. Expressing that as a missing factory, rather than a guard or a comment,
means ``_check_registry_is_total`` fails at import if someone adds a factory for either. The check
compares factories against the registering descriptors only, and ``WITHHELD_TOOLS`` names the
withheld pair as literals to catch what that comparison cannot.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from powerpack_mcp import authz
from powerpack_mcp.tools import sl1_db_descriptors as d
from powerpack_mcp.tools.sl1_db_tools import (
    make_sl1_align_dynamic_app_to_device_class,
    make_sl1_create_device_class,
    make_sl1_fetch_collection_output,
    make_sl1_get_component_tree,
    make_sl1_get_device_class_alignment,
    make_sl1_run_dynamic_collection,
    make_sl1_simulate_event,
    make_sl1_update_device_class,
)
from powerpack_mcp.tools.sl1_event_tools import (
    make_sl1_clear_event,
    make_sl1_create_icon,
    make_sl1_get_collected_values,
    make_sl1_get_recent_events,
    make_sl1_inject_alert,
    make_sl1_list_icons,
    make_sl1_set_device_class,
    make_sl1_set_device_class_icon,
)
from powerpack_mcp.tools.sl1_ops_tools import (
    make_server_health,
    make_sl1_check_capabilities,
    make_sl1_create_discovery_session,
    make_sl1_get_discovery_status,
    make_sl1_list_discovery_sessions,
    make_sl1_run_discovery_session,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from powerpack_mcp.tools.sl1_db_pipeline import Sl1DbToolContext
    from powerpack_mcp.tools.sl1_db_tools import DbToolFactory

    type FactoryMaker = Callable[[Sl1DbToolContext], DbToolFactory]

__all__ = ["WITHHELD_TOOLS", "db_read_tools", "db_write_tools", "ops_tools", "tools_for_set"]

# The inventoried tools that deliberately do not register. Spelled as literals, not derived from
# ``authz``, on purpose: the comparison in ``_check_registry_is_total`` catches descriptors and
# factories disagreeing, and this catches someone flipping ``registers=True`` in ``authz`` and
# adding a factory, so both sides agree and the surface silently widens. A derived value would
# agree too.
WITHHELD_TOOLS: Final[frozenset[str]] = frozenset({"list_capabilities", "refresh_capability_map"})

# Why each tool is withheld, so the import-time failure explains itself.
WITHHELD_REASON: Final[Mapping[str, str]] = {
    "list_capabilities": (
        "Withheld for two reasons: "
        "MCP's own tools/list already answers this, and porting it would read private FastMCP "
        "internals."
    ),
    "refresh_capability_map": (
        "Withheld: it cannot report the "
        "diff its name promises without a writable state directory, which this "
        "deployment does not provide."
    ),
}

# Tool name to the factory that builds it, one entry per registering tool.
_FACTORY_FOR: Final[Mapping[str, FactoryMaker]] = {
    # The 8 SQL tools -- `db_read` and `db_write`
    "sl1_simulate_event": make_sl1_simulate_event,
    "sl1_get_component_tree": make_sl1_get_component_tree,
    "sl1_create_device_class": make_sl1_create_device_class,
    "sl1_update_device_class": make_sl1_update_device_class,
    "sl1_align_dynamic_app_to_device_class": make_sl1_align_dynamic_app_to_device_class,
    "sl1_get_device_class_alignment": make_sl1_get_device_class_alignment,
    "sl1_run_dynamic_collection": make_sl1_run_dynamic_collection,
    "sl1_fetch_collection_output": make_sl1_fetch_collection_output,
    # The non-SQL tools from the DB modules -- `ops`
    "sl1_clear_event": make_sl1_clear_event,
    "sl1_inject_alert": make_sl1_inject_alert,
    "sl1_get_recent_events": make_sl1_get_recent_events,
    "sl1_get_collected_values": make_sl1_get_collected_values,
    "sl1_create_icon": make_sl1_create_icon,
    "sl1_list_icons": make_sl1_list_icons,
    "sl1_set_device_class_icon": make_sl1_set_device_class_icon,
    "sl1_set_device_class": make_sl1_set_device_class,
    # Health, capability and discovery tools -- `ops`
    "server_health": make_server_health,
    "sl1_list_discovery_sessions": make_sl1_list_discovery_sessions,
    "sl1_get_discovery_status": make_sl1_get_discovery_status,
    "sl1_create_discovery_session": make_sl1_create_discovery_session,
    "sl1_run_discovery_session": make_sl1_run_discovery_session,
    "sl1_check_capabilities": make_sl1_check_capabilities,
    # `list_capabilities` and `refresh_capability_map` are deliberately absent; see the module
    # docstring.
}


def _check_registry_is_total() -> None:
    """Fail at import if the descriptors and the factory table disagree, in either direction.

    A registering descriptor with no factory would raise ``KeyError`` at startup anyway. A factory
    no descriptor claims is silent: the tool never registers, and an operator sees a
    complete-looking ``tools/list`` with one tool missing. Together the two checks below also prove
    that no withheld tool has a factory, so no third check is needed.

    :raises RuntimeError: If the tables disagree, or the withheld set is not ``WITHHELD_TOOLS``.
    """
    registering = {descriptor.tool_name for descriptor in d.REGISTERING_DB_DESCRIPTORS}
    factories = set(_FACTORY_FOR)
    if registering != factories:
        raise RuntimeError(
            "SL1 DB tool registry is inconsistent with the descriptors. "
            f"Registering descriptors with no factory: {sorted(registering - factories)}. "
            f"Factories no registering descriptor claims: {sorted(factories - registering)}."
        )
    # The comparison above would also pass if a withheld tool were given a factory and moved into
    # the registering set, silently widening the surface. This second check catches that.
    withheld = {
        descriptor.tool_name
        for descriptor in d.ALL_DB_DESCRIPTORS
        if descriptor.tool_name not in registering
    }
    if withheld != WITHHELD_TOOLS:
        # Carry the reason so the failure explains itself to someone about to widen the surface.
        reasons = " ".join(
            f"`{name}`: {WITHHELD_REASON[name]}" for name in sorted(WITHHELD_TOOLS - withheld)
        )
        raise RuntimeError(
            f"Expected exactly {sorted(WITHHELD_TOOLS)} to be withheld; found "
            f"{sorted(withheld)}. {reasons}"
        )


_check_registry_is_total()


def tools_for_set(set_id: str) -> tuple[tuple[d.DbToolDescriptor, FactoryMaker], ...]:
    """Return the ordered ``(descriptor, factory)`` pairs for one tool set.

    Order and membership come from the ``authz`` inventory, the source of truth for what exists,
    not from this module, so moving a tool between the groups above cannot register it twice or
    drop it.

    :param set_id: A tool-set identifier such as ``authz.DB_READ_SET``.
    """
    names = authz.tool_names_for_set(set_id)
    return tuple((d.DB_DESCRIPTORS_BY_NAME[name], _FACTORY_FOR[name]) for name in names)


def db_read_tools() -> tuple[tuple[d.DbToolDescriptor, FactoryMaker], ...]:
    """Return the SQL read tools, gated by ``ENABLE_DB_TOOLS``."""
    return tools_for_set(authz.DB_READ_SET)


def db_write_tools() -> tuple[tuple[d.DbToolDescriptor, FactoryMaker], ...]:
    """Return the SQL write tools, gated by ``ENABLE_DB_WRITE_TOOLS`` under ``ENABLE_DB_TOOLS``.

    The nesting of the two flags is handled by ``tool_sets.resolve``, which reports
    ``DISABLED_BY_NESTING`` separately from ``DISABLED_BY_CONFIGURATION``.
    """
    return tools_for_set(authz.DB_WRITE_SET)


def ops_tools() -> tuple[tuple[d.DbToolDescriptor, FactoryMaker], ...]:
    """Return the tools in this registry that need no database, gated by ``ENABLE_OPS_TOOLS``."""
    return tools_for_set(authz.OPS_SET)

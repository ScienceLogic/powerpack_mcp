"""
SL1 Tool Registry

This module pairs each SL1 descriptor with the factory that builds its tool. Pairing is by tool
name, not by position: ``_FACTORY_FOR`` maps a name to its factory, and the ordered pairs are
derived from the descriptor tuples. Two parallel tuples zipped together would register every tool
under the wrong name after a transposition, and ``zip(strict=True)`` catches only a length
difference.

``_check_registry_is_total`` runs at import and fails closed. If descriptors and factories ever
disagree the service refuses to start, rather than starting with a tool silently missing from
``tools/list``, which an operator cannot see.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools.sl1_entity_tools import (
    make_sl1_align_dynamic_apps_to_device,
    make_sl1_create_universal_credential,
    make_sl1_create_virtual_device,
    make_sl1_delete_credential,
    make_sl1_delete_device,
    make_sl1_get_credential,
    make_sl1_get_event_policy,
    make_sl1_get_powerpack,
    make_sl1_list_credentials,
    make_sl1_list_event_policies,
    make_sl1_list_powerpacks,
    make_sl1_list_uploaded_powerpacks,
    make_sl1_list_virtual_device_classes,
    make_sl1_replace_universal_credential,
    make_sl1_unalign_dynamic_apps_from_device,
    make_sl1_update_universal_credential,
)
from powerpack_mcp.tools.sl1_graphql_tools import make_sl1_graphql, make_sl1_graphql_introspect
from powerpack_mcp.tools.sl1_guided_discovery import make_sl1_create_guided_discovery_session
from powerpack_mcp.tools.sl1_rest_tools import (
    make_sl1_get_dynamic_app,
    make_sl1_list_dynamic_apps,
    make_sl1_rest_describe,
    make_sl1_rest_index,
    make_sl1_rest_request,
    make_sl1_rest_search,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
    from powerpack_mcp.tools.sl1_rest_tools import Sl1ToolFactory

    type Sl1Descriptor = d.Sl1OperationDescriptor | d.GraphQlDescriptor
    type FactoryMaker = Callable[[Sl1ToolContext], Sl1ToolFactory]

__all__ = ["sl1_graphql_set_tools", "sl1_rest_set_tools"]

# Tool name -> the factory that builds it. Keyed by name so the pairing cannot transpose.
_FACTORY_FOR: Final[Mapping[str, FactoryMaker]] = {
    # The 4 REST passthroughs
    "sl1_rest_request": make_sl1_rest_request,
    "sl1_rest_index": make_sl1_rest_index,
    "sl1_rest_describe": make_sl1_rest_describe,
    "sl1_rest_search": make_sl1_rest_search,
    # The 2 typed REST readers for Dynamic Applications
    "sl1_list_dynamic_apps": make_sl1_list_dynamic_apps,
    "sl1_get_dynamic_app": make_sl1_get_dynamic_app,
    # Devices: 5, GraphQL
    "sl1_list_virtual_device_classes": make_sl1_list_virtual_device_classes,
    "sl1_create_virtual_device": make_sl1_create_virtual_device,
    "sl1_delete_device": make_sl1_delete_device,
    "sl1_align_dynamic_apps_to_device": make_sl1_align_dynamic_apps_to_device,
    "sl1_unalign_dynamic_apps_from_device": make_sl1_unalign_dynamic_apps_from_device,
    # Credentials: 6, GraphQL (4 writers, 2 readers)
    "sl1_create_universal_credential": make_sl1_create_universal_credential,
    "sl1_delete_credential": make_sl1_delete_credential,
    "sl1_update_universal_credential": make_sl1_update_universal_credential,
    "sl1_replace_universal_credential": make_sl1_replace_universal_credential,
    "sl1_list_credentials": make_sl1_list_credentials,
    "sl1_get_credential": make_sl1_get_credential,
    # PowerPacks: 3, GraphQL
    "sl1_list_powerpacks": make_sl1_list_powerpacks,
    "sl1_get_powerpack": make_sl1_get_powerpack,
    "sl1_list_uploaded_powerpacks": make_sl1_list_uploaded_powerpacks,
    # Event Policies: 2, GraphQL, read-only by design
    "sl1_list_event_policies": make_sl1_list_event_policies,
    "sl1_get_event_policy": make_sl1_get_event_policy,
    # The 2 GraphQL passthroughs
    "sl1_graphql": make_sl1_graphql,
    "sl1_graphql_introspect": make_sl1_graphql_introspect,
    # Create-and-run guided discovery, whose per-step documents are built from platform data.
    "sl1_create_guided_discovery_session": make_sl1_create_guided_discovery_session,
}


def _check_registry_is_total() -> None:
    """Fail at import if the descriptors and the factory table disagree, in either direction.

    A descriptor with no factory would raise ``KeyError`` at registration anyway. A factory that no
    descriptor claims is silent: it never registers, and an operator sees a complete-looking
    ``tools/list`` with one tool missing. That is the direction this check exists for.

    :raises RuntimeError: If the two sets of tool names differ.
    """
    # Two comprehensions rather than one over a merged tuple: merging widens the element type to
    # ``object``, and the resulting ``type: ignore`` would suppress the attribute error that would
    # catch a descriptor tuple losing its ``tool_name``.
    described = {rest.tool_name for rest in d.ALL_REST_DESCRIPTORS} | {
        gql.tool_name for gql in d.ALL_GRAPHQL_DESCRIPTORS
    }
    registered = set(_FACTORY_FOR)
    if described != registered:
        missing_factory = sorted(described - registered)
        orphan_factory = sorted(registered - described)
        raise RuntimeError(
            "SL1 tool registry is inconsistent with the descriptors. "
            f"Descriptors with no factory: {missing_factory}. "
            f"Factories no descriptor claims: {orphan_factory}."
        )


_check_registry_is_total()


def _pairs(descriptors: Sequence[Sl1Descriptor]) -> tuple[tuple[Sl1Descriptor, FactoryMaker], ...]:
    """Return ordered ``(descriptor, factory)`` pairs, derived from the descriptor tuples.

    The descriptor tuples are the source of truth for what exists, so the registration order and
    count come from them rather than from a second list that has to agree.
    """
    return tuple((descriptor, _FACTORY_FOR[descriptor.tool_name]) for descriptor in descriptors)


def sl1_rest_set_tools() -> tuple[tuple[Sl1Descriptor, FactoryMaker], ...]:
    """Return the SL1 REST tool set's pairs (6 REST and 16 GraphQL tools).

    The whole set is gated by ``ENABLE_SL1_REST_TOOLS``, including its GraphQL tools.
    """
    return _pairs(d.SL1_REST_SET_DESCRIPTORS)


def sl1_graphql_set_tools() -> tuple[tuple[Sl1Descriptor, FactoryMaker], ...]:
    """Return the pairs for the GraphQL passthrough tools, gated by ``ENABLE_SL1_GRAPHQL_TOOLS``.

    Callers must still consult ``GRAPHQL_PREREQUISITE_MET`` before registering them; registration
    depends on that flag, not on this docstring.
    """
    return _pairs(d.SL1_GRAPHQL_SET_DESCRIPTORS)

"""
Tool Package

This package holds the MCP tool surface and re-exports what ``mcp_app.register_tools`` needs,
plus the operation descriptors that tests refer to.

It carries two tool sets: the always-registered LCE tools and the flag-gated ``standards`` set.
``get_content_standards`` lives here because it contacts no backend at all (no LCE, REST,
GraphQL or database).
"""

from __future__ import annotations

from powerpack_mcp.tools.content_standards import (
    CATALOG_SOURCE,
    KNOWN_ENTITIES,
    RULES,
    ContentStandardRule,
)
from powerpack_mcp.tools.descriptors import (
    ALL_DESCRIPTORS,
    CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS,
    CREATE_OR_UPDATE_EVENT_POLICIES,
    GET_DYNAMIC_APPLICATION,
    GET_EVENT_POLICY,
    GET_POWERPACK,
    IDENTIFIER_FORMS,
    LIST_DYNAMIC_APPLICATIONS,
    LIST_EVENT_POLICIES,
    OperationDescriptor,
)
from powerpack_mcp.tools.lce_tools import (
    ToolFactory,
    make_create_or_update_dynamic_applications,
    make_create_or_update_event_policies,
    make_get_dynamic_application,
    make_get_event_policy,
    make_get_powerpack,
    make_list_dynamic_applications,
    make_list_event_policies,
)
from powerpack_mcp.tools.pipeline import ToolContext, run_operation, tool_boundary
from powerpack_mcp.tools.standards_tools import STANDARDS_TOOLS, get_content_standards

__all__ = [
    "ALL_DESCRIPTORS",
    "CATALOG_SOURCE",
    "CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS",
    "CREATE_OR_UPDATE_EVENT_POLICIES",
    "GET_DYNAMIC_APPLICATION",
    "GET_EVENT_POLICY",
    "GET_POWERPACK",
    "IDENTIFIER_FORMS",
    "KNOWN_ENTITIES",
    "LIST_DYNAMIC_APPLICATIONS",
    "LIST_EVENT_POLICIES",
    "RULES",
    "STANDARDS_TOOLS",
    "ContentStandardRule",
    "OperationDescriptor",
    "ToolContext",
    "ToolFactory",
    "get_content_standards",
    "make_create_or_update_dynamic_applications",
    "make_create_or_update_event_policies",
    "make_get_dynamic_application",
    "make_get_event_policy",
    "make_get_powerpack",
    "make_list_dynamic_applications",
    "make_list_event_policies",
    "run_operation",
    "tool_boundary",
]

# The seven factories, in ``ALL_DESCRIPTORS`` order. ``register_tools`` iterates this rather than
# naming each one, so adding an operation needs only a descriptor, a factory and one entry here.
TOOL_FACTORIES = (
    make_get_powerpack,
    make_get_dynamic_application,
    make_list_dynamic_applications,
    make_create_or_update_dynamic_applications,
    make_get_event_policy,
    make_list_event_policies,
    make_create_or_update_event_policies,
)

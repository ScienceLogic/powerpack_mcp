"""
LCE Tool Functions

This module defines the seven MCP tools that read and write PowerPacks, Dynamic Applications
and Event Policies through LCE. Each tool is a thin adapter that names its operation descriptor
and hands the call to the shared ``run_operation`` pipeline, so no path, method or validation rule
is hard-coded here.

Tool signatures are typed so FastMCP can derive each tool's JSON schema from them, and each tool's
docstring becomes the description an MCP client reads when choosing a tool. Docstrings are
therefore written out in full for every tool rather than composed from shared fragments: an
f-string is not a docstring and would leave ``__doc__`` as ``None``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from powerpack_mcp.query import FilterParams, SelectorParams, WriteOptions
from powerpack_mcp.tools import descriptors as d
from powerpack_mcp.tools.pipeline import ToolContext, run_operation, tool_boundary

# `PayloadRoot` and the parameter models are imported at **runtime**, not under `TYPE_CHECKING`:
# FastMCP resolves each tool's annotations with `typing.get_type_hints` to build its JSON schema, so
# a name that exists only for the type checker raises `NameError` at registration.
# TC001: resolved at runtime, see above.
from powerpack_mcp.validation import PayloadRoot  # noqa: TC001

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

__all__ = [
    "ToolFactory",
    "make_create_or_update_dynamic_applications",
    "make_create_or_update_event_policies",
    "make_get_dynamic_application",
    "make_get_event_policy",
    "make_get_powerpack",
    "make_list_dynamic_applications",
    "make_list_event_policies",
]

# What every factory returns. `tool_boundary` widens the result to `object`, because a rejected call
# returns the error envelope rather than the LCE document.
type ToolFactory = Callable[..., Awaitable[object]]


def make_get_powerpack(context: ToolContext) -> ToolFactory:
    """Build the `lce_get_powerpack` tool bound to ``context``.

    Every tool in this module is built by a factory like this one, so the LCE client and
    configuration are injected rather than read from module state, which keeps the tools testable.

    :param context: The client and configuration the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @tool_boundary(d.GET_POWERPACK, context.config)
    async def lce_get_powerpack(
        powerpack_identifier: str,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Retrieve one PowerPack from LCE by identifier.

        Args:
            powerpack_identifier: Which PowerPack to retrieve. Accepts any of three forms: a numeric
                ID (12345), a 32-character uppercase hexadecimal GUID
                (A1B2C3D4E5F6789012345678901234AB), or a name (my-powerpack).
            pretty: When true, enums are returned as strings (for example ENABLED); when false, as
                integers. This does NOT control JSON pretty-printing -- setting it false to save
                tokens silently changes every enum in the response to an integer.
            fields: Response field allowlist. Comma-separated paths, supporting nested paths and
                wildcards such as dynamic_applications.*.id. Passed to LCE unparsed.
            exclude: Response field blocklist, same syntax. If both are given, LCE applies fields
                first, then exclude.
        """
        return await run_operation(
            context,
            d.GET_POWERPACK,
            identifier=powerpack_identifier,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
        )

    return lce_get_powerpack


def make_get_dynamic_application(context: ToolContext) -> ToolFactory:
    """Build the `lce_get_dynamic_application` tool bound to ``context``."""

    @tool_boundary(d.GET_DYNAMIC_APPLICATION, context.config)
    async def lce_get_dynamic_application(
        app_identifier: str,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Retrieve one Dynamic Application from LCE by identifier.

        Args:
            app_identifier: Which Dynamic Application to retrieve. Accepts any of three forms: a
                numeric ID (12345), a 32-character uppercase hexadecimal GUID
                (A1B2C3D4E5F6789012345678901234AB), or a name (my-app).
            pretty: When true, enums are returned as strings (for example ENABLED); when false, as
                integers. This does NOT control JSON pretty-printing.
            fields: Response field allowlist. Comma-separated paths with nested paths and wildcards.
                Passed to LCE unparsed.
            exclude: Response field blocklist, same syntax. LCE applies fields first, then exclude.
        """
        return await run_operation(
            context,
            d.GET_DYNAMIC_APPLICATION,
            identifier=app_identifier,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
        )

    return lce_get_dynamic_application


def make_list_dynamic_applications(context: ToolContext) -> ToolFactory:
    """Build the `lce_list_dynamic_applications` tool bound to ``context``."""

    @tool_boundary(d.LIST_DYNAMIC_APPLICATIONS, context.config)
    async def lce_list_dynamic_applications(
        filters: FilterParams,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """List Dynamic Applications matching one or more filter conditions.

        At least one filter condition is REQUIRED -- an unfiltered list request cannot be
        constructed. The five operators are is, contains, gt, lt and search. A comma in a value
        expresses multi-value matching, so gt, lt and search -- which are single-value only --
        reject a comma-containing value. search cannot be negated.

        Args:
            filters: Conditions to match, each with field, operator, value and optional negate; plus
                require_all (true = all conditions must match, false = any may match).
            pretty: When true, enums are returned as strings (for example ENABLED); when false, as
                integers. This does NOT control JSON pretty-printing.
            fields: Response field allowlist. Comma-separated paths with nested paths and wildcards.
            exclude: Response field blocklist, same syntax. LCE applies fields first, then exclude.
        """
        return await run_operation(
            context,
            d.LIST_DYNAMIC_APPLICATIONS,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
            filters=filters,
        )

    return lce_list_dynamic_applications


def make_create_or_update_dynamic_applications(context: ToolContext) -> ToolFactory:
    """Build the `lce_create_or_update_dynamic_applications` tool bound to ``context``."""

    @tool_boundary(d.CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS, context.config)
    async def lce_create_or_update_dynamic_applications(
        payload: PayloadRoot,
        commit: bool = True,
        retrieve: bool = False,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Create or update Dynamic Applications in LCE.

        Two blocking lints run BEFORE anything is sent, and nothing reaches LCE if either produces a
        finding. Every guid-suffixed key must be an uppercase 32-character hexadecimal GUID;
        omit the
        key entirely to create a new child object and let LCE assign one, or pass null.
        threshold_objects[].type must be exactly one of PERCENTAGE, INTEGER or DECIMAL. Findings are
        returned for every offending path at once, so one round trip surfaces every problem.

        Args:
            payload: A single Dynamic Application object, an array of them, or an object with a
                dynamic_applications key mapped to an array. Sent to LCE exactly as supplied --
                never re-keyed, re-typed or normalised.
            commit: When true, objects are upserted. When false NOTHING is written -- LCE's own dry
                run, which is the safe way to validate a payload before committing it.
            retrieve: When true, the response includes a fully-expanded entities list of the
                normalized stored objects. When false, only results is returned.
            pretty: When true, enums are returned as strings; when false, as integers. This does NOT
                control JSON pretty-printing.
            fields: Response field allowlist. Comma-separated paths with nested paths and wildcards.
            exclude: Response field blocklist, same syntax. LCE applies fields first, then exclude.
        """
        return await run_operation(
            context,
            d.CREATE_OR_UPDATE_DYNAMIC_APPLICATIONS,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
            write_options=WriteOptions(commit=commit, retrieve=retrieve),
            payload=payload,
        )

    return lce_create_or_update_dynamic_applications


def make_get_event_policy(context: ToolContext) -> ToolFactory:
    """Build the `lce_get_event_policy` tool bound to ``context``."""

    @tool_boundary(d.GET_EVENT_POLICY, context.config)
    async def lce_get_event_policy(
        event_identifier: str,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Retrieve one Event Policy from LCE by identifier.

        Args:
            event_identifier: Which Event Policy to retrieve. Accepts any of three forms: a numeric
                ID (12345), a 32-character uppercase hexadecimal GUID
                (A1B2C3D4E5F6789012345678901234AB), or a name (my-policy).
            pretty: When true, enums are returned as strings (for example ENABLED); when false, as
                integers. This does NOT control JSON pretty-printing.
            fields: Response field allowlist. Comma-separated paths with nested paths and wildcards.
            exclude: Response field blocklist, same syntax. LCE applies fields first, then exclude.
        """
        return await run_operation(
            context,
            d.GET_EVENT_POLICY,
            identifier=event_identifier,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
        )

    return lce_get_event_policy


def make_list_event_policies(context: ToolContext) -> ToolFactory:
    """Build the `lce_list_event_policies` tool bound to ``context``."""

    @tool_boundary(d.LIST_EVENT_POLICIES, context.config)
    async def lce_list_event_policies(
        filters: FilterParams,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """List Event Policies matching one or more filter conditions.

        At least one filter condition is REQUIRED. The five operators are is, contains, gt, lt and
        search, with the same rules as the Dynamic Application listing: gt, lt and search are
        single-value only so they reject a comma-containing value, and search cannot be negated.

        Args:
            filters: Conditions to match, each with field, operator, value and optional negate; plus
                require_all (true = all conditions must match, false = any may match).
            pretty: When true, enums are returned as strings; when false, as integers. This does NOT
                control JSON pretty-printing.
            fields: Response field allowlist. Comma-separated paths with nested paths and wildcards.
            exclude: Response field blocklist, same syntax. LCE applies fields first, then exclude.
        """
        return await run_operation(
            context,
            d.LIST_EVENT_POLICIES,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
            filters=filters,
        )

    return lce_list_event_policies


def make_create_or_update_event_policies(context: ToolContext) -> ToolFactory:
    """Build the `lce_create_or_update_event_policies` tool bound to ``context``."""

    @tool_boundary(d.CREATE_OR_UPDATE_EVENT_POLICIES, context.config)
    async def lce_create_or_update_event_policies(
        payload: PayloadRoot,
        commit: bool = True,
        retrieve: bool = False,
        pretty: bool = True,
        fields: str | None = None,
        exclude: str | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Create or update Event Policies in LCE.

        The child-GUID lint runs BEFORE anything is sent, and nothing reaches LCE if it produces a
        finding: every guid-suffixed key must be an uppercase 32-character hexadecimal GUID, or be
        omitted, or be null. The threshold-type lint does NOT apply here, because Event Policies
        have
        no threshold collection.

        Args:
            payload: A single Event Policy object, an array of them, or an object with an
                event_policies key mapped to an array. Sent to LCE exactly as supplied -- never
                re-keyed, re-typed or normalised.
            commit: When true, objects are upserted. When false NOTHING is written -- LCE's own dry
                run, which is the safe way to validate a payload before committing it.
            retrieve: When true, the response includes a fully-expanded entities list of the
                normalized stored objects. When false, only results is returned.
            pretty: When true, enums are returned as strings; when false, as integers. This does NOT
                control JSON pretty-printing.
            fields: Response field allowlist. Comma-separated paths with nested paths and wildcards.
            exclude: Response field blocklist, same syntax. LCE applies fields first, then exclude.
        """
        return await run_operation(
            context,
            d.CREATE_OR_UPDATE_EVENT_POLICIES,
            selector=SelectorParams(pretty=pretty, fields=fields, exclude=exclude),
            write_options=WriteOptions(commit=commit, retrieve=retrieve),
            payload=payload,
        )

    return lce_create_or_update_event_policies

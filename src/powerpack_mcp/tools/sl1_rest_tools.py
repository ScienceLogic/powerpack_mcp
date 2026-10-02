"""
SL1 REST Tools

This module defines the six SL1 tools that use the REST API: the four passthroughs
(``sl1_rest_request``, ``sl1_rest_index``, ``sl1_rest_describe``, ``sl1_rest_search``) and the
two Dynamic Application readers built on ``dynamic_app/_lookup``. The other typed SL1 tools use
GraphQL and live in ``sl1_entity_tools``.

No tool takes ``target_host``, ``username`` or ``password``: every call uses the caller's
forwarded credential against the configured host. Paths and methods come from
``sl1_descriptors``. The four passthroughs refuse credential resources other than the plain
indexes and scrub every response for credential secrets; ``sl1_credential_guard`` states the rule.
Tool docstrings are written out in full because an f-string is not a docstring and would leave
``__doc__`` as ``None``, removing the tool's description.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from powerpack_mcp.errors import FindingCode, ValidationBlocked, ValidationFinding
from powerpack_mcp.shaping import shape_response
from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools.sl1_credential_guard import (
    check_rest_credential_access,
    shape_rest_response,
)
from powerpack_mcp.tools.sl1_pipeline import audit_passthrough, sl1_tool_boundary

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext

__all__ = [
    "Sl1ToolFactory",
    "make_sl1_get_dynamic_app",
    "make_sl1_list_dynamic_apps",
    "make_sl1_rest_describe",
    "make_sl1_rest_index",
    "make_sl1_rest_request",
    "make_sl1_rest_search",
]

# What every factory returns. ``sl1_tool_boundary`` widens the result to ``object``, because a
# rejected call returns the error envelope rather than the SL1 document.
type Sl1ToolFactory = Callable[..., Awaitable[object]]

# The ``_lookup`` resource caps a page at 500 rows. Not configurable, because it is SL1's
# behaviour rather than our policy.
_SCAN_LIMIT = 500

# How many loose candidates an ambiguity message names. The full list can be 500
# (``_SCAN_LIMIT``), and an error carrying 500 names is not actionable.
_LOOSE_MATCH_PREVIEW = 10

# Default page sizes for ``sl1_rest_search``, matching the reference implementation. 10 with
# ``extended_fetch`` because each row becomes a full object rather than a bare URI.
_DEFAULT_SEARCH_LIMIT = 20
_DEFAULT_EXTENDED_SEARCH_LIMIT = 10


def _stringify_query(params: dict[str, Any]) -> dict[str, str]:
    """Render query values as strings, dropping ``None``.

    SL1 takes ``limit=0`` and ``extended_fetch=1`` as text on the wire, and the client's ``query``
    is typed ``dict[str, str]`` so the URL builder has nothing to guess. Booleans are rendered as
    ``1``/``0``, because SL1 does not parse ``True``/``False``.
    """
    out: dict[str, str] = {}
    for key, value in params.items():
        if value is None:
            continue
        out[key] = str(int(value)) if isinstance(value, bool) else str(value)
    return out


def _encoded_body(body: Any | None, content_type: str) -> tuple[object | None, str | None]:
    """Split a ``sl1_rest_request`` body into the client's JSON and raw-text forms.

    :param body: The caller's body, or None for a request without one.
    :param content_type: The request content type.
    :return: ``(json_body, raw_body)``; at most one is set, and both are None without a body.
    """
    json_body: object | None = None
    raw_body: str | None = None
    if body is not None:
        if content_type == "application/json" and not isinstance(body, str | bytes):
            json_body = body
        else:
            raw_body = body if isinstance(body, str) else json.dumps(body)
    return json_body, raw_body


def _check_credential_access(
    descriptor: d.Sl1OperationDescriptor, method: str, path: str, query: dict[str, str]
) -> None:
    """Apply ``sl1_credential_guard``'s REST rule, auditing a refusal before raising it.

    Audited for the same reason a rejected verb is: the refused calls are the interesting ones to
    anyone reviewing the trail. The search and describe tools address a path refusal to
    ``resource``, their name for the path, and search addresses a query refusal to ``filters``,
    from which its ``filter.``/``order.`` parameters are built.

    :raises ValidationBlocked: If the call would read or change credential secrets.
    """
    try:
        check_rest_credential_access(
            method,
            path,
            query,
            argument="path" if descriptor is d.REST_REQUEST else "resource",
            query_argument="filters" if descriptor is d.REST_SEARCH else None,
        )
    except ValidationBlocked:
        audit_passthrough(descriptor, method=method, path=path, outcome="rejected_credential_path")
        raise


def make_sl1_rest_request(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_rest_request`` passthrough bound to ``context``.

    :param context: The clients, configuration and credential source the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @sl1_tool_boundary(d.REST_REQUEST)
    async def sl1_rest_request(
        method: str,
        path: str,
        query_params: dict[str, Any] | None = None,
        body: Any | None = None,
        content_type: str = "application/json",
        prune: bool = True,
        # ``timeout`` is forwarded to httpx, not used to race a task, so ASYNC109's advice to
        # prefer ``asyncio.timeout`` does not apply here.
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> dict[str, Any] | list[Any]:
        """Make an arbitrary request against the SL1 REST API. Covers the ENTIRE REST surface.

        Args:
            method: GET, POST, PUT or DELETE. GET fetches; POST to a collection creates; POST to
                /resource/<id> updates; DELETE removes. No other verb is accepted.
            path: Resource path relative to the REST base, leading slash optional -- for example
                device, device/1, dynamic_app, organization. Absolute URLs, schemes, protocol-
                relative //host and .. segments are rejected before anything is sent.
            query_params: SL1 conventions -- filter.name.contains=core, limit, offset,
                order.name=ASC, extended_fetch=1, hide_filterinfo=1.
            body: A dict or list is sent as JSON. For SL1's asynchronous operations -- starting a
                discovery session, applying a device template -- set content_type to
                application/em7-resource-uri and pass the resource URI as a JSON STRING, which
                means it must be quoted: body="/api/device_template/6", NOT
                body=/api/device_template/6. An unquoted path is not valid JSON and the call is
                rejected before it reaches this tool, with an error that does not name the quoting
                as the cause.
            content_type: Request content type. Only consulted when body is given.
            prune: Drop empty fields from the response to save tokens. Set false to see the literal
                shape, where an empty value and an absent one are distinguishable.
            timeout: Per-call timeout in seconds. Bounded by the service's ceiling; a larger
                value is clamped, never honoured.

        This tool can create, update and delete. Credential resources are refused except the
        plain credential and credential/<type> indexes, and secrets are withheld from every
        response; use sl1_get_credential or sl1_list_credentials. On any resource, filter. and
        order. on a secret field are refused, and link_disp_field may name only a plain display
        field such as name or description.
        """
        verb = method.upper()
        if verb not in d.ALLOWED_METHODS:
            # Audited before rejection, because the rejected calls are the interesting ones for
            # anyone probing the surface.
            audit_passthrough(d.REST_REQUEST, method=verb, path=path, outcome="rejected_method")
            allowed = ", ".join(sorted(d.ALLOWED_METHODS))
            # ``ValidationBlocked``, not ``ValueError``: ``sl1_tool_boundary`` translates only
            # ``PowerPackMcpError``, so a bare builtin would escape the boundary and reach the
            # caller as an unhandled exception instead of the error envelope.
            raise ValidationBlocked(
                [
                    ValidationFinding(
                        path="method",
                        rule=FindingCode.TOOL_ARGUMENT,
                        message=f"method must be one of {allowed}.",
                    )
                ]
            )

        query = _stringify_query(query_params or {})
        _check_credential_access(d.REST_REQUEST, verb, path, query)
        json_body, raw_body = _encoded_body(body, content_type)

        audit_passthrough(d.REST_REQUEST, method=verb, path=path, outcome="invoked")
        result = await context.client.request(
            credential=context.credential_source(),
            method=verb,  # type: ignore[arg-type]  # narrowed by ALLOWED_METHODS above
            path=path,
            query=query,
            json_body=json_body,
            raw_body=raw_body,
            content_type=content_type,
            timeout=timeout,
        )
        # Shaped before pruning and whether or not pruning is asked for: ``prune=False`` changes
        # which empty values survive, never which secrets do.
        shaped = shape_rest_response(path, result)
        return _pruned(shaped) if prune else shaped

    return sl1_rest_request


def make_sl1_rest_index(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_rest_index`` passthrough bound to ``context``."""

    @sl1_tool_boundary(d.REST_INDEX)
    async def sl1_rest_index() -> dict[str, Any] | list[Any]:
        """List every available REST resource type -- the HATEOAS directory at the API root.

        The entry point for discovering what REST exposes on this appliance. Use
        sl1_rest_describe on a resource name from this list to see its fields and filters.
        """
        audit_passthrough(d.REST_INDEX, method=d.REST_INDEX.method, path="", outcome="invoked")
        listed = await context.client.request(
            credential=context.credential_source(),
            method=d.REST_INDEX.method,
            path=d.REST_INDEX.path_base,
        )
        # The API root lists resource names and carries no credential, but every passthrough
        # response goes through the same scrub so none can be the one that was forgotten.
        return shape_rest_response(d.REST_INDEX.path_base, listed)

    return sl1_rest_index


def make_sl1_rest_describe(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_rest_describe`` passthrough bound to ``context``."""

    @sl1_tool_boundary(d.REST_DESCRIBE)
    async def sl1_rest_describe(resource: str) -> dict[str, Any] | list[Any]:
        """Describe a REST resource type: its fields, filters and options.

        Fetches the resource index with descriptions and zero rows. Use this before building filters
        or sort orders, so that the field names you use are known to be valid.

        Args:
            resource: A resource type name, as listed by sl1_rest_index -- for example device,
                dynamic_app, organization.
        """
        # ``limit=0`` asks for the description without rows; ``hide_filterinfo=0`` includes the
        # filter metadata, which is the point of this tool.
        query = _stringify_query({"limit": 0, "hide_filterinfo": 0})
        _check_credential_access(d.REST_DESCRIBE, d.REST_DESCRIBE.method, resource, query)
        audit_passthrough(
            d.REST_DESCRIBE, method=d.REST_DESCRIBE.method, path=resource, outcome="invoked"
        )
        described = await context.client.request(
            credential=context.credential_source(),
            method=d.REST_DESCRIBE.method,
            path=resource,
            query=query,
        )
        return shape_rest_response(resource, described)

    return sl1_rest_describe


def make_sl1_rest_search(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_rest_search`` passthrough bound to ``context``."""

    @sl1_tool_boundary(d.REST_SEARCH)
    async def sl1_rest_search(
        resource: str,
        filters: dict[str, Any] | None = None,
        limit: int | None = None,
        offset: int = 0,
        order: dict[str, str] | None = None,
        extended_fetch: bool = False,
    ) -> dict[str, Any] | list[Any]:
        """Query a collection over a REST resource using SL1's filter conventions.

        Args:
            resource: The resource type to query, as listed by sl1_rest_index.
            filters: Field conditions, for example {"name.contains": "core", "organization": 0},
                which become filter.name.contains=core and filter.organization=0.
            limit: Rows per page. Defaults to 20, or 10 when extended_fetch is on, because each row
                is then a full object rather than a bare URI.
            offset: Row offset, for paging.
            order: Sort directions, for example {"name": "ASC"}, which becomes order.name=ASC.
            extended_fetch: Inline linked resources instead of returning bare URIs. Much larger
                responses -- use it only when you need the linked fields.
        """
        if limit is not None:
            effective_limit = limit
        elif extended_fetch:
            effective_limit = _DEFAULT_EXTENDED_SEARCH_LIMIT
        else:
            effective_limit = _DEFAULT_SEARCH_LIMIT
        params: dict[str, Any] = {"limit": effective_limit, "offset": offset}
        for key, value in (filters or {}).items():
            params[f"filter.{key}"] = value
        for key, value in (order or {}).items():
            params[f"order.{key}"] = value
        if extended_fetch:
            params["extended_fetch"] = 1

        query = _stringify_query(params)
        _check_credential_access(d.REST_SEARCH, d.REST_SEARCH.method, resource, query)
        audit_passthrough(
            d.REST_SEARCH, method=d.REST_SEARCH.method, path=resource, outcome="invoked"
        )
        found = await context.client.request(
            credential=context.credential_source(),
            method=d.REST_SEARCH.method,
            path=resource,
            query=query,
        )
        return shape_rest_response(resource, found)

    return sl1_rest_search


# ---- The two Dynamic Application readers ---------------------------------------------------------


async def _lookup(
    context: Sl1ToolContext, descriptor: d.Sl1OperationDescriptor, params: dict[str, Any]
) -> dict[str, Any]:
    """Fetch one page from ``dynamic_app/_lookup`` and return the URI-keyed mapping.

    A non-dict body becomes an empty mapping rather than an error. The resource answers with a 302
    and its shape is not ours to guarantee; a caller asking "which Dynamic Applications match" is
    better served by "none" than by a parse complaint about a redirect.
    """
    body = await context.client.request(
        credential=context.credential_source(),
        method=descriptor.method,
        path=descriptor.path_base,
        query=_stringify_query(params),
    )
    return body if isinstance(body, dict) else {}


async def _search(
    context: Sl1ToolContext,
    descriptor: d.Sl1OperationDescriptor,
    name_contains: str | None,
    limit: int,
) -> tuple[dict[str, Any], bool]:
    """Search Dynamic Applications by name.

    A single word, or no filter, is handled server-side. A multi-word phrase is pre-filtered
    server-side on its longest word and then matched client-side, because this resource's phrase
    and exact filters do not work. Multi-word matching is an order-independent AND of words, not a
    contiguous phrase.

    ``truncated`` is True whenever the fetched pool hit the row cap, so the caller can say a match
    may lie beyond it. A truncated result set is otherwise indistinguishable from a complete one,
    and an incomplete answer would read as a confident "no match".

    :param descriptor: The descriptor supplying the method and path.
    :param name_contains: The name filter, or ``None`` for no filter.
    :param limit: The maximum number of matches to return.
    :return: ``(matches, truncated)``.
    """
    words = (name_contains or "").split()

    if len(words) <= 1:
        params: dict[str, Any] = {"limit": limit, "hide_filterinfo": 1, "extended_fetch": 1}
        if name_contains:
            params["filter.name.contains"] = name_contains
        pool = await _lookup(context, descriptor, params)
        return dict(list(pool.items())[:limit]), len(pool) >= limit

    pre_filter = max(words, key=len)
    pool = await _lookup(
        context,
        descriptor,
        {
            "limit": _SCAN_LIMIT,
            "hide_filterinfo": 1,
            "extended_fetch": 1,
            "filter.name.contains": pre_filter,
        },
    )
    truncated = len(pool) >= _SCAN_LIMIT
    needles = [word.lower() for word in words]
    matches = {
        uri: value
        for uri, value in pool.items()
        if isinstance(value, dict)
        and all(needle in str(value.get("name", "")).lower() for needle in needles)
    }
    return dict(list(matches.items())[:limit]), truncated


def make_sl1_list_dynamic_apps(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_list_dynamic_apps`` tool bound to ``context``."""

    @sl1_tool_boundary(d.LIST_DYNAMIC_APPS)
    async def sl1_list_dynamic_apps(
        name_contains: str | None = None,
        limit: int = 50,
    ) -> dict[str, Any] | list[Any]:
        """List Dynamic Applications via the REST _lookup resource.

        Read-only, and works without LCE -- unlike lce_list_dynamic_applications. Returns a mapping
        keyed by full URI, which embeds the app type and guid; each value carries name, app_type and
        state. This does NOT return the full authoring-shape JSON with collection, presentation,
        threshold and alert objects -- use lce_get_dynamic_application for that, or sl1_rest_request
        on a result's collection_objects or presentation_objects URI.

        Args:
            name_contains: Optional name filter. A single word is matched server-side. A multi-word
                value matches names containing ALL of those words in any order, pre-filtered
                server-side on the longest word and then matched here, because server-side phrase
                filtering does not work on this resource.
            limit: Maximum matches to return.

        When the result is capped, the response says so: a rarer or more specific word narrows it.
        """
        matches, truncated = await _search(context, d.LIST_DYNAMIC_APPS, name_contains, limit)
        if not truncated:
            return matches
        # The mapping keeps SL1's shape, so the warning is a sibling key rather than a wrapper that
        # would re-key every result.
        return {
            "matches": matches,
            "truncated": True,
            "note": (
                f"Showing {len(matches)}; more may match. "
                "Narrow with a more specific or rarer word."
            ),
        }

    return sl1_list_dynamic_apps


def make_sl1_get_dynamic_app(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_get_dynamic_app`` tool bound to ``context``."""

    @sl1_tool_boundary(d.GET_DYNAMIC_APP)
    async def sl1_get_dynamic_app(name: str) -> dict[str, Any] | list[Any]:
        """Get one Dynamic Application by EXACT name via the REST _lookup resource.

        Read-only, and works without LCE -- unlike lce_get_dynamic_application. Ambiguous and
        missing matches are reported explicitly rather than guessed at.

        Args:
            name: The exact Dynamic Application name. Matching is exact; loose matches are reported
                as candidates rather than returned as the answer.
        """
        matches, truncated = await _search(context, d.GET_DYNAMIC_APP, name, _SCAN_LIMIT)
        exact = {
            uri: value
            for uri, value in matches.items()
            if isinstance(value, dict) and value.get("name") == name
        }
        if exact:
            # Usually one. Keyed by URI, which embeds the app type, so if two Dynamic Applications
            # share a name across app types, return both rather than failing on "exact name".
            return exact
        if not matches:
            raise ValidationBlocked(
                [
                    ValidationFinding(
                        path="name",
                        rule=FindingCode.TOOL_ARGUMENT,
                        message="No Dynamic Application matches that name."
                        + (
                            f" The candidate pool was capped at {_SCAN_LIMIT}; if the name "
                            "shares a common word, the match may lie beyond the cap."
                            if truncated
                            else ""
                        ),
                    )
                ]
            )
        # The loose names are the actionable part: they are what the caller picks from. Capped,
        # because 500 candidates in an error message helps nobody.
        loose = sorted(
            {str(value.get("name", "?")) for value in matches.values() if isinstance(value, dict)}
        )
        shown = loose[:_LOOSE_MATCH_PREVIEW]
        raise ValidationBlocked(
            [
                ValidationFinding(
                    path="name",
                    rule=FindingCode.TOOL_ARGUMENT,
                    message=(
                        f"No exact-name match. {len(loose)} Dynamic Application(s) loosely match; "
                        f"did you mean one of {shown}?"
                    ),
                )
            ]
        )

    return sl1_get_dynamic_app


# One pruning rule for every surface: reuse ``shaping.shape_response`` rather than keeping a private
# copy, so the LCE and SL1 tools cannot drift apart in how they prune responses.
_pruned = shape_response

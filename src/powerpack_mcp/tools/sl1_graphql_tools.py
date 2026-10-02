"""
SL1 GraphQL Passthrough Tools

This module defines ``sl1_graphql``, which runs any caller-supplied query or mutation, and
``sl1_graphql_introspect``, which explores the schema in small pieces. Neither takes
``target_host``, ``username`` or ``password``; every call uses the caller's forwarded credential.

``sl1_graphql`` refuses, before sending, any document that would read credential or other secrets
(an allowlist inside credentials, a secret-name rule everywhere), and scrubs every response;
``sl1_credential_guard`` states the rule. Without that, it would return the
secrets ``sl1_list_credentials`` and ``sl1_get_credential`` exist to withhold.

SL1 applies the caller's permissions to data queries but not to introspection: a restricted
account can read the whole schema. That exposes shape, not data, and it is why the shared
``_type_names_cache`` is safe. The safety rests on that measurement, not on a guarantee.

The four introspection documents are module constants rather than descriptors because
``sl1_graphql_introspect`` is one tool with four modes and ``GraphQlDescriptor`` carries one
document. They serve this tool only.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Final

from powerpack_mcp.errors import ValidationBlocked
from powerpack_mcp.shaping import shape_response
from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools.sl1_credential_guard import (
    refuse_credential_secret_document,
    scrub_credential_secrets,
)
from powerpack_mcp.tools.sl1_pipeline import audit_passthrough, sl1_tool_boundary

if TYPE_CHECKING:
    from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
    from powerpack_mcp.tools.sl1_rest_tools import Sl1ToolFactory

__all__ = ["make_sl1_graphql", "make_sl1_graphql_introspect"]

# ---- The four introspection documents ----------------------------------------------------------

# Root query and mutation fields with descriptions. The ``list_all`` path.
_ROOT_INTROSPECT: Final = """
query Roots {
  __schema {
    queryType {
      name
      fields(includeDeprecated: true) { name description isDeprecated deprecationReason }
    }
    mutationType {
      name
      fields(includeDeprecated: true) { name description isDeprecated deprecationReason }
    }
  }
}
"""

# Root field names only: the default summary path. A separate document from ``_ROOT_INTROSPECT``
# because the summary renders names and counts, and fetching a description for each of ~400 root
# fields only to discard it would waste the caller's context.
_ROOT_NAMES: Final = """
query RootNames {
  __schema {
    queryType { name fields(includeDeprecated: true) { name isDeprecated deprecationReason } }
    mutationType { name fields(includeDeprecated: true) { name isDeprecated deprecationReason } }
  }
}
"""

# One type in full: fields, argument types, input fields, enum values. The ``type_name`` path.
_TYPE_INTROSPECT: Final = """
query TypeInfo($name: String!) {
  __type(name: $name) {
    name kind description
    fields(includeDeprecated: true) {
      name description isDeprecated deprecationReason
      args { name type { name kind ofType { name kind } } }
      type { name kind ofType { name kind ofType { name kind } } }
    }
    inputFields { name type { name kind ofType { name kind } } }
    enumValues { name }
  }
}
"""

# Every type name and kind. Backs the ``search`` path, and the only document that is cached.
_NAMES_INTROSPECT: Final = "query Names { __schema { types { name kind } } }"

# How many root fields the default summary previews, per side.
_ROOT_PREVIEW_COUNT: Final = 20

# The three stability verdicts. SL1 marks its experimental features with ``@deprecated``, and
# GraphQL's ``includeDeprecated`` defaults to ``false``, so a document that omits it hides most of
# the schema: 202 of 359 root query fields and 197 of 458 mutations on SL1 12.5.20, including all
# six ``guidedDiscovery*`` roots.
#
# The two deprecation reasons must not be collapsed. Most say "Experimental. This feature is still
# under active development" (a feature arriving) and the rest say "Deprecated. This feature is
# known to be problematic" (a feature leaving).
_STABLE: Final = "stable"
_EXPERIMENTAL: Final = "experimental"
_PROBLEMATIC: Final = "problematic"

# Dropped in favour of ``stability``. SL1's ``deprecationReason`` is ~200 characters of identical
# boilerplate, so echoing it would spend ~80 KB of caller context on ``list_all`` to say one word
# 400 times.
_DEPRECATION_KEYS: Final = frozenset({"isDeprecated", "deprecationReason"})

# Process-lifetime cache of the schema's type-name list, for the ``search`` path.
#
# A single value rather than a dict keyed by base URL: no tool takes ``target_host`` and SL1 is
# appliance-local, so there is exactly one host for the life of the process. With no key, no
# credential or derivative of one can appear in it.
#
# The cache is shared across callers, which is safe only because introspection is not
# permission-gated: a restricted account reads the same schema, so every authenticated caller is
# entitled to identical content. If SL1 ever gates introspection per account, this cache becomes a
# cross-caller leak and must be removed or keyed per principal.
_type_names_cache: list[dict[str, str]] | None = None


# Reuse the one pruning rule, ``shaping.shape_response``; see the note in ``sl1_rest_tools``.
_pruned = shape_response


def make_sl1_graphql(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_graphql`` passthrough bound to ``context``.

    :param context: The clients, configuration and credential source the tool uses.
    :return: The tool function to register with the MCP server.
    """

    @sl1_tool_boundary(d.GRAPHQL_QUERY)
    async def sl1_graphql(
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        prune: bool = True,
        # ASYNC109: transport timeout, forwarded to httpx.
        timeout: float | None = None,  # noqa: ASYNC109
    ) -> dict[str, Any] | list[Any]:
        """Execute any query or mutation against the SL1 GraphQL API. Covers the ENTIRE GQL surface.

        Use sl1_graphql_introspect first to find the type or root field you need.

        IMPORTANT for event policies: use lce_create_or_update_event_policies instead of GraphQL's
        createEventPolicy or updateEventPolicy. Those mutations mint non-hex GUIDs that break a
        later LCE read once the policy is aligned to a Dynamic Application.

        If SL1 refuses the request because the calling account lacks permission, the error says so
        explicitly and retrying will not help -- the credential needs broader rights in SL1. That is
        reported separately from a malformed query, which you CAN correct and retry.

        Args:
            query: The GraphQL document to execute.
            variables: Variable values for the document.
            operation_name: Which operation to run, when the document defines more than one.
            prune: Drop empty fields from the response to save tokens. Set false for the literal
                shape, where an empty value and an absent one are distinguishable.
            timeout: Per-call timeout in seconds. Bounded by the service's ceiling; a larger
                value is clamped, never honoured.

        This tool can run mutations as well as queries. It refuses documents that would read
        secrets: inside a credential only non-secret metadata (id, name, host, snmpVersion, ...)
        may be selected, secret-named fields (password, token, hash, ...) are refused on any type,
        and so are searches and sorts on them. Secrets are withheld from every response; use
        sl1_get_credential or sl1_list_credentials for credentials.
        """
        # Audited as a passthrough. The document is deliberately not logged: it is caller-supplied
        # and may embed credential material in variables, and payload bodies stay out of logs. For
        # GraphQL the audited path is always ``/gql``.
        try:
            # Before anything is sent: a refused document must not reach SL1 at all, not merely
            # have its answer discarded.
            refuse_credential_secret_document(query, variables)
        except ValidationBlocked:
            audit_passthrough(
                d.GRAPHQL_QUERY, method="POST", path="/gql", outcome="rejected_credential_secret"
            )
            raise
        audit_passthrough(d.GRAPHQL_QUERY, method="POST", path="/gql", outcome="invoked")
        body = await context.client.graphql(
            credential=context.credential_source(),
            query=query,
            variables=variables,
            operation_name=operation_name,
            timeout=timeout,
        )
        # The scrub runs before pruning and whether or not pruning is asked for: ``prune=False``
        # changes which empty values survive, never which secrets do.
        scrubbed = scrub_credential_secrets(body)
        return _pruned(scrubbed) if prune else scrubbed

    return sl1_graphql


def make_sl1_graphql_introspect(context: Sl1ToolContext) -> Sl1ToolFactory:
    """Build the ``sl1_graphql_introspect`` tool bound to ``context``."""

    @sl1_tool_boundary(d.GRAPHQL_INTROSPECT)
    async def sl1_graphql_introspect(
        type_name: str | None = None,
        search: str | None = None,
        list_all: bool = False,
    ) -> dict[str, Any] | list[Any]:
        """Explore the SL1 GraphQL schema without dumping the whole, very large, schema.

        The usual flow is: call with no arguments to orient, then search for a keyword, then
        describe the type you found, then build a query and run it with sl1_graphql.

        Args:
            type_name: Describe one type -- its fields, their argument and return types, its input
                fields and its enum values.
            search: List schema type names containing this substring. The type list is fetched once
                per process, so repeat searches do not re-fetch it.
            list_all: Return every root query and mutation field name with its description and
                stability, uncapped. The root surface is large -- 350+ queries and 450+ mutations
                -- so this is rarely needed just to orient.

        With no arguments, returns total counts of root query and mutation fields plus an
        alphabetical preview of each.
        """
        audit_passthrough(d.GRAPHQL_INTROSPECT, method="POST", path="/gql", outcome="invoked")

        # The most specific request wins, as in the reference implementation: passing both
        # ``type_name`` and ``search`` describes the type.
        if type_name:
            described = await _introspect(context, _TYPE_INTROSPECT, {"name": type_name})
            return {**described, "__type": _with_stability(described.get("__type"))}

        if search:
            needle = search.lower()
            matches = sorted(
                name
                for entry in await _type_names(context)
                if isinstance(name := entry.get("name"), str) and needle in name.lower()
            )
            return {"count": len(matches), "matches": matches}

        if list_all:
            return await _all_root_fields(context)

        return await _root_summary(context)

    return sl1_graphql_introspect


async def _introspect(
    context: Sl1ToolContext, document: str, variables: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Run one introspection call and return its ``data`` object."""
    body = await context.client.graphql(
        credential=context.credential_source(), query=document, variables=variables
    )
    data = body.get("data")
    return data if isinstance(data, dict) else {}


async def _type_names(context: Sl1ToolContext) -> list[dict[str, str]]:
    """Return the schema's type list, fetched once per process; see ``_type_names_cache``."""
    global _type_names_cache  # a process-lifetime memo; see the comment on the cache
    if _type_names_cache is None:
        schema = (await _introspect(context, _NAMES_INTROSPECT)).get("__schema", {})
        listed = schema.get("types") if isinstance(schema, dict) else None
        _type_names_cache = (
            [t for t in listed if isinstance(t, dict)] if isinstance(listed, list) else []
        )
    return _type_names_cache


async def _all_root_fields(context: Sl1ToolContext) -> dict[str, Any]:
    """Return every root query and mutation field, relabelled with its stability.

    The ``list_all`` path of ``sl1_graphql_introspect``.
    """
    listed = await _introspect(context, _ROOT_INTROSPECT)
    schema = listed.get("__schema")
    if not isinstance(schema, dict):
        return listed
    return {"__schema": {k: _with_stability(v) for k, v in schema.items()}}


async def _root_summary(context: Sl1ToolContext) -> dict[str, Any]:
    """Return root field counts, stability counts and an alphabetical preview of each side.

    The no-argument orientation path of ``sl1_graphql_introspect``.
    """
    schema = (await _introspect(context, _ROOT_NAMES)).get("__schema") or {}
    query_fields = _root_fields(schema, "queryType")
    mutation_fields = _root_fields(schema, "mutationType")
    queries = [str(field["name"]) for field in query_fields]
    mutations = [str(field["name"]) for field in mutation_fields]
    return {
        "query_count": len(queries),
        "mutation_count": len(mutations),
        "query_stability": _stability_counts(query_fields),
        "mutation_stability": _stability_counts(mutation_fields),
        "query_preview": queries[:_ROOT_PREVIEW_COUNT],
        "mutation_preview": mutations[:_ROOT_PREVIEW_COUNT],
        "note": (
            f"Showing {_ROOT_PREVIEW_COUNT} of each, alphabetically. Use search to find a "
            "specific type, or list_all for every root field name. Counts include "
            "experimental and problematic fields: SL1 marks experimental features deprecated, "
            "so a field being experimental does not mean it is absent or unusable."
        ),
    }


def _root_fields(schema: object, root: str) -> list[dict[str, Any]]:
    """Return the field entries under ``schema[root]``, sorted by name.

    Three nulls are possible and all occur in practice: the root type itself (``mutationType`` is
    null on a query-only schema), a present-but-null ``fields``, and an entry without a ``name``.
    Introspection describes a schema we do not control, and an exception here would fail the
    orientation call a client makes before anything else.

    Entries are returned rather than bare names because the summary needs each field's deprecation
    keys to count stability, and re-reading the schema would double the call.
    """
    if not isinstance(schema, dict):
        return []
    root_type = schema.get(root)
    if not isinstance(root_type, dict):
        return []
    fields = root_type.get("fields")
    if not isinstance(fields, list):
        return []
    return sorted(
        (
            field
            for field in fields
            if isinstance(field, dict) and isinstance(field.get("name"), str)
        ),
        key=lambda field: str(field["name"]),
    )


def _root_field_names(schema: object, root: str) -> list[str]:
    """Return just the sorted names from ``_root_fields``.

    Kept as its own function because callers and tests rely on its null-tolerance contract.
    """
    return [str(field["name"]) for field in _root_fields(schema, root)]


def _stability(field: dict[str, Any]) -> str:
    """Return which of the three stability verdicts one introspected field carries.

    Matches the word "experimental" case-insensitively anywhere in the reason, not as a prefix:
    some fields say "This is experimental; only works with SL1 8.10", which a ``startswith`` test
    would mislabel as problematic. A reason that says both counts as experimental; that precedence
    is arbitrary.
    """
    if not field.get("isDeprecated"):
        return _STABLE
    reason = field.get("deprecationReason")
    if isinstance(reason, str) and _EXPERIMENTAL in reason.lower():
        return _EXPERIMENTAL
    return _PROBLEMATIC


def _labelled(field: object) -> dict[str, Any] | None:
    """Return one field with ``stability`` replacing SL1's two deprecation keys, or None."""
    if not isinstance(field, dict):
        return None
    kept = {key: value for key, value in field.items() if key not in _DEPRECATION_KEYS}
    return {**kept, "stability": _stability(field)}


def _with_stability(container: object) -> object:
    """Return ``container`` with every ``fields`` entry relabelled, shape otherwise preserved.

    Non-dict input and a missing or null ``fields`` pass through untouched, for the same reason
    ``_root_field_names`` is defensive: orientation is the one call that must not raise.
    """
    if not isinstance(container, dict):
        return container
    fields = container.get("fields")
    if not isinstance(fields, list):
        return container
    return {
        **container,
        "fields": [tagged for field in fields if (tagged := _labelled(field)) is not None],
    }


def _stability_counts(fields: list[dict[str, Any]]) -> dict[str, int]:
    """Count how many of ``fields`` fall in each verdict.

    Zeroes are kept: an absent key reads as "not measured", which is not the same as "none exist".
    """
    counts = {_STABLE: 0, _EXPERIMENTAL: 0, _PROBLEMATIC: 0}
    for field in fields:
        counts[_stability(field)] += 1
    return counts

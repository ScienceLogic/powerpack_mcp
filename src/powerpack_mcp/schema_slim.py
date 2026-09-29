"""
Tool Schema Trimming

This module provides the trimming applied to every registered tool's input schema at startup. An
MCP client is sent every tool's name, description and ``inputSchema`` on every turn, so redundancy
compounds across the tool surface. Two rewrites are applied:

- Advisory ``title`` keys are removed. They restate a name the schema already has.
- A nullable union such as ``{"anyOf": [{"type": "string"}, {"type": "null"}]}`` is collapsed to
  the equivalent ``{"type": ["string", "null"]}``.

A trimmed schema accepts exactly the inputs the untrimmed one does. ``trim`` is pure, returning a
new schema, so that property can be tested against the original. ``title`` is only metadata in a
schema-node position: under ``properties`` and the other ``NAMED_SUBSCHEMA_KEYS`` it is the name of
a parameter, so trimming walks positions rather than matching keys.

Trimming fails closed. fastmcp exposes no synchronous public accessor for registered tools, so
``registered_tools`` reads private attributes; if an upgrade changes them, startup raises
``SchemaTrimError`` instead of silently shipping untrimmed schemas.
``tests/unit/test_schema_size.py`` is the second line of defence.

Current pydantic and fastmcp versions emit no advisory ``title`` keys, so most of the saving comes
from the union collapse; title stripping is kept because it costs nothing and a future version may
emit titles again. ``additionalProperties`` and per-parameter ``description`` values are semantics
and tool contract, and are never removed.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, Final

from powerpack_mcp.errors import SchemaTrimError

# Keys whose value is a ``{name: subschema}`` map rather than a schema node. Their keys are
# parameter or definition names, which may legitimately be ``"title"``, so trimming recurses into
# the values only and never removes from the map itself.
NAMED_SUBSCHEMA_KEYS: Final[frozenset[str]] = frozenset(
    {"properties", "$defs", "definitions", "patternProperties"}
)

# The advisory metadata key trimming removes. JSON Schema defines ``title`` as a human label and
# never as semantics, which is why removing it cannot change the accepted input set.
_METADATA_KEY: Final = "title"

# The prefix fastmcp 3.x puts on a tool's key in ``LocalProvider._components``; see
# :func:`registered_tools` for why a prefix filter is needed. ``FastMCPComponent.key`` is
# ``f"{KEY_PREFIX}:{identifier}@{version or ''}"`` and the four prefixes are ``tool``, ``prompt``,
# ``resource`` and ``template``, so ``"tool:"`` selects every tool and nothing else.
_TOOL_KEY_PREFIX: Final = "tool:"


def trim(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Return a new, trimmed copy of ``schema``. ``schema`` is not modified.

    One traversal builds the result as it goes: no ``deepcopy`` followed by a mutation pass, and no
    repeated passes to a fixed point.

    :raises SchemaTrimError: If ``schema`` is not a mapping. Trimming fails closed rather than
        passing anything through untrimmed.
    """
    if not isinstance(schema, Mapping):
        raise SchemaTrimError(
            f"a tool schema must be a mapping, got {type(schema).__name__}. Returning it untrimmed "
            "would silently undo the schema size budget, so this fails instead"
        )
    result = _trim_node(schema)
    # ``_trim_node`` returns a dict for a Mapping input. Narrowing rather than casting means a
    # future change to ``_trim_node`` cannot silently invalidate this signature.
    if not isinstance(result, dict):  # pragma: no cover -- unreachable while the input is a Mapping
        raise SchemaTrimError("trimming a mapping did not produce a mapping")
    return result


def _trim_node(node: Any) -> Any:
    """Transform one node, returning a new value. Position-aware; see ``NAMED_SUBSCHEMA_KEYS``."""
    if isinstance(node, Mapping):
        trimmed: dict[str, Any] = {}
        for key, value in node.items():
            if key == _METADATA_KEY:
                # Metadata position: this dict is a schema node, so ``title`` here is the advisory
                # label. Drop it.
                continue
            if key in NAMED_SUBSCHEMA_KEYS and isinstance(value, Mapping):
                # Named-subschema position: ``value``'s keys are parameter names, not metadata.
                # Never drop from this map, so a parameter genuinely called ``title`` survives.
                trimmed[key] = {name: _trim_node(sub) for name, sub in value.items()}
            else:
                trimmed[key] = _trim_node(value)
        return _collapse_nullable_union(trimmed)
    # ``str`` and ``bytes`` are Sequences, so they must be excluded explicitly or every string would
    # be rebuilt character by character.
    if isinstance(node, Sequence) and not isinstance(node, (str, bytes)):
        return [_trim_node(item) for item in node]
    return node


def _collapse_nullable_union(node: dict[str, Any]) -> dict[str, Any]:
    """Rewrite ``{"anyOf": [{"type": A}, {"type": B}]}`` to ``{"type": [A, B]}``.

    Only when every branch is a bare ``{"type": X}`` with no other keys, so a genuinely structured
    union (a branch carrying ``additionalProperties``, or a bare ``{}`` "any" branch) is left as it
    is. Sibling keys such as ``default`` are preserved.

    A node carrying both ``type`` and ``anyOf`` is legal and means both constraints apply.
    Collapsing it would overwrite ``type`` and change the accepted input set, so such a node is left
    alone.
    """
    branches = node.get("anyOf")
    if (
        isinstance(branches, list)
        and len(branches) >= 2
        and all(isinstance(b, Mapping) and set(b) == {"type"} for b in branches)
        and "type" not in node
    ):
        collapsed = {key: value for key, value in node.items() if key != "anyOf"}
        collapsed["type"] = [b["type"] for b in branches]
        return collapsed
    return node


def registered_tools(server: Any) -> list[Any]:
    """Return every registered tool object on ``server``.

    This is the one place the fastmcp coupling lives. fastmcp's public ``server.list_tools()`` is a
    coroutine, and this runs from the synchronous ``build_mcp_server``. ``asyncio.run`` is not an
    option, because ``create_app`` is called from inside async tests and ``asyncio.run`` raises when
    a loop is already running. So this reads the private ``server._local_provider._components``, a
    single ``dict`` holding tools, prompts, resources and templates, and selects the tools by key
    prefix. Concentrating that here means an upgrade changes one function. Private accessors have
    already changed across fastmcp releases, which is why this raises rather than returning an
    empty list.

    The prefix filter could itself select nothing and report success if the key scheme changed, so
    a non-empty ``_components`` holding no ``tool:`` key raises. A server registering only prompts
    or resources would therefore raise, but this is only reached from ``build_mcp_server``, which
    always registers tools.

    :raises SchemaTrimError: If the components cannot be reached or no tool can be selected.
    """
    provider = getattr(server, "_local_provider", None)
    components = getattr(provider, "_components", None)
    if not isinstance(components, Mapping):
        raise SchemaTrimError(
            "cannot reach fastmcp's registered components via `_local_provider._components`. These "
            "are private attributes, so an upgrade can change them -- as it already has, "
            "which is why this raises rather than reporting success having "
            "trimmed nothing. Silently shipping untrimmed schemas is what "
            "trimming exists to prevent"
        )
    tools = [
        component
        for key, component in components.items()
        if isinstance(key, str) and key.startswith(_TOOL_KEY_PREFIX)
    ]
    if components and not tools:
        raise SchemaTrimError(
            f"fastmcp's `_local_provider._components` holds {len(components)} component(s) but "
            f"none keyed {_TOOL_KEY_PREFIX!r}. The key scheme has changed, so selecting tools by "
            "prefix now selects nothing -- returning an empty list here would trim nothing and "
            "report success having trimmed nothing"
        )
    return tools


def trim_registered_tools(server: Any) -> int:
    """Trim every registered tool's parameter schema on ``server``.

    Called from ``mcp_app`` at startup. Only registered tools are trimmed; a disabled set's tools
    are never constructed.

    :return: The number of tools trimmed.
    :raises SchemaTrimError: If the tools cannot be read, or a tool has no mapping ``parameters``.
        See :func:`registered_tools`.
    """
    count = 0
    for tool in registered_tools(server):
        parameters = getattr(tool, "parameters", None)
        if not isinstance(parameters, Mapping):
            raise SchemaTrimError(
                f"registered tool {getattr(tool, 'name', '<unnamed>')!r} has no mapping "
                "`parameters` to trim"
            )
        # ``trim`` is pure, so the new schema is assigned back here. This is the one impure line in
        # the module, and it exists because fastmcp owns the tool objects.
        tool.parameters = trim(parameters)
        count += 1
    return count


def payload_bytes(server: Any) -> int:
    """Return the serialized size, in bytes, of every registered tool's schema.

    Defined beside the trimming so the measurement has one definition. ``separators`` and
    ``sort_keys`` are fixed so the number depends only on the schemas, not on dict ordering or
    whitespace, which is what makes a committed baseline meaningful.
    """
    return sum(
        len(json.dumps(getattr(tool, "parameters", None), separators=(",", ":"), sort_keys=True))
        for tool in registered_tools(server)
    )

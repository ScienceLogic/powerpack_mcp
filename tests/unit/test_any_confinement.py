"""
Any Confinement Tests

This module tests that explicit ``Any`` stays confined to declared boundary modules. With
``ANN401`` ignored, ``mypy --strict`` forbids implicit ``Any`` but permits explicit ``Any``
anywhere, so confinement is asserted here as a property of location: a new module that acquires
``Any`` fails until it is declared with the boundary it sits on. A count-based check is avoided on
purpose, because a count cannot tell a legitimate boundary ``Any`` from a leak and a numeric
baseline tends to get bumped reflexively.

These tests do not claim that ``Any`` inside a declared boundary module is minimal or stays at the
JSON edge. That remains review work; this is a containment fence.
"""

from __future__ import annotations

import io
import tokenize
from pathlib import Path

import pytest

from powerpack_mcp import db_client

SRC = Path(db_client.__file__).parent

# Modules permitted to hold boundary ``Any``, each with the boundary it sits on. Listed per module
# rather than per symbol, because per-symbol entries went stale as functions were removed.
BOUNDARY_MODULES: dict[str, str] = {
    # ---- LCE JSON boundary ----
    "errors.py": "LCE/SL1 error bodies pass through untyped",
    "lce_client/client.py": "LCE response bodies and json_body",
    "validation.py": "validate_payload's inbound payload",
    "shaping.py": "shape_response in and out",
    "tools/lce_tools.py": "the seven LCE tool signatures",
    "tools/pipeline.py": "the LCE tool pipeline",
    # ---- SL1 REST boundary ----
    "sl1_client/client.py": "SL1 REST response bodies",
    "sl1_client/bounded_read.py": "SL1 REST body reading",
    "tools/sl1_rest_tools.py": "SL1 REST tool payloads",
    "tools/sl1_entity_tools.py": "SL1 entity tool payloads",
    "tools/sl1_pipeline.py": "the SL1 tool pipeline",
    "tools/sl1_credential_definition.py": "SL1 credential-definition payloads",
    # ---- GraphQL boundary ----
    "tools/sl1_graphql_tools.py": "GraphQL response documents",
    # ---- MCP schema boundary ----
    "schema_slim.py": "fastmcp's own tool objects and JSON schemas",
    "tools/standards_tools.py": "standards tool payload",
    # ---- DB tools: REST/GraphQL payloads only ----
    "tools/sl1_db_tools.py": "REST/GraphQL payloads in the SQL tools; DB rows use `Row`, not `Any`",
    "tools/sl1_event_tools.py": "REST/GraphQL payloads -- these tools never touch the database",
    "tools/sl1_ops_tools.py": "REST/GraphQL/LCE probe payloads -- no database",
    # ---- Guided Discovery ----
    # The strongest ``Any`` case on the surface. This module resolves a workflow's
    # ``discoveryActions``, platform-authored JSON whose shape is not declared anywhere: one
    # workflow on one appliance produced two different session ``definition`` shapes. A typed model
    # would be a guess about someone else's format, so the resolver returns plain values and typing
    # stops at this boundary.
    "tools/sl1_guided_discovery.py": "workflow discoveryActions and session definitions -- "
    "platform-authored JSON with no declared schema",
}

# Modules that must contain no ``Any``. This is the half that carries the claim: an allowlist only
# says where ``Any`` may be, so these are named individually to make ``Any`` in one of them a named
# regression. ``pyproject.toml`` refuses a blanket ``ignore_missing_imports`` for the same reason:
# it would make every DB symbol ``Any``.
MUST_BE_ANY_FREE: frozenset[str] = frozenset(
    {
        # Core components
        "query.py",
        "config.py",
        "mcp_app/app.py",
        "mcp_app/concurrency.py",
        "mcp_app/correlation.py",
        "mcp_app/logging_setup.py",
        "mcp_app/routes.py",
        "tool_sets.py",
        # The DB core
        "authz.py",
        "db_client.py",
        "sql.py",
        "tools/sl1_db_statements.py",
        "tools/sl1_db_descriptors.py",
        "tools/sl1_db_registry.py",
        "tools/sl1_db_pipeline.py",
    }
)


def any_occurrences(path: Path) -> int:
    """Count ``Any`` as a NAME token, excluding the import that introduces it.

    Token-based rather than textual, because ``Any`` appears in prose in most of these modules and a
    substring search would count the discussion of the rule as a violation of it.
    """
    source = path.read_text()
    lines = source.splitlines()
    count = 0
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type != tokenize.NAME or tok.string != "Any":
            continue
        if lines[tok.start[0] - 1].lstrip().startswith(("from typing", "import typing")):
            continue
        count += 1
    return count


def shipped_modules() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)


def rel(path: Path) -> str:
    return str(path.relative_to(SRC))


class TestConfinement:
    def test_no_module_outside_the_declared_boundaries_holds_any(self) -> None:
        """A new module acquiring ``Any`` must be declared with its boundary and a reason."""
        offenders = {
            rel(p): any_occurrences(p)
            for p in shipped_modules()
            if any_occurrences(p) and rel(p) not in BOUNDARY_MODULES
        }
        assert not offenders, (
            f"`Any` outside the declared boundary modules: {offenders}. "
            "Either narrow the annotation, or declare the module in BOUNDARY_MODULES with the "
            "boundary it sits on. Adding it silently is what this test exists to prevent."
        )

    @pytest.mark.parametrize("module", sorted(MUST_BE_ANY_FREE))
    def test_the_named_clean_modules_are_still_clean(self, module: str) -> None:
        """``Any`` in the DB pipeline once hid an unguarded ``int()`` coercion on a DB column."""
        path = SRC / module
        assert path.exists(), f"{module} no longer exists; update MUST_BE_ANY_FREE deliberately"
        found = any_occurrences(path)
        assert found == 0, (
            f"{module} now has {found} `Any` and is declared `Any`-free. If this is a real "
            "boundary, move it to BOUNDARY_MODULES with a stated reason -- do not quietly "
            "delete it from the clean list."
        )

    def test_every_declared_boundary_module_exists_and_actually_uses_any(self) -> None:
        """A stale exemption makes the list look maintained while describing code that is gone."""
        missing = [m for m in BOUNDARY_MODULES if not (SRC / m).exists()]
        assert not missing, f"BOUNDARY_MODULES names modules that do not exist: {missing}"
        unnecessary = [m for m in BOUNDARY_MODULES if any_occurrences(SRC / m) == 0]
        assert not unnecessary, (
            f"these modules are declared as `Any` boundaries but hold none: {unnecessary}. "
            "Move them to MUST_BE_ANY_FREE -- a stale exemption is how entries 4 and 6 rotted."
        )

    def test_the_two_lists_are_disjoint(self) -> None:
        overlap = set(BOUNDARY_MODULES) & MUST_BE_ANY_FREE
        assert not overlap, f"a module cannot be both a boundary and `Any`-free: {overlap}"

    def test_the_sweep_is_not_vacuous(self) -> None:
        """The guard on the guard. A sweep finding no modules would pass everything above."""
        modules = shipped_modules()
        assert len(modules) > 25, f"only {len(modules)} modules swept; the glob is wrong"
        assert sum(any_occurrences(p) for p in modules) > 0, "found no `Any` at all -- impossible"

    def test_report_the_confinement_figures(self) -> None:
        """Print the figures without gating them, as ``test_schema_size.py`` does for total bytes.

        The number must be visible so drift can be argued about, but gating it would couple this
        test to every legitimate boundary addition.
        """
        per_module = {rel(p): any_occurrences(p) for p in shipped_modules() if any_occurrences(p)}
        total = sum(per_module.values())
        lines = [
            "",
            f"`Any` confinement: {total} `Any` across {len(per_module)} modules",
            f"  declared boundaries : {len(BOUNDARY_MODULES)}",
            f"  asserted `Any`-free : {len(MUST_BE_ANY_FREE)}",
        ]
        lines += [f"    {n:3d}  {m}" for m, n in sorted(per_module.items(), key=lambda kv: -kv[1])]
        print("\n".join(lines))  # noqa: T201
        assert total > 0

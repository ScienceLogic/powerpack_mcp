"""
Tool Schema Size Tests

This module tests the size of the ``tools/list`` payload against a committed baseline of bytes per
registered tool, measured per tool set. It measures bytes, not time, so it does not use
``pytest-benchmark``.

- Gated: bytes per tool for each tool set, within a two-sided +/-10% band. Two-sided because a
  broken trim that drops something it should keep makes the payload smaller.
- Recorded, not gated: the total payload bytes.

No absolute ceiling is set, because there is no data on MCP client context budgets.
"""

from __future__ import annotations

from importlib.metadata import version

import pytest
from fastmcp import FastMCP

from powerpack_mcp.config import TOOL_SET_FLAG_KEYS, Config
from powerpack_mcp.db_client import DbClient
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.mcp_app.app import register_tools
from powerpack_mcp.schema_slim import payload_bytes, registered_tools, trim_registered_tools
from powerpack_mcp.sl1_client import Sl1Client

# ---- The committed baseline, per tool set -------------------------------------------------------
#
# Regenerate from measurement, never adjust to fit:
#
#     uv run pytest tests/unit/test_schema_size.py -s -k report --no-cov
#
# The baseline is per set because the whole-surface figure is a weighted average of the enabled
# sets, and per-tool bytes differ several-fold between sets (``db_read`` against ``lce``). Adding a
# set moves the aggregate even when every schema is unchanged; a per-set figure moves only when that
# set's own schemas change, and a failure names the set.
#
# ``tools`` is each set's own tool count.
BASELINE = {
    "lce": {"tools": 7, "per_tool": 1290.3},
    "standards": {"tools": 1, "per_tool": 435.0},
    "sl1_rest": {"tools": 22, "per_tool": 502.4},
    # The guided-discovery tool is description-heavy on purpose, which lifts this set's average.
    "sl1_graphql": {"tools": 3, "per_tool": 816.3},
    # The writes declare many more arguments than the reads, hence the 2x spread between these two.
    "db_read": {"tools": 3, "per_tool": 380.0},
    "db_write": {"tools": 5, "per_tool": 767.8},
    "ops": {"tools": 14, "per_tool": 314.5},
}

# The flag that gates each set, or ``None`` for the always-on LCE set.
FLAG_FOR_SET = {
    "lce": None,
    "standards": "ENABLE_STANDARDS_TOOLS",
    "sl1_rest": "ENABLE_SL1_REST_TOOLS",
    "sl1_graphql": "ENABLE_SL1_GRAPHQL_TOOLS",
    "db_read": "ENABLE_DB_TOOLS",
    "db_write": "ENABLE_DB_WRITE_TOOLS",
    "ops": "ENABLE_OPS_TOOLS",
}

# Flags that must also be on before a set can register.
#
# Without the ``db_write`` entry its measurement would be silently zero: ``_set_contribution``
# flips one flag over an all-off base, which leaves ``db_write`` disabled by nesting, so the
# difference would be 0 tools and the band would pass while measuring nothing.
PREREQUISITE_FLAGS: dict[str, tuple[str, ...]] = {"db_write": ("ENABLE_DB_TOOLS",)}

# Recorded, not gated. The total is what bears on a client's context budget, so it stays visible,
# but gating it would couple this test to every legitimate tool addition.
#
# fastmcp 3.x adds two things to every generated input schema that trimming must not remove: a
# per-parameter ``"description"`` taken from the ``Args:`` docstring block (the dominant term), and
# ``"additionalProperties": false`` (about 34 B per tool). The descriptions are the tool contract a
# client reads, and ``additionalProperties`` changes the accepted input set, so trimming saves only
# about 3% of the full surface.
FULL_SURFACE = {"tools": 55, "untrimmed": 34590, "trimmed": 33526, "per_tool": 609.6}

TOLERANCE = 0.10

_ALL_OFF = dict.fromkeys(TOOL_SET_FLAG_KEYS, False)


def _db(config: Config) -> DbClient:
    """Return a ``DbClient`` so the DB sets take part in every measurement in this file.

    Without one the DB sets measure zero off-appliance and their bands pass vacuously. The client is
    injected rather than ``platform_available`` being patched, because a schema's size does not
    depend on whether a driver is installed. The prerequisite itself is tested in
    ``test_tool_sets.py`` and ``test_registration_surface.py``.
    """
    return DbClient(config.MAX_CONCURRENT_REQUESTS)


def _built(overrides: dict[str, bool] | None = None) -> FastMCP:
    """A server with the schemas trimmed, exactly as `build_mcp_server` produces at startup."""
    config = Config.model_validate(overrides or {})
    server: FastMCP = FastMCP(name="powerpack-mcp-size-probe")
    register_tools(server, LceClient(config), config, Sl1Client(config), _db(config))
    trim_registered_tools(server)
    return server


def _measure(overrides: dict[str, bool]) -> tuple[int, int, int]:
    """``(tool_count, untrimmed_bytes, trimmed_bytes)`` for one flag configuration."""
    config = Config.model_validate(overrides)
    server: FastMCP = FastMCP(name="powerpack-mcp-size-probe")
    register_tools(server, LceClient(config), config, Sl1Client(config), _db(config))
    untrimmed = payload_bytes(server)
    trim_registered_tools(server)
    return len(registered_tools(server)), untrimmed, payload_bytes(server)


def _set_contribution(set_id: str) -> tuple[int, int]:
    """Return one set's own ``(tool_count, trimmed_bytes)``, isolated by difference.

    Measured as (LCE + this set) minus (LCE alone), because the LCE set is always on and has no
    flag. That is also why ``lce`` is the one entry measured directly rather than as a delta.
    """
    flag = FLAG_FOR_SET[set_id]
    if flag is None:
        base_count, _, base_trimmed = _measure(_ALL_OFF)
        return base_count, base_trimmed
    # A nested set needs its parent on in both measurements, so the difference is still this set's
    # own contribution and not its parent's.
    base_over = {**_ALL_OFF, **dict.fromkeys(PREREQUISITE_FLAGS.get(set_id, ()), True)}
    base_count, _, base_trimmed = _measure(base_over)
    count, _, trimmed = _measure({**base_over, flag: True})
    return count - base_count, trimmed - base_trimmed


@pytest.mark.parametrize("set_id", sorted(BASELINE))
def test_bytes_per_tool_stays_within_the_band(set_id: str) -> None:
    """Gate each tool set's trimmed bytes per tool within a two-sided band.

    This also catches a fastmcp upgrade that makes trimming a no-op: bytes per tool would jump out
    of the band. ``trim_registered_tools`` raising is the first line of defence; this is the second.
    Measuring per set means a failure names the set that drifted.
    """
    count, trimmed = _set_contribution(set_id)
    expected = BASELINE[set_id]
    assert count == expected["tools"], (
        f"{set_id} now carries {count} tools, not {expected['tools']}. Regenerate the baseline "
        "deliberately rather than widening the band -- a band widened to fit is not a guard."
    )
    per_tool = trimmed / count
    low = expected["per_tool"] * (1 - TOLERANCE)
    high = expected["per_tool"] * (1 + TOLERANCE)
    assert low <= per_tool <= high, (
        f"bytes per tool for {set_id} is {per_tool:.1f}, outside the +/-10% band "
        f"[{low:.1f}, {high:.1f}] around the committed {expected['per_tool']}. If this is a "
        "legitimate change, regenerate the baseline; if trimming has regressed, fix the trim."
    )


def test_the_measured_sets_cover_the_whole_surface() -> None:
    """Guard the guard: per-set bands are worthless if a set escapes measurement.

    A new tool set added without a ``BASELINE`` entry would sit outside this file, so the per-set
    counts must add up to the full surface.
    """
    measured = sum(entry["tools"] for entry in BASELINE.values())
    full_count, _, _ = _measure({})
    assert measured == full_count == FULL_SURFACE["tools"], (
        f"per-set counts sum to {measured} but the full surface is {full_count}: a tool set is "
        "registered without a baseline entry, so nothing is guarding its schema size."
    )


def test_trimming_actually_reduces_the_payload() -> None:
    """Assert that trimming reduces the payload, without pinning by how much.

    The magnitude is small (about 3%) and is printed by ``test_report_the_measured_payload``.
    """
    config = Config()
    server: FastMCP = FastMCP(name="powerpack-mcp-size-probe")
    register_tools(server, LceClient(config), config, Sl1Client(config), _db(config))
    untrimmed = payload_bytes(server)
    trim_registered_tools(server)
    assert payload_bytes(server) < untrimmed


def test_total_payload_is_recorded_not_gated() -> None:
    """The total is measured and visible, with no band.

    Gating it would couple this test to every legitimate tool addition. The loose sanity bound
    below only catches an order-of-magnitude surprise.
    """
    total = payload_bytes(_built())
    assert 0 < total < 10 * FULL_SURFACE["trimmed"]


def test_report_the_measured_payload(capsys: pytest.CaptureFixture[str]) -> None:
    """Print the measured payload so regenerating the baseline needs no ad-hoc script.

    Run ``uv run pytest tests/unit/test_schema_size.py -s -k report --no-cov`` to read the current
    numbers.

    Trimming saves about 3% of the full surface. The generated schemas carry no advisory ``title``
    keys, so the saving is almost all the nullable-union collapse; the per-parameter descriptions
    and ``additionalProperties`` that fastmcp 3.x adds make up much of the payload and must not be
    removed. Trimming therefore does not decide whether a client can afford the payload. The
    operator controls the payload size with the ``ENABLE_*`` flags.
    """
    lines = ["", f"tools/list payload measurement (fastmcp {version('fastmcp')}):"]
    for set_id in sorted(BASELINE):
        count, trimmed = _set_contribution(set_id)
        lines.append(
            f"  set {set_id:14s} tools={count:3d} trimmed={trimmed:6d} per_tool={
                trimmed / count:7.1f}"
        )
    for point, overrides in (("lce_only", _ALL_OFF), ("full_surface", {})):
        count, untrimmed, trimmed = _measure(overrides)
        lines.append(
            f"  {point:18s} tools={count:3d} untrimmed={untrimmed:6d} trimmed={trimmed:6d} "
            f"per_tool={trimmed / count:7.1f} saved={100 * (untrimmed - trimmed) / untrimmed:4.1f}%"
        )
    print("\n".join(lines))  # noqa: T201

"""
SQL Statement Builder Tests

This module tests ``powerpack_mcp.sql`` with worked examples; the adversarial properties live
in ``tests/property``.

Read ``TestNoLiteralPercent`` before changing its assertions. They check the rendered statement
text, not the absence of an exception. A literal ``%`` plus any parameter makes MySQLdb's
``sql % args`` treat it as a format specifier, and the platform cursor returns an empty result set
instead of raising. A tool built that way reports "nothing found", a mocked test cannot see it
because the mock never interpolates, and a ``does_not_raise()`` test passes.
"""

from __future__ import annotations

import re

import pytest

from powerpack_mcp.errors import FindingCode, ValidationBlocked
from powerpack_mcp.sql import (
    LIKE_ESCAPE_CHAR,
    PLACEHOLDER,
    Statement,
    checked_identifier,
    escape_like_operand,
    like_contains,
    like_prefix,
    placeholders,
)


class TestStatementAcceptsWellFormed:
    def test_a_statement_with_matching_placeholders_and_params_is_built(self) -> None:
        stmt = Statement("SELECT a FROM t WHERE b = %s AND c = %s", ("x", 1))
        assert stmt.sql == "SELECT a FROM t WHERE b = %s AND c = %s"
        assert stmt.params == ("x", 1)
        assert stmt.placeholder_count == 2

    def test_a_statement_with_no_parameters_needs_no_params_argument(self) -> None:
        assert Statement("SELECT 1").params == ()

    def test_a_statement_is_frozen_so_invariants_cannot_be_invalidated_later(self) -> None:
        stmt = Statement("SELECT 1")
        with pytest.raises(AttributeError):
            stmt.sql = "SELECT 2"  # type: ignore[misc]

    def test_placeholders_at_the_very_end_are_counted(self) -> None:
        # A '%s' with nothing after it still has a word boundary; regressions here would undercount
        # and then trip the mismatch guard for the wrong reason.
        assert Statement("SELECT %s", ("a",)).placeholder_count == 1


class TestNoLiteralPercent:
    """The guard exists because the failure is silent, not loud."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT a FROM t WHERE n LIKE '%Event%'",
            "SELECT a FROM t WHERE n LIKE 'Event%'",
            "SELECT a FROM t WHERE n LIKE '%Event'",
            "SELECT 100 % 7",
            "SELECT a FROM t WHERE n LIKE '%%Event%%'",
        ],
    )
    def test_a_literal_percent_is_refused_at_construction(self, sql: str) -> None:
        with pytest.raises(ValueError, match="literal '%'"):
            Statement(sql)

    def test_the_double_percent_escape_is_refused_too_because_patterns_are_bound(self) -> None:
        # LIKE patterns are bound as parameters rather than escaped. Permitting '%%' would leave two
        # routes, and the escaped one is the one that silently survives review.
        with pytest.raises(ValueError, match="literal '%'"):
            Statement("SELECT a FROM t WHERE n LIKE '%%'")

    def test_a_placeholder_followed_by_a_word_character_is_refused(self) -> None:
        # '%sfoo' is not a placeholder; MySQLdb would fail on an unknown format character.
        with pytest.raises(ValueError, match="literal '%'"):
            Statement("SELECT %sfoo", ("a",))

    def test_the_rendered_statement_carries_no_percent_outside_placeholders(self) -> None:
        # The assertion this class exists for: inspect the text, do not merely survive it.
        stmt = Statement("SELECT a FROM t WHERE n LIKE %s ESCAPE '\\'", (like_contains("Event"),))
        assert re.sub(r"%s\b", "", stmt.sql).count("%") == 0
        # ...and the wildcards are in the parameter, which is where they are inert.
        assert stmt.params == ("%Event%",)


class TestPlaceholderCountMustMatch:
    def test_more_placeholders_than_params_is_refused(self) -> None:
        with pytest.raises(ValueError, match="2 placeholder"):
            Statement("SELECT a FROM t WHERE b = %s AND c = %s", ("only-one",))

    def test_more_params_than_placeholders_is_refused(self) -> None:
        with pytest.raises(ValueError, match="1 placeholder"):
            Statement("SELECT a FROM t WHERE b = %s", ("one", "two"))

    def test_params_with_no_placeholders_is_refused(self) -> None:
        with pytest.raises(ValueError, match="0 placeholder"):
            Statement("SELECT 1", ("stray",))


class TestPlaceholders:
    def test_it_renders_a_comma_separated_list(self) -> None:
        assert placeholders(3) == "%s, %s, %s"

    def test_one_placeholder_has_no_comma(self) -> None:
        assert placeholders(1) == PLACEHOLDER

    @pytest.mark.parametrize("count", [0, -1])
    def test_a_non_positive_count_is_refused_rather_than_producing_in_nothing(
        self, count: int
    ) -> None:
        # 'IN ()' is a MariaDB syntax error reported far from its cause.
        with pytest.raises(ValueError, match="count >= 1"):
            placeholders(count)

    def test_it_composes_into_a_valid_statement(self) -> None:
        stmt = Statement(f"SELECT a FROM t WHERE id IN ({placeholders(3)})", (1, 2, 3))
        assert stmt.placeholder_count == 3


class TestEscapeLikeOperand:
    def test_caller_wildcards_are_neutralised(self) -> None:
        assert escape_like_operand("50%") == "50\\%"
        assert escape_like_operand("a_b") == "a\\_b"

    def test_the_escape_character_is_escaped_first(self) -> None:
        # If '%' were escaped before the backslash, this would double-escape and change semantics.
        assert escape_like_operand(LIKE_ESCAPE_CHAR) == LIKE_ESCAPE_CHAR * 2
        assert escape_like_operand("\\%") == "\\\\\\%"

    def test_an_ordinary_operand_is_unchanged(self) -> None:
        assert escape_like_operand("Event") == "Event"

    def test_like_contains_and_prefix_wrap_the_escaped_operand(self) -> None:
        # A caller's '%' must not widen the rows matched.
        assert like_contains("50%") == "%50\\%%"
        assert like_prefix("50%") == "50\\%%"


class TestCheckedIdentifier:
    ALLOWED = frozenset({"device_name", "device_id"})

    def test_an_allowlisted_identifier_is_returned(self) -> None:
        assert checked_identifier("device_id", self.ALLOWED, argument="sort_by") == "device_id"

    def test_a_value_outside_the_allowlist_raises_validation_blocked(self) -> None:
        with pytest.raises(ValidationBlocked) as exc:
            checked_identifier("1; DROP TABLE x", self.ALLOWED, argument="sort_by")
        (finding,) = exc.value.findings
        assert finding.path == "sort_by"
        assert finding.rule is FindingCode.TOOL_ARGUMENT
        # The caller is told the permitted values, not merely that they were wrong.
        assert "device_id" in finding.message

    def test_a_careless_allowlist_entry_is_our_defect_not_the_callers(self) -> None:
        # Membership is the control; the shape check catches an allowlist built with a backtick or
        # a space in it, which would otherwise be trusted purely for being a constant.
        with pytest.raises(ValueError, match="allowlist is wrong"):
            checked_identifier("a b", frozenset({"a b"}), argument="col")

    def test_a_schema_qualified_identifier_is_permitted(self) -> None:
        allowed = frozenset({"master.device"})
        assert checked_identifier("master.device", allowed, argument="table") == "master.device"

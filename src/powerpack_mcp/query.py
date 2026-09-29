"""
LCE Query Parameters

This module provides the models and serializers for LCE query-string parameters: response field
selectors, write options, and list filters. It also defines the boolean wire form, lowercase
``true`` and ``false``.

The module is pure and uses no ``Any``. ``build_filter_params`` raises ``ValidationBlocked`` for
filter combinations LCE does not support; that exception derives only from its inputs, so the
functions stay property-testable. ``parse_filter_params`` is the declared inverse of
``build_filter_params``, so the round trip can be tested against this module rather than against a
second parser written in a test.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from powerpack_mcp.errors import FindingCode, ValidationBlocked, ValidationFinding

__all__ = [
    "MAX_FIELD_LENGTH",
    "MAX_FILTER_CONDITIONS",
    "MAX_SELECTOR_LENGTH",
    "MAX_VALUE_LENGTH",
    "MIN_FILTER_CONDITIONS",
    "NON_NEGATABLE",
    "SINGLE_VALUE_ONLY",
    "FilterCondition",
    "FilterOperator",
    "FilterParams",
    "SelectorParams",
    "WriteOptions",
    "build_filter_params",
    "build_selector_params",
    "build_write_options",
    "parse_filter_params",
    "serialize_bool",
]

# Explicit maxima, so a caller cannot submit an unbounded parameter.
MAX_FIELD_LENGTH: Final = 128
MAX_VALUE_LENGTH: Final = 1024
MAX_FILTER_CONDITIONS: Final = 32
MIN_FILTER_CONDITIONS: Final = 1
# Length only. The character set is deliberately unrestricted, because ``.``, ``,`` and ``*`` are
# all legitimate: the specification documents nested paths and wildcards such as
# ``dynamic_applications.*.id``.
MAX_SELECTOR_LENGTH: Final = 2048


class FilterOperator(StrEnum):
    """The five operators, verified exhaustive against the specification.

    A `StrEnum` makes this structural: an unsupported operator fails pydantic validation at the
    tool signature, before the builder is reached, and the members are what appear in the JSON
    schema a caller reads.
    """

    IS = "is"
    CONTAINS = "contains"
    GT = "gt"
    LT = "lt"
    SEARCH = "search"


# Operators the specification documents as single-value only.
SINGLE_VALUE_ONLY: Final[frozenset[FilterOperator]] = frozenset(
    {FilterOperator.GT, FilterOperator.LT, FilterOperator.SEARCH}
)

# Operators the specification documents as not negatable.
NON_NEGATABLE: Final[frozenset[FilterOperator]] = frozenset({FilterOperator.SEARCH})

_REQUIRE_ALL_PARAM: Final = "require_all_filters"


def serialize_bool(value: bool) -> str:
    """Render a boolean in the LCE query-string wire form: lowercase ``true`` or ``false``.

    This is the single place the form is decided. Python's ``str(True)`` is ``"True"``, which LCE
    must not receive.

    The wire form is a convention, not something the specification states. It declares
    ``pretty``, ``commit``, ``retrieve`` and ``require_all_filters`` as ``type: boolean`` with
    defaults but never their serialization. Lowercase is the Swagger 2.0 / OpenAPI convention,
    matches the specification's own default notation, and has been confirmed against a live LCE.
    """
    return "true" if value else "false"


class SelectorParams(BaseModel):
    """Response field selectors, accepted by every LCE tool.

    The fields are flattened onto each tool signature rather than nested, because the JSON schema a
    client reads is derived from the signature.
    """

    model_config = ConfigDict(frozen=True)

    # Not JSON pretty-printing. When true, LCE returns enums as strings (for example ``ENABLED``);
    # when false, as integers. Every tool description says so, because an agent that believed this
    # controlled whitespace would set it false to save tokens and silently turn every enum into an
    # integer.
    pretty: bool = True
    fields: str | None = Field(default=None, max_length=MAX_SELECTOR_LENGTH)
    exclude: str | None = Field(default=None, max_length=MAX_SELECTOR_LENGTH)


class WriteOptions(BaseModel):
    """Write options for the two write operations. Defaults match the specification's own."""

    model_config = ConfigDict(frozen=True)

    # ``commit=false`` is LCE's own dry run: nothing is upserted. It is what makes a write safe to
    # try, and why the no-retry rule for writes matters less for a dry run than for a commit.
    commit: bool = True
    retrieve: bool = False


class FilterCondition(BaseModel):
    """One filter condition. Frozen."""

    model_config = ConfigDict(frozen=True)

    field: str = Field(min_length=1, max_length=MAX_FIELD_LENGTH)
    operator: FilterOperator
    # A comma expresses multi-value matching, for example ``filter[id][is]=1,2,3``. That is why the
    # single-value test is "contains a comma" rather than a count.
    value: str = Field(max_length=MAX_VALUE_LENGTH)
    negate: bool = False


class FilterParams(BaseModel):
    """Filter conditions for a list request.

    The minimum of one condition is a model constraint, not a runtime check, so an unfiltered list
    request cannot be constructed at all.
    """

    model_config = ConfigDict(frozen=True)

    conditions: list[FilterCondition] = Field(
        min_length=MIN_FILTER_CONDITIONS, max_length=MAX_FILTER_CONDITIONS
    )
    # Maps to the LCE parameter ``require_all_filters``, a boolean defaulting to ``true``. ``true``
    # means all conditions must match (AND); ``false`` means any may match (OR).
    require_all: bool = True


def build_selector_params(selector: SelectorParams) -> dict[str, str]:
    """Serialize ``SelectorParams`` into query parameters.

    A selector that is ``None`` is omitted from the query string, not sent empty, because an empty
    ``fields`` is a different request from an absent one. ``fields`` and ``exclude`` are passed
    through unparsed; how they interact is LCE's documented behaviour and is not reimplemented here.
    """
    params: dict[str, str] = {"pretty": serialize_bool(selector.pretty)}
    if selector.fields is not None:
        params["fields"] = selector.fields
    if selector.exclude is not None:
        params["exclude"] = selector.exclude
    return params


def build_write_options(options: WriteOptions) -> dict[str, str]:
    """Serialize ``WriteOptions`` into query parameters.

    Both options are always sent, because both have a documented default and neither is optional
    once the operation supports them.
    """
    return {
        "commit": serialize_bool(options.commit),
        "retrieve": serialize_bool(options.retrieve),
    }


def _condition_key(condition: FilterCondition) -> str:
    """Return ``filter[<field>][<operator>]``, or ``filter[<field>][not][<operator>]`` if negated.

    The ``[not]`` segment sits between field and operator, as the specification documents.
    """
    if condition.negate:
        return f"filter[{condition.field}][not][{condition.operator.value}]"
    return f"filter[{condition.field}][{condition.operator.value}]"


def build_filter_params(filters: FilterParams) -> dict[str, str]:
    """Serialize ``FilterParams`` into query parameters.

    Rules that cannot be expressed as pydantic field constraints are checked here:

    * ``negate=true`` with ``search``, which the specification documents as not negatable.
    * A comma-containing value with ``gt``, ``lt`` or ``search``, which are single-value only.
    * Two conditions that would serialize to the same query key.

    Messages name the rule broken and the condition's index, never the offending value. No caller
    value is concatenated into a URL: parameters are returned as a mapping for the HTTP client to
    encode.

    :param filters: The filter conditions.
    :return: The query parameters.
    :raises ValidationBlocked: Carrying every offending condition, not just the first.
    """
    findings: list[ValidationFinding] = []
    for index, condition in enumerate(filters.conditions):
        if condition.negate and condition.operator in NON_NEGATABLE:
            findings.append(
                ValidationFinding(
                    path=f"conditions[{index}]",
                    rule=FindingCode.FILTER_CONSTRAINT,
                    message=(
                        f"The {condition.operator.value} operator cannot be negated. "
                        f"Remove negate, or choose an operator that supports it."
                    ),
                )
            )
        if "," in condition.value and condition.operator in SINGLE_VALUE_ONLY:
            findings.append(
                ValidationFinding(
                    path=f"conditions[{index}]",
                    rule=FindingCode.FILTER_CONSTRAINT,
                    message=(
                        f"The {condition.operator.value} operator accepts a single value "
                        f"only, and a "
                        f"comma expresses multi-value matching. Use the is operator for multiple "
                        f"values, or supply one value without a comma."
                    ),
                )
            )
    # The duplicate-key rule is cross-condition, so it needs its own pass.
    #
    # Two conditions sharing field, operator and negation produce the same query key, and the dict
    # below would silently keep only the last, turning an AND query into a plausible wrong answer.
    # Passing repeated keys through would not help: LCE is first-value-wins, not AND. With
    # ``filter[name][contains]=SSH&filter[name][contains]=Zombie`` it returns the SSH result set,
    # and with the order reversed the Zombie set. So rejecting is the only correct option.
    #
    # ``negate`` is part of the key, so ``is`` and ``not is`` on one field do not collide.
    seen: dict[str, int] = {}
    for index, condition in enumerate(filters.conditions):
        key = _condition_key(condition)
        first = seen.get(key)
        if first is None:
            seen[key] = index
            continue
        findings.append(
            ValidationFinding(
                path=f"conditions[{index}]",
                rule=FindingCode.FILTER_CONSTRAINT,
                message=(
                    f"This condition targets the same field, operator and negation as "
                    f"conditions[{first}], so both would serialize to one query parameter and only "
                    f"one would take effect. Combine them into a single is condition with a "
                    f"comma-separated value, or filter on a different field."
                ),
            )
        )

    if findings:
        raise ValidationBlocked(findings)

    params: dict[str, str] = {_REQUIRE_ALL_PARAM: serialize_bool(filters.require_all)}
    for condition in filters.conditions:
        # For ``is``, the literal value ``null`` (any case) passes through unchanged so LCE performs
        # a SQL NULL check. It is not treated as absence, so no special case is needed.
        params[_condition_key(condition)] = condition.value
    return params


def parse_filter_params(params: dict[str, str]) -> FilterParams:
    """Parse query parameters back into ``FilterParams``; the inverse of ``build_filter_params``.

    Condition order is preserved, because ``dict`` preserves insertion order and
    ``build_filter_params`` inserts in condition order, so the round trip recovers the original
    sequence and not merely the original set.

    :param params: Query parameters produced by ``build_filter_params``.
    :return: The equivalent filter parameters.
    """
    require_all = params.get(_REQUIRE_ALL_PARAM, "true") == "true"
    conditions: list[FilterCondition] = []
    for key, value in params.items():
        if not key.startswith("filter["):
            continue
        segments = _split_bracketed(key)
        if len(segments) == 2:
            field, operator = segments
            negate = False
        else:
            field, _not, operator = segments
            negate = True
        conditions.append(
            FilterCondition(
                field=field,
                operator=FilterOperator(operator),
                value=value,
                negate=negate,
            )
        )
    return FilterParams(conditions=conditions, require_all=require_all)


def _split_bracketed(key: str) -> list[str]:
    """Split ``filter[a][b]`` into ``["a", "b"]``.

    Deliberately simple rather than a regular expression, because the input is a key this module
    produced. A field name containing ``]`` would break it, and no real LCE field name contains
    one. It is private for that reason: it inverts this module's output and is not a general
    parser.
    """
    return [
        segment.removesuffix("]") for segment in key.removeprefix("filter").split("[") if segment
    ]

"""
Response Shaping

This module provides the response shaping applied to every LCE document: empty fields are removed
and everything else is returned structurally unchanged, with no re-keying, re-typing or
summarising. There is deliberately no DTO layer, because that would be exactly the mutation this
module must not perform.

It imports nothing from this package, raises nothing and logs nothing, so ``drop_empty`` is a total
function over ``JsonValue`` that needs no stubs to test.
"""

from __future__ import annotations

from typing import Any

__all__ = ["JsonValue", "drop_empty", "shape_response"]

# A JSON value, fully checkable under ``mypy --strict`` without ``Any``. ``shape_response`` is the
# boundary where untyped LCE bodies meet this type.
type JsonValue = dict[str, "JsonValue"] | list["JsonValue"] | str | int | float | bool | None


def _is_empty(value: JsonValue) -> bool:
    """Return whether ``value`` counts as absence.

    An explicit test rather than a truthiness check on purpose: ``not value`` is ``True`` for
    ``0``, ``0.0`` and ``False``, which are values. This is the one place that distinction is made.
    """
    if value is None:
        return True
    if isinstance(value, bool):
        # Before any ``int`` consideration: ``False`` is a value, never absence.
        return False
    if isinstance(value, str):
        return value == ""
    if isinstance(value, (dict, list)):
        return len(value) == 0
    # ``int`` and ``float``, including ``0`` and ``0.0``, are values.
    return False


def drop_empty(value: JsonValue) -> JsonValue:
    """Remove empty members recursively, bottom-up, in a single post-order pass.

    ``null``, the empty string, the empty list and the empty object are dropped. ``0`` and
    ``false`` are kept: ``numeric_range_low: 0`` is real threshold data and ``state: false`` is the
    opposite of absent. Whitespace-only strings are kept too, because judging ``"   "`` empty is a
    judgement about content, and fields such as ``identifier_format`` may legitimately hold
    whitespace.

    A container left empty by dropping its members is dropped as well, so ``{"a": {"b": None}}``
    becomes ``{}``. Children are resolved before their parent is tested, so one pass is enough and
    the function is idempotent: ``f(f(x)) == f(x)``.

    :param value: The JSON value to shape. It is never mutated.
    :return: A new structure with no added keys and no altered non-empty leaves.
    """
    if isinstance(value, dict):
        shaped_object: dict[str, JsonValue] = {}
        for key, member in value.items():
            reduced = drop_empty(member)
            if not _is_empty(reduced):
                shaped_object[key] = reduced
        return shaped_object
    if isinstance(value, list):
        shaped_array: list[JsonValue] = []
        for member in value:
            reduced = drop_empty(member)
            if not _is_empty(reduced):
                shaped_array.append(reduced)
        return shaped_array
    # A leaf, returned unchanged. Whether a leaf is empty is decided by the caller through
    # ``_is_empty``, so ``0`` and ``False`` pass through untouched.
    return value


def shape_response(body: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Apply response shaping to an LCE document.

    This is the boundary where ``LceResponse.body``'s untyped ``dict[str, Any] | list[Any]``
    meets ``JsonValue``; ``drop_empty`` itself needs no ``Any``.

    It applies to whatever LCE returned, whether ``results`` alone or the expanded ``entities``
    list that ``retrieve=true`` adds. It decides only which fields are empty, never which fields
    matter. ``fields``, ``exclude`` and ``pretty`` are not applied here: they are query parameters
    passed to LCE unparsed, and LCE applies them.

    :param body: The parsed LCE response body.
    :return: The body with empty fields removed, of the same top-level type.
    """
    shaped = drop_empty(body)
    if isinstance(shaped, (dict, list)):
        return shaped
    # Unreachable in practice: ``drop_empty`` preserves the top-level container type. The
    # narrowing keeps the return type honest under ``mypy --strict`` without a ``cast``.
    raise AssertionError("drop_empty must preserve the top-level container type")

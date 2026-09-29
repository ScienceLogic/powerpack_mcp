"""
Property Test Generators

This module provides the domain-specific Hypothesis strategies the property tests draw from:
target hostnames (valid, and invalid for each rejection reason), hostile correlation IDs, LCE
error bodies, tool-set flags, JSON schemas, hostile SQL operands and access-hook values.

Several generators deliberately over-weight the one input a property is about, because a uniform
generator would reach it only by chance.
"""

from __future__ import annotations

from hypothesis import strategies as st

from powerpack_mcp.errors import SECRET_FIELD_DENYLIST
from powerpack_mcp.tool_sets import ToolSetFlags

__all__ = [
    "hook_deny_branches",
    "hook_ids",
    "hook_payloads",
    "hostile_correlation_ids",
    "hostile_sql_operands",
    "instances_for",
    "invalid_target_hosts",
    "json_bodies",
    "json_schemas",
    "lce_error_bodies",
    "principals",
    "rejection_reasons",
    "required_hook_sets",
    "tool_set_flags",
    "valid_target_hosts",
]

_LABEL_CHARS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    min_size=1,
    max_size=1,
)


@st.composite
def _label(draw: st.DrawFn) -> str:
    """One RFC-1123 label: alphanumeric at each end, hyphens interior only, 1 to 63 characters."""
    size = draw(st.integers(min_value=1, max_value=8))
    if size == 1:
        return draw(_LABEL_CHARS)
    first = draw(_LABEL_CHARS)
    last = draw(_LABEL_CHARS)
    middle = draw(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-",
            min_size=size - 2,
            max_size=size - 2,
        )
    )
    return f"{first}{middle}{last}"


@st.composite
def valid_target_hosts(draw: st.DrawFn) -> str:
    """Generate RFC-1123 hostnames and IPv4 literals, the accepted target-host forms."""
    if draw(st.booleans()):
        octets = draw(st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=4))
        return ".".join(str(o) for o in octets)
    labels = draw(st.lists(_label(), min_size=1, max_size=4))
    candidate = ".".join(labels)
    # Keep within the 253-character bound so this generator produces only accepted values; length
    # rejection is the invalid generator's job.
    return candidate if len(candidate) <= 253 else labels[0]


# Every target-host rejection reason, including IPv6. Named so a failure report says which reason
# regressed rather than only showing a string.
rejection_reasons: dict[str, st.SearchStrategy[str]] = {
    "scheme": st.sampled_from(["https://host", "http://host", "HTTPS://host.example"]),
    "port": st.integers(min_value=1, max_value=65535).map(lambda p: f"host:{p}"),
    "path": st.sampled_from(["host/path", "host/", "host/a/b"]),
    "query": st.sampled_from(["host?q=1", "host?"]),
    "fragment": st.sampled_from(["host#frag", "host#"]),
    "userinfo": st.sampled_from(["user@host", "user:pass@host"]),
    "percent_encoding": st.sampled_from(["ho%73t", "%2Fhost", "host%00"]),
    "whitespace": st.sampled_from(["ho st", " host", "host ", "host\t"]),
    "control_character": st.sampled_from(["host\n", "host\r", "host\x00", "\x1bhost"]),
    "empty": st.just(""),
    "trailing_dot": st.sampled_from(["host.", "a.b."]),
    "leading_hyphen": st.sampled_from(["-host", "-a.b"]),
    "trailing_hyphen": st.sampled_from(["host-", "a-.b"]),
    "ipv6": st.sampled_from(["::1", "fe80::1", "2001:db8::8a2e:370:7334"]),
    "too_long": st.just("a" * 254),
    "empty_label": st.sampled_from(["a..b", ".host", "..."]),
}


def invalid_target_hosts() -> st.SearchStrategy[str]:
    """Combine every rejection reason into one strategy."""
    return st.one_of(*rejection_reasons.values())


def hostile_correlation_ids() -> st.SearchStrategy[str | None]:
    """Generate arbitrary and adversarial inputs for `sanitize_correlation_id`.

    Deliberately includes ``None``, the empty string, control characters, very long strings and
    arbitrary Unicode; the totality property must hold for every one of them.
    """
    return st.one_of(
        st.none(),
        st.just(""),
        st.text(),
        st.text(alphabet=st.characters(min_codepoint=0, max_codepoint=0x10FFFF)),
        st.text(alphabet="\n\r\t\x00\x1b ", min_size=1, max_size=20),
        st.text(min_size=129, max_size=4000),
        st.binary().map(lambda b: b.decode("utf-8", errors="replace")),
    )


# ---- LCE error bodies, for `sanitize_lce_body` ----

# Arbitrary text would almost never produce "authorization" or "password", so the redaction
# property would pass while testing nothing. Keys are drawn from the denylist itself, from
# case-varied forms of it (matching is case-insensitive), and from arbitrary text.
_BODY_KEYS: st.SearchStrategy[str] = st.one_of(
    st.sampled_from(sorted(SECRET_FIELD_DENYLIST)),
    st.sampled_from([name.upper() for name in sorted(SECRET_FIELD_DENYLIST)]),
    st.sampled_from([name.capitalize() for name in sorted(SECRET_FIELD_DENYLIST)]),
    st.text(max_size=12),
)

_BODY_LEAVES: st.SearchStrategy[object] = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=30),
    # Long enough to cross MAX_LCE_BODY_CHARS, so the cap is actually exercised rather than assumed.
    st.text(min_size=2100, max_size=2400),
)


def json_bodies() -> st.SearchStrategy[object]:
    """Generate nested JSON-shaped values, including denylisted keys and over-long strings."""
    return st.recursive(
        _BODY_LEAVES,
        lambda children: st.one_of(
            st.dictionaries(_BODY_KEYS, children, max_size=4),
            st.lists(children, max_size=4),
        ),
        max_leaves=12,
    )


def lce_error_bodies() -> st.SearchStrategy[dict[str, object] | list[object] | str]:
    """Generate the three shapes `_read_error_body` can return: `dict`, `list` or `str`.

    Narrower than `json_bodies` on purpose: this matches `LceHttpError.lce_body`'s declared type, so
    a property asserting the sanitiser preserves the top-level type has something meaningful to
    assert. A bare scalar is excluded because `_read_error_body` never produces one.
    """
    return st.one_of(
        st.dictionaries(_BODY_KEYS, json_bodies(), max_size=4),
        st.lists(json_bodies(), max_size=4),
        st.text(max_size=60),
        st.text(min_size=2100, max_size=2400),
    )


# ---- Tool-set gating ----


@st.composite
def tool_set_flags(draw: st.DrawFn) -> ToolSetFlags:
    """Generate the six ``ENABLE_*`` values, weighted toward the nesting case.

    The property that matters is that ``ENABLE_DB_TOOLS=false`` disables all DB tools, writes
    included, whatever the write key says. Six independent draws reach write ``True`` with read
    ``False`` only incidentally, so one draw in four is forced into exactly that shape.
    """
    if draw(st.integers(min_value=0, max_value=3)) == 0:
        # The nesting case, drawn on purpose rather than hoped for.
        return ToolSetFlags(
            sl1_rest=draw(st.booleans()),
            sl1_graphql=draw(st.booleans()),
            db_tools=False,
            db_write_tools=True,
            ops_tools=draw(st.booleans()),
            standards_tools=draw(st.booleans()),
        )
    return ToolSetFlags(
        sl1_rest=draw(st.booleans()),
        sl1_graphql=draw(st.booleans()),
        db_tools=draw(st.booleans()),
        db_write_tools=draw(st.booleans()),
        ops_tools=draw(st.booleans()),
        standards_tools=draw(st.booleans()),
    )


# ---- Tool-set gating: schemas for the schema-trimming oracle property ----

# The pool deliberately contains `title`, `type` and `properties`. A parameter named `title` must
# survive trimming while `title` in a metadata position is removed, and an arbitrary name generator
# would almost never draw "title". `type` and `properties` are JSON Schema keywords that are also
# legal parameter names.
_SCHEMA_PROPERTY_NAMES: st.SearchStrategy[str] = st.one_of(
    st.sampled_from(["title", "type", "properties", "$defs", "required", "anyOf"]),
    st.sampled_from(["host", "severity", "guid", "payload", "fields"]),
    st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=8),
)

_LEAF_SCHEMAS: st.SearchStrategy[dict[str, object]] = st.sampled_from(
    [
        {"type": "string"},
        {"type": "integer"},
        {"type": "boolean"},
        # The nullable union that trimming collapses.
        {"anyOf": [{"type": "string"}, {"type": "null"}]},
        {"anyOf": [{"type": "integer"}, {"type": "null"}]},
        # A structured union, which must be left untouched.
        {"anyOf": [{"type": "object", "additionalProperties": True}, {"type": "null"}]},
        # A sibling `type` beside `anyOf`. Collapsing would overwrite it.
        {"type": "string", "anyOf": [{"type": "string"}, {"type": "null"}]},
        # An "any" branch, also left untouched.
        {"anyOf": [{}, {"type": "null"}]},
        {"type": "string", "minLength": 1},
    ]
)


@st.composite
def json_schemas(draw: st.DrawFn) -> dict[str, object]:
    """Generate an object schema shaped like the ones pydantic generates for a tool's arguments.

    Carries advisory ``title`` metadata at most levels, which trimming removes, while sometimes
    naming a parameter ``title``, which trimming must keep.
    """
    names = draw(st.lists(_SCHEMA_PROPERTY_NAMES, min_size=0, max_size=4, unique=True))
    properties: dict[str, object] = {}
    for name in names:
        leaf = dict(draw(_LEAF_SCHEMAS))
        if draw(st.booleans()):
            leaf["title"] = name.replace("_", " ").title()
        properties[name] = leaf
    schema: dict[str, object] = {"type": "object", "properties": properties}
    if draw(st.booleans()):
        schema["title"] = "ArgumentsModel"
    # `len(names) > 0` rather than `names`: with a bare truthiness test the `and` expression has
    # type `list[str] | bool`, and mypy --strict then tries to unify `draw`'s return type with
    # `list[str]`.
    if len(names) > 0 and draw(st.booleans()):
        schema["required"] = draw(st.lists(st.sampled_from(names), unique=True, max_size=2))
    if draw(st.booleans()):
        schema["additionalProperties"] = draw(st.booleans())
    return schema


@st.composite
def instances_for(draw: st.DrawFn, schema: dict[str, object]) -> dict[str, object]:
    """Generate a candidate instance for ``schema``: sometimes valid, often not.

    The trimmed schema must accept exactly the same inputs as the original, so the oracle has to
    see rejections as well as acceptances; valid-only instances would never detect a trimmed schema
    that had become more permissive.
    """
    properties = schema.get("properties")
    names = sorted(properties) if isinstance(properties, dict) else []
    values: st.SearchStrategy[object] = st.one_of(
        st.text(max_size=6),
        st.integers(min_value=-5, max_value=5),
        st.booleans(),
        st.none(),
        st.just({}),
        st.just([]),
    )
    chosen = draw(st.lists(st.sampled_from(names), unique=True)) if names else []
    instance: dict[str, object] = {name: draw(values) for name in chosen}
    if draw(st.booleans()):
        instance["unexpected_extra"] = draw(values)
    return instance


# ---- SL1 DB surface ----
#
# Parameterisation is the primary control against SQL injection in the DB tools, and there is no
# downstream check, so this generator is what stands between a caller and `master.*`.
#
# The alphabet covers the two things that break SQL construction here: classic injection
# punctuation, and `LIKE` wildcards plus the backslash escape. A '%' smuggled into statement text
# is silent (empty rows); a '%' left unescaped in an operand silently widens the rows matched.

_SQL_HOSTILE_CHARS = "'\"`;\\%_-#/*()=<> \t\r\n\x00"


def hostile_sql_operands() -> st.SearchStrategy[str]:
    """Generate operands designed to escape a statement.

    Mixes raw hostile alphabets with named payloads, because the two find different defects:
    random punctuation explores escaping, while the named payloads are the shapes a human attacker
    would actually try and are what make a failure legible in a Hypothesis report.
    """
    return st.one_of(
        st.text(alphabet=_SQL_HOSTILE_CHARS, max_size=12),
        st.text(max_size=12),
        st.sampled_from(
            [
                "' OR 1=1 --",
                '" OR ""="',
                "'; DROP TABLE master.device; --",
                "1' UNION SELECT NULL,NULL,NULL--",
                "%",
                "%%",
                "_",
                "\\",
                "\\%",
                "100%_off",
                "admin'/*",
                "\x00truncated",
                "name\nOR\t1=1",
            ]
        ),
    )


# ---- The authorization gate ----
#
# The alphabet and category prefixes are taken from a real 81-hook profile of a restricted account
# on a test appliance: `DEV` 64, `EVT` 7, `ORG` 6, `ACT` 6, plus `AP`, `AST`, `CONTACT`, `DASH`,
# `DGRP`, `IP`, `MON`, `SYS`. A random string does not resemble a ``master_access.hooks.hook_id``,
# and the disclosure properties are only meaningful against values that do.

# Categories in use on the measured build. `API` and `PPK` are defined but empty there.
_HOOK_CATEGORIES = (
    "ACT", "AP", "AST", "CONTACT", "CRED", "DASH", "DEV", "DGRP", "EVT",
    "IP", "MON", "ORG", "RPRT", "SYS", "TKT",
)  # fmt: skip

_HOOK_WORDS = (
    "VIEW", "EDIT", "ADD", "REM", "ADDREM", "DELETE", "PAGE", "REG_PAGE",
    "CLEAR", "RUN", "MANAGEMENT", "POLICY", "CLASS", "TOOLS", "COLLECTIONS",
)  # fmt: skip


@st.composite
def hook_ids(draw: st.DrawFn) -> str:
    """Generate one plausible ``hook_id``: uppercase ``<CAT>_<WORD>[_<WORD>]``, <= 32 chars.

    Never the ``name`` column's ``Thing:Verb`` shape. Hook IDs written as display labels rather
    than primary keys do not exist, so a generator producing colons would test the wrong vocabulary.
    """
    category = draw(st.sampled_from(_HOOK_CATEGORIES))
    words = draw(st.lists(st.sampled_from(_HOOK_WORDS), min_size=1, max_size=2))
    candidate = "_".join((category, *words))
    # `hook_id` is `varchar(32)`; keep the generator inside the accepted range so length rejection
    # stays the malformed generator's job.
    return candidate if len(candidate) <= 32 else f"{category}_VIEW"


@st.composite
def hook_payloads(draw: st.DrawFn) -> list[str]:
    """Generate an ``/access_hooks`` answer as SL1 returns it: a bag, with duplicates.

    A measured live answer carried 96 entries for 81 unique IDs. A generator producing only
    distinct values would never exercise the deduplication, which looks incidental in
    `lce_service`'s implementation but is load-bearing.

    Includes the empty bag, which is a legitimate answer meaning "granted nothing".
    """
    unique = draw(st.lists(hook_ids(), min_size=0, max_size=12, unique=True))
    if not unique:
        return []
    extra = draw(st.lists(st.sampled_from(unique), min_size=0, max_size=8))
    payload = [*unique, *extra]
    return draw(st.permutations(payload))


@st.composite
def required_hook_sets(draw: st.DrawFn) -> frozenset[str]:
    """Generate a per-tool hook requirement, deliberately including the empty set.

    ``set().issubset(anything)`` is always ``True``, and that is `lce_service`'s one genuine
    fail-open: ``require_all=True`` with an empty required set allows everyone. Generating it turns
    "we reject the empty set at registration" from a claim into a tested property.
    """
    return frozenset(draw(st.lists(hook_ids(), min_size=0, max_size=4, unique=True)))


@st.composite
def principals(draw: st.DrawFn) -> tuple[int, str]:
    """Generate ``(account_id, authorization_header)`` covering both Basic and Bearer.

    Generating Bearer is the point. ``username_from_authorization`` returns ``None`` for every
    non-Basic scheme, and SL1 API keys authenticate as ``Authorization: Bearer``, so keying the
    cache on it would collapse every API-key caller onto one entry. A Basic-only generator would
    never find that.
    """
    account_id = draw(st.integers(min_value=1, max_value=4_294_967_295))
    if draw(st.booleans()):
        return account_id, "Basic dXNlcjpwYXNz"
    return account_id, f"Bearer token-{account_id}"


# The gate's deny branches for a malformed hook answer, named so a failure report says which
# branch regressed. `test_properties` asserts this table is complete, because a branch silently
# dropped from it would weaken the suite without failing anything.
hook_deny_branches: dict[str, st.SearchStrategy[object]] = {
    # A malformed body: not a list at all.
    "not_a_list": st.one_of(
        st.dictionaries(st.text(max_size=6), st.integers(), max_size=3),
        st.text(max_size=20),
        st.integers(),
        st.none(),
    ),
    # An implausible element.
    "blank_element": st.just(["DEV_VIEW", ""]),
    "non_string_element": st.sampled_from([["DEV_VIEW", 1], ["DEV_VIEW", None], ["DEV_VIEW", []]]),
    "over_long_element": st.just(["X" * 65]),
    # An over-large answer.
    "over_cap": st.just(["DEV_VIEW"] * 8193),
}

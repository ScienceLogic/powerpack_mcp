"""
Credential Guard Tests

This module tests ``sl1_credential_guard`` and the scanner under it, ``graphql_document``: the
controls that stop ``sl1_graphql``, the REST passthroughs and the Guided Discovery tool from
returning the credential secrets ``sl1_list_credentials`` and ``sl1_get_credential`` withhold.

The scanner tests come first, because the rule is only as sound as the scanner's idea of what a
field name is and which field it sits under. Then the rule itself -- the global secret-field rule,
the credential allowlist, the template allowlist, probes and mutations -- then attempts to get past
it, the scrub and the REST rule, then the tools end to end with ``httpx.MockTransport``: a refused
call must send nothing, and an answered one must carry no secret whatever shape SL1 put it in.

The fixtures (``CANARY``, ``definition_for``, ``node_for``) come from
``test_credential_definition_filter`` so the two suites plant the same secrets.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, Final

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import LogEvent, ValidationBlocked
from powerpack_mcp.lce_client import LceClient
from powerpack_mcp.sl1_client import Sl1Client
from powerpack_mcp.tools import sl1_credential_guard as guard
from powerpack_mcp.tools import sl1_graphql_tools as gql
from powerpack_mcp.tools import sl1_guided_discovery as gd
from powerpack_mcp.tools import sl1_rest_tools as rest
from powerpack_mcp.tools.graphql_document import (
    FieldSelection,
    GraphQlSyntaxError,
    TokenKind,
    summarize_executable_document,
    tokenize,
)
from powerpack_mcp.tools.sl1_credential_definition import CRED_SECRET_KEYS, CREDENTIAL_SECRET_KEYS
from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext
from tests.unit.test_credential_definition_filter import (
    CANARY,
    CREDENTIAL_TYPES,
    KNOWN_SECRET_KEYS,
    definition_for,
    node_for,
)

Handler = Callable[[httpx.Request], httpx.Response]

# A document that touches credentials and selects nothing secret: the shape a caller resolving a
# credential name to a guid would send. It must keep working.
_CREDENTIAL_LOOKUP: Final = (
    "query($n: String) { credentials(search: { name: { contains: $n } }) "
    "{ edges { node { id guid name type } } } }"
)


def _ctx(
    config: Config, credential: LceCredential, handler: Handler
) -> tuple[Sl1ToolContext, list[httpx.Request]]:
    """A context whose SL1 transport is mocked and whose requests are recorded."""
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    sl1 = Sl1Client(config)
    sl1._client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    lce = LceClient(config)
    lce._client = httpx.AsyncClient(transport=httpx.MockTransport(record))
    context = Sl1ToolContext(
        client=sl1, config=config, credential_source=lambda: credential, lce_client=lce
    )
    return context, seen


def _gql_ok(payload: Any) -> Handler:
    return lambda _r: httpx.Response(200, json={"data": payload})


def _rest_ok(body: Any) -> Handler:
    return lambda _r: httpx.Response(200, json=body)


def _refused(query: str, variables: dict[str, Any] | None = None) -> bool:
    return guard.graphql_document_refusal(query, variables) is not None


def _assert_no_secret(payload: object) -> None:
    """No planted secret value, in any encoding, anywhere in ``payload``."""
    rendered = json.dumps(payload)
    assert CANARY not in rendered, f"a planted secret reached the caller: {rendered[:400]}"


# ---- the scanner --------------------------------------------------------------------------------


class TestTheLexer:
    """The lexical grammar, including the places a lenient lexer would disagree with a server."""

    def test_punctuators_names_and_numbers(self) -> None:
        tokens = tokenize("query Q($a: [Int!]! = [1, -2.5e3]) @d { ...F }")
        kinds = [(t.kind, t.value) for t in tokens]
        assert (TokenKind.NAME, "query") in kinds
        assert (TokenKind.PUNCTUATOR, "...") in kinds
        assert (TokenKind.INT, "1") in kinds
        assert (TokenKind.FLOAT, "-2.5e3") in kinds
        assert tokens[-1].kind is TokenKind.EOF

    def test_commas_whitespace_and_the_bom_are_ignored_anywhere(self) -> None:
        values = [t.value for t in tokenize("\ufeff{,a\ufeff,\t b\r\n}")]
        assert values == ["{", "a", "b", "}", ""]

    def test_a_comment_runs_to_the_line_break_and_no_further(self) -> None:
        tokens = tokenize("{ a # b c\n d # e\r f }")
        assert [t.value for t in tokens if t.kind is TokenKind.NAME] == ["a", "d", "f"]

    @pytest.mark.parametrize("char", ["\x85", "\u2028", "\u2029", "\x0b", "\x0c", "\x00", "\x7f"])
    def test_an_ambiguous_character_inside_a_comment_is_refused(self, char: str) -> None:
        """A comment the server ends earlier than we do would hide live text from the guard."""
        with pytest.raises(GraphQlSyntaxError):
            tokenize(f"{{ a # x{char} definition\n }}")

    def test_string_escapes_are_decoded(self) -> None:
        tokens = tokenize(r'"a\"b\\c\/\nA\u{1F600}"')
        assert tokens[0].kind is TokenKind.STRING
        assert tokens[0].value == 'a"b\\c/\nA\U0001f600'

    @pytest.mark.parametrize(
        "source",
        [
            '"unterminated',
            '"line\nbreak"',
            r'"bad \x escape"',
            r'"\u12"',
            r'"\u{}"',
            r'"\u{110000}"',
            '"""unterminated',
            '"ctl \x01"',
        ],
    )
    def test_malformed_strings_raise(self, source: str) -> None:
        with pytest.raises(GraphQlSyntaxError):
            tokenize(source)

    def test_a_block_string_ends_only_at_an_unescaped_triple_quote(self) -> None:
        """A backslash before a triple quote escapes it; two backslashes are a backslash and then
        an escaped triple quote, as the reference implementation scans them, not a terminator."""
        tokens = tokenize('"""a \\""" b \\\\""" c""" d')
        assert tokens[0].kind is TokenKind.BLOCK_STRING
        assert tokens[0].value == 'a """ b \\""" c'
        assert tokens[1].value == "d"

    def test_a_block_string_may_span_lines(self) -> None:
        tokens = tokenize('"""one\ntwo\r\nthree""" x')
        assert tokens[0].value == "one\ntwo\r\nthree"
        assert (tokens[1].line, tokens[1].column) == (3, 10)

    @pytest.mark.parametrize(
        "source",
        ["01", "1.", "1.e5", "1e", "1a", "0x1", "1.2.3", "-", "..", ".", "\xe9", "\x01", "%"],
    )
    def test_malformed_tokens_raise(self, source: str) -> None:
        with pytest.raises(GraphQlSyntaxError):
            tokenize(source)

    def test_an_exponent_may_be_signed(self) -> None:
        assert [t.value for t in tokenize("1e+5 2E-3")][:2] == ["1e+5", "2E-3"]

    def test_the_token_count_is_bounded(self) -> None:
        from powerpack_mcp.tools.graphql_document import MAX_TOKENS

        with pytest.raises(GraphQlSyntaxError):
            tokenize("a " * (MAX_TOKENS + 1))

    def test_errors_carry_a_position_and_no_document_text(self) -> None:
        with pytest.raises(GraphQlSyntaxError) as raised:
            tokenize("{ a }\n  %secret-ish")
        assert (raised.value.line, raised.value.column) == (2, 3)
        assert "secret-ish" not in str(raised.value)

    @pytest.mark.parametrize(
        "source", ["{ a # \ud800\n definition }", '{ a(x: "\udfff") }', '{ a(x: """\ud800""") }']
    )
    def test_a_lone_surrogate_is_refused_in_comments_and_strings(self, source: str) -> None:
        """JSON can deliver one; the reference lexer ends a comment at one, so it is refused."""
        with pytest.raises(GraphQlSyntaxError):
            tokenize(source)

    def test_line_numbers_count_crlf_once(self) -> None:
        tokens = tokenize("a\r\nb\rc\nd")
        assert [(t.value, t.line) for t in tokens[:-1]] == [("a", 1), ("b", 2), ("c", 3), ("d", 4)]


class TestTheParser:
    """Only field selections become fields; everything else that is a name stays a name."""

    def test_an_alias_does_not_hide_the_field(self) -> None:
        summary = summarize_executable_document("{ id: definition definition: id }")
        assert [(f.alias, f.name) for f in summary.fields] == [
            ("id", "definition"),
            ("definition", "id"),
        ]

    def test_arguments_enum_values_variables_and_types_are_not_fields(self) -> None:
        summary = summarize_executable_document(
            "query($definition: definition = definition) "
            "{ a(definition: definition, b: $definition, c: {definition: 1}) @definition { b } }"
        )
        assert [f.name for f in summary.fields] == ["a", "b"]
        assert summary.fields[0].argument_names == ("definition", "b", "c")
        assert summary.object_field_names == ["definition"]
        assert "definition" in summary.names

    def test_enum_values_are_recorded_including_variable_defaults(self) -> None:
        summary = summarize_executable_document(
            "query($o: [O] = [{field: definition}], $b: Boolean = true) "
            "{ a(order: [{field: password, direction: asc}], x: null, y: false) { b } }"
        )
        assert summary.enum_values == ["definition", "password", "asc"]
        assert summary.operations[0].variables[0].default is not None

    def test_the_tree_keeps_each_selection_under_its_field(self) -> None:
        summary = summarize_executable_document(
            "query Q { a(x: 1) { b ... on T { c } ...F } } fragment F on U { d { e } }"
        )
        (operation,) = summary.operations
        assert operation.name == "Q"
        (a,) = operation.selections
        assert isinstance(a, FieldSelection)
        assert [type(s).__name__ for s in a.selections] == [
            "FieldSelection",
            "InlineFragment",
            "FragmentSpread",
        ]
        (fragment,) = summary.fragments
        assert (fragment.name, fragment.type_condition) == ("F", "U")

    def test_fragments_inline_fragments_and_spreads(self) -> None:
        summary = summarize_executable_document(
            "{ a { ...F ... on T { b } ... @include(if: true) { c } } } fragment F on U { d }"
        )
        assert [f.name for f in summary.fields] == ["a", "b", "c", "d"]
        assert summary.type_conditions == ["T", "U"]

    def test_a_spread_name_is_not_a_field(self) -> None:
        summary = summarize_executable_document(
            "{ a { ...definition } } fragment definition on T { b }"
        )
        assert [f.name for f in summary.fields] == ["a", "b"]

    def test_strings_are_recorded_decoded(self) -> None:
        summary = summarize_executable_document('{ a(x: "\\u0064efinition", y: """b""") }')
        assert summary.string_values == ["definition", "b"]

    @pytest.mark.parametrize(
        "source",
        [
            "",
            "   # only a comment",
            "{}",
            "{ a(",
            "{ a() }",
            "query ()  { a }",
            "{ a: }",
            "{ ...on }",
            "{ a",
            "type Query { a: Int }",
            "schema { query: Q }",
            "extend type Q { a: Int }",
            '"description" query { a }',
            "fragment on on T { a }",
            "fragment F($x: Int) on T { a }",
            "fragment F { a }",
            "query($a: Int = $b) { a }",
            "{ a(x: [1, 2) }",
            "{ a(x: [1, 2",
            "{ a(x: {b: 1",
            "{ a(x: {b 1}) }",
            "{ a } }",
        ],
    )
    def test_anything_outside_the_executable_grammar_raises(self, source: str) -> None:
        with pytest.raises(GraphQlSyntaxError):
            summarize_executable_document(source)

    def test_nesting_is_bounded_rather_than_exhausting_the_stack(self) -> None:
        deep = "{ a " * 5000 + "}" * 5000
        with pytest.raises(GraphQlSyntaxError):
            summarize_executable_document(deep)
        deep_value = "{ a(x: " + "[" * 5000 + "]" * 5000 + ") }"
        with pytest.raises(GraphQlSyntaxError):
            summarize_executable_document(deep_value)


# ---- the rule -----------------------------------------------------------------------------------

# The typed credential root fields and their measured secrets. The guard does not depend on the
# root field names (each contains ``cred``); the secrets are the per-type fields that introspection
# found on SL1 12.5.x.
TYPED_SECRETS: Final[dict[str, list[str]]] = {
    "basicCredentials": ["password"],
    "dbCredentials": ["password"],
    "ldapCredentials": ["password"],
    "powerShellCredentials": ["password"],
    "snmpCredentials": [
        "password",
        "snmpReadOnlyCommunity",
        "snmpReadWriteCommunity",
        "snmpV3PrivacyPassword",
    ],
    "soapCredentials": [
        "password",
        "curlProxyPassword",
        "curlRequestPassword",
        "curlRequestSub1",
        "curlRequestSub2",
        "curlRequestSub3",
        "curlRequestSub4",
        "curlHeaders",
        "curlOptions { COOKIE }",
        "curlOptions { CAINFO }",
    ],
    "sshCredentials": ["password", "sshKeyData"],
    "credentials": ["definition"],
}

# Fields outside the allowlist that the secret patterns do not catch: refused by R2 alone.
UNLISTED: Final[list[str]] = [
    "definition",
    "alignedOrganizations { id }",
    "editedBy { id }",
    "updatedBy { id }",
    "somethingNew",
]

# The typed credential types, for fragments.
CREDENTIAL_TYPE_NAMES: Final[list[str]] = [
    "Credential",
    "BasicCredential",
    "DbCredential",
    "LdapCredential",
    "PowerShellCredential",
    "SnmpCredential",
    "SoapCredential",
    "SshCredential",
    "CredentialTest",
    "CredentialTestLog",
]

# Metadata each typed root may select.
TYPED_METADATA: Final[dict[str, str]] = {
    "basicCredentials": "id guid name host port user timeout dateEdited allOrganizations",
    "dbCredentials": "id name databaseConnect databaseName databaseSID databaseType host port",
    "ldapCredentials": "id name ldapDomain ldapRootDn ldapScope ldapSecure ldapType ldapUserDn",
    "powerShellCredentials": (
        "id name powerShellActiveDirectoryDomain powerShellActiveDirectoryHost "
        "powerShellEncrypted powerShellProxyHost powerShellType"
    ),
    "snmpCredentials": (
        "id name snmpVersion snmpRetries snmpV3AuthorizationProtocol snmpV3PrivacyProtocol "
        "snmpV3SecurityLevel snmpV3Context snmpV3EngineId"
    ),
    "soapCredentials": (
        "id name curlUrl curlMethod curlEncoding curlHttpVersion curlProxyIp curlProxyPort "
        "curlProxyAccount curlSslMode"
    ),
    "sshCredentials": "id guid name host port user timeout",
    "credentials": "id guid name type subType typeDescription timeout dateEdited allOrganizations",
}


def _connection(root: str, selection: str) -> str:
    return f"{{ {root} {{ edges {{ node {{ {selection} }} }} pageInfo {{ matchCount }} }} }}"


# Measured secrets on types that are not credentials: refused by R1 wherever they are.
NON_CREDENTIAL_SECRETS: Final[list[str]] = [
    "{ agentTokenSecrets { jwt } }",
    "{ x { ... on AgentTokenSecret { id } } }",
    "{ x { ... on CollectorToken { tokenDetails { name } } } }",
    "{ x { token } }",
    "{ x { ... on AccessKey { id name } } }",
    "{ accessKeys { edges { node { id } } } }",
    "{ accounts { edges { node { id accessKeys { id } } } } }",
    "{ accounts { edges { node { id hash } } } }",
    "{ organizations { edges { node { id h: hash } } } }",
    "{ x { httpUsernamePassword } }",
    "{ x { proxyUsernamePassword } }",
    "{ x { cookieValue } }",
    "{ x { proxyAccountPassword } }",
    "{ x { customHeader } }",
    "{ x { apiKey { jwt } } }",
    'mutation { createAgentTokenSecret(agent: "1") { id } }',
    'mutation { updateAgentTokenSecret(id: "1") { id } }',
    'mutation { createAccessKey(name: "k") { id } }',
    'mutation { updateAccessKey(id: "1") { id name } }',
    '{ credentialTranslatedByCustomType(guid: "g") }',
    '{ x: credentialTranslatedByCustomType(guid: "g") { a } }',
]

# Documents the rule must refuse, each with the reason it is in the table.
REFUSED: Final[list[tuple[str, str]]] = [
    *(
        (_connection(root, secret), f"{root} selecting {secret}")
        for root, secrets in TYPED_SECRETS.items()
        for secret in secrets
    ),
    *((_connection("snmpCredentials", f"id {field}"), f"unlisted {field}") for field in UNLISTED),
    *(
        (f"{{ x {{ ... on {t} {{ id definition }} }} }}", f"inline fragment on {t}")
        for t in CREDENTIAL_TYPE_NAMES
    ),
    *(
        (f"{{ x {{ ...F }} }} fragment F on {t} {{ password }}", f"fragment on {t}")
        for t in CREDENTIAL_TYPE_NAMES
    ),
    *((document, "a measured non-credential secret") for document in NON_CREDENTIAL_SECRETS),
    ('{ credential(guid: "G") { definition } }', "the single read"),
    ("{ credentials { edges { node { d: definition } } } }", "aliased"),
    ("{ credentials { edges { node { definition: definition } } } }", "aliased to itself"),
    ("{ credentials { edges { node { id: snmpReadOnlyCommunity } } } }", "aliased as id"),
    (
        "{ credentials { edges { node { ...F } } } } fragment F on Credential { definition }",
        "via a fragment",
    ),
    (
        "fragment F on Device { definition } { credentials { edges { node { ...F } } } }",
        "a fragment on another type spread inside a credential",
    ),
    ("{ credentials { edges { node { ... { definition } } } } }", "untyped inline fragment"),
    ("{ node(id: 1) { ... on Credential { definition } } }", "only the type condition opens it"),
    ("{ CREDENTIALS { edges { node { DEFINITION } } } }", "re-cased"),
    ("{ SnmpCredentials { edges { node { SNMPREADONLYCOMMUNITY } } } }", "mixed case"),
    ("{ creds { definition } }", "abbreviated"),
    (
        "{ devices { edges { node { id snmpReadCredential { id snmpReadOnlyCommunity } } } } }",
        "Device.snmpReadCredential's secret",
    ),
    (
        "{ devices { edges { node { snmpReadCredential { alignedOrganizations { id } } } } } }",
        "a nested non-credential object inside a credential",
    ),
    ("{ credentials { pageInfo { matchCount startCursor } } }", "pageInfo is held to its three"),
    ("{ a { ... on SoapCredential { curlOptions { CAINFO } } } }", "curlOptions, any member"),
    ('mutation { createCredential(name: "n") { id definition } }', "a create's result"),
    ('mutation { updateCredential(guid: "g") { password } }', "an update's result"),
    ('mutation { duplicateCredential(guid: "g") { id definition } }', "a duplicate's result"),
    (
        'mutation { createCredential(name: "n") { alignedOrganizations { hash } } }',
        "a create selecting organizations",
    ),
    ("{ credentials { edges { node { id definition @skip(if: false) } } } }", "with a directive"),
    ("{ device(id: 1) { password } }", "a secret key as a field, anywhere"),
    ("{ a { sshKeyData } }", "the SSH private key, wherever it is"),
    ("{ a { apikey } }", "a definition secret key, wherever it is"),
    # Fragment graph.
    ("{ a { ...A } } fragment A on X { ...B } fragment B on Y { ...A }", "a fragment cycle"),
    ("{ a { ...A } } fragment A on X { ...A }", "a self-spread"),
    ("{ a { ...Missing } }", "an unresolvable spread"),
    ("{ a { id } } fragment A on X { id } fragment A on Y { id }", "a duplicate fragment"),
    ("fragment F on Credential { definition }", "an unused fragment is still checked"),
    # Probes.
    (
        '{ credentials(search: { definition: { contains: "a" } }) { edges { node { id } } } }',
        "search on definition",
    ),
    (
        '{ credentials(search: { password: { eq: "a" } }) { pageInfo { matchCount } } }',
        "search on a secret",
    ),
    (
        (
            '{ credentials(order: [{ field: "definition", direction: asc }]) '
            "{ pageInfo { hasNextPage } } }"
        ),
        "string sort",
    ),
    (
        (
            "{ credentials(order: [{ field: definition, direction: asc }]) "
            "{ pageInfo { matchCount } } }"
        ),
        "enum-literal sort",
    ),
    (
        (
            "{ snmpCredentials(order: [{ field: snmpReadOnlyCommunity }]) "
            "{ pageInfo { matchCount } } }"
        ),
        "enum-literal sort on a typed secret",
    ),
    (
        "{ credentials(order: [{ field: alignedOrganizations }]) { pageInfo { matchCount } } }",
        "a sort on an unlisted field",
    ),
    (
        (
            "query($o: [ConnectionOrder] = [{ field: definition }]) "
            "{ credentials(order: $o) { pageInfo { matchCount } } }"
        ),
        "a variable default carrying the enum",
    ),
    (
        (
            'query($o: [ConnectionOrder] = [{ field: "password" }]) '
            "{ credentials(order: $o) { pageInfo { matchCount } } }"
        ),
        "a variable default carrying the string",
    ),
    (
        '{ credentials(order: [{ field: """password""" }]) { pageInfo { matchCount } } }',
        "block-string sort",
    ),
    ('{ credentials(definition: "x") { pageInfo { matchCount } } }', "a filter argument"),
    ('{ credentials(password: "x") { pageInfo { matchCount } } }', "a secret-named argument"),
    (
        (
            "{ devices(search: { snmpReadCredential: "
            '{ has: { snmpReadOnlyCommunity: { eq: "x" } } } }) '
            "{ pageInfo { matchCount } } }"
        ),
        "a device search reaching into its credential's secret",
    ),
    (
        '{ accounts(search: { hash: { contains: "a" } }) { pageInfo { matchCount } } }',
        "a probe on a non-credential secret",
    ),
    ('{ accounts(order: [{ field: "hash" }]) { pageInfo { matchCount } } }', "a sort on hash"),
    (
        'mutation { createCredential(name: "n", search: { password: { eq: "x" } }) { id } }',
        "a create's non-input argument is still checked",
    ),
    (
        'mutation { createCredential(name: "n", password: "x") { id } }',
        "a create's argument other than its input",
    ),
    (
        'mutation { createCredentialX(definition: { password: "x" }) { id } }',
        "the exemption is by exact field name, not prefix",
    ),
    (
        'mutation { duplicateCredential(guid: "g", definition: { password: "x" }) { id } }',
        "duplicate is not exempt",
    ),
]

# Documents the rule must let through. Over-refusal is the safe direction, but a guard that
# refused everything would be removed, so the useful cases are pinned too.
ALLOWED: Final[list[tuple[str, str]]] = [
    *((_connection(root, fields), f"{root} metadata") for root, fields in TYPED_METADATA.items()),
    ("{ devices(first: 5) { edges { node { id name } } } }", "an ordinary read"),
    (_CREDENTIAL_LOOKUP, "a credential lookup without the definition"),
    ('{ credential(guid: "G") { id guid name type subType timeout } }', "the safe fields"),
    (
        '{ credential(guid: "G") { id customType editDate } }',
        "Credential's two problematic-stability metadata fields, found by the live tripwire",
    ),
    (
        (
            "{ credentials { edges { cursor node { __typename id } } pageInfo "
            "{ hasNextPage hasPreviousPage matchCount __typename } } }"
        ),
        "plumbing and typename",
    ),
    (
        "{ devices { edges { node { id snmpReadCredential { id name } } } } }",
        "Device.snmpReadCredential metadata",
    ),
    (
        (
            "{ credentialTests { edges { node { id name type typeDescription dateEdited logs "
            "{ date description id logMessage spoolId status step stepTip } } } } }"
        ),
        "credential tests and their logs",
    ),
    (
        "{ x { ...F } } fragment F on SnmpCredential { id name snmpVersion }",
        "a fragment of metadata",
    ),
    (
        "{ x { ... on SnmpCredential { id ...G } } } fragment G on SnmpCredential { snmpRetries }",
        "nested fragments of metadata",
    ),
    (
        "{ credentials { edges { node { ...F ...F } } } } fragment F on Credential { id }",
        "a fragment spread twice",
    ),
    # The template.
    (
        (
            '{ credentialFields(search: { type: { eq: UNIVERSAL }, subType: { eq: "aws ec2" } }) '
            "{ edges { node { type subType typeDescription definition "
            "powerPack { id guid name } } } } }"
        ),
        "the credential guide's template query",
    ),
    ("{ credentialField(id: 1) { definition } }", "one template"),
    (
        "{ x { ... on CredentialField { definition } } }",
        "a template by type condition",
    ),
    (
        "{ guidedDiscoveryWorkflows { edges { node { id name definition } } } }",
        "workflow definitions",
    ),
    ("{ guidedDiscoverySession(id: 1) { id definition } }", "session definitions (scrubbed)"),
    (
        (
            "{ credentials { edges { node { id } } } guidedDiscoveryWorkflows { edges { node "
            "{ definition } } } }"
        ),
        "a definition outside any credential context, beside one",
    ),
    ("query credentials { x { definition } }", "an operation name is not a field"),
    ("{ credentials { edges { node { id } } } } # definition", "definition in a comment"),
    ('{ credentials(search: { name: { contains: "x" } }) { edges { node { id } } } }', "a search"),
    (
        (
            '{ credentials(search: { type: { eq: "SNMP" } }, '
            'order: [{ field: "name", direction: asc }]) '
            "{ pageInfo { matchCount } } }"
        ),
        "the typed reader's own search and sort",
    ),
    ('{ credential(guid: "GI7I6QDXBG75AX3C2C1BCT1SE79PWDYD") { id } }', "a GUID spelling PWD"),
    ('{ x(note: "definition") { y } }', "definition in a string, no credential"),
    (
        '{ devices(search: { name: { contains: "hashicorp" } }) { pageInfo { matchCount } } }',
        "a search term containing a pattern word",
    ),
    ('{ x(note: """credential definition""") { y } }', "both words in a block string"),
    ("{ x(credential: 1) { y } }", "an argument named credential"),
    ("query($definition: JSON) { x(definition: $definition) { y } }", "definition as an argument"),
    ("{ x(search: { hasHarProvider: { id: 1 } }) { id } }", "a has-relation, not a hash"),
    (
        (
            'mutation($d: JSON) { createCredential(name: "n", type: UNIVERSAL, definition: $d) '
            "{ id guid name } }"
        ),
        "a create sending a definition, selecting id guid name",
    ),
    (
        'mutation($d: JSON) { updateCredential(guid: "g", definition: $d) { id guid } }',
        "an update sending a definition",
    ),
    (
        (
            'mutation { createCredential(name: "n", type: SNMP, alignedOrganizations: ["1"], '
            'definition: { password: "x" }) { id name } }'
        ),
        "a create's inline input",
    ),
    ("{ __typename }", "typename"),
    ('{ __type(name: "Credential") { fields { name } } }', "introspection of the type"),
    ("\ufeff{ devices { id } }", "a leading BOM"),
    ("query Definition { devices { id } }", "an operation named definition"),
    ("{ devices { id } } fragment definition on Device { id }", "a fragment named definition"),
]

# The measured metadata the patterns would otherwise match.
EXCEPTIONS: Final[list[str]] = [
    (
        "{ accounts { edges { node { passwordExpiration passwordReuseRule passwordStrength "
        "requirePasswordReset } } } }"
    ),
    "{ x { tokenDetails { tokenState tokenType name } } }",
    "{ accountPolicies { accessKeysEnabled } }",
    "{ accessKeyCategories { id name } }",
    "{ accessKeyHooks { edges { node { id name category { id name } } } } }",
    "{ x { httpHostNameHeader } }",
    "{ snmpCredentials { edges { node { snmpV3PrivacyProtocol } } } }",
    "{ devices { edges { node { bypassInterfaceInventory } } } }",
]


def _ids(table: list[tuple[str, str]]) -> list[str]:
    return [f"{index}-{why}" for index, (_, why) in enumerate(table)]


class TestTheRule:
    @pytest.mark.parametrize(("document", "why"), REFUSED, ids=_ids(REFUSED))
    def test_refused(self, document: str, why: str) -> None:
        assert _refused(document), f"not refused: {why}"

    @pytest.mark.parametrize(("document", "why"), ALLOWED, ids=_ids(ALLOWED))
    def test_allowed(self, document: str, why: str) -> None:
        assert guard.graphql_document_refusal(document) is None, f"refused: {why}"

    @pytest.mark.parametrize("document", EXCEPTIONS)
    def test_each_exception_is_allowed(self, document: str) -> None:
        assert guard.graphql_document_refusal(document) is None

    def test_each_exception_is_metadata_the_patterns_would_match(self) -> None:
        """An exception that no pattern matches is dead weight, and one that grew is a hole."""
        for name in guard.SECRET_NAME_EXCEPTIONS:
            assert any(pattern in name for pattern in guard.SECRET_NAME_PATTERNS), name
        assert len(guard.SECRET_NAME_EXCEPTIONS) == 12

    def test_neither_bare_pass_nor_bare_key_is_a_pattern(self) -> None:
        assert "pass" not in guard.SECRET_NAME_PATTERNS
        assert "key" not in guard.SECRET_NAME_PATTERNS
        assert not guard.is_secret_name("bypassInterfaceInventory")
        assert not guard.is_secret_name("deviceKey")

    def test_no_allowlisted_name_is_a_secret_name(self) -> None:
        """The union allowlist is sound only if none of its names is refused by R1 anyway."""
        for name in guard.CREDENTIAL_FIELD_ALLOWLIST | guard.TEMPLATE_FIELD_ALLOWLIST:
            assert not guard.is_secret_name(name), name

    @pytest.mark.parametrize(
        "variables",
        [
            {"s": {"definition": {"contains": "a"}}},
            {"o": [{"field": "definition", "direction": "asc"}]},
            {"o": [{"field": "snmpReadOnlyCommunity"}]},
            {"f": "password"},
            {"s": {"or": [{"sshKeyData": {"eq": "x"}}]}},
            {"s": {"editedBy": {"has": {"id": {"eq": "1"}}}}},
        ],
    )
    def test_a_secret_search_in_the_variables_is_refused(self, variables: dict[str, Any]) -> None:
        """The search shape can come entirely from variables, where no token can show it."""
        document = (
            "query($s: CredentialSearch, $o: [ConnectionOrder], $f: String) "
            "{ credentials(search: $s, order: $o) { pageInfo { matchCount } } }"
        )
        assert _refused(document, variables)

    def test_a_definition_variable_used_only_as_a_write_input_is_not_a_search(self) -> None:
        """``createCredential`` takes the caller's own definition, whose keys are not inspected."""
        document = (
            'mutation($definition: JSON) { createCredential(name: "n", type: SNMP, '
            "definition: $definition) { id guid } }"
        )
        for value in (
            json.dumps({"snmpRoCommunity": "x", "password": "y"}),
            {"snmpRoCommunity": "x", "password": "y"},
        ):
            assert guard.graphql_document_refusal(document, {"definition": value}) is None

    def test_a_write_variable_also_used_in_a_search_is_checked(self) -> None:
        document = (
            "query($d: JSON) { a: createCredential(definition: $d) { id } "
            "b: credentials(search: $d) { pageInfo { matchCount } } }"
        )
        assert _refused(document, {"d": {"password": {"eq": "x"}}})

    def test_variables_outside_a_credential_document_are_checked_for_secret_names(self) -> None:
        """Outside a credential document, only secret names count, not ``definition``."""
        document = "query($s: AccountSearch) { accounts(search: $s) { pageInfo { matchCount } } }"
        assert _refused(document, {"s": {"hash": {"contains": "a"}}})
        assert _refused(document, {"s": {"order": "token"}})
        assert guard.graphql_document_refusal(document, {"s": {"definition": "x"}}) is None
        assert guard.graphql_document_refusal(document, {"s": {"name": "hashicorp"}}) is None

    def test_non_string_variables_and_directive_arguments(self) -> None:
        """Numbers carry no name; a directive's argument is checked like a field's."""
        document = "query($n: Int) { credentials(first: $n) { pageInfo { matchCount } } }"
        assert guard.graphql_document_refusal(document, {"n": 5}) is None
        assert _refused(
            "{ credentials @x(order: [{ field: definition }]) { pageInfo { matchCount } } }"
        )

    def test_a_document_that_does_not_parse_is_refused_and_says_where(self) -> None:
        reason = guard.graphql_document_refusal("{ credentials { edges { node { id }")
        assert reason is not None
        assert "could not be read" in reason
        assert "line 1" in reason

    def test_every_refusal_points_at_the_typed_readers(self) -> None:
        for document, _ in REFUSED:
            reason = guard.graphql_document_refusal(document)
            assert reason is not None
            if "could not be read" not in reason:
                assert "sl1_get_credential" in reason
                assert "sl1_list_credentials" in reason

    def test_a_refusal_names_the_field(self) -> None:
        reason = guard.graphql_document_refusal(_connection("snmpCredentials", "snmpV3Context x"))
        assert reason is not None
        assert "x inside a credential" in reason

    def test_every_secret_key_is_refused_as_a_field(self) -> None:
        for key in CREDENTIAL_SECRET_KEYS:
            assert _refused(f"{{ a {{ {key} }} }}"), key

    def test_a_long_fragment_chain_is_refused_rather_than_exhausting_the_stack(self) -> None:
        count = 400
        chain = " ".join(f"fragment F{i} on T {{ a {{ ...F{i + 1} }} }}" for i in range(count))
        document = f"{{ x {{ ...F0 }} }} {chain} fragment F{count} on T {{ b }}"
        assert _refused(document)

    def test_many_spreads_of_one_fragment_are_walked_once_per_context(self) -> None:
        spreads = " ".join("...F" for _ in range(2000))
        document = (
            f"{{ credentials {{ edges {{ node {{ {spreads} }} }} }} }} fragment F on T {{ id }}"
        )
        assert guard.graphql_document_refusal(document) is None


class TestBypassAttempts:
    """Each of these was tried against the rule. Every one must stay refused."""

    @pytest.mark.parametrize(
        "document",
        [
            # Comments and strings cannot hide a selection, and cannot fake one away.
            '{ credentials { edges { node { "x" } } } }',
            "{ credentials { edges { node { id #\n definition } } } }",
            "{ credentials { edges { node { id #\r definition } } } }",
            '{ credentials(x: "#") { edges { node { definition } } } }',
            '{ credentials(x: """ \\""" { """) { edges { node { definition } } } }',
            # Unicode lookalikes and escapes: names are ASCII and cannot be escaped.
            "{ credentials { edges { node { d\u0435finition } } } }",
            "{ credentials { edges { node { \\u0064efinition } } } }",
            # Line terminators GraphQL does not recognise.
            "{ credentials { edges { node { id # \u2028 definition\n } } } }",
            # Fragments split across the document, nested, and spread from a sibling.
            "fragment A on X { ...B } fragment B on Y { definition } { credentials { ...A } }",
            "{ credentials { ...A } } fragment A on X { ... on Y { ... { definition } } }",
            (
                "{ x { ...A } } fragment A on X { ... on SshCredential { ...B } } fragment B on Z "
                "{ sshKeyData }"
            ),
            # The typename trick: a credential reached through a union field.
            "{ search { __typename ... on Credential { definition } } }",
            "{ search { ... on SnmpCredential { id snmpReadOnlyCommunity } } }",
            # Operation-name tricks: the dangerous operation is not the one named.
            "query Safe { devices { id } } query Unsafe { credentials { node { definition } } }",
            # Mutations, aliased.
            'mutation { a: createCredential(name: "n") { b: definition } }',
            # Commas and whitespace everywhere.
            "{,credentials,{,edges,{,node,{,definition,},},},}",
            "\ufeff\t{\r\ncredentials\n{edges{node{definition}}}}",
            # A credential field re-entered from inside a template.
            "{ credentialFields { edges { node { credential { definition } } } } }",
            # The template's powerPack is held to id, guid and name.
            "{ credentialFields { edges { node { powerPack { hash } } } } }",
            "{ credentialFields { edges { node { powerPack { editedBy { id } } } } } }",
        ],
    )
    def test_still_refused(self, document: str) -> None:
        assert _refused(document)

    def test_a_bom_inside_a_name_splits_it_for_the_server_too(self) -> None:
        """The BOM is an ignored token, so ``de<BOM>finition`` is two fields, not ``definition``.

        Not a bypass: SL1 sees the same two fields. Pinned so that a scanner change that glued the
        halves together (and so disagreed with the server) shows up.
        """
        summary = summarize_executable_document("{ a { de\ufefffinition } }")
        assert [f.name for f in summary.fields] == ["a", "de", "finition"]
        assert _refused("{ credentials { edges { node { de\ufefffinition } } } }")

    @settings(deadline=None)
    @given(
        separators=st.lists(
            st.sampled_from([" ", ",", "\t", "\n", "\r\n", "\ufeff", " # c\n", ",,\n"]),
            min_size=40,
            max_size=40,
        ),
        alias=st.one_of(st.none(), st.from_regex(r"[A-Za-z_][A-Za-z0-9_]{0,8}", fullmatch=True)),
        target=st.sampled_from(
            [
                ("credentials", "definition"),
                ("credential", "definition"),
                ("snmpCredentials", "snmpReadOnlyCommunity"),
                ("soapCredentials", "curlProxyPassword"),
                ("devices", "hash"),
                ("x", "credentialTranslatedByCustomType"),
                ("y", "sshKeyData"),
                ("accounts", "httpUsernamePassword"),
            ]
        ),
    )
    def test_ignored_tokens_and_aliases_never_change_the_verdict(
        self, separators: list[str], alias: str | None, target: tuple[str, str]
    ) -> None:
        """Rebuild one refused document with random ignored tokens between every token."""
        root, leaf = target
        selected = [alias, ":", leaf] if alias else [leaf]
        tokens = ["{", root, "{", "edges", "{", "node", "{", "id", *selected, "}", "}", "}", "}"]
        document = "".join(sep + tok for sep, tok in zip(separators, tokens, strict=False))
        assert _refused(document)

    @settings(deadline=None)
    @given(
        allowed=st.lists(st.sampled_from(sorted(guard.CREDENTIAL_FIELD_ALLOWLIST)), min_size=1),
        secret=st.one_of(
            st.none(),
            st.sampled_from([s for secrets in TYPED_SECRETS.values() for s in secrets] + UNLISTED),
        ),
        position=st.integers(min_value=0, max_value=20),
        wrap=st.sampled_from(["plain", "inline", "fragment"]),
    )
    def test_the_allowlist_admits_its_names_and_nothing_else(
        self, allowed: list[str], secret: str | None, position: int, wrap: str
    ) -> None:
        """Any mix of allowlisted names passes; one unlisted name anywhere among them refuses."""
        fields = list(allowed)
        if secret is not None:
            fields.insert(position % (len(fields) + 1), secret)
        body = " ".join(fields)
        if wrap == "plain":
            document = _connection("snmpCredentials", body)
        elif wrap == "inline":
            document = f"{{ x {{ ... on SnmpCredential {{ {body} }} }} }}"
        else:
            document = f"{{ x {{ ...F }} }} fragment F on SoapCredential {{ {body} }}"
        assert _refused(document) is (secret is not None)


class TestCredentialNamedFields:
    """R2: a field named with ``cred`` is a known credential-returning field, or it is refused."""

    @pytest.mark.parametrize(
        "document",
        [
            # The measured leak: a String holding HTTP authentication as ``user:password``.
            "{ monitorSoapXmlTransaction(id: 1) { httpAuthenticationCredential } }",
            (
                "{ monitorSoapXmlTransactions { edges { node { id url httpAuthenticationMethod "
                "httpAuthenticationCredential } } } }"
            ),
            "{ x { a: httpAuthenticationCredential } }",
            # Unknown ``cred`` fields, scalar or object, outside any credential context.
            "{ devices { edges { node { proxyCredentialRef } } } }",
            "{ x { someCredential { id } } }",
            "{ creds { id } }",
            # And inside one: no longer a way to open a fresh credential context.
            "{ credential(id: 1) { credentialXyz } }",
            "{ credentials { edges { node { id lastCredentialValue } } } }",
            "{ snmpCredentials { edges { node { credentialsBlob { id } } } } }",
            # A mutation returning a scalar is not a known credential field either.
            'mutation { deleteCredential(guid: "g") }',
            '{ credentialTranslatedBySubType(guid: "g") { id } }',
        ],
    )
    def test_refused(self, document: str) -> None:
        reason = guard.graphql_document_refusal(document)
        assert reason is not None, document
        assert "sl1_get_credential" in reason

    def test_an_unknown_cred_field_is_named_in_the_refusal(self) -> None:
        for document in (
            "{ x { someCredentialThing } }",
            "{ credential(id: 1) { someCredentialThing } }",
        ):
            reason = guard.graphql_document_refusal(document)
            assert reason is not None
            assert "someCredentialThing" in reason
            assert "not one of the credential fields" in reason

    def test_the_soap_http_authentication_is_a_secret_name(self) -> None:
        assert guard.is_secret_name("httpAuthenticationCredential")
        assert "httpauthenticationcredential" in guard.KNOWN_SECRET_FIELD_NAMES
        assert _refused(
            "{ monitorSoapXmlTransactions(order: [{ field: httpAuthenticationCredential }]) "
            "{ pageInfo { matchCount } } }"
        )

    @pytest.mark.parametrize("field", sorted(guard.CREDENTIAL_CONTEXT_FIELDS))
    def test_every_context_opening_field_admits_metadata_and_nothing_else(self, field: str) -> None:
        assert guard.graphql_document_refusal(f"{{ x {{ {field} {{ id name }} }} }}") is None
        assert _refused(f"{{ x {{ {field} {{ id definition }} }} }}")

    @pytest.mark.parametrize(
        "document",
        [
            "{ globalManagerStacks { edges { node { credential { id name } } } } }",
            "{ devices { edges { node { alignedDynamicApplications { credential { id } } } } } }",
            "{ discoverySessions { edges { node { credentials { id guid name } } } } }",
            "{ devices { edges { node { snmpReadWriteCredential { id name } } } } }",
            "{ credentialTestLogs { edges { node { id logMessage status } } } }",
        ],
    )
    def test_a_context_opening_field_with_safe_fields_is_allowed(self, document: str) -> None:
        assert guard.graphql_document_refusal(document) is None


# R3's path rule: probes a document can carry without naming ``cred`` in any token.
_DEVICE_SEARCH: Final = (
    "query($s: DeviceSearch) { devices(search: $s) { pageInfo { matchCount } } }"
)
_DEVICE_ORDER: Final = (
    "query($o: [ConnectionOrder]) { devices(order: $o) { edges { node { id } } } }"
)


class TestPathProbes:
    """A search or sort reaching a credential through an input key or a field-path string."""

    @pytest.mark.parametrize(
        ("document", "variables"),
        [
            # The reported bypass: the whole search in the variables.
            (
                _DEVICE_SEARCH,
                {"s": {"snmpReadCredential": {"has": {"definition": {"contains": "p"}}}}},
            ),
            (_DEVICE_SEARCH, {"s": {"snmpReadCredential": {"has": {"somethingNew": {"eq": "p"}}}}}),
            (_DEVICE_SEARCH, {"s": {"and": [{"snmpReadCredential": {"definition": {"eq": "p"}}}]}}),
            (_DEVICE_SEARCH, {"s": {"unknownCredential": {"has": {"id": {"eq": "1"}}}}}),
            # A variable placed beneath a credential key written in the document.
            (
                (
                    "query($x: X) { devices(search: { snmpReadCredential: $x }) "
                    "{ pageInfo { matchCount } } }"
                ),
                {"x": {"has": {"definition": {"contains": "p"}}}},
            ),
            # The dotted string form, in the variables.
            (_DEVICE_ORDER, {"o": [{"field": "snmpReadCredential.definition"}]}),
            (_DEVICE_ORDER, {"o": [{"field": "snmpReadCredential[definition]"}]}),
            (_DEVICE_ORDER, {"o": [{"field": 'snmpReadCredential["definition"]'}]}),
            (_DEVICE_ORDER, {"o": [{"field": "snmpReadCredential[0].definition"}]}),
            (_DEVICE_ORDER, {"o": [{"field": "snmpReadCredential.somethingNew"}]}),
            (_DEVICE_ORDER, {"o": [{"field": " snmpReadCredential . alignedOrganizations "}]}),
            (_DEVICE_ORDER, {"o": [{"field": "someCredential.id"}]}),
        ],
    )
    def test_variable_borne_probes_are_refused(
        self, document: str, variables: dict[str, Any]
    ) -> None:
        assert _refused(document, variables)

    @pytest.mark.parametrize(
        "document",
        [
            (
                "{ devices(search: { snmpReadCredential: "
                '{ has: { definition: { contains: "p" } } } }) { pageInfo { matchCount } } }'
            ),
            '{ devices(order: [{ field: "snmpReadCredential.definition" }]) { edges { id } } }',
            '{ devices(order: [{ field: "snmpReadCredential[definition]" }]) { pageInfo { x } } }',
            '{ devices(order: [{ field: """snmpReadCredential.editedBy""" }]) { pageInfo { x } } }',
            (
                'query($o: [ConnectionOrder] = [{ field: "snmpReadCredential.definition" }]) '
                "{ devices(order: $o) { pageInfo { matchCount } } }"
            ),
            (
                '{ devices @include(if: true) { x(order: [{ field: "snmpReadCredential.foo" }]) '
                "{ id } } }"
            ),
            "{ devices(search: { snmpReadCredential: { has: { foo: { eq: 1 } } } }) { id } }",
        ],
    )
    def test_literal_probes_are_refused(self, document: str) -> None:
        reason = guard.graphql_document_refusal(document)
        assert reason is not None
        assert "sl1_get_credential" in reason

    @pytest.mark.parametrize(
        ("document", "variables"),
        [
            ('{ devices(search: { name: { contains: "x" } }) { edges { node { id } } } }', None),
            (_DEVICE_SEARCH, {"s": {"name": {"contains": "x"}}}),
            # A device's credential searched on its metadata, and sorted by it.
            (_DEVICE_SEARCH, {"s": {"snmpReadCredential": {"has": {"name": {"contains": "x"}}}}}),
            (_DEVICE_SEARCH, {"s": {"snmpReadCredential": {"has": {"id": {"in": ["1", "2"]}}}}}),
            (_DEVICE_ORDER, {"o": [{"field": "snmpReadCredential.name", "direction": "asc"}]}),
            # Comparison data is not a field path, even where it contains ``cred``.
            (_DEVICE_SEARCH, {"s": {"name": {"contains": "acme.creditunion.org"}}}),
            (
                _DEVICE_SEARCH,
                {"s": {"snmpReadCredential": {"has": {"name": {"eq": "creds.prod.east"}}}}},
            ),
            (
                '{ devices(search: { name: { contains: "creditunion" } }) { pageInfo { x } } }',
                None,
            ),
            ('{ x(note: """credential definition""") { y } }', None),
        ],
    )
    def test_ordinary_searches_still_pass(
        self, document: str, variables: dict[str, Any] | None
    ) -> None:
        assert guard.graphql_document_refusal(document, variables) is None

    @pytest.mark.parametrize(
        "document",
        [
            'mutation($d: JSON) { createCredential(name: "n", type: SNMP, definition: $d) { id } }',
            'mutation($d: JSON) { updateCredential(guid: "g", definition: $d) { id guid } }',
        ],
    )
    def test_a_credential_write_still_carries_its_own_secrets(self, document: str) -> None:
        """The write's own input is exempt, as before, whatever keys or strings it holds."""
        secret = {
            "password": "x",
            "snmpRoCommunity": "y",
            "credentialRef": {"definition": "snmpReadCredential.definition"},
        }
        for value in (secret, json.dumps(secret)):
            assert guard.graphql_document_refusal(document, {"d": value}) is None

    def test_a_variable_nested_beyond_the_walk_limit_is_refused(self) -> None:
        deep: object = "x"
        for _ in range(200):
            deep = [deep]
        assert _refused(_DEVICE_ORDER, {"o": deep})

    def test_the_write_exemption_is_no_wider(self) -> None:
        """A write variable used anywhere else is still checked, by the path rule too."""
        document = (
            "mutation($d: JSON) { a: createCredential(definition: $d) { id } "
            "b: devices(search: $d) { pageInfo { matchCount } } }"
        )
        assert _refused(document, {"d": {"snmpReadCredential": {"has": {"foo": {"eq": "x"}}}}})


# ---- the response scrub -------------------------------------------------------------------------


def _shapes_for(credential_type: str) -> list[object]:
    """Every shape a credential's secrets have been, or could plausibly be, returned in."""
    node = node_for(credential_type)
    as_object = {**node, "definition": json.loads(node["definition"])}
    untyped = {k: v for k, v in node.items() if k not in {"type", "subType"}}
    aliased = {k: v for k, v in node.items() if k != "definition"} | {"d": node["definition"]}
    return [
        {"credential": node},
        {"credentials": {"edges": [{"node": node}, {"node": as_object}]}},
        {"credential": untyped},
        {"credential": {**untyped, "__typename": "Credential"}},
        # An aliased definition: the node is not recognised as one, and still loses its secrets.
        {"credential": aliased},
        # A bare stringified definition under some other key, with and without a BOM.
        {"translated": node["definition"]},
        {"translated": "\ufeff" + node["definition"]},
        {"translated": " \ufeff\n" + json.dumps(node["definition"])},
        # A bare definition object with no type anywhere.
        {"definition_like": json.loads(node["definition"])},
        # A Guided Discovery session whose definition embeds full credential objects, as the UI
        # writes them -- and the same, stringified twice.
        {"session": {"definition": json.dumps({"rootDevice": 1, "credentials": [node]})}},
        {"session": {"definition": json.dumps(json.dumps({"credentials": [as_object]}))}},
        # A template-shaped credential: kept as a template, its secret keys still dropped.
        {"n": {"type": credential_type, "definition": json.dumps({"fields": [], **as_object})}},
        [[{"deep": [{"x": node}]}]],
    ]


class TestTheScrub:
    @pytest.mark.parametrize("credential_type", sorted(CREDENTIAL_TYPES))
    def test_no_secret_survives_in_any_shape(self, credential_type: str) -> None:
        for shape in _shapes_for(credential_type):
            _assert_no_secret(guard.scrub_credential_secrets(shape))

    def test_a_typed_node_keeps_its_safe_fields_and_names_what_it_lost(self) -> None:
        scrubbed = guard.scrub_credential_secrets({"credential": node_for("SNMP")})
        node = scrubbed["credential"]
        assert node["definition"]["port"] == "safe-value"
        assert "snmpRoCommunity" in node["definition_withheld_keys"]
        assert node["name"] == "Sample SNMP"

    def test_a_node_of_unknown_type_withholds_its_whole_definition(self) -> None:
        node = {k: v for k, v in node_for("SNMP").items() if k != "type"}
        scrubbed = guard.scrub_credential_secrets(node)
        assert scrubbed["definition"] == {}
        assert "definition_withheld_reason" in scrubbed

    def test_fields_outside_the_safe_set_are_dropped_from_a_node(self) -> None:
        node = {**node_for("SSH_KEY"), "alignedOrganizations": [{"hash": CANARY}]}
        scrubbed = guard.scrub_credential_secrets({"n": node})
        assert "alignedOrganizations" not in scrubbed["n"]
        _assert_no_secret(scrubbed)

    def test_a_secret_bearing_object_lists_what_was_withheld(self) -> None:
        scrubbed = guard.scrub_credential_secrets({"password": CANARY, "host": "h"})
        assert scrubbed == {"host": "h", guard.WITHHELD_KEYS_FIELD: ["password"]}

    @pytest.mark.parametrize(
        ("body", "withheld"),
        [
            ({"id": "1", "hash": CANARY, "passwordStrength": "high"}, ["hash"]),
            ({"jwt": CANARY, "agent": "1"}, ["jwt"]),
            ({"token": CANARY, "tokenDetails": {"tokenState": "ACTIVE"}}, ["token"]),
            (
                {"url": "u", "httpUsernamePassword": CANARY, "cookieValue": CANARY},
                ["cookieValue", "httpUsernamePassword"],
            ),
            ({"customHeader": CANARY, "httpHostNameHeader": "h"}, ["customHeader"]),
            ({"proxyAccountPassword": CANARY, "name": "n"}, ["proxyAccountPassword"]),
            ({"snmpReadOnlyCommunity": CANARY, "snmpVersion": 2}, ["snmpReadOnlyCommunity"]),
            ({"curlRequestSub1": CANARY, "curlUrl": "u"}, ["curlRequestSub1"]),
            ({"verification_answer": CANARY, "user": "u"}, ["verification_answer"]),
            ({"accessKeys": [{"id": "1"}], "accessKeysEnabled": True}, ["accessKeys"]),
        ],
    )
    def test_secret_named_keys_are_dropped_from_any_object(
        self, body: dict[str, Any], withheld: list[str]
    ) -> None:
        """Pattern-based, on every object, not only credential-shaped ones."""
        scrubbed = guard.scrub_credential_secrets({"data": {"x": body}})["data"]["x"]
        assert scrubbed[guard.WITHHELD_KEYS_FIELD] == withheld
        for key in body:
            if key not in withheld:
                assert key in scrubbed
        _assert_no_secret(scrubbed)

    def test_scrubbing_twice_keeps_the_withheld_list(self) -> None:
        once = guard.scrub_credential_secrets({"hash": CANARY, "id": "1"})
        assert guard.scrub_credential_secrets(once) == once

    def test_a_template_keeps_its_definition(self) -> None:
        """``CredentialField`` is a field-mapping template; the credential guide needs it whole."""
        template = json.dumps({"fields": [{"propName": "ProxyPasswd", "encryption": True}]})
        for node in (
            {"type": "UNIVERSAL", "subType": "aws ec2", "definition": template},
            {"__typename": "CredentialField", "type": "UNIVERSAL", "definition": template},
        ):
            body = {"data": {"credentialFields": {"edges": [{"node": node}]}}}
            assert guard.scrub_credential_secrets(body) == body

    def test_a_template_shaped_node_with_an_id_is_a_credential(self) -> None:
        node = {"id": "1", "type": "UNIVERSAL", "definition": json.dumps({"fields": []})}
        assert "definition_withheld_keys" in guard.scrub_credential_secrets(node)

    @pytest.mark.parametrize(
        "row",
        [
            {"cred_name": "n", "cred_pwd": CANARY},
            {"cred_user": "u", "snmp_ro_community": CANARY, "snmpv3_priv_pwd": CANARY},
            {"cred_name": "n", "curl_options": CANARY, "ssh_key": CANARY, "cred_cert": CANARY},
            {"URI": "/api/credential/basic/7", "proxy_passwd": CANARY, "api_token": CANARY},
        ],
    )
    def test_rest_credential_shaped_objects_lose_secret_named_keys(
        self, row: dict[str, Any]
    ) -> None:
        """REST field names were not recorded here, so a name heuristic stands in, closed."""
        _assert_no_secret(guard.scrub_credential_secrets({"result_set": [row]}))

    def test_ordinary_responses_are_untouched(self) -> None:
        body = {
            "data": {
                "devices": {
                    "edges": [
                        {"node": {"id": "1", "name": "core", "opts_note": "x", "deviceKey": "k"}}
                    ]
                },
                "workflow": {
                    "definition": json.dumps({"workflowSteps": [{"field": "rootDevice"}]})
                },
                "text": "not json {",
                "log": "  connected [ok]",
                "n": [1, 2.5, True, None],
                "bypassInterfaceInventory": False,
            }
        }
        assert guard.scrub_credential_secrets(body) == body

    def test_an_untouched_json_string_keeps_its_exact_text(self) -> None:
        for text in ('{ "a" :   1 }', '\ufeff{"a": 1}'):
            assert guard.scrub_credential_secrets({"s": text}) == {"s": text}

    def test_a_scrubbed_json_string_stays_a_string(self) -> None:
        for text in (json.dumps({"password": CANARY}), "\ufeff" + json.dumps({"password": CANARY})):
            scrubbed = guard.scrub_credential_secrets({"s": text})
            assert isinstance(scrubbed["s"], str)
            assert json.loads(scrubbed["s"]) == {guard.WITHHELD_KEYS_FIELD: ["password"]}

    @pytest.mark.parametrize(
        "text",
        [
            '{"password": "' + CANARY + '", "pad": "xx',
            '\ufeff  [{"definition": "{\\"snmpRoCommunity\\": \\"' + CANARY,
            "\n{not json " + CANARY,
            "[" + CANARY,
        ],
    )
    def test_a_string_that_starts_like_json_and_does_not_parse_is_withheld(self, text: str) -> None:
        """A truncated JSON string cannot be checked, so it is not passed through."""
        scrubbed = guard.scrub_credential_secrets({"s": text, "t": [text]})
        _assert_no_secret(scrubbed)
        assert scrubbed["s"].startswith("**withheld:")
        assert "does not parse" in scrubbed["s"]

    @pytest.mark.parametrize(
        "text", ["not json {", "x[1]", "  plain", '"a quoted string', "", "{}", "[1, 2]"]
    )
    def test_other_strings_are_not_withheld(self, text: str) -> None:
        assert guard.scrub_credential_secrets({"s": text}) == {"s": text}

    def test_the_soap_http_authentication_is_scrubbed(self) -> None:
        body = {"node": {"id": "1", "httpAuthenticationCredential": "admin:" + CANARY}}
        scrubbed = guard.scrub_credential_secrets(body)
        _assert_no_secret(scrubbed)
        assert scrubbed["node"][guard.WITHHELD_KEYS_FIELD] == ["httpAuthenticationCredential"]

    def test_depth_is_bounded_and_fails_closed(self) -> None:
        value: object = {"password": CANARY}
        for _ in range(guard.MAX_SCRUB_DEPTH + 5):
            value = [value]
        _assert_no_secret(guard.scrub_credential_secrets(value))

    def test_the_input_is_not_mutated(self) -> None:
        body = {"credential": node_for("UNIVERSAL")}
        before = json.dumps(body, sort_keys=True)
        guard.scrub_credential_secrets(body)
        assert json.dumps(body, sort_keys=True) == before

    @settings(deadline=None)
    @given(data=st.data())
    def test_no_planted_secret_survives_any_nesting(self, data: st.DataObject) -> None:
        """Plant credential payloads at random places in random JSON and look for any of them."""
        planted = st.builds(
            lambda credential_type, key, stringify, typed: (
                lambda definition: {
                    **({"type": credential_type} if typed else {}),
                    "definition": json.dumps(definition) if stringify else definition,
                }
            )({**json.loads(definition_for(credential_type, secrets=False)), key: CANARY}),
            st.sampled_from(sorted(CREDENTIAL_TYPES)),
            st.sampled_from(KNOWN_SECRET_KEYS),
            st.booleans(),
            st.booleans(),
        )
        # A secret under a key matching the patterns, on an object that is not credential-shaped.
        pattern_keyed = st.builds(
            lambda prefix, pattern, suffix: {f"{prefix}{pattern}{suffix}": CANARY, "id": "1"},
            st.sampled_from(["", "x", "proxy", "Http"]),
            st.sampled_from(guard.SECRET_NAME_PATTERNS),
            st.sampled_from(["", "Value", "1", "_data"]),
        )
        leaves = st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=6), planted)
        tree = st.recursive(
            leaves,
            lambda children: st.one_of(
                st.lists(children, max_size=3),
                st.dictionaries(st.text(max_size=5), children, max_size=3),
                children.map(json.dumps),
            ),
            max_leaves=12,
        )
        # One payload is always planted, wrapped in random layers, beside the random tree; drawn
        # this way rather than filtered, so every example carries a secret.
        wrapped: object = data.draw(st.one_of(planted, pattern_keyed))
        for layer in data.draw(st.lists(st.sampled_from(["list", "dict", "json"]), max_size=5)):
            if layer == "list":
                wrapped = [wrapped]
            elif layer == "dict":
                wrapped = {data.draw(st.text(max_size=5)): wrapped}
            else:
                wrapped = json.dumps(wrapped)
        value = [data.draw(tree), wrapped] if data.draw(st.booleans()) else {"x": wrapped}
        assert CANARY in json.dumps(value), "non-vacuity: the example carries a secret"
        _assert_no_secret(guard.scrub_credential_secrets(value))


class TestTheCanonicalSecretKeys:
    def test_the_tests_and_the_source_share_one_list(self) -> None:
        assert tuple(KNOWN_SECRET_KEYS) == CREDENTIAL_SECRET_KEYS

    def test_the_write_path_subset_is_a_subset(self) -> None:
        assert set(CRED_SECRET_KEYS) <= set(CREDENTIAL_SECRET_KEYS)

    def test_no_duplicates(self) -> None:
        assert len(set(CREDENTIAL_SECRET_KEYS)) == len(CREDENTIAL_SECRET_KEYS)

    def test_every_secret_key_is_a_secret_name(self) -> None:
        for key in CREDENTIAL_SECRET_KEYS:
            assert guard.is_secret_name(key), key


# ---- the REST rule ------------------------------------------------------------------------------


class TestRestPathNormalisation:
    @pytest.mark.parametrize(
        ("path", "segments"),
        [
            ("credential", ("credential",)),
            ("/credential/", ("credential",)),
            ("/api/credential", ("credential",)),
            ("api/api/credential", ("credential",)),
            ("CREDENTIAL/SNMP", ("credential", "snmp")),
            ("credential//snmp///1", ("credential", "snmp", "1")),
            ("credential%2Fsnmp%2F1", ("credential", "snmp", "1")),
            ("cred%65ntial/snmp/1", ("credential", "snmp", "1")),
            ("cred%2565ntial/snmp/1", ("credential", "snmp", "1")),
            ("device/%2e%2e/credential/snmp/1", ("credential", "snmp", "1")),
            ("device/%2E%2E/%2e%2e/credential", ("credential",)),
            ("./credential/./snmp", ("credential", "snmp")),
            ("credential;x=1/snmp", ("credential", "snmp")),
            ("credential?extended_fetch=1", ("credential",)),
            ("credential#frag", ("credential",)),
            ("device/1", ("device", "1")),
        ],
    )
    def test_segments(self, path: str, segments: tuple[str, ...]) -> None:
        normalized = guard.normalized_rest_path(path)
        assert normalized is not None
        assert normalized[0] == segments

    def test_a_path_that_never_stops_decoding_counts_as_a_credential_path(self) -> None:
        # Five levels of encoding: still changing after the normaliser's last round.
        path = "device/%252525252541"
        assert guard.normalized_rest_path(path) is None
        assert guard.is_credential_path(path)


class TestRestRule:
    @pytest.mark.parametrize(
        ("method", "path", "query"),
        [
            ("GET", "credential", {}),
            ("GET", "/api/credential/snmp", {"limit": "10", "offset": "0"}),
            ("GET", "credential/universal/", {"hide_filterinfo": "1"}),
            ("GET", "device/1", {"extended_fetch": "1"}),
            ("POST", "device/1", {}),
            ("GET", "device", {"link_disp_field": "name"}),
            ("GET", "device", {"link_disp_field": "Description"}),
            ("GET", "device", {"filter.name.contains": "password"}),
            ("GET", "account", {"order.user": "ASC", "filter.passwordStrength": "1"}),
            ("GET", "device?filter.name.contains=core&link_disp_field=name", {}),
            ("GET", "device", {"filter.bypass_interface.eq": "1"}),
        ],
    )
    def test_allowed(self, method: str, path: str, query: dict[str, str]) -> None:
        guard.check_rest_credential_access(method, path, query)

    @pytest.mark.parametrize(
        ("method", "path", "query"),
        [
            ("GET", "credential/snmp/1", {}),
            ("GET", "/api/credential/basic/1/", {}),
            ("GET", "credential/ssh/1/extra", {}),
            ("GET", "credential/1", {}),
            ("GET", "credential/notatype", {}),
            ("GET", "CREDENTIAL%2Fsnmp%2F1", {}),
            ("GET", "credential/snmp", {"extended_fetch": "1"}),
            ("GET", "credential/snmp", {"extended_fetch": "0"}),
            ("GET", "credential", {"filter.cred_pwd.begins_with": "a"}),
            ("GET", "credential", {"order.cred_pwd": "ASC"}),
            ("GET", "credential", {"filter.cred_name.contains": "a"}),
            ("GET", "credential?extended_fetch=1", {}),
            ("GET", "credential;x", {}),
            ("GET", "credential/snmp/_lookup", {}),
            ("POST", "credential/snmp", {}),
            ("PUT", "credential/snmp/1", {}),
            ("DELETE", "credential/snmp/1", {}),
            ("POST", "/api/credential", {}),
        ],
    )
    def test_refused(self, method: str, path: str, query: dict[str, str]) -> None:
        with pytest.raises(ValidationBlocked) as raised:
            guard.check_rest_credential_access(method, path, query)
        message = raised.value.findings[0].message
        assert "sl1_" in message, "every refusal names the typed tool to use instead"

    @pytest.mark.parametrize(
        ("path", "query"),
        [
            ("device", {"link_disp_field": "cred_pwd"}),
            ("device/1", {"link_disp_field": "snmp_ro_community"}),
            ("dynamic_app", {"LINK_DISP_FIELD": "anything"}),
            ("device", {"link%5Fdisp%5Ffield": "cred_pwd"}),
            ("device", {"link_disp_field": "na%6De,cred_pwd"}),
            ("account", {"filter.passwd.contains": "a"}),
            ("account", {"filter.verification_answer.begins_with": "a"}),
            ("account", {"order.verification_question": "ASC"}),
            ("account", {"order.hash": "DESC"}),
            ("account", {"filter%2Epassword": "a"}),
            ("account", {"FILTER.Password.eq": "a"}),
            ("account", {"filter[password][eq]": "a"}),
            ("account", {"filter.0.cred_pwd": "a"}),
            ("monitor/web_content", {"order.http_username_password": "ASC"}),
            ("account?order.verification_answer=ASC", {}),
            ("account?link_disp_field=cred_pwd", {}),
            ("account%3Forder.hash%3DASC", {}),
        ],
    )
    def test_query_parameters_are_checked_on_every_path(
        self, path: str, query: dict[str, str]
    ) -> None:
        """``link_disp_field`` and ``filter.``/``order.`` on a secret, wherever the resource is.

        Off a credential path the refusal says what to do instead without pointing at the
        credential tools, which are no alternative for a device or account read.
        """
        with pytest.raises(ValidationBlocked) as raised:
            guard.check_rest_credential_access("GET", path, query)
        message = raised.value.findings[0].message
        assert "sl1_get_credential" not in message
        assert "instead" in message or "Omit it" in message

    def test_a_query_refusal_is_addressed_to_the_parameters(self) -> None:
        with pytest.raises(ValidationBlocked) as raised:
            guard.check_rest_credential_access("GET", "device", {"link_disp_field": "x"})
        assert raised.value.findings[0].path == "query_params"
        with pytest.raises(ValidationBlocked) as raised:
            guard.check_rest_credential_access("GET", "device?link_disp_field=x", {})
        assert raised.value.findings[0].path == "path"

    def test_a_parameter_that_never_stops_decoding_is_refused(self) -> None:
        with pytest.raises(ValidationBlocked):
            guard.check_rest_credential_access("GET", "device", {"x": "%252525252541"})

    def test_a_path_that_never_stops_decoding_is_refused(self) -> None:
        with pytest.raises(ValidationBlocked):
            guard.check_rest_credential_access("GET", "device/%252525252541", {})

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("POST", "%2e%2e/gql"),
            ("POST", "device/%2E%2E/%2e%2e/gql"),
            ("GET", "device/%252e%252e/account"),
            ("GET", "device%2f%2e%2e%2fcredential"),
        ],
    )
    def test_an_encoded_traversal_is_refused_on_any_path(self, method: str, path: str) -> None:
        """``%2e%2e`` passes the literal-``..`` check and could reach ``/gql``, past its guard."""
        with pytest.raises(ValidationBlocked) as raised:
            guard.check_rest_credential_access(method, path, {})
        assert "'..'" in raised.value.findings[0].message

    def test_the_index_is_projected_onto_uri_and_description(self) -> None:
        body = {
            "searchspec": {"fields": {"cred_name": {"type": "string"}}},
            "total_matched": 2,
            "total_returned": 2,
            "result_set": [
                {"URI": "/api/credential/snmp/1", "description": "public", "cred_pwd": CANARY},
                "/api/credential/snmp/2",
            ],
        }
        shaped = guard.shape_rest_response("credential/snmp", body)
        assert shaped["result_set"] == [
            {"URI": "/api/credential/snmp/1", "description": "public"},
            "/api/credential/snmp/2",
        ]
        assert shaped["total_matched"] == 2
        _assert_no_secret(shaped)

    @pytest.mark.parametrize(
        "body",
        [
            {"/api/credential/snmp/1": {"cred_pwd": CANARY}},
            {"result_set": {"/api/credential/snmp/1": {"cred_pwd": CANARY}}},
            {"cred_name": "n", "cred_pwd": CANARY},
            [[CANARY]],
            "plain",
        ],
    )
    def test_an_index_in_any_other_shape_is_withheld_entirely(self, body: object) -> None:
        with pytest.raises(ValidationBlocked):
            guard.shape_rest_response("credential", body)

    def test_a_non_credential_response_loses_rest_secret_fields(self) -> None:
        body = {"user": "u", "verification_answer": CANARY, "passwd": CANARY, "email": "e"}
        shaped = guard.shape_rest_response("account/1", body)
        assert shaped == {
            "user": "u",
            "email": "e",
            guard.WITHHELD_KEYS_FIELD: ["passwd", "verification_answer"],
        }


# ---- the tools end to end -----------------------------------------------------------------------


class TestSl1GraphqlEndToEnd:
    @pytest.mark.anyio
    @pytest.mark.parametrize(("document", "why"), REFUSED, ids=_ids(REFUSED))
    async def test_a_refused_document_sends_nothing(
        self, config: Config, credential: LceCredential, document: str, why: str
    ) -> None:
        context, seen = _ctx(config, credential, _gql_ok({"x": 1}))
        payload = await gql.make_sl1_graphql(context)(query=document)
        assert seen == [], f"a refused document reached SL1: {why}"
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        detail = payload["error"]["details"][0]
        assert detail["path"] == "query"
        assert detail["rule"] == "tool_argument"
        assert "sl1_get_credential" in detail["message"]

    @pytest.mark.anyio
    async def test_a_refused_variable_sends_nothing(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen = _ctx(config, credential, _gql_ok({"x": 1}))
        payload = await gql.make_sl1_graphql(context)(
            query=(
                "query($o: [ConnectionOrder]) "
                "{ credentials(order: $o) { pageInfo { matchCount } } }"
            ),
            variables={"o": [{"field": "definition"}]},
        )
        assert seen == []
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"

    @pytest.mark.anyio
    async def test_the_soap_http_authentication_is_refused_and_sends_nothing(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Ported from review: the field was selected, sent, and echoed with its password."""
        query = (
            "{ monitorSoapXmlTransactions { edges { node { id url httpAuthenticationMethod "
            "httpAuthenticationCredential } } } }"
        )
        body = {
            "monitorSoapXmlTransactions": {
                "edges": [{"node": {"id": "1", "httpAuthenticationCredential": "admin:" + CANARY}}]
            }
        }
        context, seen = _ctx(config, credential, _gql_ok(body))
        payload = await gql.make_sl1_graphql(context)(query=query)
        assert seen == []
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        _assert_no_secret(payload)

    @pytest.mark.anyio
    async def test_a_probe_carried_only_by_the_variables_sends_nothing(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Ported from review: no ``cred`` token in the document, the search in the variables."""
        context, seen = _ctx(config, credential, _gql_ok({"devices": {"pageInfo": {"x": 3}}}))
        payload = await gql.make_sl1_graphql(context)(
            query=_DEVICE_SEARCH,
            variables={"s": {"snmpReadCredential": {"has": {"definition": {"contains": "p"}}}}},
        )
        assert seen == []
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        dotted = (
            '{ devices(order: [{field: "snmpReadCredential.definition"}]) '
            "{ edges { node { id } } } }"
        )
        payload = await gql.make_sl1_graphql(context)(query=dotted)
        assert seen == []
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"

    @pytest.mark.anyio
    async def test_a_malformed_document_sends_nothing(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen = _ctx(config, credential, _gql_ok({"x": 1}))
        payload = await gql.make_sl1_graphql(context)(query="{ credentials { ")
        assert seen == []
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"

    @pytest.mark.anyio
    async def test_a_refusal_is_audited(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        context, _ = _ctx(config, credential, _gql_ok({}))
        with caplog.at_level(logging.INFO):
            await gql.make_sl1_graphql(context)(query=REFUSED[0][0])
        outcomes = [
            r.__dict__["outcome"]
            for r in caplog.records
            if r.__dict__.get("event") == LogEvent.SL1_PASSTHROUGH_INVOKED
        ]
        assert outcomes == ["rejected_credential_secret"]

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "query",
        [
            _CREDENTIAL_LOOKUP,
            _connection("snmpCredentials", TYPED_METADATA["snmpCredentials"]),
            ALLOWED[-30][0],
        ],
    )
    async def test_an_allowed_credential_read_is_sent(
        self, config: Config, credential: LceCredential, query: str
    ) -> None:
        nodes = {"credentials": {"edges": [{"node": {"id": "1", "guid": "G", "name": "n"}}]}}
        context, seen = _ctx(config, credential, _gql_ok(nodes))
        result = await gql.make_sl1_graphql(context)(query=query, variables={"n": "x"})
        assert len(seen) == 1
        assert result == {"data": nodes}

    @pytest.mark.anyio
    async def test_the_credential_template_comes_back_whole(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The credential guide's query, end to end: allowed, sent, and not scrubbed."""
        template = json.dumps({"fields": [{"propName": "AwsSecretAccessKey", "encryption": True}]})
        nodes = {
            "credentialFields": {
                "edges": [
                    {"node": {"type": "UNIVERSAL", "subType": "aws iam", "definition": template}}
                ]
            }
        }
        context, seen = _ctx(config, credential, _gql_ok(nodes))
        result = await gql.make_sl1_graphql(context)(
            query=(
                '{ credentialFields(search: { subType: { eq: "aws iam" } }) '
                "{ edges { node { type subType definition } } } }"
            )
        )
        assert len(seen) == 1
        assert result == {"data": nodes}

    @pytest.mark.anyio
    @pytest.mark.parametrize("credential_type", sorted(CREDENTIAL_TYPES))
    @pytest.mark.parametrize("prune", [True, False])
    async def test_no_secret_comes_back_whatever_sl1_answers(
        self, config: Config, credential: LceCredential, credential_type: str, prune: bool
    ) -> None:
        """The second layer, end to end: SL1 answers an allowed document with secrets anyway."""
        for shape in _shapes_for(credential_type):
            context, _ = _ctx(config, credential, _gql_ok(shape))
            result = await gql.make_sl1_graphql(context)(query="{ devices { id } }", prune=prune)
            _assert_no_secret(result)


class TestSl1RestEndToEnd:
    @pytest.mark.anyio
    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("GET", "credential/snmp/1"),
            ("GET", "/api/CREDENTIAL/ssh/2"),
            ("GET", "cred%65ntial/basic/3"),
            ("POST", "credential/universal"),
            ("PUT", "credential/db/4"),
            ("DELETE", "credential/soap/5"),
            ("GET", "account?order.verification_answer=ASC"),
        ],
    )
    async def test_a_refused_request_sends_nothing(
        self,
        config: Config,
        credential: LceCredential,
        method: str,
        path: str,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        context, seen = _ctx(config, credential, _rest_ok({"cred_pwd": CANARY}))
        with caplog.at_level(logging.INFO):
            payload = await rest.make_sl1_rest_request(context)(method=method, path=path)
        assert seen == []
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        assert payload["error"]["details"][0]["path"] == "path"
        outcomes = [
            r.__dict__["outcome"]
            for r in caplog.records
            if r.__dict__.get("event") == LogEvent.SL1_PASSTHROUGH_INVOKED
        ]
        assert outcomes == ["rejected_credential_path"]

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "query_params",
        [
            {"extended_fetch": 1},
            {"link_disp_field": "cred_pwd"},
            {"filter.password.contains": "a"},
            {"order.verification_answer": "ASC"},
        ],
    )
    async def test_a_refused_query_parameter_is_refused_before_dispatch(
        self, config: Config, credential: LceCredential, query_params: dict[str, object]
    ) -> None:
        context, seen = _ctx(config, credential, _rest_ok({}))
        for path in ("credential/snmp", "account"):
            if path == "account" and "extended_fetch" in query_params:
                continue
            payload = await rest.make_sl1_rest_request(context)(
                method="GET", path=path, query_params=query_params
            )
            assert isinstance(payload, dict)
            assert payload["error"]["details"][0]["path"] == "query_params"
        assert seen == []

    @pytest.mark.anyio
    async def test_the_plain_index_is_sent_and_projected(
        self, config: Config, credential: LceCredential
    ) -> None:
        rows = [{"URI": "/api/credential/snmp/1", "description": "public", "cred_pwd": CANARY}]
        context, seen = _ctx(config, credential, _rest_ok(rows))
        result = await rest.make_sl1_rest_request(context)(
            method="GET", path="credential", query_params={"limit": 10, "hide_filterinfo": 1}
        )
        assert seen[0].url.path == "/api/credential"
        assert result == [{"URI": "/api/credential/snmp/1", "description": "public"}]

    @pytest.mark.anyio
    @pytest.mark.parametrize("credential_type", sorted(CREDENTIAL_TYPES))
    @pytest.mark.parametrize("prune", [True, False])
    async def test_no_secret_comes_back_from_any_other_path(
        self, config: Config, credential: LceCredential, credential_type: str, prune: bool
    ) -> None:
        for shape in _shapes_for(credential_type):
            context, _ = _ctx(config, credential, _rest_ok(shape))
            result = await rest.make_sl1_rest_request(context)(
                method="GET", path="device/1", prune=prune
            )
            _assert_no_secret(result)

    @pytest.mark.anyio
    async def test_search_and_describe_follow_the_same_rule(
        self, config: Config, credential: LceCredential
    ) -> None:
        context, seen = _ctx(config, credential, _rest_ok({"result_set": []}))
        search = rest.make_sl1_rest_search(context)
        for kwargs, addressed in (
            ({"resource": "credential", "extended_fetch": True}, "filters"),
            ({"resource": "credential/snmp", "filters": {"cred_pwd.begins_with": "a"}}, "filters"),
            ({"resource": "credential", "order": {"cred_pwd": "ASC"}}, "filters"),
            ({"resource": "credential/snmp/1"}, "resource"),
            ({"resource": "account", "filters": {"verification_answer": "a"}}, "filters"),
            ({"resource": "account", "order": {"hash": "ASC"}}, "filters"),
            ({"resource": "device", "filters": {"password.contains": "a"}}, "filters"),
        ):
            payload = await search(**kwargs)
            assert isinstance(payload, dict)
            assert payload["error"]["type"] == "validation_blocked", kwargs
            assert payload["error"]["details"][0]["path"] == addressed, kwargs
        assert seen == []

        assert await search(resource="credential") == {"result_set": []}
        assert await search(resource="account", filters={"user.contains": "a"}) == {
            "result_set": []
        }
        described = await rest.make_sl1_rest_describe(context)(resource="credential/snmp")
        assert described == {"result_set": []}
        refused = await rest.make_sl1_rest_describe(context)(resource="credential/snmp/1")
        assert isinstance(refused, dict)
        assert refused["error"]["type"] == "validation_blocked"
        assert len(seen) == 3

    @pytest.mark.anyio
    async def test_search_and_index_responses_are_scrubbed(
        self, config: Config, credential: LceCredential
    ) -> None:
        body = {"result_set": {"/api/device/1": {"note": node_for("SNMP")["definition"]}}}
        context, _ = _ctx(config, credential, _rest_ok(body))
        _assert_no_secret(await rest.make_sl1_rest_search(context)(resource="device"))
        _assert_no_secret(await rest.make_sl1_rest_index(context)())


class TestGuidedDiscoveryEndToEnd:
    """A workflow is platform data a caller can author, so its actions get the GraphQL rule too."""

    @staticmethod
    def _workflow(selection: list[str], variables: dict[str, Any] | None = None) -> dict[str, Any]:
        query_variables = variables or {
            "guid": {
                "fieldType": "ID!",
                "fieldName": {"field": "discoverySession.definition.credential"},
            }
        }
        return {
            "id": "7",
            "name": "wf",
            "definition": json.dumps(
                {
                    "discoveryActions": [
                        {
                            "mutationName": "createVirtualDevice",
                            "queryVariables": {
                                "name": {
                                    "fieldType": "String!",
                                    "fieldName": {"field": "discoverySession.definition.root"},
                                }
                            },
                            "result": [{"field": "id"}],
                        },
                        {
                            "mutationName": "updateCredential",
                            "queryVariables": query_variables,
                            "result": [{"field": field} for field in selection],
                        },
                    ]
                }
            ),
        }

    def _handler(self, workflow: dict[str, Any], result: dict[str, Any]) -> Handler:
        def handler(request: httpx.Request) -> httpx.Response:
            document = json.loads(request.content)["query"]
            if "guidedDiscoveryWorkflow(" in document:
                return httpx.Response(200, json={"data": {"guidedDiscoveryWorkflow": workflow}})
            if "createGuidedDiscoverySession" in document:
                session = {
                    "id": "1",
                    "name": "s",
                    "definition": json.dumps(
                        {"credential": "G", "root": "r", "credentials": [node_for("SNMP")]}
                    ),
                }
                return httpx.Response(200, json={"data": {"createGuidedDiscoverySession": session}})
            if "createVirtualDevice" in document:
                return httpx.Response(200, json={"data": {"createVirtualDevice": {"id": "13"}}})
            return httpx.Response(200, json={"data": {"updateCredential": result}})

        return handler

    @staticmethod
    def _documents(seen: list[httpx.Request]) -> list[str]:
        return [json.loads(r.content)["query"] for r in seen]

    @pytest.mark.anyio
    @pytest.mark.parametrize("dry_run", [False, True])
    @pytest.mark.parametrize("selection", [["id", "definition"], ["password"], ["id", "hash"]])
    async def test_a_refused_action_stops_everything_before_the_create(
        self, config: Config, credential: LceCredential, dry_run: bool, selection: list[str]
    ) -> None:
        """The second action is refused, so neither the session nor the first action is sent."""
        workflow = self._workflow(selection)
        context, seen = _ctx(config, credential, self._handler(workflow, {"definition": CANARY}))
        payload = await gd.make_sl1_create_guided_discovery_session(context)(
            name="s",
            discovery_workflow="7",
            organization="0",
            definition={"credential": "G", "root": "r"},
            dry_run=dry_run,
        )
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        assert payload["error"]["details"][0]["path"] == "definition"
        documents = self._documents(seen)
        assert len(documents) == 1, "only the workflow read may have been sent"
        assert "guidedDiscoveryWorkflow(" in documents[0]

    @pytest.mark.anyio
    async def test_a_dry_run_applies_the_variable_check(
        self, config: Config, credential: LceCredential
    ) -> None:
        """A probe carried by a literal variable is invisible in the document text."""
        workflow = self._workflow(
            ["id"],
            {"search": {"fieldType": "CredentialSearch", "fieldName": {"value": {"password": {}}}}},
        )
        context, seen = _ctx(config, credential, self._handler(workflow, {}))
        payload = await gd.make_sl1_create_guided_discovery_session(context)(
            name="s",
            discovery_workflow="7",
            organization="0",
            definition={"credential": "G", "root": "r"},
            dry_run=True,
        )
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        assert len(seen) == 1

    @pytest.mark.anyio
    async def test_an_allowed_workflow_runs_and_the_result_is_scrubbed(
        self, config: Config, credential: LceCredential
    ) -> None:
        workflow = self._workflow(["id", "guid"])
        context, seen = _ctx(
            config, credential, self._handler(workflow, {"id": "1", "password": CANARY})
        )
        payload = await gd.make_sl1_create_guided_discovery_session(context)(
            name="s",
            discovery_workflow="7",
            organization="0",
            definition={"credential": "G", "root": "r"},
        )
        assert isinstance(payload, dict)
        assert "error" not in payload
        assert [step["mutation"] for step in payload["executed"]] == [
            "createVirtualDevice",
            "updateCredential",
        ]
        documents = self._documents(seen)
        assert "guidedDiscoveryWorkflow(" in documents[0]
        assert "createGuidedDiscoverySession" in documents[1]
        _assert_no_secret(payload)

    def test_the_aws_workflow_fixture_passes(self) -> None:
        """The measured AWS workflow, with the result selection the appliance's copy carries."""
        from tests.unit.test_guided_discovery import _API_SESSION, _AWS_WORKFLOW, _UI_SESSION

        actions = _AWS_WORKFLOW["discoveryActions"]
        with_results = [
            actions[0]
            | {"result": [{"field": "id"}, {"field": "name"}, {"field": "icon { id name svg }"}]},
            actions[1] | {"result": [{"field": "id"}]},
        ]
        for action in [*actions, *with_results]:
            assert guard.graphql_document_refusal(gd.build_mutation_document(action)) is None
        for session in (_API_SESSION, _UI_SESSION):
            plan = gd.build_action_plan(
                session, _AWS_WORKFLOW, {"createVirtualDevice": {"id": "13"}}
            )
            assert len(plan) == len(actions)
            for action, planned in zip(actions, plan, strict=True):
                document = gd.build_mutation_document(action)
                assert guard.graphql_document_refusal(document, planned.variables) is None

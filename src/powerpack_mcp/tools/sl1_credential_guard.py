"""
Credential Secret Guard for the SL1 Passthroughs

This module keeps credential secrets, and the other secrets SL1's schema exposes, out of what
``sl1_graphql``, the four REST passthroughs and ``sl1_create_guided_discovery_session`` return. The
typed readers ``sl1_list_credentials`` and ``sl1_get_credential`` promise that no secret is ever
returned; without this module, the passthroughs would hand the same secrets to anyone who asked
for them directly.

There are two layers, and the first one is the control:

1. Refusal before anything is sent. ``refuse_credential_secret_document`` refuses a GraphQL
   document that could select or probe secret material, and ``check_rest_credential_access``
   refuses REST calls on credential resources other than the plain indexes, and secret-revealing
   query parameters on any resource.
2. A response scrub, ``scrub_credential_secrets``, run on every passthrough response before
   pruning. It exists for what the first layer cannot see: credentials embedded in other objects'
   JSON (a Guided Discovery session's ``definition`` can carry full credential objects), and keys
   that look like secrets wherever they turn up.

The GraphQL rule
----------------

GraphQL cannot hide a field's name. An alias renames the response key, never the field
(``x: definition`` selects ``definition``); a fragment's body still names its fields; names cannot
contain escapes; and variables carry values, never selections. So a rule over field names is sound
as long as the field names, and which field each sits under, are found correctly, which is why
``graphql_document`` parses the document into a tree instead of searching its text.

A document is refused, before any network call, when:

R1. Secret fields, everywhere. It selects, on any type and in any position, a field whose real
    name matches ``SECRET_NAME_PATTERNS`` (case-insensitive substrings: ``password``, ``pwd``,
    ``community``, ``token``, ``hash``, ...) and is not one of the measured metadata names in
    ``SECRET_NAME_EXCEPTIONS``; a field named like a ``Credential.definition`` secret key
    (``CREDENTIAL_SECRET_KEYS``) or one of ``SECRET_FIELD_NAMES``;
    ``credentialTranslatedByCustomType`` (or ``...BySubType``), which returns a credential with its
    secrets; or a fragment on ``AgentTokenSecret``, ``AccessKey``, ``CollectorToken`` or ``ApiKey``.
    This is what refuses ``Organization.hash``, ``AgentTokenSecret.jwt``,
    ``MonitorWebContent.httpUsernamePassword``, ``MonitorSoapXmlTransaction``'s
    ``httpAuthenticationCredential`` and the rest, on types that are not credentials.
R2. The credential allowlist. A known credential-returning field (``CREDENTIAL_CONTEXT_FIELDS``,
    taken from the live schema), or an inline fragment or fragment definition whose type condition
    contains ``cred``, opens a credential context. Any other field whose real name contains
    ``cred``, scalar or object, in any context, is refused: the name says it holds or reaches a
    credential, and an unclassified one is not given the benefit of the doubt. Inside, every
    selected field, through any depth of inline fragments and fragment spreads, must be on
    ``CREDENTIAL_FIELD_ALLOWLIST``; anything else is refused. ``credentialField`` and
    ``credentialFields``, and a type condition starting ``CredentialField``, open the template
    context instead, whose list (``TEMPLATE_FIELD_ALLOWLIST``) includes ``definition``: a
    ``CredentialField`` is the field-mapping template a UNIVERSAL credential is built from, not a
    credential. Inside either, ``pageInfo`` allows only its three counters and the template's
    ``powerPack`` only ``id``, ``guid`` and ``name``, and a known credential field opens a
    credential context again. A spread naming no fragment, or fragments that spread each other in
    a cycle, are refused.
R3. Probes. A search, sort or filter over a secret turns ``pageInfo.matchCount`` or the result
    order into an oracle that reads the secret one guess at a time, without ever selecting it.
    In every document, an input-object key or an enum value matching R1's patterns, or a string
    that is exactly a known secret field name, is refused, in arguments, in variable defaults and
    in the caller's variables. In a document that mentions credentials (a name token, a
    field-path-shaped string or a variable key containing ``cred``), the check widens to any name a
    credential field outside the allowlist could go by: R1's patterns, ``definition``,
    ``alignedOrganizations``, ``editedBy`` and the like, now also as an argument name and as any
    segment of a dotted or bracketed field-path string.
    And by path, wherever the input value sits (literals, variable defaults, directive arguments,
    and the caller's variables, from where each is used): once an input-object key contains
    ``cred``, it must be a known credential field, and every key beneath it and every field-path
    string or enum value beneath it must be on the allowlist or a neutral search operator
    (``and``, ``has``, ``eq``, ``contains``, ...). A field-path string naming a credential
    (``"snmpReadCredential.definition"``) is held to the same rule from that segment on. The value
    a comparison operator compares is data, not a path, and is not read as one; prose and JSON are
    not paths either. The one exemption is a write of the caller's own input: the ``definition``
    and ``alignedOrganizations`` arguments of ``createCredential`` and ``updateCredential``, and the
    variables used only there.
R4. It does not lex or parse. Fail closed: a document the guard cannot read is one it cannot vouch
    for.

The rule covers every operation and every fragment in the document, whichever operation
``operationName`` selects, and mutations the same way as queries: ``createCredential``,
``updateCredential`` and ``duplicateCredential`` open a credential context, so their result
selection is held to the allowlist.

Why per-name allowlists rather than per type: without the schema, the guard does not know which
credential type a selection is on, only which names it uses. One union allowlist for every
credential type is sound because none of its names is a secret on any credential type (measured by
introspection on SL1 12.5.x, and re-checked against a live schema by the integration suite).

What the rule cannot see: a credential object reached through a field whose name does not contain
``cred`` and without a fragment typed on it. In the measured schema, every field returning a
credential type contains ``cred`` or is a connection's ``edges``/``node`` under one, and the schema
has no interfaces through which a credential field could be selected untyped. The response scrub is
the backstop for anything else; it withholds a string that starts like a JSON object or array and
does not parse, since it cannot check one, and the Guided Discovery tool scrubs each action result
before bounding its length.

The REST rule
-------------

On every path, before anything is sent: ``link_disp_field`` must name one of the plain display
fields in ``REST_LINK_DISPLAY_FIELDS``, because it inlines the named field of every linked resource
into the response; and a ``filter.<field>...`` or ``order.<field>`` parameter may not name a field
matching R1's patterns or SL1's ``verification_answer``/``verification_question``, for R3's oracle
reason. Keys and values are percent-decoded and case-folded first, and parameters embedded in the
path are checked as well as the separate ones.

SL1's REST credential resources are ``credential`` (the index), ``credential/<type>`` for the
eight types (``snmp``, ``db``, ``soap``, ``ldap``, ``basic``, ``ssh``, ``powershell``,
``universal``) and ``credential/<type>/<id>``, as observed on an appliance; their field names are
REST-style (``cred_*``) and not the GraphQL ``definition`` keys, so the GraphQL allowlist does not
map onto them and no REST allowlist has been measured. So, after normalising the path (see
``normalized_rest_path``):

- Only ``GET`` of the plain indexes is allowed, with no ``extended_fetch``, no filter or sort, and
  no query string embedded in the path. The plain indexes return only ``URI`` and
  ``description`` per row, and the response is projected onto exactly that shape; anything else
  is withheld.
- Every other credential path and every write (``POST``, ``PUT``, ``DELETE``) is refused, pointing
  at the typed tools: ``sl1_get_credential``, ``sl1_list_credentials``, the universal-credential
  writers and ``sl1_delete_credential``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Final, cast
from urllib.parse import parse_qsl, unquote

from powerpack_mcp.errors import FindingCode, ValidationBlocked, ValidationFinding
from powerpack_mcp.tools.graphql_document import (
    FieldSelection,
    FragmentSpread,
    GraphQlSyntaxError,
    InlineFragment,
    ValueKind,
    summarize_executable_document,
)
from powerpack_mcp.tools.sl1_credential_definition import CREDENTIAL_SECRET_KEYS
from powerpack_mcp.tools.sl1_entity_tools import _DEFINITION_ALLOWLIST, _safe_credential

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Mapping

    from powerpack_mcp.tools.graphql_document import (
        Argument,
        DocumentSummary,
        FragmentDefinition,
        Selection,
        Value,
    )

__all__ = [
    "CREDENTIAL_CONTEXT_FIELDS",
    "CREDENTIAL_FIELD_ALLOWLIST",
    "CREDENTIAL_MARKER",
    "KNOWN_SECRET_FIELD_NAMES",
    "REFUSED_TYPE_CONDITIONS",
    "REST_LINK_DISPLAY_FIELDS",
    "REST_SECRET_NAME_FRAGMENTS",
    "SECRET_FIELD_NAMES",
    "SECRET_NAME_EXCEPTIONS",
    "SECRET_NAME_PATTERNS",
    "TEMPLATE_FIELD_ALLOWLIST",
    "WITHHELD_KEYS_FIELD",
    "check_rest_credential_access",
    "graphql_document_refusal",
    "is_credential_path",
    "is_rest_secret_field",
    "is_secret_name",
    "normalized_rest_path",
    "refuse_credential_secret_document",
    "scrub_credential_secrets",
    "shape_rest_response",
]

# The typed tools every refusal points to. One constant so every message names the same tools.
_TYPED_READERS: Final = (
    "Use sl1_get_credential or sl1_list_credentials instead: they return every non-secret field, "
    "with the withheld keys named."
)

# The same pointer for refusals that are not always about a credential: the secret-field rule and
# the probe rule apply to every type, and an agent token or access key has no typed reader.
_TYPED_READERS_IF_CREDENTIAL: Final = (
    "For credential data, use sl1_get_credential or sl1_list_credentials: they return every "
    "non-secret field, with the withheld keys named."
)

# ---- secret names -------------------------------------------------------------------------------

# The substring that marks a name as credential-related: a type condition containing it opens a
# credential context and a field containing it must be a known credential field (R2), and it marks
# a document, a key or a path string as touching credentials (R3). ``cred`` rather than
# ``credential`` so an abbreviated name counts too; the cost is an occasional over-refusal.
CREDENTIAL_MARKER: Final = "cred"

# R1. Matched as case-insensitive substrings of a field's real name, on every type. Neither bare
# ``pass`` nor bare ``key`` is here: they would refuse ``bypassInterfaceInventory`` and the many
# benign ``*Key`` fields. Each entry was chosen against the names measured on SL1 12.5.x: ``pwd``
# and ``passwd`` for REST- and curl-style names, ``keydata`` for ``sshKeyData``, ``requestsub`` for
# the SOAP ``curlRequestSub1``-``4`` substitutions, ``curloptions`` for the object carrying
# ``COOKIE``, ``SSLKEYPASSWD`` and ``HTTPHEADER``, ``accesskey`` for ``Account.accessKeys`` and the
# ``AccessKey`` mutations, ``privacy`` for the SNMPv3 privacy password.
SECRET_NAME_PATTERNS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "pwd",
    "community",
    "secret",
    "token",
    "jwt",
    "hash",
    "cookie",
    "header",
    "keydata",
    "privacy",
    "requestsub",
    "curloptions",
    "accesskey",
)

# Names the patterns match that are measured metadata, not secrets, each checked by its type in the
# live schema. All are enums, booleans or plain strings except three objects whose own fields go
# through the same rule: ``tokenDetails`` (``CollectorTokenDetails``: name, dates, state, type),
# ``accessKeyHooks`` (``AccessKeyHook``: id, name, description, category) and
# ``accessKeyCategories`` (``AccessKeyCategory``: id, name). ``httpHostNameHeader`` is the Host
# header a web-content monitor sends, a host name. ``snmpV3PrivacyProtocol`` is the SNMPv3 privacy
# algorithm (an enum such as AES or DES); it is on the credential allowlist, and ``privacy`` would
# otherwise refuse it.
SECRET_NAME_EXCEPTIONS: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (
        "passwordExpiration",
        "passwordReuseRule",
        "passwordStrength",
        "requirePasswordReset",
        "tokenState",
        "tokenType",
        "tokenDetails",
        "accessKeysEnabled",
        "accessKeyCategories",
        "accessKeyHooks",
        "httpHostNameHeader",
        "snmpV3PrivacyProtocol",
    )
)

# R1. Measured secret fields on types that are not credentials whose names no pattern catches.
# ``MonitorSoapXmlTransaction.httpAuthenticationCredential`` is a String holding the SOAP/XML
# monitor's HTTP authentication as ``user:password``.
SECRET_FIELD_NAMES: Final[tuple[str, ...]] = ("httpAuthenticationCredential",)

_SECRET_KEY_NAMES: Final[frozenset[str]] = frozenset(
    key.casefold() for key in (*CREDENTIAL_SECRET_KEYS, *SECRET_FIELD_NAMES)
)

# R1's explicit refusals. Most are matched by the patterns too; they are listed so the refusal does
# not depend on a pattern staying in place. ``credentialTranslatedByCustomType`` returns a full
# credential with its secrets; ``credentialTranslatedBySubType`` is its sibling, refused on the same
# grounds without having been measured. The agent-token and access-key mutations return ``jwt`` and
# ``hash``.
_ALWAYS_REFUSED_FIELDS: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (
        "credentialTranslatedByCustomType",
        "credentialTranslatedBySubType",
        "createAgentTokenSecret",
        "updateAgentTokenSecret",
        "createAccessKey",
        "updateAccessKey",
    )
)

# R1. Types whose purpose is a secret: a fragment on one is refused whatever it selects.
REFUSED_TYPE_CONDITIONS: Final[frozenset[str]] = frozenset(
    name.casefold() for name in ("AgentTokenSecret", "AccessKey", "CollectorToken", "ApiKey")
)

# R3, in every document: strings exactly equal to one of these are treated as naming a secret
# field. Strings are free text, so the substring patterns would refuse ordinary searches
# (``contains: "hashicorp"``); exact names are what a sort or filter on a field would carry. The
# measured secret fields, the pattern words themselves and the definition secret keys.
KNOWN_SECRET_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (
        *SECRET_NAME_PATTERNS,
        *CREDENTIAL_SECRET_KEYS,
        *SECRET_FIELD_NAMES,
        "accessKeys",
        "cookieValue",
        "customHeader",
        "curlHeaders",
        "curlProxyPassword",
        "curlRequestPassword",
        "httpUsernamePassword",
        "proxyAccountPassword",
        "proxyUsernamePassword",
        "snmpReadOnlyCommunity",
        "snmpReadWriteCommunity",
        "snmpV3PrivacyPassword",
        "sshKeyData",
    )
)


def _pattern_match(name: str) -> bool:
    """Return whether ``name`` contains one of ``SECRET_NAME_PATTERNS``, case-insensitively.

    One false positive is excluded by shape: ``hash`` straddling a camel-case boundary as
    ``hasH`` (``hasHarProvider``, ``hasHooks`` in SL1's search inputs) is a ``has...`` relation,
    not a hash.
    """
    folded = name.casefold()
    aligned = len(folded) == len(name)
    for pattern in SECRET_NAME_PATTERNS:
        start = folded.find(pattern)
        while start != -1:
            if not (pattern == "hash" and aligned and name[start : start + 4] == "hasH"):
                return True
            start = folded.find(pattern, start + 1)
    return False


def is_secret_name(name: str) -> bool:
    """Return whether ``name`` is a secret field or key name under R1.

    :param name: A field name, input-object key or response key.
    :return: ``True`` if it matches ``SECRET_NAME_PATTERNS``, ``CREDENTIAL_SECRET_KEYS`` or
        ``SECRET_FIELD_NAMES`` and is not in ``SECRET_NAME_EXCEPTIONS``.
    """
    folded = name.casefold()
    if folded in SECRET_NAME_EXCEPTIONS:
        return False
    return folded in _SECRET_KEY_NAMES or _pattern_match(name)


# ---- the credential allowlists (R2) ------------------------------------------------------------

# Connection plumbing, allowed in both credential contexts.
_PLUMBING: Final = ("edges", "node", "cursor")

# Every field a credential context may select, as one union across the credential types: matched
# by name, because without the schema the type is unknown. Measured by introspection (``__type``,
# which shows the experimental fields ``__schema`` leaves out) on SL1 12.5.x. Left out on purpose:
# ``definition`` (every secret of a ``Credential``), ``alignedOrganizations``, ``editedBy`` and
# ``updatedBy`` (they open ``Organization``, which has ``hash``, and ``Account``), the secrets the
# patterns catch (``password``, ``snmpReadOnlyCommunity``, ``curlProxyPassword``, ``curlHeaders``,
# ``curlOptions``, ``sshKeyData``, ...), and anything not measured.
CREDENTIAL_FIELD_ALLOWLIST: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (
        *_PLUMBING,
        # Common to the credential types.
        "id",
        "guid",
        "name",
        "type",
        "subType",
        "typeDescription",
        "timeout",
        "dateEdited",
        "allOrganizations",
        "host",
        "port",
        "user",
        # Credential only, measured live through ``__type`` (both marked "problematic", which is
        # why the ``__schema`` dump the list was first built from lacked them): ``customType`` is
        # the caller-supplied type label and ``editDate`` a date string.
        "customType",
        "editDate",
        # SnmpCredential.
        "snmpVersion",
        "snmpRetries",
        "snmpV3AuthorizationProtocol",
        "snmpV3PrivacyProtocol",
        "snmpV3SecurityLevel",
        "snmpV3Context",
        "snmpV3EngineId",
        # LdapCredential.
        "ldapDomain",
        "ldapRootDn",
        "ldapScope",
        "ldapSecure",
        "ldapType",
        "ldapUserDn",
        # PowerShellCredential.
        "powerShellActiveDirectoryDomain",
        "powerShellActiveDirectoryHost",
        "powerShellEncrypted",
        "powerShellProxyHost",
        "powerShellType",
        # DbCredential.
        "databaseConnect",
        "databaseName",
        "databaseSID",
        "databaseType",
        # SoapCredential.
        "curlUrl",
        "curlMethod",
        "curlEncoding",
        "curlHttpVersion",
        "curlProxyIp",
        "curlProxyPort",
        "curlProxyAccount",
        "curlSslMode",
        # CredentialTest and CredentialTestLog. ``logMessage`` is a test's diagnostic output.
        "logs",
        "date",
        "description",
        "logMessage",
        "spoolId",
        "status",
        "step",
        "stepTip",
    )
)

# The template context's list: ``CredentialField`` and its connection.
TEMPLATE_FIELD_ALLOWLIST: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (*_PLUMBING, "definition", "subType", "type", "typeDescription", "powerPack")
)

_PAGE_INFO_FIELDS: Final[frozenset[str]] = frozenset(
    {"hasnextpage", "haspreviouspage", "matchcount"}
)
_POWER_PACK_FIELDS: Final[frozenset[str]] = frozenset({"id", "guid", "name"})

_TEMPLATE_FIELDS: Final[frozenset[str]] = frozenset({"credentialfield", "credentialfields"})
_TEMPLATE_TYPE_PREFIX: Final = "credentialfield"

# R2. The fields that return a credential, a credential connection or a credential test, and so
# open a credential context. A field whose name contains ``cred`` and is not one of these (or of
# ``_TEMPLATE_FIELDS``) is refused, scalar or object, wherever it is: the name says it holds or
# reaches a credential, and this tool has not classified it. Built from the live schema: every field
# whose unwrapped return type is a credential type or its connection (``__schema``), plus the typed
# roots and the ``Device`` fields that only ``__type`` shows. The live tripwire re-checks the list.
CREDENTIAL_CONTEXT_FIELDS: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (
        # Query, AlignedDynamicApplication and GlobalManagerStack (``credential``), DiscoverySession
        # (``credentials``).
        "credential",
        "credentials",
        # The typed roots, singular and connection.
        "basicCredential",
        "basicCredentials",
        "dbCredential",
        "dbCredentials",
        "ldapCredential",
        "ldapCredentials",
        "powerShellCredential",
        "powerShellCredentials",
        "snmpCredential",
        "snmpCredentials",
        "soapCredential",
        "soapCredentials",
        "sshCredential",
        "sshCredentials",
        # Device.
        "snmpReadCredential",
        "snmpReadWriteCredential",
        # Mutations returning the credential they wrote.
        "createCredential",
        "updateCredential",
        "duplicateCredential",
        # CredentialTest and CredentialTestLog.
        "credentialTest",
        "credentialTests",
        "credentialTestLog",
        "credentialTestLogs",
    )
)
_TYPENAME: Final = "__typename"

# R3, in a credential document: names of credential fields outside the allowlist that the patterns
# do not catch. Together with ``is_secret_name`` this is every non-allowlisted field measured on the
# credential types, which the live tripwire test checks.
_UNLISTED_CREDENTIAL_NAMES: Final[frozenset[str]] = frozenset(
    {"definition", "alignedorganizations", "editedby", "updatedby", "createdby"}
)

# R3's exemption: the arguments through which ``sl1_graphql`` writes a credential's own input.
_WRITE_ARGUMENTS: Final[dict[str, frozenset[str]]] = {
    "createcredential": frozenset({"definition", "alignedorganizations"}),
    "updatecredential": frozenset({"definition", "alignedorganizations"}),
}

# How many nested selection sets, counting through fragment spreads, the walk follows. The parser
# bounds nesting within one definition; a chain of fragments each spreading the next is bounded
# here, so a hostile document is refused rather than exhausting the stack.
_MAX_WALK_DEPTH: Final = 128

# ``re.ASCII`` keeps ``\w`` and ``\d`` to ASCII: GraphQL names are ASCII-only, and without the
# flag both match any Unicode letter or digit.
_IDENTIFIER: Final = re.compile(r"[_A-Za-z]\w*", re.ASCII)

# A 16-or-more character run of upper-case letters and digits, with a digit: an SL1 GUID, not a
# field name, even where it happens to spell ``PWD`` or ``JWT``.
_GUID_LIKE: Final = re.compile(r"(?=[A-Z\d]*\d)[A-Z\d]{16,}", re.ASCII)


class _Context(Enum):
    """Where in the document a selection sits, for R2."""

    OPEN = "open"
    CREDENTIAL = "credential"
    TEMPLATE = "template"
    PAGE_INFO = "page_info"
    POWER_PACK = "power_pack"


_CONTEXT_FIELDS: Final[dict[_Context, frozenset[str]]] = {
    _Context.CREDENTIAL: CREDENTIAL_FIELD_ALLOWLIST,
    _Context.TEMPLATE: TEMPLATE_FIELD_ALLOWLIST,
    _Context.PAGE_INFO: _PAGE_INFO_FIELDS,
    _Context.POWER_PACK: _POWER_PACK_FIELDS,
}


# N818 wants an ``Error`` suffix, but this is a control-flow signal, not an error type.
class _Refused(Exception):  # noqa: N818
    """Raised inside the walk to stop at the first refusal; carries the caller-facing reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _secret_field(name: str) -> _Refused:
    return _Refused(
        f"The document selects {name}, which can return a secret or a secret-derived value, so it "
        f"is refused before anything is sent. {_TYPED_READERS_IF_CREDENTIAL}"
    )


def _unlisted_field(name: str, context: _Context) -> _Refused:
    where = "a credential template" if context is _Context.TEMPLATE else "a credential"
    return _Refused(
        f"The document selects {name} inside {where}, and only the fields this tool has "
        "classified as non-secret may be selected there, so it is refused before anything is "
        f"sent. {_TYPED_READERS}"
    )


def _unknown_credential_field(name: str) -> _Refused:
    return _Refused(
        f"The document selects {name}, whose name says it holds or reaches a credential, but it is "
        "not one of the credential fields this tool knows how to check, so it is refused before "
        f"anything is sent. {_TYPED_READERS_IF_CREDENTIAL}"
    )


def _opens_credentials(folded: str) -> bool:
    """Whether a case-folded name is a known credential-returning or template field (R2)."""
    return folded in CREDENTIAL_CONTEXT_FIELDS or folded in _TEMPLATE_FIELDS


def _context_for_type(condition: str | None, context: _Context) -> _Context:
    """The context a fragment's type condition puts its selections in (R1's type refusal first)."""
    if condition is None:
        return context
    folded = condition.casefold()
    if folded in REFUSED_TYPE_CONDITIONS:
        raise _secret_field(f"a fragment on {condition}")
    if folded.startswith(_TEMPLATE_TYPE_PREFIX):
        return _Context.TEMPLATE
    if CREDENTIAL_MARKER in folded:
        return _Context.CREDENTIAL
    return context


def _context_for_field(name: str, context: _Context) -> _Context:
    """Check one selected field against R1 and R2 and return the context of its own selections."""
    folded = name.casefold()
    if folded in _ALWAYS_REFUSED_FIELDS or is_secret_name(name):
        raise _secret_field(name)
    if folded in _TEMPLATE_FIELDS:
        return _Context.TEMPLATE
    if folded in CREDENTIAL_CONTEXT_FIELDS:
        return _Context.CREDENTIAL
    if CREDENTIAL_MARKER in folded and folded not in CREDENTIAL_FIELD_ALLOWLIST:
        raise _unknown_credential_field(name)
    if context is _Context.OPEN:
        return context
    if folded == "pageinfo" and context in {_Context.CREDENTIAL, _Context.TEMPLATE}:
        return _Context.PAGE_INFO
    if folded == "powerpack" and context is _Context.TEMPLATE:
        return _Context.POWER_PACK
    if folded in _CONTEXT_FIELDS[context]:
        return context
    raise _unlisted_field(name, context)


class _SelectionWalk:
    """R1 and R2 over the document tree, resolving fragment spreads in the context they occur."""

    __slots__ = ("_done", "_fragments")

    def __init__(self, fragments: dict[str, FragmentDefinition]) -> None:
        self._fragments = fragments
        self._done: set[tuple[str, _Context]] = set()

    def selections(self, selections: tuple[Selection, ...], context: _Context, depth: int) -> None:
        if depth > _MAX_WALK_DEPTH:
            raise _Refused(
                "The document nests selections, through its fragments, more deeply than this tool "
                "follows, so it is refused rather than sent unchecked."
            )
        for selection in selections:
            if isinstance(selection, FieldSelection):
                if selection.name == _TYPENAME:
                    continue
                inner = _context_for_field(selection.name, context)
                self.selections(selection.selections, inner, depth + 1)
            elif isinstance(selection, InlineFragment):
                inner = _context_for_type(selection.type_condition, context)
                self.selections(selection.selections, inner, depth + 1)
            else:
                self.spread(selection, context, depth)

    def spread(self, spread: FragmentSpread, context: _Context, depth: int) -> None:
        # Every spread resolves and the spread graph is acyclic: ``_fragment_graph_refusal`` ran
        # first. Memoised per context, so a fragment spread many times is walked once per context.
        key = (spread.name, context)
        if key in self._done:
            return
        fragment = self._fragments[spread.name]
        inner = _context_for_type(fragment.type_condition, context)
        self.selections(fragment.selections, inner, depth + 1)
        self._done.add(key)


def _spreads_in(selections: tuple[Selection, ...]) -> Iterator[str]:
    for selection in selections:
        if isinstance(selection, FragmentSpread):
            yield selection.name
        else:
            yield from _spreads_in(selection.selections)


def _fragment_graph_refusal(summary: DocumentSummary) -> str | None:
    """R2: refuse a spread with no fragment, a duplicate fragment name, or a spread cycle."""
    fragments: dict[str, FragmentDefinition] = {}
    for fragment in summary.fragments:
        if fragment.name in fragments:
            return "The document defines two fragments with the same name, so it is refused."
        fragments[fragment.name] = fragment
    edges = {name: set(_spreads_in(fragment.selections)) for name, fragment in fragments.items()}
    used = {name for operation in summary.operations for name in _spreads_in(operation.selections)}
    if any(name not in fragments for name in used | set().union(*edges.values())):
        return (
            "The document spreads a fragment it does not define, so what it selects cannot be "
            "checked; it is refused."
        )
    # Kahn's algorithm: whatever cannot be peeled off sits on a cycle.
    remaining = {name: set(targets) for name, targets in edges.items()}
    while True:
        leaves = [name for name, targets in remaining.items() if not targets]
        if not leaves:
            break
        for leaf in leaves:
            del remaining[leaf]
        for targets in remaining.values():
            targets.difference_update(leaves)
    if remaining:
        return "The document's fragments spread each other in a cycle, so it is refused."
    return None


# ---- probes (R3) --------------------------------------------------------------------------------

# R3's path rule. The operator keys of SL1's search inputs: they name no field, so they may sit
# beneath a credential key. A comparison operator's own value is the data being compared, not a
# field name, so it is not read as a path.
_LOGICAL_OPERATORS: Final[frozenset[str]] = frozenset({"and", "or", "not", "has"})
_COMPARISON_OPERATORS: Final[frozenset[str]] = frozenset(
    name.casefold()
    for name in (
        "eq",
        "ne",
        "neq",
        "in",
        "nin",
        "notIn",
        "gt",
        "gte",
        "lt",
        "lte",
        "contains",
        "notContains",
        "beginsWith",
        "begins_with",
        "notBeginsWith",
        "endsWith",
        "ends_with",
        "notEndsWith",
        "isNull",
    )
)
_NEUTRAL_NAMES: Final[frozenset[str]] = frozenset(
    {*_LOGICAL_OPERATORS, *_COMPARISON_OPERATORS, "asc", "desc"}
)

# What separates the segments of a dotted or bracketed field path in a string
# (``snmpReadCredential.definition``, ``snmpReadCredential[definition]``), and what is stripped
# from each segment (whitespace and the quotes of ``a["b"]``).
_PATH_SEPARATORS: Final = re.compile(r"[.\[\]]")
_SEGMENT_STRIP: Final = " \t\r\n\"'"


def _path_segments(text: str) -> list[str] | None:
    """The segments of a string shaped like a field path, or ``None`` for any other text.

    Path-shaped means every segment is an identifier or a list index. Prose and JSON are not paths:
    no server resolves ``credential definition`` as a field.
    """
    segments = [part.strip(_SEGMENT_STRIP) for part in _PATH_SEPARATORS.split(text)]
    segments = [segment for segment in segments if segment]
    if not segments or not all(
        _IDENTIFIER.fullmatch(segment) or segment.isdecimal() for segment in segments
    ):
        return None
    return segments


def _names_credential_path(text: str) -> bool:
    """Whether a string is a field path with a segment naming a credential (GUIDs aside)."""
    segments = _path_segments(text)
    return segments is not None and any(
        CREDENTIAL_MARKER in segment.casefold() and not _GUID_LIKE.fullmatch(segment)
        for segment in segments
    )


def _variable_names_credentials(value: object, depth: int = 0) -> bool:
    """Whether a caller variable has a key containing ``cred`` or a string naming a credential."""
    if depth > _MAX_WALK_DEPTH:
        return True
    if isinstance(value, str):
        return _names_credential_path(value)
    if isinstance(value, dict):
        return any(
            CREDENTIAL_MARKER in str(key).casefold()
            or _variable_names_credentials(member, depth + 1)
            for key, member in value.items()
        )
    if isinstance(value, list):
        return any(_variable_names_credentials(member, depth + 1) for member in value)
    return False


def _touches_credentials(summary: DocumentSummary, variables: Mapping[str, object]) -> bool:
    """Whether R3's wider check applies: a name, a field-path string or a variable key with cred."""
    return (
        any(CREDENTIAL_MARKER in name.casefold() for name in summary.names)
        or any(_names_credential_path(text) for text in summary.string_values)
        or _variable_names_credentials(dict(variables))
    )


def _names_unlisted_credential_field(name: str) -> bool:
    return is_secret_name(name) or name.casefold() in _UNLISTED_CREDENTIAL_NAMES


@dataclass(frozen=True, slots=True)
class _ProbeRule:
    """Which names R3's name check refuses, in one document.

    :ivar name_refused: For input-object keys, enum values and (in a credential document) argument
        names.
    :ivar string_refused: For string literals and string variable values.
    :ivar check_arguments: Whether argument names are checked: only in a credential document,
        because elsewhere an argument named ``password`` is a write of the caller's own input.
    """

    name_refused: Callable[[str], bool]
    string_refused: Callable[[str], bool]
    check_arguments: bool


def _known_secret_string(text: str) -> bool:
    return text.strip().casefold() in KNOWN_SECRET_FIELD_NAMES


def _credential_string(text: str) -> bool:
    """In a credential document: a field-path-shaped string naming an unlisted field.

    Dotted and bracketed paths are checked segment by segment. GUID-like segments are skipped: a
    credential GUID in ``credential(guid: ...)`` is not a field name, even where it happens to spell
    one.
    """
    segments = _path_segments(text)
    if segments is None:
        return False
    return any(
        not _GUID_LIKE.fullmatch(segment) and _names_unlisted_credential_field(segment)
        for segment in segments
    ) or _known_secret_string(text)


def _probe_rule(summary: DocumentSummary, variables: Mapping[str, object]) -> _ProbeRule:
    if _touches_credentials(summary, variables):
        return _ProbeRule(
            _names_unlisted_credential_field, _credential_string, check_arguments=True
        )
    return _ProbeRule(is_secret_name, _known_secret_string, check_arguments=False)


def _value_probe(value: Value, rule: _ProbeRule) -> bool:
    """Whether a literal value names a refused field as a key, an enum value or a string."""
    if value.kind is ValueKind.STRING:
        return rule.string_refused(value.text)
    if value.kind is ValueKind.ENUM:
        return rule.name_refused(value.text)
    if value.kind is ValueKind.LIST:
        return any(_value_probe(item, rule) for item in value.items)
    if value.kind is ValueKind.OBJECT:
        return any(
            rule.name_refused(key) or _value_probe(member, rule) for key, member in value.fields
        )
    return False


def _variables_in(value: Value) -> Iterator[str]:
    if value.kind is ValueKind.VARIABLE:
        yield value.text
    for item in value.items:
        yield from _variables_in(item)
    for _, member in value.fields:
        yield from _variables_in(member)


def _directive_arguments(summary: DocumentSummary) -> Iterator[Argument]:
    for operation in summary.operations:
        yield from operation.directive_arguments
    for fragment in summary.fragments:
        yield from fragment.directive_arguments
    stack: list[Selection] = [
        *(s for operation in summary.operations for s in operation.selections),
        *(s for fragment in summary.fragments for s in fragment.selections),
    ]
    while stack:
        selection = stack.pop()
        yield from selection.directive_arguments
        if not isinstance(selection, FragmentSpread):
            stack.extend(selection.selections)


def _variable_probe(value: object, rule: _ProbeRule, *, top_level: bool = True) -> bool:
    """Whether a caller variable names a refused field as a key or a string.

    The variable names themselves are labels the caller chose and are not inspected.
    """
    if isinstance(value, str):
        return rule.string_refused(value)
    if isinstance(value, dict):
        return any(
            (not top_level and isinstance(key, str) and rule.name_refused(key))
            or _variable_probe(member, rule, top_level=False)
            for key, member in value.items()
        )
    if isinstance(value, list):
        return any(_variable_probe(member, rule, top_level=False) for member in value)
    return False


@dataclass(frozen=True, slots=True)
class _Position:
    """Where an input value sits, for R3's path rule.

    :ivar credential: Beneath an input-object key that names a credential.
    :ivar compared: The direct value (or a list member of it) of a comparison operator: data
        compared against a field, not a field name.
    """

    credential: bool = False
    compared: bool = False


_TOP: Final = _Position()


def _inner_credential(name: str, credential: bool) -> bool | None:
    """The path rule for one key or path segment: ``None`` to refuse, else the inner ``credential``.

    A name containing ``cred`` must be a known credential field (and puts what is beneath it in a
    credential); beneath one, every name must be on the allowlist or a neutral operator.
    """
    folded = name.casefold()
    if CREDENTIAL_MARKER in folded:
        if _opens_credentials(folded):
            return True
        return None if folded not in CREDENTIAL_FIELD_ALLOWLIST else credential
    if credential and folded not in CREDENTIAL_FIELD_ALLOWLIST and folded not in _NEUTRAL_NAMES:
        return None
    return credential


def _path_refused(text: str, at: _Position) -> bool:
    """The path rule for a string or enum value; comparison data and non-path text pass."""
    if at.compared:
        return False
    segments = _path_segments(text)
    if segments is None:
        return False
    credential = at.credential
    for segment in segments:
        if segment.isdecimal() or _GUID_LIKE.fullmatch(segment):
            continue
        inner = _inner_credential(segment, credential)
        if inner is None:
            return True
        credential = inner
    return False


def _key_position(key: str, at: _Position) -> _Position | None:
    """The position of an input-object member under ``key``, or ``None`` to refuse."""
    credential = _inner_credential(key, at.credential)
    if credential is None:
        return None
    return _Position(credential, key.casefold() in _COMPARISON_OPERATORS)


class _PathWalk:
    """R3's path rule over literal input values, recording where each variable is used.

    Once an input-object key contains ``cred``, every key and every field-path-shaped string or
    enum value beneath it must name only allowlisted fields or neutral operators; and a string
    naming a credential path is held to the same rule from its credential segment on.
    """

    __slots__ = ("placements",)

    def __init__(self) -> None:
        self.placements: dict[str, set[_Position]] = {}

    def literal(self, value: Value, at: _Position) -> bool:
        """Whether a literal value is refused; records each variable's position on the way.

        Recursion is bounded by the parser, which refuses values nested beyond ``MAX_NESTING``.
        """
        if value.kind is ValueKind.VARIABLE:
            self.placements.setdefault(value.text, set()).add(at)
            return False
        if value.kind in {ValueKind.STRING, ValueKind.ENUM}:
            return _path_refused(value.text, at)
        if value.kind is ValueKind.LIST:
            return any(self.literal(item, at) for item in value.items)
        for key, member in value.fields:
            inner = _key_position(key, at)
            if inner is None or self.literal(member, inner):
                return True
        return False


def _variable_path_refused(value: object, at: _Position, depth: int = 0) -> bool:
    """R3's path rule over one caller variable's value, from the position it is used at."""
    if depth > _MAX_WALK_DEPTH:
        return True
    if isinstance(value, str):
        return _path_refused(value, at)
    if isinstance(value, dict):
        for key, member in value.items():
            inner = _key_position(str(key), at)
            if inner is None or _variable_path_refused(member, inner, depth + 1):
                return True
        return False
    if isinstance(value, list):
        return any(_variable_path_refused(member, at, depth + 1) for member in value)
    return False


def _checked_arguments(summary: DocumentSummary) -> tuple[list[Argument], set[str]]:
    """Every field argument R3 checks, and the variables used only in exempt write arguments.

    The exempt arguments are the caller's own input to ``createCredential``/``updateCredential``.
    A variable used there and anywhere else is checked.
    """
    checked: list[Argument] = []
    exempt_variables: set[str] = set()
    for selected in summary.fields:
        exempt = _WRITE_ARGUMENTS.get(selected.name.casefold(), frozenset())
        for argument in selected.arguments:
            if argument.name.casefold() in exempt:
                exempt_variables.update(_variables_in(argument.value))
            else:
                checked.append(argument)
    used = {name for argument in checked for name in _variables_in(argument.value)}
    return checked, exempt_variables - used


_PROBE_REFUSAL: Final = (
    "The document or its variables search, sort or filter on a secret field, or on a "
    "credential field outside the allowlist, which would reveal it through match counts "
    f"or ordering, so it is refused before anything is sent. {_TYPED_READERS_IF_CREDENTIAL}"
)

_PATH_REFUSAL: Final = (
    "The document or its variables search, sort or filter through a credential (an input key or "
    "a field path naming one) on something other than its allowlisted non-secret fields, or name "
    "a credential field this tool does not know, which could reveal a secret through match counts "
    f"or ordering, so it is refused before anything is sent. {_TYPED_READERS_IF_CREDENTIAL}"
)


def _probe_refusal(summary: DocumentSummary, variables: Mapping[str, object] | None) -> str | None:
    """R3: why the document or its variables search, sort or filter on a secret, if they do."""
    arguments, skipped = _checked_arguments(summary)
    # A variable used only in an exempt write argument is the caller's own input and is skipped;
    # one used anywhere else, or nowhere, is checked.
    scoped = {k: v for k, v in (variables or {}).items() if k not in skipped}
    defaults = [
        definition.default
        for operation in summary.operations
        for definition in operation.variables
        if definition.default is not None
    ]
    values = [
        *(argument.value for argument in arguments),
        *(argument.value for argument in _directive_arguments(summary)),
        *defaults,
    ]

    # The name check: secret names everywhere, and in a credential document every name a
    # credential field outside the allowlist could go by.
    rule = _probe_rule(summary, scoped)
    if rule.check_arguments and any(rule.name_refused(argument.name) for argument in arguments):
        return _PROBE_REFUSAL
    if any(_value_probe(value, rule) for value in values) or _variable_probe(scoped, rule):
        return _PROBE_REFUSAL

    # The path rule, over literals first (which records where each variable is used), then over
    # each variable from every position it is used at; an unused variable from the top.
    walk = _PathWalk()
    if any(walk.literal(value, _TOP) for value in values):
        return _PATH_REFUSAL
    for name, value in scoped.items():
        positions = walk.placements.get(name) or {_TOP}
        if any(_variable_path_refused(value, at) for at in positions):
            return _PATH_REFUSAL
    return None


# ---- the GraphQL entry points -------------------------------------------------------------------


def graphql_document_refusal(
    query: str, variables: Mapping[str, object] | None = None
) -> str | None:
    """Apply the module's GraphQL rule to one document and say why it is refused, if it is.

    The reason names only field and type names, which are ASCII identifiers by the grammar, never
    other document text: the document is caller input.

    :param query: The GraphQL document.
    :param variables: The caller's variables, for R3.
    :return: The caller-facing refusal reason, or ``None`` if the document may be sent.
    """
    try:
        summary = summarize_executable_document(query)
    except GraphQlSyntaxError as exc:
        return (
            f"The GraphQL document could not be read ({exc.reason}, line {exc.line}, column "
            f"{exc.column}), so it is refused rather than sent: this tool must check what a "
            "document selects before sending it, and cannot check one it cannot parse."
        )

    graph = _fragment_graph_refusal(summary)
    if graph is not None:
        return f"{graph} {_TYPED_READERS}"
    walk = _SelectionWalk({fragment.name: fragment for fragment in summary.fragments})
    try:
        for operation in summary.operations:
            walk.selections(operation.selections, _Context.OPEN, 0)
        # Every fragment on its own too, so one that no operation spreads is still checked.
        for fragment in summary.fragments:
            walk.selections(
                fragment.selections, _context_for_type(fragment.type_condition, _Context.OPEN), 0
            )
    except _Refused as refused:
        return refused.reason
    return _probe_refusal(summary, variables)


def refuse_credential_secret_document(
    query: str, variables: Mapping[str, object] | None = None, *, argument: str = "query"
) -> None:
    """Raise the standard refusal if ``query`` could read secret material.

    :param query: The GraphQL document.
    :param variables: The caller's variables.
    :param argument: The tool argument the refusal is addressed to.
    :raises ValidationBlocked: If ``graphql_document_refusal`` refuses the document.
    """
    reason = graphql_document_refusal(query, variables)
    if reason is not None:
        raise _blocked(argument, reason)


def _blocked(path: str, message: str) -> ValidationBlocked:
    # ``ValidationBlocked``, not a builtin: ``sl1_tool_boundary`` translates only
    # ``PowerPackMcpError`` into the caller-facing envelope.
    return ValidationBlocked(
        (ValidationFinding(path=path, rule=FindingCode.TOOL_ARGUMENT, message=message),)
    )


# ---- the REST rule ------------------------------------------------------------------------------

# The eight typed sub-collections the REST credential index lists, as observed on an appliance.
_REST_CREDENTIAL_TYPES: Final[frozenset[str]] = frozenset(
    {"snmp", "db", "soap", "ldap", "basic", "ssh", "powershell", "universal"}
)

# The only query parameters a credential index read may carry. Paging and the filter-info toggle
# change how many rows come back, never what a row contains.
_REST_INDEX_PARAMS: Final[frozenset[str]] = frozenset({"limit", "offset", "hide_filterinfo"})

# How many rounds of percent-decoding the normaliser applies. A path still changing after this
# many is not a real SL1 path, and is treated as a credential path (fail closed).
_MAX_DECODE_ROUNDS: Final = 4

# Characters that start a query string, a fragment or a matrix parameter inside a path segment.
_PATH_PARAMETER_START: Final = re.compile(r"[?#;]")

# The fields ``link_disp_field`` may name, on any path. SL1 inlines the named field of every linked
# resource in place of its URI, so ``link_disp_field=cred_pwd`` would print the password of every
# credential a row links to. A modest list of plain display fields: names, labels, addresses and
# dates, none of which is a secret on any resource.
REST_LINK_DISPLAY_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "name",
        "description",
        "user",
        "device",
        "ip",
        "hostname",
        "email",
        "organization",
        "class_type",
        "state",
        "title",
        "active",
        "create_date",
        "edit_date",
    }
)

# REST field names that are secrets on non-credential resources and that the patterns miss,
# measured on an appliance: ``account`` carries the security question and its answer.
_REST_SECRET_FIELDS: Final[frozenset[str]] = frozenset(
    {"verification_answer", "verification_question"}
)

# The query-parameter prefixes that name a field: ``filter.<field>.<op>`` and ``order.<field>``.
_FIELD_PARAMETER_PREFIXES: Final = ("filter", "order")

_LINK_DISPLAY_PARAMETER: Final = "link_disp_field"


def _decoded(text: str) -> str | None:
    """Percent-decode ``text`` to a fixed point and case-fold it; ``None`` if it never settles."""
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(text)
        if decoded == text:
            return text.strip().casefold()
        text = decoded
    return None


def is_rest_secret_field(name: str) -> bool:
    """Return whether a REST field or response key is a secret: R1, or ``_REST_SECRET_FIELDS``.

    :param name: A REST field name or response key.
    :return: ``True`` for a secret name.
    """
    return is_secret_name(name) or name.casefold() in _REST_SECRET_FIELDS


def _field_parameter_names(key: str) -> list[str]:
    """The field names a ``filter.``/``order.`` key refers to, or ``[]`` for any other key.

    Every segment after the prefix is returned, not only the first, so a nested or operator-first
    spelling is covered; ``.``, ``[`` and ``]`` all separate.
    """
    for prefix in _FIELD_PARAMETER_PREFIXES:
        if key.startswith(prefix) and key[len(prefix) : len(prefix) + 1] in {".", "["}:
            return [part for part in re.split(r"[.\[\]]+", key[len(prefix) :]) if part]
    return []


def _query_parameter_refusal(pairs: list[tuple[str, str]]) -> str | None:
    """The REST rule for query parameters on every path; see the module docstring."""
    for raw_key, raw_value in pairs:
        key = _decoded(raw_key)
        value = _decoded(raw_value)
        if key is None or value is None:
            return (
                "A query parameter is percent-encoded more deeply than any SL1 parameter, so what "
                "it does cannot be decided; it is refused."
            )
        if key == _LINK_DISPLAY_PARAMETER and value not in REST_LINK_DISPLAY_FIELDS:
            return (
                "link_disp_field puts the named field of every linked resource into its "
                "description, so it may name only one of "
                f"{', '.join(sorted(REST_LINK_DISPLAY_FIELDS))}. Omit it to use the resource's "
                "default description, or read the resource itself for its other fields."
            )
        if any(is_rest_secret_field(name) for name in _field_parameter_names(key)):
            return (
                "A filter or sort on a secret field would reveal it through match counts or "
                "ordering, so it is refused before anything is sent. Filter or sort on a "
                "non-secret field instead."
            )
    return None


def _embedded_query(path: str) -> list[tuple[str, str]]:
    """The query parameters written into ``path`` itself, after its first ``?``.

    Read twice, as written and fully percent-decoded, so an encoded ``?``, ``&`` or ``=`` cannot
    hide a parameter from one reading that a lenient server would see in the other.
    """
    pairs: list[tuple[str, str]] = []
    decoded = _decoded(path)
    for text in (path, decoded if decoded is not None else ""):
        if "?" in text:
            query = text.split("?", 1)[1].split("#", 1)[0]
            pairs.extend(parse_qsl(query, keep_blank_values=True))
    return pairs


def normalized_rest_path(path: str) -> tuple[tuple[str, ...], bool, bool] | None:
    """Normalise a REST path the way a lenient server might, for matching only.

    Percent-decoding is repeated to a fixed point, backslashes become slashes, the query string,
    fragment and ``;`` matrix parameters are cut off, case is folded, empty and ``.`` segments are
    dropped, ``..`` pops a segment, and a leading ``api`` segment (the REST base itself) is removed.
    The result is used only to decide whether a path names a credential resource; the path that is
    sent is the caller's, validated separately by ``sl1_client.paths``.

    :param path: The caller-supplied path.
    :return: ``(segments, has_parameters, has_traversal)``, or ``None`` if decoding never settles.
        ``has_traversal`` is whether any decoded segment was ``..``.
    """
    text = path
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    else:
        return None
    text = text.replace("\\", "/")
    has_parameters = _PATH_PARAMETER_START.search(text) is not None
    head = re.split(r"[?#]", text, maxsplit=1)[0]
    segments: list[str] = []
    has_traversal = False
    for raw in head.split("/"):
        segment = raw.split(";", 1)[0].strip().casefold()
        if segment in {"", "."}:
            continue
        if segment == "..":
            has_traversal = True
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    while segments and segments[0] == "api":
        segments.pop(0)
    return tuple(segments), has_parameters, has_traversal


def is_credential_path(path: str) -> bool:
    """Return whether ``path`` names a credential resource, failing closed.

    Any segment containing ``cred`` counts, not only a leading ``credential``, so a sub-resource
    spelling the shape of which has not been measured is treated as a credential path too.

    :param path: The caller-supplied path.
    :return: ``True`` for a credential path or a path that cannot be normalised.
    """
    normalized = normalized_rest_path(path)
    if normalized is None:
        return True
    segments, _, _ = normalized
    return any(CREDENTIAL_MARKER in segment for segment in segments)


def _is_plain_index(segments: tuple[str, ...]) -> bool:
    if segments == ("credential",):
        return True
    return (
        len(segments) == 2 and segments[0] == "credential" and segments[1] in _REST_CREDENTIAL_TYPES
    )


def check_rest_credential_access(
    method: str,
    path: str,
    query: Mapping[str, object] | None = None,
    *,
    argument: str = "path",
    query_argument: str | None = None,
) -> None:
    """Refuse a REST call on a credential resource unless it is a plain index read.

    Pure and network-free, so a refusal provably sends nothing. Two refusals apply to every path,
    not only credential ones: a path whose percent-decoding never settles, and a percent-encoded
    ``..`` segment. ``sl1_client.paths`` refuses a literal ``..``, but ``%2e%2e`` passes it, and a
    server that decodes before resolving would let it leave the REST base -- to ``/gql``, say,
    where ``sl1_graphql``'s document check would never run.

    The query-parameter rule (``link_disp_field``, and ``filter.``/``order.`` on a secret field)
    applies on every path too, to the separate parameters and to any embedded in the path.

    :param method: The HTTP method, upper-cased.
    :param path: The caller-supplied path or resource name.
    :param query: The query parameters the tool will send.
    :param argument: The tool argument the refusal is addressed to.
    :param query_argument: The tool argument a query-parameter refusal is addressed to; by default
        ``query_params`` when ``argument`` is ``path``, else ``argument``.
    :raises ValidationBlocked: If the call could read or change credential secrets.
    """
    parameters_argument = query_argument or ("query_params" if argument == "path" else argument)
    _check_query_parameters(path, query, argument=argument, parameters_argument=parameters_argument)
    normalized = normalized_rest_path(path)
    if normalized is None:
        raise _blocked(
            argument,
            "The path is percent-encoded more deeply than any SL1 path, so whether it names a "
            "credential resource cannot be decided; it is refused.",
        )
    segments, has_parameters, has_traversal = normalized
    if has_traversal:
        raise _blocked(
            argument,
            "The path contains a percent-encoded '..' segment, which could leave the SL1 REST "
            "base; it is refused. Send the resource path itself.",
        )
    if any(CREDENTIAL_MARKER in segment for segment in segments):
        _check_credential_path(
            method,
            segments,
            has_parameters=has_parameters,
            query=query,
            argument=argument,
            parameters_argument=parameters_argument,
        )


def _check_query_parameters(
    path: str, query: Mapping[str, object] | None, *, argument: str, parameters_argument: str
) -> None:
    """Apply the every-path query-parameter rule to the separate and the embedded parameters."""
    separate = [(str(key), str(value)) for key, value in (query or {}).items()]
    for pairs, addressed in ((separate, parameters_argument), (_embedded_query(path), argument)):
        reason = _query_parameter_refusal(pairs)
        if reason is not None:
            # These two rules apply to every path, so the typed-reader pointer is added only where
            # it is the right alternative.
            if is_credential_path(path):
                reason = f"{reason} {_TYPED_READERS}"
            raise _blocked(addressed, reason)


def _check_credential_path(
    method: str,
    segments: tuple[str, ...],
    *,
    has_parameters: bool,
    query: Mapping[str, object] | None,
    argument: str,
    parameters_argument: str,
) -> None:
    """Refuse anything on a credential path but a plain index GET with paging parameters."""
    if method != "GET":
        raise _blocked(
            argument,
            "Writes to SL1 REST credential resources are refused here, because their responses "
            "echo the stored credential. Use sl1_create_universal_credential, "
            "sl1_update_universal_credential, sl1_replace_universal_credential or "
            "sl1_delete_credential.",
        )
    if not _is_plain_index(segments) or has_parameters:
        raise _blocked(
            argument,
            "Only the plain SL1 REST credential indexes (credential, credential/<type>) can be "
            "read here; an individual credential's REST resource carries its secrets. "
            f"{_TYPED_READERS}",
        )
    extra = sorted(key for key in (query or {}) if key.casefold() not in _REST_INDEX_PARAMS)
    if extra:
        raise _blocked(
            parameters_argument,
            "A credential index read may carry only limit, offset and hide_filterinfo. "
            "extended_fetch would inline each credential with its secrets, and a filter or sort "
            f"could reveal a secret through match counts. {_TYPED_READERS}",
        )


# The keys an index row may keep, and the envelope keys around the rows.
_INDEX_ROW_KEYS: Final = ("URI", "description")
_INDEX_COUNT_KEYS: Final = ("total_matched", "total_returned")
_INDEX_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset(
    {"searchspec", "result_set", *_INDEX_COUNT_KEYS}
)


def _unfilterable() -> ValidationBlocked:
    return _blocked(
        "path",
        "SL1 returned a credential index in a shape this tool cannot reduce to URI and "
        f"description, so the response is withheld entirely. {_TYPED_READERS}",
    )


def _index_row(row: object) -> dict[str, object] | str:
    if isinstance(row, str):
        return row
    if not isinstance(row, dict):
        raise _unfilterable()
    return {key: row[key] for key in _INDEX_ROW_KEYS if isinstance(row.get(key), str)}


def _credential_index(body: object) -> object:
    """Project a credential index response onto ``URI`` and ``description`` per row.

    The two shapes SL1 returns for a collection are accepted: a bare list of rows
    (``hide_filterinfo=1``) and the ``searchspec``/``result_set`` envelope. Anything else, including
    the URI-keyed mapping ``extended_fetch`` produces, raises rather than being passed through.
    """
    if isinstance(body, list):
        return [_index_row(row) for row in body]
    if not isinstance(body, dict) or not set(body) <= _INDEX_ENVELOPE_KEYS:
        raise _unfilterable()
    shaped: dict[str, object] = {
        key: body[key]
        for key in _INDEX_COUNT_KEYS
        if isinstance(body.get(key), int) and not isinstance(body.get(key), bool)
    }
    if "searchspec" in body:
        # Filter metadata: field names and operators, which are schema rather than data. Still
        # scrubbed, like everything else.
        shaped["searchspec"] = scrub_credential_secrets(body["searchspec"])
    if "result_set" in body:
        rows = body["result_set"]
        if not isinstance(rows, list):
            raise _unfilterable()
        shaped["result_set"] = [_index_row(row) for row in rows]
    return shaped


def shape_rest_response[T](path: str, body: T) -> T:
    """Apply the REST rule's projection, then the response scrub, to one REST response.

    :param path: The path or resource name the response came from.
    :param body: The decoded response.
    :return: The shaped response, of the same top-level type.
    :raises ValidationBlocked: If a credential index came back in a shape that cannot be projected.
    """
    projected = _credential_index(body) if is_credential_path(path) else body
    return cast("T", scrub_credential_secrets(projected))


# ---- the response scrub -------------------------------------------------------------------------

# Where a scrubbed object lists the keys it lost, so an omission is visible rather than silent.
WITHHELD_KEYS_FIELD: Final = "credential_secrets_withheld"

# Fragments that mark a key as secret inside a credential-shaped object whose type is unknown, on
# top of the patterns applied to every object. REST credential field names have not been recorded
# in this repository, so this is a name heuristic and deliberately broad: it withholds
# ``snmpv3_auth_proto`` along with ``snmpv3_auth_pwd`` rather than guess which ``auth`` is which.
REST_SECRET_NAME_FRAGMENTS: Final[tuple[str, ...]] = (
    "pwd",
    "pass",
    "community",
    "key",
    "secret",
    "token",
    "cert",
    "priv",
    "header",
    "opts",
    "option",
    "curl",
    "auth",
)

# The scrub stops descending here and withholds what is below, rather than return it unexamined.
# GraphQL and REST documents are a few levels deep; JSON nested inside strings adds a level each.
MAX_SCRUB_DEPTH: Final = 64

_TOO_DEEP: Final = "**withheld: nested beyond the credential scrub's depth limit**"

# A string that starts like a JSON object or array but does not parse (truncated, say) cannot be
# checked for the secrets it may carry, so it is withheld rather than passed through.
_UNPARSEABLE_JSON: Final = (
    "**withheld: text that starts like JSON but does not parse, so the credential scrub cannot "
    "check it for secrets**"
)

# ``CredentialType`` names, read from the allowlist's keys rather than restated, so a new type
# needs one edit. Only membership is used here; which keys are safe stays ``_filter_definition``'s
# decision alone.
_CREDENTIAL_TYPE_NAMES: Final[frozenset[str]] = frozenset(_DEFINITION_ALLOWLIST)


# What may precede a JSON value in a string the scrub parses: JSON whitespace and the BOM.
_JSON_LEADING: Final = " \t\r\n\ufeff"


def _starts_like_json_container(text: str) -> bool:
    """Whether ``text`` starts, after whitespace and any BOM, like a JSON object or array."""
    return text.lstrip(_JSON_LEADING).startswith(("{", "["))


def _parsed_json(text: str) -> object | None:
    """Return ``text`` parsed if it is a JSON object, array or string, else ``None``.

    A JSON string counts because SL1's double encoding nests: a definition stringified twice is a
    string whose JSON is a string whose JSON is the object. Stopping at the first layer would
    return the inner layers as opaque text with every secret in them.
    """
    # A leading byte-order mark is skipped as well as whitespace: ``json.loads`` refuses one, and a
    # string the walk could not parse would be returned whole, secrets and all.
    stripped = text.lstrip(_JSON_LEADING)
    if not stripped.startswith(("{", "[", '"')):
        return None
    try:
        parsed: object = json.loads(stripped)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict | list | str) else None


def _as_object(value: object) -> dict[str, object]:
    """Type a value already checked to be a ``dict`` as a decoded JSON object; the one cast."""
    return cast("dict[str, object]", value)


def _definition_mapping(definition: object) -> dict[str, object] | None:
    if isinstance(definition, dict):
        return _as_object(definition)
    if isinstance(definition, str):
        parsed = _parsed_json(definition)
        if isinstance(parsed, dict):
            return _as_object(parsed)
    return None


def _is_credential_node(mapping: dict[str, object]) -> bool:
    """Return whether ``mapping`` is a credential carrying a ``definition``.

    Recognised by any one of: a ``__typename`` naming a credential type, a ``type`` that is a
    ``CredentialType`` member, or a ``definition`` with a known secret key at its top level. The
    last is what catches a credential selected without ``type`` or ``__typename``; it looks at the
    top level only, so a Guided Discovery definition that merely contains credentials further down
    is walked into rather than treated as one.
    """
    if "definition" not in mapping:
        return False
    if _is_template_node(mapping):
        return False
    typename = mapping.get("__typename")
    if isinstance(typename, str) and CREDENTIAL_MARKER in typename.casefold():
        return True
    if mapping.get("type") in _CREDENTIAL_TYPE_NAMES:
        return True
    definition = _definition_mapping(mapping["definition"])
    return definition is not None and any(key in CREDENTIAL_SECRET_KEYS for key in definition)


def _is_template_node(mapping: dict[str, object]) -> bool:
    """Return whether ``mapping`` is a ``CredentialField`` template rather than a credential.

    A template is a field-mapping (``definition.fields``: property names and flags), not a secret,
    and the credential guide needs it whole. Recognised by its ``__typename``, or, without one, by
    having neither ``id`` nor ``guid`` (a ``CredentialField`` has neither; every credential has
    both) and a ``definition`` with a ``fields`` list. Either way its keys still pass through the
    pattern scrub, so a template-shaped credential loses its secret-named keys all the same.
    """
    typename = mapping.get("__typename")
    if isinstance(typename, str):
        return typename.casefold().startswith(_TEMPLATE_TYPE_PREFIX)
    if "id" in mapping or "guid" in mapping:
        return False
    definition = _definition_mapping(mapping["definition"])
    return definition is not None and isinstance(definition.get("fields"), list)


def _is_bearing_secret_name(key: str) -> bool:
    """The wider heuristic for objects that look credential-shaped (``_is_secret_bearing``)."""
    folded = key.casefold()
    return folded in _SECRET_KEY_NAMES or any(part in folded for part in REST_SECRET_NAME_FRAGMENTS)


def _is_withheld_everywhere(key: str) -> bool:
    """A key withheld from every object: R1's names and the REST secret fields.

    ``WITHHELD_KEYS_FIELD`` contains ``secret`` and is this module's own, so it is exempt; without
    that, scrubbing a scrubbed response would withhold the list of what was withheld.
    """
    return key != WITHHELD_KEYS_FIELD and is_rest_secret_field(key)


def _is_secret_bearing(mapping: dict[str, object]) -> bool:
    """Return whether ``mapping`` looks like a credential or a definition, though not a node.

    A known secret key, a REST ``cred_*`` key, or a ``URI`` under a credential resource.
    """
    for key, value in mapping.items():
        if key in CREDENTIAL_SECRET_KEYS or key.casefold().startswith("cred_"):
            return True
        if key == "URI" and isinstance(value, str) and "/credential" in value.casefold():
            return True
    return False


def _scrubbed_node(mapping: dict[str, object]) -> dict[str, object]:
    """Reduce a credential node through the typed readers' own ``_safe_credential``.

    The same function, not a copy: the allowlist decides, and fields outside
    ``_SAFE_CREDENTIAL_FIELDS`` (``alignedOrganizations`` with its ``hash``, ``editedBy``) go.
    ``__typename`` is put back because it is schema, not data, and callers branch on it.
    """
    shaped: dict[str, object] = dict(_safe_credential(dict(mapping)))
    typename = mapping.get("__typename")
    if isinstance(typename, str):
        shaped["__typename"] = typename
    return shaped


def _scrubbed_mapping(mapping: dict[str, object], depth: int) -> dict[str, object]:
    if _is_credential_node(mapping):
        return _scrubbed_node(mapping)
    bearing = _is_secret_bearing(mapping)
    kept: dict[str, object] = {}
    withheld: list[str] = []
    for key, value in mapping.items():
        if _is_withheld_everywhere(key) or (bearing and _is_bearing_secret_name(key)):
            withheld.append(key)
        else:
            kept[key] = _scrub(value, depth + 1)
    if withheld:
        kept[WITHHELD_KEYS_FIELD] = sorted(withheld)
    return kept


def _scrub(value: object, depth: int) -> object:
    if depth >= MAX_SCRUB_DEPTH:
        return _TOO_DEEP
    if isinstance(value, dict):
        return _scrubbed_mapping(_as_object(value), depth)
    if isinstance(value, list):
        return [_scrub(member, depth + 1) for member in value]
    if isinstance(value, str):
        parsed = _parsed_json(value)
        if parsed is None:
            return _UNPARSEABLE_JSON if _starts_like_json_container(value) else value
        scrubbed = _scrub(parsed, depth + 1)
        # Re-serialised only when something was withheld, so an untouched JSON string keeps its
        # exact text. When it was, the string stays a string: the caller's parser still works.
        return value if scrubbed == parsed else json.dumps(scrubbed)
    return value


def scrub_credential_secrets[T](value: T) -> T:
    """Withhold credential secrets from a decoded SL1 response, wherever they sit.

    The walk handles three shapes:

    - A credential node (an object with a ``definition``; see ``_is_credential_node``) is reduced by
      the typed readers' ``_safe_credential``: the per-type allowlist decides, and a node whose
      type is unknown has its whole definition withheld.
    - Every other object loses each key that is a secret name under R1 (``is_secret_name``: the
      patterns, minus the exceptions, and the definition secret keys) or a REST secret field
      (``verification_answer``, ``verification_question``). An object that looks credential-shaped
      (``_is_secret_bearing``) also loses every key containing a ``REST_SECRET_NAME_FRAGMENTS``
      fragment. The lost keys are listed under ``WITHHELD_KEYS_FIELD``. A ``CredentialField``
      template is not a credential node and keeps its ``definition`` (``_is_template_node``).
    - A string that parses as a JSON object or array, after any leading whitespace or byte-order
      mark, is walked as JSON, and re-serialised if anything inside it was withheld. That is how a
      stringified definition, or a Guided Discovery session's definition carrying credential
      objects, is reached. A string that starts like a JSON object or array but does not parse
      (a truncated one, say) is replaced by a marker saying so: it cannot be checked.

    Never raises, never echoes a withheld value, and never mutates its input. The top-level type is
    preserved: an object stays an object and an array an array.

    :param value: The decoded response.
    :return: The scrubbed response.
    """
    return cast("T", _scrub(value, 0))

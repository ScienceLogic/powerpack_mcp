"""
Credential Definition Filter Tests

This module tests the withholding guard in ``sl1_list_credentials`` and ``sl1_get_credential``.
These are the only tools that fetch a secret and then drop it rather than never requesting it:
``Credential.definition`` is a ``JSON`` scalar carrying stringified JSON, so GraphQL cannot select
``host`` without ``password``. The withholding is post-processing in
``sl1_entity_tools._filter_definition``, and post-processing is the kind of control that rots
silently.

The eight ``CredentialType`` members are spelled out here, not imported. The real source of truth
is SL1's schema, which no unit test can reach, and comparing a source-module enum to an allowlist
in the same module would let both be edited together and agree while disagreeing with the
appliance. A ninth type means editing this file, which fails the allowlist coverage test until its
fields have been classified.
"""

from __future__ import annotations

import io
import json
import re
import tokenize
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

import httpx
import pytest

from powerpack_mcp.errors import (
    SECRET_FIELD_DENYLIST,
    FindingCode,
    ValidationBlocked,
    ValidationFinding,
    build_error_payload,
)
from powerpack_mcp.tools import sl1_descriptors as d
from powerpack_mcp.tools import sl1_entity_tools as ent
from powerpack_mcp.tools.sl1_pipeline import Sl1ToolContext

if TYPE_CHECKING:
    from powerpack_mcp.config import Config
    from powerpack_mcp.credentials import LceCredential

# The ``CredentialType`` enum as introspected from a test appliance: eight members. See the module
# docstring for why this is not imported from the source.
CREDENTIAL_TYPES: frozenset[str] = frozenset(
    {
        "BASIC_SNIPPET",
        "DATABASE",
        "LDAP",
        "POWERSHELL",
        "SNMP",
        "SOAP_XML",
        "SSH_KEY",
        "UNIVERSAL",
    }
)

# Every definition key that carries secret material. None may ever be returned, under any type.
#
# The first twenty were observed on an appliance across all eight types. ``authHeader`` and
# ``tokenKey`` were not observed; they are withheld because they were classified safe only from
# SL1's defaults table, and ``authHeader`` can carry a literal ``Authorization`` value. Fail closed
# on ambiguity.
#
# ``sshKeyData`` matters most. There is no field named ``pemkey`` in the schema, so a rule that
# excluded "password or pemkey" would ship every SSH private key while looking deliberate.
KNOWN_SECRET_KEYS: tuple[str, ...] = (
    "password",
    "apikey",
    "snmpRoCommunity",
    "snmpRwCommunity",
    "snmpv3PrivPwd",
    "proxyPasswd",
    "requestPasswd",
    "sshKeyData",
    "oauth2ClientSecret",
    "oauth2ResourceOwnerPassword",
    "oauth2ResourceOwnerAdditionalParams",
    "httpHeaders",
    "httpHeader1",
    "httpHeader2",
    "curlOptions",
    "requestSub1",
    "requestSub2",
    "requestSub3",
    "requestSub4",
    "authOverride",
    "opts",
    "authHeader",
    "tokenKey",
    # Measured from the AWS ``credentialFields`` templates. These are not redundant case variants:
    # matching is exact, so ``ProxyPasswd`` and ``proxyPasswd`` are different keys and both must be
    # listed. That is why the AWS subtypes needed their own measurement.
    "AwsSecretAccessKey",
    "ProxyPasswd",
    # The platform does not flag ``AwsAccessKeyId`` with ``encryption: true``. It is withheld as
    # one half of a key pair, on the same fail-closed rule as ``authHeader``. See the header of
    # ``_SUBTYPE_DEFINITION_ALLOWLIST``.
    "AwsAccessKeyId",
)

# The ten secret keys actually observed on the appliance, for the denylist measurement below.
OBSERVED_SECRET_KEYS: tuple[str, ...] = (
    "password",
    "snmpRoCommunity",
    "snmpRwCommunity",
    "snmpv3PrivPwd",
    "sshKeyData",
    "proxyPasswd",
    "requestPasswd",
    "curlOptions",
    "httpHeaders",
    "oauth2ClientSecret",
)

# A value distinctive enough that finding it anywhere in a payload is unambiguous. Synthetic.
CANARY = "CANARY-SECRET-VALUE-c0ffee"

SRC = Path(ent.__file__)


def code_only(path: Path) -> str:
    """Return ``path``'s source with comments and string literals removed.

    Copied from ``test_source_invariants`` rather than imported, so the two guard suites are not
    coupled. Comments carry the prose discussing the denylist, and string literals carry the
    docstrings, which in this codebase name almost everything they forbid.
    """
    out: list[str] = []
    for tok in tokenize.generate_tokens(io.StringIO(path.read_text()).readline):
        if tok.type in (tokenize.COMMENT, tokenize.STRING):
            continue
        out.append(tok.string)
    return " ".join(out)


def definition_for(credential_type: str, *, secrets: bool = True) -> str:
    """Return a stringified definition with every allowed key and every secret key.

    Deliberately over-full. A real SNMP definition has no ``sshKeyData``; including one anyway
    makes the guard test a statement about ``_filter_definition`` rather than about SL1's data.
    """
    payload: dict[str, Any] = dict.fromkeys(
        ent._DEFINITION_ALLOWLIST.get(credential_type, frozenset()), "safe-value"
    )
    if secrets:
        payload.update(dict.fromkeys(KNOWN_SECRET_KEYS, CANARY))
    return json.dumps(payload)


def node_for(credential_type: str, *, node_id: str = "1", secrets: bool = True) -> dict[str, Any]:
    """Return one ``Credential`` node as SL1 returns it, with ``definition`` as a string."""
    return {
        "id": node_id,
        "guid": "A8BE00FB3A661D4DF478D826D801C86A",
        "name": f"Sample {credential_type}",
        "type": credential_type,
        "subType": "",
        "typeDescription": credential_type.title(),
        "timeout": 10000,
        "dateEdited": 1788203045,
        "allOrganizations": True,
        "definition": definition_for(credential_type, secrets=secrets),
    }


def _ctx(
    config: Config, credential: LceCredential, payload: dict[str, Any]
) -> tuple[Sl1ToolContext, list[httpx.Request]]:
    """Build a context whose SL1 transport is mocked, so no appliance or network is needed."""
    from powerpack_mcp.lce_client import LceClient
    from powerpack_mcp.sl1_client import Sl1Client

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": payload})

    sl1 = Sl1Client(config)
    sl1._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    lce = LceClient(config)
    lce._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return (
        Sl1ToolContext(
            client=sl1, config=config, credential_source=lambda: credential, lce_client=lce
        ),
        seen,
    )


def leaked_keys(shaped: dict[str, Any]) -> list[str]:
    """Return every known secret key that reached ``shaped``'s returned definition.

    Checked as a key and as a value: a filter that dropped the key but stringified the whole
    definition elsewhere in the payload would pass a key-only check.
    """
    definition = shaped.get("definition")
    keys = list(definition) if isinstance(definition, dict) else []
    found = [key for key in KNOWN_SECRET_KEYS if key in keys]
    if CANARY in json.dumps(shaped):
        found.append(f"<canary value present in payload> {sorted(keys)}")
    return found


class TestTheAllowlistIsClosedOverTheEnum:
    """A ninth ``CredentialType`` must fail here, not reach the withhold-all branch in production.

    The withhold-all branch is safe but silently useless: both tools would return metadata and an
    empty definition for every credential of that type. This makes it a deliberate code change.
    """

    def test_the_allowlist_covers_exactly_the_eight_credential_types(self) -> None:
        assert set(ent._DEFINITION_ALLOWLIST) == set(CREDENTIAL_TYPES), (
            "the per-type allowlist and SL1's CredentialType enum disagree. If SL1 has gained a "
            "type, classify its definition fields against a live appliance and add it here and in "
            "_DEFINITION_ALLOWLIST -- do not leave it to the withhold-all branch, which is safe "
            "but returns nothing useful for every credential of that type."
        )

    def test_no_allowlist_entry_names_a_known_secret_key(self) -> None:
        """The table read directly, before any filtering runs. A typo here is a shipped leak."""
        # Listed as pairs rather than merged into one dict: the two tables have different key types
        # (``str`` vs ``tuple[str, str]``), and ``mypy --strict`` rejects the merge.
        every_table: list[tuple[object, frozenset[str]]] = [
            *ent._DEFINITION_ALLOWLIST.items(),
            *ent._SUBTYPE_DEFINITION_ALLOWLIST.items(),
        ]
        offenders = {
            key: sorted(allowed & set(KNOWN_SECRET_KEYS))
            for key, allowed in every_table
            if allowed & set(KNOWN_SECRET_KEYS)
        }
        assert offenders == {}, f"an allowlist names secret keys: {offenders}"

    def test_the_sweep_actually_covers_the_subtype_table(self) -> None:
        """A control on the test above, so its sweep cannot silently lose the subtype table.

        This fails if ``_SUBTYPE_DEFINITION_ALLOWLIST`` is empty, absent, or no longer a mapping of
        key sets.
        """
        assert ent._SUBTYPE_DEFINITION_ALLOWLIST, "the subtype table is empty; the sweep is vacuous"
        for (credential_type, sub_type), allowed in ent._SUBTYPE_DEFINITION_ALLOWLIST.items():
            assert credential_type in CREDENTIAL_TYPES, (
                f"subtype entry {(credential_type, sub_type)!r} names a type outside SL1's enum"
            )
            assert sub_type, "an empty subType would shadow nothing; use _DEFINITION_ALLOWLIST"
            assert allowed, f"{(credential_type, sub_type)!r} allows nothing -- omit it instead"

    def test_authheader_and_tokenkey_are_absent_from_universal(self) -> None:
        """Pinned as a decision, so restoring them needs a deliberate edit and a measurement.

        Both were classified safe from a defaults table and never observed on an appliance. They are
        withheld for the same reason as ``httpHeader1``/``httpHeader2``: a header field can carry an
        ``Authorization`` value. If a measurement shows they are safe, delete this test in the same
        commit that adds them.
        """
        assert "authHeader" not in ent._DEFINITION_ALLOWLIST["UNIVERSAL"]
        assert "tokenKey" not in ent._DEFINITION_ALLOWLIST["UNIVERSAL"]
        # The selector ``oauth2TokenKey`` is a different field and is allowed. Pinned so removing
        # ``tokenKey`` does not remove this one by name similarity.
        assert "oauth2TokenKey" in ent._DEFINITION_ALLOWLIST["UNIVERSAL"]


class TestTheAwsSubtypesAreClassifiedFromTheMeasuredTemplates:
    """The AWS subtype allowlist is checked against the measured templates.

    ``AWS_FIELD_TEMPLATES`` is the ``credentialFields`` ``definition.fields`` for the three
    ``UNIVERSAL`` AWS subtypes, read from a test appliance: each propName and whether the platform
    set ``encryption: true``. Pinning it here makes the tests derivations rather than a second copy
    of ``_AWS_UNIVERSAL_SAFE``. The platform flag marks two of these fields, and the allowlist
    withholds three; see ``test_the_platform_flag_alone_is_not_sufficient``.
    """

    # propName -> ``encryption: true``, measured per subtype.
    AWS_FIELD_TEMPLATES: ClassVar[dict[str, dict[str, bool]]] = {
        "aws assume role": {
            "AwsAccessKeyId": False,
            "AwsSecretAccessKey": True,
            "AwsEndpoint": False,
            "Config": False,
            "ProxyHost": False,
            "ProxyPort": False,
            "ProxyUser": False,
            "ProxyPasswd": True,
            "Regions": False,
            "AssumeRole": False,
            "AssumeRoleSession": False,
            "OrganizationCreation": False,
            "Tags": False,
            "ProxyProtocol": False,
            "SL1APISSLVerify": False,
        },
        "aws ec2": {
            "AwsEndpoint": False,
            "OrganizationArn": False,
            "Config": False,
            "ProxyHost": False,
            "ProxyPort": False,
            "ProxyUser": False,
            "ProxyPasswd": True,
            "Regions": False,
            "AssumeRole": False,
            "AssumeRoleSession": False,
            "OrganizationCreation": False,
            "Tags": False,
            "IAM": False,
            "ProxyProtocol": False,
            "SL1APISSLVerify": False,
        },
        "aws iam": {
            "AwsAccessKeyId": False,
            "AwsSecretAccessKey": True,
            "AwsEndpoint": False,
            "Config": False,
            "ProxyHost": False,
            "ProxyPort": False,
            "ProxyUser": False,
            "ProxyPasswd": True,
            "Regions": False,
            "Tags": False,
            "ProxyProtocol": False,
            "SL1APISSLVerify": False,
        },
    }

    def test_no_encryption_flagged_field_is_allowlisted(self) -> None:
        """The floor. Anything the platform itself calls secret must not be returned."""
        flagged = {
            name
            for template in self.AWS_FIELD_TEMPLATES.values()
            for name, encrypted in template.items()
            if encrypted
        }
        assert flagged == {"AwsSecretAccessKey", "ProxyPasswd"}, (
            "the measured templates changed; re-read them before touching the allowlist"
        )
        assert not (flagged & ent._AWS_UNIVERSAL_SAFE)

    def test_the_platform_flag_alone_is_not_sufficient(self) -> None:
        """Deriving the withheld set from ``encryption: true`` would return ``AwsAccessKeyId``.

        The platform does not flag it. This fails if someone later "simplifies" the table into a
        flag lookup.
        """
        unflagged = {
            name
            for template in self.AWS_FIELD_TEMPLATES.values()
            for name, encrypted in template.items()
            if not encrypted
        }
        assert "AwsAccessKeyId" in unflagged
        assert "AwsAccessKeyId" not in ent._AWS_UNIVERSAL_SAFE
        assert "AwsAccessKeyId" in KNOWN_SECRET_KEYS

    def test_the_allowlist_names_no_field_no_template_declares(self) -> None:
        """A misspelled safe name is inert, which is why nothing else would catch it.

        Allowlisting an absent key is harmless for secrecy, but ``AwsEndpiont`` would also withhold
        a safe field forever. This tells "kept for a key SL1 might return" apart from a typo.
        """
        declared = {name for template in self.AWS_FIELD_TEMPLATES.values() for name in template}
        assert declared >= ent._AWS_UNIVERSAL_SAFE, (
            f"allowlisted but declared by no measured template: "
            f"{sorted(ent._AWS_UNIVERSAL_SAFE - declared)}"
        )

    @pytest.mark.parametrize("sub_type", ["aws assume role", "aws ec2", "aws iam"])
    def test_every_non_secret_field_of_each_subtype_is_returned(self, sub_type: str) -> None:
        """Subtype by subtype, the safe fields come back and the secrets do not."""
        template = self.AWS_FIELD_TEMPLATES[sub_type]
        definition = json.dumps(dict.fromkeys(template, "measured-value"))

        kept, withheld, reason = ent._filter_definition(definition, "UNIVERSAL", sub_type)

        assert reason is None
        expected_secret = {name for name, enc in template.items() if enc} | {"AwsAccessKeyId"}
        assert set(withheld) == expected_secret & set(template)
        assert set(kept) == set(template) - expected_secret
        assert CANARY not in json.dumps(kept)
        assert kept, "every field withheld is the defect, not a fix"

    def test_the_reported_credential_reads_back(self) -> None:
        """An AWS assume-role credential returns 12 of its 15 fields.

        It used to return ``definition: {}`` with every key withheld. The withheld three are named,
        so the omission stays visible.
        """
        observed_keys = sorted(self.AWS_FIELD_TEMPLATES["aws assume role"])
        definition = json.dumps(dict.fromkeys(observed_keys, "v"))

        kept, withheld, reason = ent._filter_definition(definition, "UNIVERSAL", "aws assume role")

        assert reason is None
        assert len(kept) == 12
        assert withheld == ["AwsAccessKeyId", "AwsSecretAccessKey", "ProxyPasswd"]

    def test_an_unlisted_subtype_still_uses_the_type_level_allowlist(self) -> None:
        """A subtype with no entry of its own behaves exactly as its type does.

        ``Low-code Tools: REST v104`` is not in ``_SUBTYPE_DEFINITION_ALLOWLIST``, so it falls
        through to ``UNIVERSAL``'s allowlist.
        """
        definition = definition_for("UNIVERSAL")

        with_sub = ent._filter_definition(definition, "UNIVERSAL", "Low-code Tools: REST v104")
        without_sub = ent._filter_definition(definition, "UNIVERSAL")

        assert with_sub == without_sub
        assert with_sub[0], "the REST fallback returned nothing; the fallback is broken"

    def test_an_unknown_type_withholds_everything_whatever_the_subtype(self) -> None:
        """The fail-closed branch is reached through the fallback, so a subtype cannot bypass it."""
        definition = json.dumps({"AwsEndpoint": "https://example.invalid", "Regions": "ALL"})

        kept, withheld, reason = ent._filter_definition(definition, "QUANTUM_SNIPPET", "aws iam")

        assert kept == {}
        assert withheld == ["AwsEndpoint", "Regions"]
        assert reason is not None
        assert "QUANTUM_SNIPPET" in reason


class TestEverySecretIsWithheldForEveryType:
    """The central table: every ``KNOWN_SECRET_KEYS`` entry for each of the 8 types.

    The count is not written here on purpose; ``parametrize`` reports the real one, and a number in
    a docstring goes stale silently.
    """

    @pytest.mark.parametrize("secret_key", KNOWN_SECRET_KEYS)
    def test_the_key_is_withheld_under_every_credential_type(self, secret_key: str) -> None:
        for credential_type in sorted(CREDENTIAL_TYPES):
            allowed, withheld, reason = ent._filter_definition(
                definition_for(credential_type), credential_type
            )
            assert secret_key not in allowed, (
                f"{secret_key!r} was RETURNED for type {credential_type} -- this is a secret leak"
            )
            assert reason is None
            assert secret_key in withheld, (
                f"{secret_key!r} was dropped for {credential_type} but is not reported in "
                "definition_withheld_keys, so the omission is invisible to the caller"
            )

    @pytest.mark.parametrize("credential_type", sorted(CREDENTIAL_TYPES))
    def test_the_allowed_keys_do_survive(self, credential_type: str) -> None:
        """The other half. A filter that returned ``{}`` always would pass every test above."""
        allowed, _, reason = ent._filter_definition(
            definition_for(credential_type), credential_type
        )
        assert reason is None
        assert set(allowed) == set(ent._DEFINITION_ALLOWLIST[credential_type]), (
            f"{credential_type}: the filter dropped keys the allowlist permits"
        )

    def test_withheld_keys_are_sorted(self) -> None:
        _, withheld, _ = ent._filter_definition(definition_for("SNMP"), "SNMP")
        assert withheld == sorted(withheld)

    def test_a_container_under_an_allowed_key_is_withheld_too(self) -> None:
        """An allowed key name with an unmeasured shape is withheld.

        Every value observed live is a JSON scalar. A nested object under ``host`` could hold secret
        material a key-level check cannot see, so it is withheld and reported.
        """
        definition = json.dumps({"host": {"inner": CANARY}, "port": 22, "user": "root"})
        allowed, withheld, reason = ent._filter_definition(definition, "SSH_KEY")
        assert reason is None
        assert set(allowed) == {"port", "user"}
        assert withheld == ["host"]
        assert CANARY not in json.dumps(allowed)


class TestAnUnrecognisedTypeWithholdsEverything:
    """What makes a ninth ``CredentialType`` safe by default rather than by remembering."""

    @pytest.mark.parametrize("credential_type", ["QUANTUM_TUNNEL", "", "snmp", None, 7])
    def test_nothing_is_returned_for_a_type_not_in_the_allowlist(
        self, credential_type: object
    ) -> None:
        allowed, withheld, reason = ent._filter_definition(
            definition_for("UNIVERSAL"), credential_type
        )
        assert allowed == {}
        assert reason is not None, "the payload must SAY the definition was withheld"
        assert set(KNOWN_SECRET_KEYS) <= set(withheld)

    def test_the_lowercase_spelling_of_a_real_type_is_not_accepted(self) -> None:
        """Matching is exact: ``snmp`` is not ``SNMP``, and guessing would be the loose way."""
        allowed, _, reason = ent._filter_definition(definition_for("SNMP"), "snmp")
        assert allowed == {}
        assert reason is not None

    def test_an_unparseable_definition_is_withheld_without_being_echoed(self) -> None:
        """The one path where the content is unknown, so it must not appear in the message."""
        allowed, withheld, reason = ent._filter_definition(f"not json {CANARY}", "SNMP")
        assert allowed == {}
        assert withheld == []
        assert reason is not None
        assert CANARY not in reason

    def test_a_null_definition_is_empty_rather_than_an_error(self) -> None:
        allowed, withheld, reason = ent._filter_definition(None, "SNMP")
        assert (allowed, withheld, reason) == ({}, [], None)

    def test_a_definition_that_is_not_a_mapping_is_withheld(self) -> None:
        allowed, _, reason = ent._filter_definition(json.dumps([CANARY]), "SNMP")
        assert allowed == {}
        assert reason is not None
        assert CANARY not in reason

    def test_a_definition_arriving_as_a_real_object_is_still_filtered(self) -> None:
        """SL1 sends a string today, but ``definition``'s GraphQL type is ``JSON``.

        If a future build returns an object, the filter must still filter, not withhold everything
        as an unknown shape and certainly not pass it along. "SL1 sends a string" is an
        observation, not a contract.
        """
        raw = json.loads(definition_for("SSH_KEY"))
        allowed, withheld, reason = ent._filter_definition(raw, "SSH_KEY")
        assert reason is None
        assert set(allowed) == {"host", "port", "user"}
        assert "sshKeyData" in withheld
        assert CANARY not in json.dumps(allowed)

    @pytest.mark.parametrize("definition", [7, 4.5, True, [1, 2]])
    def test_a_definition_of_an_unexpected_python_type_is_withheld(
        self, definition: object
    ) -> None:
        """Neither a string nor a mapping: nothing to parse, so nothing is returned."""
        allowed, withheld, reason = ent._filter_definition(definition, "SNMP")
        assert (allowed, withheld) == ({}, [])
        assert reason is not None


class TestNeitherToolReturnsARawDefinitionString:
    """The end-to-end claim, through the real tool functions and a mocked transport.

    ``_filter_definition`` being correct does not mean either tool uses it.
    """

    @pytest.mark.anyio
    async def test_the_list_tool_emits_a_parsed_object_and_no_secret(
        self, config: Config, credential: LceCredential
    ) -> None:
        payload = {
            "credentials": {
                "pageInfo": {"matchCount": 8, "hasNextPage": False},
                "edges": [
                    {"node": node_for(t, node_id=str(i))}
                    for i, t in enumerate(sorted(CREDENTIAL_TYPES), start=1)
                ],
            }
        }
        context, _ = _ctx(config, credential, payload)
        result = await ent.make_sl1_list_credentials(context)()
        assert isinstance(result, list)
        assert len(result) == len(CREDENTIAL_TYPES)
        for shaped in result:
            assert isinstance(shaped["definition"], dict), (
                "definition must leave as a parsed object; the string SL1 sent contains the secrets"
            )
            assert leaked_keys(shaped) == []
        assert CANARY not in json.dumps(result)

    @pytest.mark.anyio
    async def test_the_get_tool_emits_a_parsed_object_and_no_secret(
        self, config: Config, credential: LceCredential
    ) -> None:
        for credential_type in sorted(CREDENTIAL_TYPES):
            context, _ = _ctx(config, credential, {"credential": node_for(credential_type)})
            shaped = await ent.make_sl1_get_credential(context)(credential_id=131)
            assert isinstance(shaped, dict)
            assert isinstance(shaped["definition"], dict)
            assert leaked_keys(shaped) == [], credential_type
            assert CANARY not in json.dumps(shaped)

    @pytest.mark.anyio
    async def test_a_ninth_credential_type_reaches_the_caller_as_an_explicit_refusal(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The withhold-all branch, asserted through the tool and not just the filter.

        This is what a future SL1 release would produce: an empty definition plus a
        ``definition_withheld_reason`` saying why, rather than an empty definition that looks like
        a credential with no settings.
        """
        node = node_for("UNIVERSAL")
        node["type"] = "QUANTUM_TUNNEL"
        context, _ = _ctx(config, credential, {"credential": node})
        shaped = await ent.make_sl1_get_credential(context)(credential_id=131)
        assert isinstance(shaped, dict)
        assert shaped["definition"] == {}
        assert "QUANTUM_TUNNEL" in shaped["definition_withheld_reason"]
        assert set(KNOWN_SECRET_KEYS) <= set(shaped["definition_withheld_keys"])
        assert CANARY not in json.dumps(shaped)

    @pytest.mark.anyio
    async def test_a_credential_that_is_not_an_object_is_refused_not_wrapped(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Fail closed. The PowerPack reader wraps an odd shape under a key; this must not.

        Wrapping would hand the caller a value ``_safe_credential`` never inspected.
        """
        context, _ = _ctx(config, credential, {"credential": [CANARY]})
        payload = await ent.make_sl1_get_credential(context)(credential_id=131)
        assert isinstance(payload, dict)
        assert "error" in payload
        assert CANARY not in json.dumps(payload)

    @pytest.mark.anyio
    async def test_neither_tool_returns_alignedorganizations_or_editedby(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``Organization`` has a ``hash`` field, so the fence drops it even if a document adds it.

        Simulates SL1 answering with fields neither document asks for.
        """
        node = node_for("SNMP")
        node["alignedOrganizations"] = [{"id": "0", "company": "System", "hash": CANARY}]
        node["editedBy"] = 1
        context, _ = _ctx(config, credential, {"credential": node})
        shaped = await ent.make_sl1_get_credential(context)(credential_guid="A" * 32)
        assert isinstance(shaped, dict)
        assert "alignedOrganizations" not in shaped
        assert "editedBy" not in shaped
        assert CANARY not in json.dumps(shaped)

    @pytest.mark.anyio
    async def test_truncation_is_reported_rather_than_inferred(
        self, config: Config, credential: LceCredential
    ) -> None:
        payload = {
            "credentials": {
                "pageInfo": {"matchCount": 36, "hasNextPage": True},
                "edges": [{"node": node_for("LDAP")}],
            }
        }
        context, _ = _ctx(config, credential, payload)
        result = await ent.make_sl1_list_credentials(context)(first=1)
        assert isinstance(result, dict)
        assert result["truncated"] is True
        assert result["match_count"] == 36
        assert CANARY not in json.dumps(result)

    @pytest.mark.anyio
    async def test_a_glob_is_stripped_because_sl1_matches_it_literally(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Measured: ``contains: "Cisco*"`` returns 0 on the appliance; ``"cisco"`` returns 4."""
        payload = {"credentials": {"pageInfo": {"matchCount": 0}, "edges": []}}
        context, seen = _ctx(config, credential, payload)
        await ent.make_sl1_list_credentials(context)(name_contains="*Cisco*")
        sent = json.loads(seen[-1].content)
        assert sent["variables"]["search"] == {"or": [{"name": {"contains": "Cisco"}}]}

    @pytest.mark.anyio
    async def test_all_three_lookups_become_one_or_clause(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Search pushes down: one round trip serves name, id and guid, with no client filtering."""
        payload = {"credentials": {"pageInfo": {"matchCount": 0}, "edges": []}}
        context, seen = _ctx(config, credential, payload)
        await ent.make_sl1_list_credentials(context)(
            name_contains="sample", credential_id=131, credential_guid="A" * 32
        )
        assert len(seen) == 1
        sent = json.loads(seen[-1].content)
        assert sent["variables"]["search"] == {
            "or": [
                {"name": {"contains": "sample"}},
                {"id": {"eq": "131"}},
                {"guid": {"eq": "A" * 32}},
            ]
        }

    @pytest.mark.anyio
    async def test_no_lookup_sends_a_null_search_not_an_empty_disjunction(
        self, config: Config, credential: LceCredential
    ) -> None:
        payload = {"credentials": {"pageInfo": {"matchCount": 0}, "edges": []}}
        context, seen = _ctx(config, credential, payload)
        await ent.make_sl1_list_credentials(context)()
        sent = json.loads(seen[-1].content)
        assert sent["variables"]["search"] is None


class TestGetRequiresExactlyOneIdentifier:
    """Validated client-side, because SL1 answers both-null with an unhelpful loader error."""

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "kwargs",
        [{}, {"credential_id": 131, "credential_guid": "A" * 32}, {"credential_guid": "   "}],
    )
    async def test_neither_or_both_is_refused_before_dispatch(
        self, config: Config, credential: LceCredential, kwargs: dict[str, Any]
    ) -> None:
        """An envelope, not an escaping exception.

        ``sl1_tool_boundary`` translates ``ValidationBlocked`` through ``build_error_payload``, so
        the caller sees a ``validation_blocked`` envelope with the ``tool_argument`` code. Asserting
        ``pytest.raises`` here would be asserting that the boundary is broken.
        """
        context, seen = _ctx(config, credential, {"credential": node_for("LDAP")})
        payload = await ent.make_sl1_get_credential(context)(**kwargs)
        assert seen == [], "the request must not be issued"
        assert isinstance(payload, dict)
        assert payload["error"]["type"] == "validation_blocked"
        assert payload["error"]["details"][0]["rule"] == "tool_argument"

    def test_the_refusal_really_is_a_validationblocked(self) -> None:
        """Pin the exception type the boundary translates into the envelope above.

        ``sl1_tool_boundary`` translates ``PowerPackMcpError`` and nothing else, so a bare
        ``ValueError`` would escape as an unhandled exception while the test above still read as
        checking the same thing.
        """
        finding = ValidationFinding(
            path="credential_id", rule=FindingCode.TOOL_ARGUMENT, message="pinned"
        )
        # ``build_error_payload`` is annotated ``dict[str, object]``, so the nested reads need a
        # narrowing step rather than a chain of subscripts.
        error = build_error_payload(ValidationBlocked([finding]))["error"]
        assert isinstance(error, dict)
        assert error["type"] == "validation_blocked"
        details = error["details"]
        assert isinstance(details, list)
        assert details[0]["rule"] == "tool_argument"

    @pytest.mark.anyio
    async def test_only_the_supplied_variable_is_sent(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The other argument is absent, not null: ``credential(id: null, guid: null)`` fails
        server-side, so a stray null is worth not sending.
        """
        context, seen = _ctx(config, credential, {"credential": node_for("LDAP")})
        await ent.make_sl1_get_credential(context)(credential_id=131)
        assert json.loads(seen[-1].content)["variables"] == {"id": "131"}

        context, seen = _ctx(config, credential, {"credential": node_for("LDAP")})
        await ent.make_sl1_get_credential(context)(credential_guid=" a8be ")
        assert json.loads(seen[-1].content)["variables"] == {"guid": "a8be"}


class TestTheDocumentsAndTheFieldFenceAgree:
    """``_SAFE_CREDENTIAL_FIELDS`` is narrower than the documents on purpose; drift must be visible.

    Without this, widening a document would either forward a new field unreviewed or have the fence
    drop it silently.
    """

    @staticmethod
    def selected(document: str) -> frozenset[str]:
        match = re.search(r"(?:node|credential\([^)]*\))\s*\{([^{}]*)\}", document)
        assert match is not None, "could not find the Credential selection set in the document"
        return frozenset(match.group(1).split())

    @pytest.mark.parametrize(
        "descriptor", [d.LIST_CREDENTIALS, d.GET_CREDENTIAL], ids=lambda x: x.tool_name
    )
    def test_the_document_selects_exactly_the_fence_plus_definition(
        self, descriptor: d.GraphQlDescriptor
    ) -> None:
        assert self.selected(descriptor.document) == frozenset(
            {*ent._SAFE_CREDENTIAL_FIELDS, "definition"}
        )

    @pytest.mark.parametrize(
        "descriptor", [d.LIST_CREDENTIALS, d.GET_CREDENTIAL], ids=lambda x: x.tool_name
    )
    def test_no_document_selects_alignedorganizations(
        self, descriptor: d.GraphQlDescriptor
    ) -> None:
        """`Organization` has a ``hash`` field. The field is absent, not narrowly selected."""
        assert "alignedOrganizations" not in descriptor.document

    @staticmethod
    def arguments(document: str) -> frozenset[str]:
        """The argument names of the ``credentials(...)`` call, nested values excluded.

        ``order``'s value is a list of objects carrying their own ``field:``/``direction:`` keys,
        so the bracketed value is removed before the names are read.
        """
        match = re.search(r"credentials\(\s*([^)]*)\)", document)
        assert match is not None, "could not find the credentials() call in the document"
        return frozenset(re.findall(r"(\w+)\s*:", re.sub(r"\[[^\]]*\]", "", match.group(1))))

    def test_the_list_document_never_passes_the_ignored_type_argument(self) -> None:
        """The top-level ``type:`` argument of ``credentials`` is silently ignored by SL1.

        ``credentials(first: 1000, type: "SNMP")`` returned all 36 records, of every type, while
        ``search: { type: { eq: "SNMP" } }`` pushes down and returned 12 (see ``sl1_descriptors``).
        The failure is a filter that appears to work and does not, and ``type:`` is in SL1's schema,
        so a future editor would naturally add it. The argument set is pinned positively, so a
        renamed argument with the same defect is caught too.
        """
        assert self.arguments(d.LIST_CREDENTIALS.document) == frozenset(
            {"first", "search", "order"}
        )
        assert "$type" not in d.LIST_CREDENTIALS.document, "nor declared as a variable"

    def test_the_sort_direction_is_lowercase(self) -> None:
        """``direction: ASC`` is a validation error, because ``SortOrder``'s members are lowercase.

        Likewise ``field: "name"`` is a quoted scalar, not an enum member. Both read like typos and
        get "corrected" into a broken document, and the error only appears against a real server.
        """
        assert 'order: [{ field: "name", direction: asc }]' in d.LIST_CREDENTIALS.document

    def test_both_readers_are_non_mutating_and_declare_no_secret_input(self) -> None:
        for descriptor in (d.LIST_CREDENTIALS, d.GET_CREDENTIAL):
            assert descriptor.is_mutating is False
            assert descriptor.carries_secret_input is False
            assert descriptor.is_passthrough is False


class TestNonVacuity:
    """The guard on the guard: a check that cannot fail is not a check."""

    def test_the_check_would_catch_a_violation(self) -> None:
        """Feed the definitions through a deliberately broken filter and prove a leak is found.

        The broken filter is a denylist over ``errors.SECRET_FIELD_DENYLIST``, the approach that was
        rejected. If ``KNOWN_SECRET_KEYS`` were empty, ``definition_for`` produced nothing, or
        ``leaked_keys`` looked at the wrong key, this test would find no leaks and fail.
        """

        def broken_filter(definition: str) -> dict[str, Any]:
            parsed: dict[str, Any] = json.loads(definition)
            return {k: v for k, v in parsed.items() if k.lower() not in SECRET_FIELD_DENYLIST}

        leaks: dict[str, list[str]] = {}
        for credential_type in sorted(CREDENTIAL_TYPES):
            shaped = {"definition": broken_filter(definition_for(credential_type))}
            found = leaked_keys(shaped)
            if found:
                leaks[credential_type] = found
        assert len(leaks) == len(CREDENTIAL_TYPES), (
            "the denylist filter leaked nothing for some type -- then this file's machinery is "
            f"not detecting leaks at all. leaks: {leaks}"
        )
        assert "sshKeyData" in broken_filter(definition_for("SSH_KEY")), (
            "the rejected denylist really does return the SSH private key; if this stops being "
            "true the measurement in _DEFINITION_ALLOWLIST's header needs revisiting"
        )

    def test_the_shipped_denylist_catches_one_of_the_ten_observed_secret_keys(self) -> None:
        """The measurement that decided allowlist over denylist, asserted rather than recalled.

        ``SECRET_FIELD_DENYLIST`` is a logging control matching whole field names, and it is correct
        at that job. It is not a credential-definition classifier.
        """
        caught = [k for k in OBSERVED_SECRET_KEYS if k.lower() in SECRET_FIELD_DENYLIST]
        assert caught == ["password"], (
            f"expected the denylist to catch only 'password' of the ten observed keys; got {caught}"
        )

    def test_there_is_no_field_named_pemkey_anywhere(self) -> None:
        """A rule naming a nonexistent field reads as deliberate and withholds nothing."""
        every_allowed = {k for allowed in ent._DEFINITION_ALLOWLIST.values() for k in allowed}
        assert "pemkey" not in every_allowed
        assert "pemkey" not in KNOWN_SECRET_KEYS
        assert "sshKeyData" in KNOWN_SECRET_KEYS

    def test_the_filter_is_defined_exactly_once(self) -> None:
        """Share the filter, not the tools: security logic that exists twice gets fixed once.

        There are two tables behind one filter. Each table is defined exactly once, and
        ``_filter_definition`` is the only reader. The subtype table's name contains the type
        table's name, so the type-level count subtracts it.
        """
        code = code_only(SRC)
        assert code.count("def _filter_definition") == 1
        assert code.count("_SUBTYPE_DEFINITION_ALLOWLIST : Final") == 1
        # The type-level table, counted without matching the subtype one that ends in the same name.
        assert (
            code.count("_DEFINITION_ALLOWLIST : Final")
            - code.count("_SUBTYPE_DEFINITION_ALLOWLIST : Final")
            == 1
        )

    def test_both_allowlists_are_read_only_inside_the_filter(self) -> None:
        """Two tables are safe only while one function consults them.

        A tool reading either table directly could apply its own rule. Asserted on stripped code,
        so the prose in both table headers cannot satisfy it.
        """
        code = code_only(SRC)
        body = code.split("def _filter_definition")[1].split("def _safe_credential")[0]

        # Counted by subtraction: ``_SUBTYPE_DEFINITION_ALLOWLIST . get`` contains
        # ``_DEFINITION_ALLOWLIST . get``, so a naive count of the shorter name double-counts.
        subtype_reads = code.count("_SUBTYPE_DEFINITION_ALLOWLIST . get")
        type_reads = code.count("_DEFINITION_ALLOWLIST . get") - subtype_reads
        assert subtype_reads == 1, "the subtype allowlist is consulted in more than one place"
        assert type_reads == 1, "the type allowlist is consulted in more than one place"
        assert "_SUBTYPE_DEFINITION_ALLOWLIST . get" in body
        assert (
            body.count("_DEFINITION_ALLOWLIST . get")
            - body.count("_SUBTYPE_DEFINITION_ALLOWLIST . get")
            == 1
        ), "the type allowlist is consulted outside _filter_definition"

    def test_the_readers_do_not_fall_back_to_the_denylist(self) -> None:
        """Asserted on code, not text.

        ``sl1_entity_tools``' comments name ``SECRET_FIELD_DENYLIST`` to explain why it must not be
        used here, so a plain ``in source`` search would pass for the wrong reason. The second
        assertion proves the stripping is load-bearing.
        """
        assert "SECRET_FIELD_DENYLIST" not in code_only(SRC), (
            "the credential readers must not classify definition keys with the logging denylist"
        )
        assert "SECRET_FIELD_DENYLIST" in SRC.read_text(), (
            "expected the rejected denylist to be discussed in prose; if it no longer is, the "
            "assertion above has become vacuous and this pairing must be re-established"
        )

    def test_the_comment_stripper_actually_strips(self, tmp_path: Path) -> None:
        """The mechanism, pinned separately, since a refactor of ``code_only`` could invert it."""
        sample = tmp_path / "s.py"
        sample.write_text('"""mentions sshKeyData."""\n# and password\nx = 1  # apikey\n')
        stripped = code_only(sample)
        for name in ("sshKeyData", "password", "apikey"):
            assert name in sample.read_text()
            assert name not in stripped

    def test_the_secret_table_is_not_empty_and_the_fixtures_use_it(self) -> None:
        """The cheapest vacuity check of all, and the one most likely to be needed."""
        assert len(KNOWN_SECRET_KEYS) >= 20
        assert len(CREDENTIAL_TYPES) == 8
        for credential_type in CREDENTIAL_TYPES:
            parsed = json.loads(definition_for(credential_type))
            assert set(KNOWN_SECRET_KEYS) <= set(parsed), (
                f"{credential_type}'s fixture does not actually contain the secret keys"
            )
            assert ent._DEFINITION_ALLOWLIST[credential_type] <= set(parsed)


class TestTheToolsAreRegistered:
    """The registry is total at import, but "registered" is still worth asserting from outside."""

    def test_both_readers_have_a_factory_and_a_descriptor(self) -> None:
        from powerpack_mcp.tools.sl1_registry import sl1_rest_set_tools

        names = {descriptor.tool_name for descriptor, _ in sl1_rest_set_tools()}
        assert {"sl1_list_credentials", "sl1_get_credential"} <= names

    def test_the_inner_function_is_named_exactly_the_tool_name(
        self, config: Config, credential: LceCredential
    ) -> None:
        """``schema_slim`` and fastmcp register by name, so a mismatch registers the wrong tool."""
        context, _ = _ctx(config, credential, {})
        assert ent.make_sl1_list_credentials(context).__name__ == "sl1_list_credentials"
        assert ent.make_sl1_get_credential(context).__name__ == "sl1_get_credential"

    def test_both_descriptions_survive_as_literal_docstrings(
        self, config: Config, credential: LceCredential
    ) -> None:
        """An f-string leaves ``__doc__`` as ``None`` and strips the MCP tool description."""
        context, _ = _ctx(config, credential, {})
        for factory in (ent.make_sl1_list_credentials, ent.make_sl1_get_credential):
            doc = factory(context).__doc__
            assert doc is not None
            assert "Args:" in doc
            assert "NO SECRET IS EVER RETURNED" in doc

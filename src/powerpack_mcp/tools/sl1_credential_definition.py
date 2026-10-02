"""
UNIVERSAL Credential Definition Normalisation

This module shapes the ``definition`` of an SL1 UNIVERSAL credential before it is written. Every
rule is an SL1 constraint established by live testing, not a design choice. REST ``POST`` cannot
create universal credentials (its read shape differs from its write shape and the endpoint returns
500), so GraphQL ``createCredential`` with these constraints is the only working path:

- ``type = UNIVERSAL``, an enum, supplied by the caller of this module.
- ``definition`` is passed as a stringified JSON scalar, not an object.
- secret fields are plain strings, never ``{"type": "Buffer", ...}`` read wrappers.
- ``proxy`` and ``sslverifypeer`` are booleans (REST v104 only).
- ``tokenExpiresInSelector`` is non-empty even under static refresh (REST v104 only).

The defaults table is the ``Low-code Tools: REST v104`` subtype's full shape and is merged into
that subtype only. SL1 rejects or silently mis-stores a partial REST v104 definition, so do not
trim the table. Merging it into another subtype corrupts that definition (SL1 rejects the
``aws assume role`` subtype with '"authType" is not allowed'), so other subtypes are passed
through. Do not fold another subtype's keys into the table; a second subtype needs its own table,
once measured.
"""

from __future__ import annotations

import json
from typing import Any, Final

__all__ = [
    "CREDENTIAL_SECRET_KEYS",
    "CRED_REFRESH_DYNAMIC",
    "CRED_REFRESH_STATIC",
    "CRED_SECRET_KEYS",
    "CRED_SUBTYPE_REST_V104",
    "CRED_TYPE_UNIVERSAL",
    "UNIVERSAL_DEFINITION_DEFAULTS",
    "UniversalDefinitionError",
    "normalize_universal_definition",
    "serialize_universal_definition",
]

CRED_TYPE_UNIVERSAL: Final[str] = "UNIVERSAL"
CRED_SUBTYPE_REST_V104: Final[str] = "Low-code Tools: REST v104"
CRED_REFRESH_STATIC: Final[str] = "tokenAuthRefreshStatic"
CRED_REFRESH_DYNAMIC: Final[str] = "tokenAuthRefreshDynamic"

# The keys whose values are secret material.
#
# The no-logging rule is not enforced by consulting this tuple: ``sl1_tool_boundary`` never logs
# tool arguments at all. This tuple exists for the Buffer-wrapper check in ``_reject_read_shapes``,
# which is a correctness rule, not a logging rule.
#
# These are REST v104's secret field names, so on any other subtype this tuple names nothing. That
# is why ``_reject_read_shapes`` also matches on the Buffer shape for keys it does not recognise;
# ``test_every_secret_key_is_a_key_of_the_table_it_guards`` guards against the tuple going vacuous.
CRED_SECRET_KEYS: Final[tuple[str, ...]] = (
    "password",
    "proxyPasswd",
    "oauth2ClientSecret",
    "oauth2ResourceOwnerPassword",
    "apikey",
)

# Every ``Credential.definition`` key known to carry secret material, across all eight credential
# types: the single source of truth for those names. ``CRED_SECRET_KEYS`` above is the REST v104
# subset that the write path shapes; this is the read-side superset.
#
# This is NOT how the typed readers decide what to return. ``sl1_entity_tools._filter_definition``
# keeps only allowlisted keys, so a secret missing from this tuple is still withheld there. This
# tuple serves the places where no allowlist can apply because the credential type is unknown:
# the response scrub in ``sl1_credential_guard`` and the GraphQL document guard. A denylist has to
# be complete to be safe, which is why neither of those is the primary control either.
#
# The first twenty were observed on an appliance across all eight types. ``authHeader`` and
# ``tokenKey`` were not observed; they are listed because they were classified safe only from the
# defaults table below, and ``authHeader`` can carry a literal ``Authorization`` value. Fail closed
# on ambiguity. ``sshKeyData`` matters most: there is no field named ``pemkey``, so a rule that
# excluded "password or pemkey" would ship every SSH private key while looking deliberate.
#
# The AWS names were measured from the ``credentialFields`` templates. They are not redundant case
# variants: matching is exact, so ``ProxyPasswd`` and ``proxyPasswd`` are different keys.
# ``AwsAccessKeyId`` is not flagged ``encryption: true`` by the platform; it is listed as one half
# of a key pair, on the same fail-closed rule as ``authHeader``.
CREDENTIAL_SECRET_KEYS: Final[tuple[str, ...]] = (
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
    "AwsSecretAccessKey",
    "ProxyPasswd",
    "AwsAccessKeyId",
    # Measured from the remaining ``credentialFields`` templates on two appliances: the other
    # UNIVERSAL subtypes, and the SOAP_XML subtypes, whose field names differ from their type's.
    # ``AccessKeyId``, ``awsAccessKeyId`` and Aliyun's ``accessKey`` are key ids, listed on the same
    # rule as ``AwsAccessKeyId``.
    "cred_pwd",
    "ssh_key_data",
    "AccessKeyId",
    "SecretAccessKey",
    "EncryptionPassword",
    "EncryptionSalt",
    "secret",
    "vmwareWebServicePassword",
    "awsAccessKeyId",
    "awsSecretAccessKey",
    "azureSecretKey",
    "accessKey",
    "accessKeyPassword",
)

# SL1's full UNIVERSAL definition shape for REST v104. Ported key-for-key; do not trim. A partial
# definition is rejected or silently mis-stored, and the failure surfaces only on an appliance.
UNIVERSAL_DEFINITION_DEFAULTS: Final[dict[str, Any]] = {
    "authType": "AuthToken",
    "url": "https://%D",
    "authEndpoint": "",
    "authHeader": "Authorization",
    "tokenKey": "access_token",
    "tokenFormat": "Bearer {}",
    "username": "",
    "proxy_scheme": "https",
    "proxyHost": "",
    "proxyPort": 443,
    "proxyUser": "",
    "httpHeader1": "",
    "httpHeader2": "",
    "httpHeaders": "",
    "sslverifypeer": False,
    "ca_path": "",
    "timeToNextRequest": 0,
    "opts": "",
    "debug": False,
    "tokenAuthRefresh": CRED_REFRESH_STATIC,
    "tokenRefreshTTL": 3600,
    "tokenExpiresInSelector": "expires_in",
    "oauth2ClientId": "",
    "oauth2TokenURL": "",
    "oauth2TokenLabel": "Authorization",
    "oauth2TokenFormat": "Bearer {}",
    "oauth2TokenKey": "access_token",
    "oauth2Type": "None",
    "oauth2AuthType": "basic_auth",
    "oauth2ClientCredentialsScope": "",
    "oauth2ResourceOwnerUsername": "",
    "oauth2ResourceOwnerScope": "",
    "oauth2ResourceOwnerAdditionalParams": "{}",
    "prefix": "",
    "suffix": "",
    "authOverride": "",
    "password": "",
    "proxy": False,
    "proxyPasswd": "",
    "oauth2ClientSecret": "",
    "oauth2ResourceOwnerPassword": "",
    "apikey": "",
}


class UniversalDefinitionError(ValueError):
    """A caller-supplied definition violates an SL1 constraint.

    A ``ValueError`` subclass rather than a ``PowerPackMcpError``: it is raised while shaping an
    argument, before any transport exists to have failed. The calling tool translates it, so the
    caller-facing envelope stays the job of ``build_error_payload``.
    """


def _is_rest_v104(sub_type: str | None) -> bool:
    """Return whether ``sub_type`` names the subtype ``UNIVERSAL_DEFINITION_DEFAULTS`` describes.

    ``None`` counts as yes: both writers default to this subtype, and treating "unspecified" as
    anything else would change what an existing caller gets. For
    ``sl1_update_universal_credential``, omitting ``sub_type`` means "leave the stored subtype
    alone", so that tool reads the stored subtype and passes it here.

    The comparison is case- and whitespace-insensitive, the opposite of
    ``sl1_entity_tools._DEFINITION_ALLOWLIST``'s exact match, because the direction of harm is
    reversed. There, a loose match could admit a re-cased secret. Here, a loose match only admits
    the completion: if the string is genuinely wrong SL1 rejects it, whereas an exact match would
    quietly send a partial definition. The caller's own spelling is what gets sent.
    """
    return sub_type is None or sub_type.strip().casefold() == CRED_SUBTYPE_REST_V104.casefold()


def _reject_read_shapes(definition: dict[str, Any]) -> None:
    """Refuse a value that arrived as SL1's ``{"type": "Buffer", ...}`` read shape.

    This rule applies to every subtype: it catches a read response being fed back as a write, which
    is a property of how SL1 renders secrets on the way out. It rejects rather than rewrites, which
    is what makes it safe to apply to fields we have never measured.

    A key named in ``CRED_SECRET_KEYS`` is refused on any dict. Any other key is refused only on the
    Buffer shape itself, because an unmeasured subtype may legitimately nest an object. Matching the
    shape covers secret fields whose names we do not know; keying on ``CRED_SECRET_KEYS`` alone
    would let a non-REST subtype's password be written as the literal text of a Buffer wrapper.

    :raises UniversalDefinitionError: If any value is a Buffer read wrapper.
    """
    for key, value in definition.items():
        if not isinstance(value, dict):
            continue
        if key in CRED_SECRET_KEYS:
            # The message names the key and says nothing about the value, which matters most for
            # a field we have just identified as secret.
            raise UniversalDefinitionError(
                f"Secret field {key!r} must be a plain string, not a Buffer wrapper."
            )
        if value.get("type") == "Buffer":
            raise UniversalDefinitionError(
                f"Field {key!r} is SL1's Buffer read shape, which is not a valid value to write."
            )


def _completed_rest_v104(supplied: dict[str, Any]) -> dict[str, Any]:
    """Merge ``supplied`` over the full REST v104 shape and apply that subtype's two value rules."""
    merged: dict[str, Any] = {**UNIVERSAL_DEFINITION_DEFAULTS, **supplied}

    # SL1 requires real booleans here; a truthy string would be stored as a string.
    merged["proxy"] = bool(merged.get("proxy"))
    merged["sslverifypeer"] = bool(merged.get("sslverifypeer"))

    # This must be non-empty even under static refresh, where it is unused. An empty value is
    # rejected, so the default is reinstated rather than passed through.
    if not merged.get("tokenExpiresInSelector"):
        merged["tokenExpiresInSelector"] = UNIVERSAL_DEFINITION_DEFAULTS["tokenExpiresInSelector"]

    return merged


def normalize_universal_definition(
    definition: dict[str, Any] | None, sub_type: str | None = None
) -> dict[str, Any]:
    """Shape a caller's definition for ``sub_type``, enforcing the rules measured for that subtype.

    For REST v104 (and for an unspecified subtype; see ``_is_rest_v104``) a partial definition is
    merged over SL1's full shape and that subtype's value rules are applied. For any other subtype
    the definition is passed through, because ``authType`` and the rest of the table are REST fields
    that SL1 rejects elsewhere; the caller owns supplying a definition SL1 accepts.

    On the pass-through path values are rejected, never rewritten. Coercing ``proxy`` or
    reinstating ``tokenExpiresInSelector`` are facts about REST v104's fields; rewriting a value in
    a subtype whose semantics we have not measured would be accepted by SL1 and mis-stored,
    surfacing only at collection time. The secret rules still apply to every subtype.

    A secret field arriving as a Buffer wrapper (SL1's read shape, ``{"type": "Buffer", "data":
    [...]}``) is rejected rather than coerced: ``str()`` of that dict would store the literal text
    as the password, which SL1 would accept and which would fail authentication at collection time.

    :param definition: The caller's definition, or ``None`` for an empty one.
    :param sub_type: The credential subtype, or ``None`` for the REST v104 default.
    :return: A new dict; the caller's is never mutated.
    :raises UniversalDefinitionError: If a value is a Buffer read wrapper.
    """
    # A copy, so the caller's dict is never mutated and the pass-through path can be shaped in
    # place. Checked before the merge: the defaults contribute ``""`` for every secret key, so on
    # the REST path inspecting the supplied keys alone is equivalent, and on the pass-through path
    # it is the only thing there is to inspect.
    supplied: dict[str, Any] = dict(definition or {})
    _reject_read_shapes(supplied)

    shaped = _completed_rest_v104(supplied) if _is_rest_v104(sub_type) else supplied

    # A secret is stored as a plain string. Applied to the keys that are present, so the
    # pass-through path gains no key the caller did not supply. ``str()`` of a ``str`` is identity,
    # so this only affects a non-string scalar, where a string is the shape SL1 wants anyway.
    for key in CRED_SECRET_KEYS:
        if key in shaped:
            value = shaped[key]
            shaped[key] = "" if value is None else str(value)

    return shaped


def serialize_universal_definition(
    definition: dict[str, Any] | None, sub_type: str | None = None
) -> str:
    """Normalise for ``sub_type``, then render as the stringified JSON scalar SL1 expects.

    The double encoding is SL1's requirement. The GraphQL variable is declared ``$definition:
    JSON``, yet the resolver expects a string containing JSON; passing the dict directly produces a
    create that looks well-formed and is rejected by the server.

    :raises UniversalDefinitionError: If a value is a Buffer read wrapper.
    """
    return json.dumps(normalize_universal_definition(definition, sub_type))

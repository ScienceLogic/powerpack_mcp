"""
Request Credentials

This module provides ``LceCredential``, the holder for the caller's credential, and the functions
that extract it from each inbound request. The credential is the end user's own Skylar One
credential, passed through from the ``Authorization`` header on every request; this service has no
credential of its own.

This is the only module that binds the plaintext credential. No module outside it calls
``SecretStr.get_secret_value()``, and a test asserts that by scanning the source. It sits at the top
level rather than under ``lce_client`` because importing that package from ``config`` would create
an import cycle.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Final

from pydantic import SecretStr

from powerpack_mcp.errors import CredentialMissing

if TYPE_CHECKING:
    from collections.abc import Iterable

    from starlette.types import Scope

__all__ = [
    "AUTHORIZATION_HEADER",
    "LceCredential",
    "contains_control_characters",
    "credential_for_request",
    "extract_from_scope",
    "username_from_authorization",
    "username_from_scope",
]

# ASGI delivers header names lower-cased as bytes, which is why this is not "Authorization".
# This header is the only place a credential may come from: never a query parameter, a request
# body or a tool argument. A tool argument in particular would put it in the model's context and in
# client-side tool-call logs.
AUTHORIZATION_HEADER: Final[bytes] = b"authorization"

# The outbound header name. Fixed, because inbound and outbound are both ``Authorization``.
OUTBOUND_HEADER_NAME: Final[str] = "Authorization"

_REDACTED: Final[str] = "**redacted**"

_BASIC_PREFIX: Final[str] = "basic "


def contains_control_characters(value: str) -> bool:
    """Return whether ``value`` holds any C0 control character or DEL.

    A CR or LF in a value this service re-emits on an outbound request is a header-injection
    vector. Pure and total: never raises for any ``str``, including the empty string.
    """
    return any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)


def username_from_authorization(value: str) -> str | None:
    """Return the non-secret username from a Basic credential, or ``None``.

    ``actor`` attribution in logs comes from the credential the caller actually authenticated
    with, rather than from nginx's ``X-User-ID``. This does not weaken the no-getter rule on
    ``LceCredential``: the parse happens inside this module, and the username is returned as a
    separate plain value, not a slice of the secret, so the password is not reachable through it.

    It is best-effort and never affects what is forwarded. Non-Basic schemes are forwarded verbatim
    and yield ``None`` here, and ``actor`` then falls back to ``X-User-ID`` or is omitted. A
    malformed payload also yields ``None`` rather than raising, because attribution must never fail
    a request LCE would have accepted.

    Pure and total: never raises for any ``str``, returns ``None`` for every non-Basic scheme, and
    never returns a value containing ``:``.
    """
    if not value.lower().startswith(_BASIC_PREFIX):
        return None
    encoded = value[len(_BASIC_PREFIX) :].strip()
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    # ``binascii.Error`` and ``UnicodeDecodeError`` are both ``ValueError`` subclasses.
    except ValueError:
        return None
    username, separator, _password = decoded.partition(":")
    if not separator or not username:
        return None
    return username


class LceCredential:
    """Hold a request's credential and apply it to outbound headers.

    There is deliberately no getter for the secret. A ``get_credential() -> str`` would put the
    plaintext in ``lce_client``'s local scope, where it would appear in traceback frames and could
    be logged by any future edit. Applying itself to the headers means no component outside this
    module ever binds the plaintext to a name.

    An instance does not outlive its request. It is never cached, stored or attached to
    ``LceClient``, which holds no credential and receives one per call, so the shared connection
    pool carries no credential affinity.

    :param secret: The full ``Authorization`` header value.
    :param username: The non-secret username, if one could be parsed.
    """

    __slots__ = ("_header_name", "_secret", "_username")

    def __init__(self, secret: SecretStr, username: str | None = None) -> None:
        self._secret = secret
        self._header_name = OUTBOUND_HEADER_NAME
        self._username = username

    @property
    def header_name(self) -> str:
        """The outbound header name. Not secret: it is a fixed constant, not the credential."""
        return self._header_name

    @property
    def username(self) -> str | None:
        """The non-secret username, for ``actor`` attribution only.

        ``None`` for any non-Basic scheme or an unparseable payload. Never exposes the password.
        """
        return self._username

    def apply_to_headers(self, headers: dict[str, str]) -> None:
        """Write the credential into an outbound header mapping.

        This is the only way the secret leaves this object. It is attached to every LCE request;
        there is no unauthenticated outbound path.
        """
        headers[self._header_name] = self._secret.get_secret_value()

    def __repr__(self) -> str:
        """Return a fixed redacted string.

        Renders neither the secret nor its length, which is why this is a constant rather than a
        masked-to-length rendering. The username is omitted too: it is not secret, but a repr is
        not the place to volunteer identity.
        """
        return f"LceCredential(header_name={self._header_name!r}, secret={_REDACTED})"

    __str__ = __repr__


def _header_value(scope: Scope, name: bytes) -> str | None:
    """Read one header from an ASGI scope, or ``None``. Decoded as latin-1, as HTTP headers are."""
    headers: Iterable[tuple[bytes, bytes]] = scope.get("headers", ())
    for key, value in headers:
        if key == name:
            decoded: str = value.decode("latin-1")
            return decoded
    return None


def extract_from_scope(scope: Scope) -> LceCredential:
    """Build a request-scoped `LceCredential` from the inbound ``Authorization`` header.

    There is no fallback to any other credential source. There is no configured credential to
    fall back to, and that must stay true by construction.

    The value is forwarded verbatim after validation: the scheme is data, not code. A caller
    presenting ``Bearer`` has it forwarded and receives LCE's own 401, which is the caller's error
    to see rather than this service's to interpret.

    :param scope: The ASGI scope of the inbound request.
    :return: A credential for this request only.
    :raises CredentialMissing: If the header is absent, empty or contains control characters.
    """
    raw = _header_value(scope, AUTHORIZATION_HEADER)
    if raw is None or not raw.strip():
        raise CredentialMissing
    if contains_control_characters(raw):
        # Deliberately the same exception as absence: telling "malformed" from "absent" in a
        # caller-visible error would report on credential material.
        raise CredentialMissing
    return LceCredential(SecretStr(raw), username_from_authorization(raw))


def credential_for_request() -> LceCredential:
    """Return the current request's credential; the production ``ToolContext.credential_source``.

    It takes no arguments so that the injected callable owns its own request lookup. If callers had
    to fetch the request first, a unit test calling a tool function directly would fail on the
    missing HTTP context before reaching an injected stub. Owning the lookup here lets a test
    substitute a source that never touches HTTP.

    :raises CredentialMissing: If there is no HTTP request context, rather than surfacing a
        ``RuntimeError`` as a generic 500. That cannot happen for a tool invoked over HTTP, so this
        is defence in depth. Also raised for any reason ``extract_from_scope`` raises it.
    """
    # Imported here rather than at module scope to keep this module a leaf: ``fastmcp.server``
    # pulls in the server stack, and ``config`` imports this module's sibling predicate.
    from fastmcp.server.dependencies import get_http_request

    try:
        scope = get_http_request().scope
    except RuntimeError as exc:
        raise CredentialMissing from exc
    return extract_from_scope(scope)


def username_from_scope(scope: Scope) -> str | None:
    """The non-secret username from the request's ``Authorization`` header, or ``None``.

    This is an independent second read of the header. ``actor`` is resolved in ``tool_boundary``'s
    wrapper after the wrapped function returns, while the credential is obtained deeper in
    ``run_operation``. Threading a credential-bearing object out to the logging layer would weaken
    the credential's containment, so this reads the header again for the username alone. It shares
    no state with ``extract_from_scope``, touches nothing secret, and never raises.
    """
    raw = _header_value(scope, AUTHORIZATION_HEADER)
    if raw is None:
        return None
    return username_from_authorization(raw)

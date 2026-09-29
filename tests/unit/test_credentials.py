"""
Credential Tests

This module tests ``powerpack_mcp.credentials``: extraction from the request, the fail-closed
path, redaction, actor resolution and the two pure predicates. The module under test handles an
end user's Skylar One password in production, so every credential here is synthetic.

The property tests use structurally valid but meaningless strings on purpose. Hypothesis prints
falsifying examples, so a credential-shaped generator would write credential material into CI
logs. Any change to realistic inputs must also suppress example reporting.
"""

from __future__ import annotations

import base64

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from powerpack_mcp.credentials import (
    AUTHORIZATION_HEADER,
    LceCredential,
    contains_control_characters,
    credential_for_request,
    extract_from_scope,
    username_from_authorization,
    username_from_scope,
)
from powerpack_mcp.errors import CredentialMissing

# Synthetic, and meaningless by construction.
_SYNTHETIC_BASIC = "Basic " + base64.b64encode(b"testuser:testpass").decode()


def _scope(*headers: tuple[bytes, bytes]) -> dict[str, object]:
    return {"type": "http", "headers": list(headers)}


class TestExtraction:
    def test_reads_the_authorization_header(self) -> None:
        """The credential comes from ``Authorization``, and only from there."""
        credential = extract_from_scope(_scope((AUTHORIZATION_HEADER, _SYNTHETIC_BASIC.encode())))
        headers: dict[str, str] = {}
        credential.apply_to_headers(headers)
        assert headers == {"Authorization": _SYNTHETIC_BASIC}

    def test_forwards_verbatim_including_a_non_basic_scheme(self) -> None:
        """Scheme-agnostic: the value is data, not code.

        A ``Bearer`` caller has it forwarded and receives LCE's own 401, which is the caller's error
        to see, not this service's to interpret. LCE rejects Bearer.
        """
        credential = extract_from_scope(_scope((AUTHORIZATION_HEADER, b"Bearer opaque-token")))
        headers: dict[str, str] = {}
        credential.apply_to_headers(headers)
        assert headers["Authorization"] == "Bearer opaque-token"

    @pytest.mark.parametrize("headers", [(), ((b"x-user-id", b"alice"),)])
    def test_absent_header_raises_credential_missing(
        self, headers: tuple[tuple[bytes, bytes], ...]
    ) -> None:
        """Fail closed, with no fallback to any other source."""
        with pytest.raises(CredentialMissing):
            extract_from_scope(_scope(*headers))

    @pytest.mark.parametrize("value", [b"", b"   "])
    def test_empty_header_raises_credential_missing(self, value: bytes) -> None:
        with pytest.raises(CredentialMissing):
            extract_from_scope(_scope((AUTHORIZATION_HEADER, value)))

    @pytest.mark.parametrize(
        "value", [b"Basic abc\r\nX-Evil: 1", b"Basic abc\ndef", b"Basic a\x00b"]
    )
    def test_control_characters_raise_credential_missing(self, value: bytes) -> None:
        """A CR or LF in a value this service re-emits outbound is a header-injection vector."""
        with pytest.raises(CredentialMissing):
            extract_from_scope(_scope((AUTHORIZATION_HEADER, value)))

    def test_malformed_and_absent_are_indistinguishable_to_a_caller(self) -> None:
        """Both raise the same bare exception.

        Distinguishing "malformed" from "absent" in a caller-visible error would be reporting on
        credential material, so ``CredentialMissing`` carries nothing beyond its class.
        """
        absent = pytest.raises(CredentialMissing)
        with absent as a:
            extract_from_scope(_scope())
        with pytest.raises(CredentialMissing) as b:
            extract_from_scope(_scope((AUTHORIZATION_HEADER, b"Basic a\nb")))
        assert type(a.value) is type(b.value)
        assert str(a.value) == str(b.value)
        assert a.value.args == b.value.args == ()


class TestNoHttpContext:
    def test_credential_for_request_fails_closed_outside_a_request(self) -> None:
        """The production source raises ``CredentialMissing``, not ``RuntimeError``.

        ``get_http_request()`` raises ``RuntimeError`` with no HTTP context, which would surface as
        a generic 500 rather than an authentication failure. It cannot happen for a tool invoked
        over HTTP, so this is defence in depth. It is also why ``ToolContext.credential_source`` is
        injected: a test substitutes a source instead of needing a request.
        """
        with pytest.raises(CredentialMissing):
            credential_for_request()


class TestActorResolutionOrder:
    """The actor resolution order: credential username, then ``X-User-ID``, then omission.

    Exercised by substituting ``get_http_request``, because ``_current_actor`` reads the request
    scope and the tool tests run outside an HTTP context.
    """

    @staticmethod
    def _install_scope(monkeypatch: pytest.MonkeyPatch, *headers: tuple[bytes, bytes]) -> None:
        """Substitute the request lookup in both namespaces that resolve it.

        ``pipeline`` binds ``get_http_request`` at import, so patching only
        ``fastmcp.server.dependencies`` would leave its bound name untouched and the test would pass
        vacuously with ``_current_actor()`` returning ``None``. ``credentials`` imports it inside
        the function, so it resolves through the source module.
        """

        class _Request:
            def __init__(self) -> None:
                self.scope = {"type": "http", "headers": list(headers)}

        monkeypatch.setattr(
            "fastmcp.server.dependencies.get_http_request", lambda: _Request(), raising=True
        )
        monkeypatch.setattr(
            "powerpack_mcp.tools.pipeline.get_http_request", lambda: _Request(), raising=True
        )

    def test_credential_username_wins_over_x_user_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The credential is the identity LCE will actually authorise, so it takes precedence."""
        from powerpack_mcp.tools.pipeline import _current_actor

        self._install_scope(
            monkeypatch,
            (AUTHORIZATION_HEADER, _SYNTHETIC_BASIC.encode()),
            (b"x-user-id", b"someone-else"),
        )
        assert _current_actor() == "testuser"

    def test_falls_back_to_x_user_id_for_a_non_basic_scheme(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A ``Bearer`` caller yields no username, so the forwarded identity is used."""
        from powerpack_mcp.tools.pipeline import _current_actor

        self._install_scope(
            monkeypatch, (AUTHORIZATION_HEADER, b"Bearer opaque"), (b"x-user-id", b"alice")
        )
        assert _current_actor() == "alice"

    def test_omitted_when_neither_is_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Omission, never a placeholder: ``unknown`` would be indistinguishable from a principal
        genuinely named ``unknown``.
        """
        from powerpack_mcp.tools.pipeline import _current_actor

        self._install_scope(monkeypatch)
        assert _current_actor() is None

    def test_a_hostile_username_is_omitted_rather_than_replaced(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """It lands in a log record, so an unsanitised newline would forge a log line.

        The rule is omission, never substitution. A weaker ``actor is None or "\\n" not in actor``
        check would also pass for a minted UUID, which is a fabricated principal.
        """
        from powerpack_mcp.tools.pipeline import _current_actor

        hostile = base64.b64encode(b"bad\nuser:pw").decode()
        self._install_scope(monkeypatch, (AUTHORIZATION_HEADER, f"Basic {hostile}".encode()))
        assert _current_actor() is None

    def test_an_email_form_username_falls_back_to_x_user_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`@` is outside the identity pattern, so the credential username cannot be used directly.

        Email-form logins are the norm for federated Skylar One users, so this is the common case
        rather than an edge one. `X-User-ID` is nginx-asserted and still trustworthy, so it is the
        right answer here.
        """
        from powerpack_mcp.tools.pipeline import _current_actor

        email = base64.b64encode(b"user@example.com:pw").decode()
        self._install_scope(
            monkeypatch,
            (AUTHORIZATION_HEADER, f"Basic {email}".encode()),
            (b"x-user-id", b"alice"),
        )
        assert _current_actor() == "alice"

    def test_an_email_form_username_is_omitted_when_no_x_user_id_is_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With no forwarded identity either, omission is the correct outcome."""
        from powerpack_mcp.tools.pipeline import _current_actor

        email = base64.b64encode(b"user@example.com:pw").decode()
        self._install_scope(monkeypatch, (AUTHORIZATION_HEADER, f"Basic {email}".encode()))
        assert _current_actor() is None

    def test_a_rejected_username_never_mints_a_fake_principal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A rejected username must not be replaced by a minted identifier.

        Routing the username through ``sanitize_correlation_id`` would discard a non-conforming
        value and mint a fresh UUID4 hex, so every audit record would carry a different fake
        principal that reads as real. Two properties are checked because either alone is weak: the
        result must not look like a minted id, and it must be stable across calls. Instability is
        the signature of minting.
        """
        import re

        from powerpack_mcp.tools.pipeline import _current_actor

        email = base64.b64encode(b"user@example.com:pw").decode()
        self._install_scope(monkeypatch, (AUTHORIZATION_HEADER, f"Basic {email}".encode()))

        first, second = _current_actor(), _current_actor()
        assert first == second, "actor changed between calls -- a value is being minted"
        assert first is None or not re.fullmatch(r"[0-9a-f]{32}", first), (
            f"actor {first!r} looks like a minted UUID4 hex, not a real principal"
        )

    def test_credential_for_request_uses_the_live_scope(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The production source's happy path, with a real HTTP context present."""
        self._install_scope(monkeypatch, (AUTHORIZATION_HEADER, _SYNTHETIC_BASIC.encode()))
        credential = credential_for_request()
        headers: dict[str, str] = {}
        credential.apply_to_headers(headers)
        assert headers["Authorization"] == _SYNTHETIC_BASIC
        assert credential.username == "testuser"
        assert credential.header_name == "Authorization"


class TestUsernameDerivation:
    def test_basic_yields_the_username(self) -> None:
        assert username_from_authorization(_SYNTHETIC_BASIC) == "testuser"

    @pytest.mark.parametrize("value", ["Bearer token", "Digest x", "", "Basic", "NotAScheme"])
    def test_non_basic_yields_none(self, value: str) -> None:
        """A non-Basic scheme has no username, so ``actor`` falls through to ``X-User-ID``."""
        assert username_from_authorization(value) is None

    @pytest.mark.parametrize("payload", ["not-base64!!", "", base64.b64encode(b"nocolon").decode()])
    def test_malformed_payload_yields_none_and_does_not_raise(self, payload: str) -> None:
        """Attribution must never fail a request LCE would have accepted."""
        assert username_from_authorization(f"Basic {payload}") is None

    def test_scheme_match_is_case_insensitive(self) -> None:
        assert username_from_authorization(_SYNTHETIC_BASIC.replace("Basic", "basic")) == "testuser"

    def test_username_from_scope_is_none_without_the_header(self) -> None:
        assert username_from_scope(_scope()) is None

    def test_username_from_scope_never_raises_on_a_hostile_value(self) -> None:
        """It feeds a log record, so it must not raise, and must not be trusted blindly."""
        assert username_from_scope(_scope((AUTHORIZATION_HEADER, b"Basic \xff\xfe"))) is None


class TestRedaction:
    def test_repr_renders_neither_the_secret_nor_its_length(self) -> None:
        """A repr that varies with the secret's length would disclose it."""
        short = LceCredential(SecretStr("a"))
        long = LceCredential(SecretStr("a" * 500))
        assert repr(short) == repr(long), "a length-revealing repr leaks the length"
        assert "a" * 500 not in repr(long)
        assert str(short) == repr(short)

    def test_repr_omits_the_username(self) -> None:
        """Not secret, but a repr is not the place to volunteer identity."""
        credential = LceCredential(SecretStr(_SYNTHETIC_BASIC), "testuser")
        assert "testuser" not in repr(credential)

    def test_the_secret_has_no_getter(self) -> None:
        """``apply_to_headers`` is the only way out, asserted structurally.

        A ``get_credential()`` would put the plaintext in a caller's local scope, where it would
        appear in traceback frames and could be logged by any future edit to that module.
        """
        credential = LceCredential(SecretStr("x"), None)
        public = {name for name in dir(credential) if not name.startswith("_")}
        assert public == {"apply_to_headers", "header_name", "username"}


class TestPureProperties:
    """Property tests for the two pure predicates.

    Synthetic inputs only; see the module docstring on why a realistic generator would leak
    credential material through CI logs.
    """

    @given(st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126)))
    def test_control_check_is_total_and_false_for_printable_ascii(self, value: str) -> None:
        assert contains_control_characters(value) is False

    @given(st.text())
    def test_control_check_never_raises(self, value: str) -> None:
        assert isinstance(contains_control_characters(value), bool)

    @given(st.text())
    def test_control_check_is_idempotent(self, value: str) -> None:
        first = contains_control_characters(value)
        assert first == contains_control_characters(value)

    @given(st.text())
    def test_username_parse_never_raises(self, value: str) -> None:
        result = username_from_authorization(value)
        assert result is None or isinstance(result, str)

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789"))
    def test_no_username_for_any_non_basic_scheme(self, value: str) -> None:
        """Structural: only ``basic `` may yield a username."""
        if not value.lower().startswith("basic "):
            assert username_from_authorization(value) is None

    @given(
        # Disjoint alphabets on purpose. With the same alphabet, ``user="a"`` and ``secret="a"``
        # would fail ``secret not in parsed`` by coincidence. Letters for the username and digits
        # for the password mean a hit can only be a real leak.
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12),
        st.text(alphabet="0123456789", min_size=1, max_size=12),
    )
    def test_the_password_half_is_never_returned(self, user: str, secret: str) -> None:
        """The parse stops at the first colon, so only the username can escape."""
        encoded = base64.b64encode(f"{user}:{secret}".encode()).decode()
        parsed = username_from_authorization(f"Basic {encoded}")
        assert parsed == user
        assert parsed is not None
        assert ":" not in parsed
        assert secret not in parsed

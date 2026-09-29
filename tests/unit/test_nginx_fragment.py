"""
Nginx Fragment Tests

This module tests content invariants of the shipped nginx fragment: credential and identity
forwarding, the error envelopes, the authentication challenge, rate limiting and the public
surface. It guards configuration, not code, and needs no Docker or nginx, so it runs on every
commit; the RPM lifecycle harness still owns ``nginx -t`` validity and the proxy behaviour tests.

Comments are stripped before every content check. The fragment documents the defects it fixes and
quotes the very directives these tests forbid, so a test that could not tell a comment from a
directive would fail on the prose, or could be "fixed" by deleting the explanation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

import pytest

FRAGMENT_PATH = (
    Path(__file__).resolve().parents[2] / "packaging" / "nginx" / "powerpack-mcp.fragment"
)

ERROR_ENVELOPES = ["@mcp_401", "@mcp_403", "@mcp_500", "@mcp_502"]


def _strip_comments(text: str) -> str:
    """Drop whole-line `#` comments. nginx has no block comments, so this is sufficient."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def _block(text: str, name: str) -> str:
    """Return the body of `location <name> { ... }`, brace-matched.

    Brace matching rather than a line range so the test does not break when comments are added or
    directives reordered inside a block.
    """
    marker = f"location {name} "
    start = text.index(marker)
    open_brace = text.index("{", start)
    depth = 0
    for i in range(open_brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1 : i]
    raise AssertionError(f"unbalanced braces in location {name}")


@pytest.fixture(scope="module")
def fragment() -> str:
    assert FRAGMENT_PATH.is_file(), f"fragment not found at {FRAGMENT_PATH}"
    return FRAGMENT_PATH.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def directives(fragment: str) -> str:
    """The fragment with commentary removed -- what nginx actually acts on."""
    return _strip_comments(fragment)


class TestCredentialForwarding:
    """The caller's ``Authorization`` header is forwarded explicitly."""

    def test_mcp_forwards_authorization_explicitly(self, directives: str) -> None:
        """The service holds no credential of its own, so this header is the authorisation path.

        It must be set explicitly rather than rely on nginx's default pass-through of unknown
        headers.
        """
        mcp = _block(directives, "/mcp")
        assert "proxy_set_header Authorization $http_authorization;" in mcp

    def test_authorization_forwarding_is_not_merely_commented(self, fragment: str) -> None:
        """Guard against the directive being commented out while the prose still claims it."""
        active = _strip_comments(fragment)
        assert active.count("proxy_set_header Authorization $http_authorization;") == 1


class TestReadyRouteRemoved:
    """The service has no ``/ready`` route, so the fragment must not claim one."""

    def test_no_ready_location(self, directives: str) -> None:
        assert "location /ready" not in directives

    def test_ready_is_absent_from_every_active_directive(self, directives: str) -> None:
        """Not just the ``location`` block: no rewrite, alias or exact match may resurrect it.

        ``location = /ready``, a ``rewrite`` targeting it, or a ``proxy_pass`` to a /ready upstream
        would each reintroduce the route, and none contains the literal "location /ready".
        """
        offenders = [ln.strip() for ln in directives.splitlines() if "ready" in ln.lower()]
        assert offenders == [], offenders


class TestErrorEnvelopeContentType:
    """Error envelopes must send exactly one ``Content-Type``.

    With an ``add_header``, a 401 returns both ``application/octet-stream`` (nginx ``default_type``,
    set by ``return``) and ``application/json``. Content-Type is a singleton field per RFC 9110
    s5.5, and a client honouring the first value parses the JSON envelope as a binary blob.
    """

    def test_no_add_header_content_type(self, directives: str) -> None:
        """``add_header`` appends; it cannot override what ``return`` set.

        ``nginx -t`` cannot catch this. The fragment's own comments quote this directive while
        explaining the bug, which is why comments must be stripped first.
        """
        assert "add_header Content-Type" not in directives

    @pytest.mark.parametrize("envelope", ERROR_ENVELOPES)
    def test_envelope_sets_default_type(self, directives: str, envelope: str) -> None:
        body = _block(directives, envelope)
        assert "default_type application/json;" in body

    @pytest.mark.parametrize("envelope", ERROR_ENVELOPES)
    def test_envelope_reincludes_security_headers(self, directives: str, envelope: str) -> None:
        """``add_header`` replaces the inherited set, so every envelope must re-include it.

        The platform fragment declares all four of its headers ``always``, so the include reaches a
        ``return`` response rather than being decorative.
        """
        body = _block(directives, envelope)
        assert "security_headers.fragment" in body


class TestAuthenticationChallenge:
    """RFC 7235: a 401 without a challenge is not a valid 401."""

    def test_401_sends_www_authenticate(self, directives: str) -> None:
        body = _block(directives, "@mcp_401")
        assert "add_header WWW-Authenticate" in body

    def test_challenge_is_flagged_always(self, directives: str) -> None:
        """Without ``always``, ``add_header`` never reaches a ``return 401``.

        This is the same rule that makes the security_headers include work, and the easiest thing to
        get wrong here: the config stays valid and the header simply never appears.
        """
        body = _block(directives, "@mcp_401")
        line = next(ln for ln in body.splitlines() if "add_header WWW-Authenticate" in ln)
        assert line.rstrip().endswith("always;"), line.strip()

    def test_challenge_declares_basic_and_realm(self, directives: str) -> None:
        body = _block(directives, "@mcp_401")
        line = next(ln for ln in body.splitlines() if "add_header WWW-Authenticate" in ln)
        assert "Basic" in line
        assert 'realm="' in line

    @pytest.mark.parametrize("envelope", ["@mcp_403", "@mcp_500", "@mcp_502"])
    def test_only_401_carries_a_challenge(self, directives: str, envelope: str) -> None:
        """403/500/502 are not authentication challenges; a challenge there would be wrong."""
        assert "WWW-Authenticate" not in _block(directives, envelope)


class TestRateLimitZoneStillConsumed:
    """The ``powerpack_mcp`` rate-limit zone must still have a consumer."""

    def test_mcp_still_rate_limited(self, directives: str) -> None:
        """``/mcp`` carries ``burst=20`` and keeps the zone in use.

        So ``powerpack-mcp-zone.conf`` needs no change.
        """
        assert "limit_req zone=powerpack_mcp" in _block(directives, "/mcp")

    def test_zone_has_exactly_one_consumer(self, directives: str) -> None:
        assert directives.count("limit_req zone=powerpack_mcp") == 1


class TestPublicSurfaceUnchanged:
    """``/health`` stays the only anonymously reachable route."""

    def test_health_has_no_auth_request(self, directives: str) -> None:
        assert "auth_request" not in _block(directives, "/health")

    def test_mcp_still_requires_auth(self, directives: str) -> None:
        assert "auth_request /auth_user;" in _block(directives, "/mcp")


class TestForwardedHeaderAllowlist:
    """Bound the set of headers ``/mcp`` forwards, rather than only naming one of them.

    ``TestCredentialForwarding`` asserts that ``Authorization`` is forwarded, but nothing else caps
    the set. If the application reads a header nginx does not manage, the client's value passes
    straight through, so a caller sending ``X-Remote-User: admin`` would be attributed as admin.

    This bounds ``proxy_set_header`` only. It does not see ``auth_request_set``, and it does not
    constrain what nginx forwards by default: unknown client headers still pass through unless
    cleared, which is why the three clears below exist and why a client-sent ``X-API-Key`` reaches
    the application.
    """

    # Every header ``/mcp`` may set on the upstream request. Adding to this list is a decision: each
    # entry carries a credential, carries authenticator-asserted identity, or is standard proxy
    # provenance. Nothing else belongs.
    ALLOWED: ClassVar[frozenset[str]] = frozenset(
        {
            "Host",
            "X-Forwarded-For",
            "X-Forwarded-Proto",
            # The caller's own credential. The service holds none, so this header is the
            # authorisation path, and also the hook gate's input.
            "Authorization",
            # Authenticator-asserted and overwritten by ``proxy_set_header``, so unforgeable. Read
            # by ``forwarded_actor`` and by ``actor_user_id``, which keys the hook cache.
            "X-User-ID",
            # The three legacy identity headers, cleared. Set to "" rather than absent; see below.
            "X-Remote-User",
            "X-Forwarded-User",
            "X-Authenticated-User",
        }
    )

    def _set_headers(self, block: str) -> set[str]:
        return set(re.findall(r"proxy_set_header\s+(\S+)", block))

    def test_mcp_forwards_nothing_outside_the_allowlist(self, directives: str) -> None:
        forwarded = self._set_headers(_block(directives, "/mcp"))
        unexpected = forwarded - self.ALLOWED
        assert not unexpected, (
            f"/mcp forwards {sorted(unexpected)}, which is not in this test's allowlist. "
            "If that is deliberate, add it here WITH its reason -- a header reaching the "
            "application unexamined is how caller attribution gets forged."
        )

    def test_the_allowlist_is_not_vacuous(self, directives: str) -> None:
        """The risk in a bound is that nothing is bounded.

        If ``/mcp`` set no headers at all the test above would pass while proving nothing. This
        asserts the two that carry security meaning are present.
        """
        forwarded = self._set_headers(_block(directives, "/mcp"))
        assert "Authorization" in forwarded
        assert "X-User-ID" in forwarded
        assert len(forwarded) >= 5

    def test_the_three_attribution_clears_survive(self, directives: str) -> None:
        """Do not remove these because they look redundant.

        ``FORWARDED_ACTOR_HEADERS`` is pinned to ``(b"x-user-id",)``, so these are defence in depth
        against a future widening of that tuple silently reopening the hole.
        """
        mcp = _block(directives, "/mcp")
        for header in ("X-Remote-User", "X-Forwarded-User", "X-Authenticated-User"):
            assert f"proxy_set_header {header}" in mcp, f"{header} clear was removed"
            assert '""' in next(
                line for line in mcp.splitlines() if f"proxy_set_header {header}" in line
            ), f"{header} must be cleared to the empty string, not set to a value"

    def test_x_api_account_base_is_gone_in_both_places(self, directives: str) -> None:
        """Both halves, because removing one leaves an orphan the allowlist cannot see.

        This header is the ingredient of a privilege-minting bug in ``lce_service``, whose oracle
        URL was built from ``Host`` + ``X-API-Account-Base``, and the hook gate uses that same
        oracle. It must never reach the application.
        """
        assert "X-API-Account-Base" not in directives, "the forward came back"
        assert "mcp_api_base" not in directives, "the auth_request_set capture came back"

    def test_the_access_log_survives(self, directives: str) -> None:
        """Editing the header block must not disturb the log target.

        Its limit: an MCP tool denial is an in-band JSON error inside an HTTP 200, so this log never
        records an authorization failure. The ``authorization_denied`` ``LogEvent`` is the only
        record of those.
        """
        mcp = _block(directives, "/mcp")
        assert "access_log syslog:" in mcp
        assert "em7silo_nginx" in mcp

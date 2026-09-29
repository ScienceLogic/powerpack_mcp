"""
LCE Client Tests

This module tests ``powerpack_mcp.lce_client``: the request happy path, every error path, TLS
warnings, pool shutdown and the target-host allowlist. Every test uses ``httpx.MockTransport``, so
no appliance, credential or network is needed, and "the request was never issued to LCE" can be
asserted directly.
"""

from __future__ import annotations

import ast
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import LceHttpError, LceMalformedResponse, LceUnreachable
from powerpack_mcp.lce_client import (
    LCE_BASE_PATH,
    LceClient,
    is_valid_target_host,
)


def _client_with(
    config: Config,
    credential: LceCredential,
    handler: Callable[[httpx.Request], httpx.Response],
) -> tuple[LceClient, list[httpx.Request]]:
    """Build an `LceClient` whose pool is replaced by a mock transport, capturing every request."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = LceClient(config)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(recording))
    return client, seen


_UNSET = object()


def _json_ok(body: Any = _UNSET) -> Any:
    """A 200 handler. Uses a sentinel so ``None`` can be passed as a genuine JSON ``null`` body."""
    payload = {"ok": True} if body is _UNSET else body
    return lambda _request: httpx.Response(200, json=payload)


class TestRequestHappyPath:
    @pytest.mark.anyio
    async def test_returns_parsed_body_and_status(
        self, config: Config, credential: LceCredential
    ) -> None:
        client, _ = _client_with(config, credential, _json_ok({"id": 7}))
        response = await client.request(credential=credential, method="GET", path="/powerpacks/7")
        assert response.status_code == 200
        assert response.body == {"id": 7}

    @pytest.mark.anyio
    async def test_uses_https_and_the_lce_base_path(
        self, config: Config, credential: LceCredential
    ) -> None:
        """HTTPS against /lce/api. There is no HTTP path and no way to configure one."""
        client, seen = _client_with(config, credential, _json_ok())
        await client.request(credential=credential, method="GET", path="/powerpacks/7")
        assert seen[0].url.scheme == "https"
        assert seen[0].url.path == f"{LCE_BASE_PATH}/powerpacks/7"

    @pytest.mark.anyio
    async def test_credential_is_attached_to_every_request(
        self, config: Config, credential: LceCredential, credential_value: str
    ) -> None:
        """There is no unauthenticated outbound path."""
        client, seen = _client_with(config, credential, _json_ok())
        await client.request(credential=credential, method="GET", path="/powerpacks/7")
        assert seen[0].headers["Authorization"] == credential_value

    @pytest.mark.anyio
    async def test_query_parameters_go_through_the_encoder(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Query parameters are never interpolated, always encoded by the library."""
        client, seen = _client_with(config, credential, _json_ok())
        await client.request(
            credential=credential, method="GET", path="/x", query={"filter[name]": "a b&c=d"}
        )
        assert seen[0].url.params["filter[name]"] == "a b&c=d"

    @pytest.mark.anyio
    async def test_default_target_host_is_used_when_none_supplied(
        self, config: Config, credential: LceCredential
    ) -> None:
        client, seen = _client_with(config, credential, _json_ok())
        await client.request(credential=credential, method="GET", path="/x")
        assert seen[0].url.host == "localhost"

    @pytest.mark.anyio
    async def test_supplied_target_host_overrides_the_default(
        self, config: Config, credential: LceCredential
    ) -> None:
        client, seen = _client_with(config, credential, _json_ok())
        await client.request(
            credential=credential, method="GET", path="/x", target_host="lce-01.example.internal"
        )
        assert seen[0].url.host == "lce-01.example.internal"


class TestRequestErrorPaths:
    @pytest.mark.anyio
    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422, 500, 502, 503])
    async def test_non_2xx_raises_lce_http_error_preserving_status_and_body(
        self, config: Config, credential: LceCredential, status: int
    ) -> None:
        handler = lambda _request: httpx.Response(status, json={"detail": "why"})  # noqa: E731
        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceHttpError) as exc:
            await client.request(credential=credential, method="GET", path="/x")
        assert exc.value.status_code == status
        assert exc.value.lce_body == {"detail": "why"}

    @pytest.mark.anyio
    async def test_non_json_error_body_falls_back_to_text(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Discarding LCE's own explanation of an error would make the error less useful."""
        handler = lambda _request: httpx.Response(  # noqa: E731
            502, text="<html>bad gateway</html>"
        )
        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceHttpError) as exc:
            await client.request(credential=credential, method="GET", path="/x")
        assert exc.value.lce_body == "<html>bad gateway</html>"

    @pytest.mark.anyio
    @pytest.mark.parametrize(
        "failure",
        [
            httpx.ConnectError("refused"),
            httpx.ConnectTimeout("timed out"),
            httpx.ReadTimeout("timed out"),
            httpx.PoolTimeout("pool exhausted"),
            httpx.TransportError("something else"),
        ],
    )
    async def test_transport_failures_raise_lce_unreachable(
        self, config: Config, credential: LceCredential, failure: Exception
    ) -> None:
        """Catching the base class means a new httpx error type cannot leak out."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise failure

        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceUnreachable) as exc:
            await client.request(credential=credential, method="GET", path="/x")
        assert exc.value.target_host == "localhost"

    @pytest.mark.anyio
    async def test_unreachable_carries_no_library_detail(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The message omits the resolved IP, the port and the library's exception text."""

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("[Errno 61] Connection refused to 127.0.0.1:8443")

        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceUnreachable) as exc:
            await client.request(credential=credential, method="GET", path="/x")
        assert "Errno" not in str(exc.value)
        assert "8443" not in str(exc.value)

    @pytest.mark.anyio
    @pytest.mark.parametrize("body", ["not json at all", '{"truncated": ', ""])
    async def test_unparseable_body_raises_malformed(
        self, config: Config, credential: LceCredential, body: str
    ) -> None:
        """No attempt is made to salvage a partial document."""
        handler = lambda _request: httpx.Response(200, text=body)  # noqa: E731
        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceMalformedResponse):
            await client.request(credential=credential, method="GET", path="/x")

    @pytest.mark.anyio
    @pytest.mark.parametrize("body", [42, "a string", True, None])
    async def test_scalar_json_is_malformed(
        self, config: Config, credential: LceCredential, body: Any
    ) -> None:
        """LCE returns objects and arrays; failing on a bare scalar keeps ``LceResponse.body``'s
        type honest.
        """
        client, _ = _client_with(config, credential, _json_ok(body))
        with pytest.raises(LceMalformedResponse):
            await client.request(credential=credential, method="GET", path="/x")

    @pytest.mark.anyio
    async def test_invalid_target_host_is_rejected_before_any_request(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The client's own host check is a second layer: the request is never issued."""
        client, seen = _client_with(config, credential, _json_ok())
        with pytest.raises(LceUnreachable):
            await client.request(
                credential=credential, method="GET", path="/x", target_host="evil.example.com:8443"
            )
        assert seen == [], "no request may be issued for a rejected target_host"

    @pytest.mark.anyio
    async def test_rejection_does_not_echo_the_offending_value(
        self, config: Config, credential: LceCredential
    ) -> None:
        """Name the rule that was broken; never reflect caller input."""
        client, _ = _client_with(config, credential, _json_ok())
        with pytest.raises(LceUnreachable) as exc:
            await client.request(
                credential=credential,
                method="GET",
                path="/x",
                target_host="attacker.example.com:9999",
            )
        assert "attacker" not in str(exc.value)


def _deeply_nested_json(depth: int) -> str:
    """Return a JSON document nested past CPython's scanner guard, so ``json.loads`` raises.

    The C scanner refuses beyond 9,997 levels using its own guard, independent of
    ``sys.getrecursionlimit()``. Built as text, because ``json.dumps`` on a structure this deep
    would hit the same limit from the other direction.
    """
    return "[" * depth + "]" * depth


class TestDeeplyNestedResponses:
    """A deeply nested response must raise ``LceMalformedResponse``, not ``RecursionError``.

    ``RecursionError`` inherits from ``RuntimeError``, not ``ValueError``, so an ``except
    ValueError`` handler misses it and the caller would see a generic 500.
    """

    @pytest.mark.anyio
    async def test_success_path_raises_malformed_not_recursion_error(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The success path's ``response.json()`` in ``request``."""
        handler = lambda _request: httpx.Response(  # noqa: E731
            200, text=_deeply_nested_json(50_000)
        )
        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceMalformedResponse):
            await client.request(credential=credential, method="GET", path="/x")

    @pytest.mark.anyio
    async def test_error_body_preserves_lce_status(
        self, config: Config, credential: LceCredential
    ) -> None:
        """The error path parses the body too, and must keep the LCE status.

        A deeply nested error body would otherwise raise ``RecursionError`` straight through
        ``raise LceHttpError(...)``. It must fall back to text and still raise ``LceHttpError``.
        """
        handler = lambda _request: httpx.Response(  # noqa: E731
            502, text=_deeply_nested_json(50_000)
        )
        client, _ = _client_with(config, credential, handler)
        with pytest.raises(LceHttpError) as exc:
            await client.request(credential=credential, method="GET", path="/x")
        assert exc.value.status_code == 502, "the LCE status must survive an unparseable error body"
        assert isinstance(exc.value.lce_body, str), "falls back to text rather than raising"


class TestTlsRelaxationWarning:
    @pytest.mark.anyio
    async def test_warns_on_every_affected_request_not_once(
        self, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Warn on every request while TLS verification is off; a startup warning scrolls away."""
        config = Config(LCE_VERIFY_TLS=False)
        client, _ = _client_with(config, credential, _json_ok())
        with caplog.at_level(logging.WARNING, logger="powerpack_mcp.lce_client.client"):
            await client.request(credential=credential, method="GET", path="/x")
            await client.request(credential=credential, method="GET", path="/y")
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 2
        assert warnings[0].event == "tls_verification_relaxed"  # type: ignore[attr-defined]

    @pytest.mark.anyio
    async def test_silent_when_verification_is_on(
        self, config: Config, credential: LceCredential, caplog: pytest.LogCaptureFixture
    ) -> None:
        client, _ = _client_with(config, credential, _json_ok())
        with caplog.at_level(logging.WARNING, logger="powerpack_mcp.lce_client.client"):
            await client.request(credential=credential, method="GET", path="/x")
        assert "tls_verification_relaxed" not in caplog.text


class TestAclose:
    """Pool release, and idempotence under a repeated signal."""

    @pytest.mark.anyio
    async def test_is_idempotent(self, config: Config, credential: LceCredential) -> None:
        """A repeated or duplicated SIGTERM must be harmless."""
        client, _ = _client_with(config, credential, _json_ok())
        await client.aclose()
        await client.aclose()
        await client.aclose()

    @pytest.mark.anyio
    async def test_releases_the_pool(self, config: Config, credential: LceCredential) -> None:
        client, _ = _client_with(config, credential, _json_ok())
        await client.aclose()
        assert client._client.is_closed


class TestPoolAndTimeoutWiring:
    def test_timeouts_come_from_configuration(self, config: Config) -> None:
        """Explicit connect and read timeouts. A missing one is a defect."""
        client = LceClient(config)
        timeout = client._client.timeout
        assert timeout.connect == config.LCE_CONNECT_TIMEOUT_SECONDS
        assert timeout.read == config.LCE_READ_TIMEOUT_SECONDS
        assert timeout.write is not None
        assert timeout.pool is not None

    def test_construction_opens_no_connections(self, config: Config) -> None:
        client = LceClient(config)
        assert not client._client.is_closed


class TestTargetHostAllowlist:
    """Example-based coverage; the property tests are in ``tests/property``."""

    @pytest.mark.parametrize(
        "value",
        ["localhost", "lce-01.example.internal", "127.0.0.1", "a", "A-B.c-d", "x" * 63],
    )
    def test_accepted_forms(self, value: str) -> None:
        assert is_valid_target_host(value) is True

    @pytest.mark.parametrize(
        ("value", "reason"),
        [
            ("https://host", "scheme prefix"),
            ("http://host", "scheme prefix"),
            ("host:8443", "port"),
            ("host/path", "path"),
            ("host?q=1", "query"),
            ("host#frag", "fragment"),
            ("user:pass@host", "userinfo"),
            ("ho%73t", "percent-encoding"),
            ("ho st", "whitespace"),
            ("host\n", "control character"),
            ("", "empty"),
            ("host.", "trailing dot"),
            ("-host", "leading hyphen"),
            ("host-", "trailing hyphen"),
            ("::1", "IPv6"),
            ("x" * 254, "over 253 characters"),
        ],
    )
    def test_rejected_forms(self, value: str, reason: str) -> None:
        assert is_valid_target_host(value) is False, f"should reject: {reason}"

    def test_is_case_insensitive(self) -> None:
        for value in ["LOCALHOST", "LCE-01.Example.Internal"]:
            assert is_valid_target_host(value) == is_valid_target_host(value.lower())


# ---- LCE paths must be absolute ----
#
# ``_build_url`` composes ``f"{LCE_BASE_PATH}{path}"`` with no separator, so every LCE path must
# be absolute. A relative path such as ``"event_policies"`` gives ``/lce/apievent_policies``, which
# made ``server_health`` report LCE as unreachable while it was healthy, and broke dynamic-app
# resolution for the align and unalign tools. ``Sl1Client`` normalises a missing leading slash
# (``sl1_client/client.py``); ``LceClient`` does not. The tripwire below makes it safe to leave the
# two conventions as they are.

_LCE_PATH_CONSTANT_RE = re.compile(r"^_LCE_\w*PATH\w*$")


class TestLcePathsMustBeAbsolute:
    def test_the_client_does_not_normalise_a_relative_path(self) -> None:
        """``_build_url`` concatenates, so a relative path is malformed.

        Asserted as current behaviour. If ``LceClient`` is changed to normalise like ``Sl1Client``,
        this fails and the tripwire below can be retired deliberately.
        """
        client = LceClient(Config())
        relative = client._build_url("localhost", "event_policies", None)
        absolute = client._build_url("localhost", "/event_policies", None)
        assert relative.path == "/lce/apievent_policies"
        assert absolute.path == "/lce/api/event_policies"

    def test_the_two_regressed_constants_are_absolute(self) -> None:
        """The two constants that were once relative, named so a revert is unmistakable."""
        from powerpack_mcp.tools.sl1_entity_tools import _LCE_DYNAMIC_APP_PATH
        from powerpack_mcp.tools.sl1_ops_tools import _LCE_PROBE_PATH

        assert _LCE_PROBE_PATH == "/event_policies"
        assert _LCE_DYNAMIC_APP_PATH == "/dynamic_applications"

    def test_every_lce_path_constant_in_the_tool_layer_is_absolute(self) -> None:
        """The tripwire: a new slashless ``_LCE_*_PATH`` anywhere in ``tools/`` fails here.

        By AST over the source rather than by import, so a module that does not import cleanly
        cannot silently drop out of the sweep.
        """
        tools = Path(__file__).resolve().parents[2] / "src" / "powerpack_mcp" / "tools"
        modules = sorted(tools.glob("*.py"))
        # Guard the sweep itself: an empty or mis-rooted glob would make this pass vacuously.
        assert len(modules) > 5, f"expected the tool layer, found {len(modules)} modules at {tools}"

        checked: list[str] = []
        for module in modules:
            for node in ast.parse(module.read_text(encoding="utf-8")).body:
                if not isinstance(node, ast.Assign):
                    continue
                for target in node.targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if not _LCE_PATH_CONSTANT_RE.match(target.id):
                        continue
                    assert isinstance(node.value, ast.Constant), (
                        f"{module.name}:{target.id} is not a string literal, so this tripwire "
                        f"cannot check it -- assert its absoluteness where it is built"
                    )
                    value = node.value.value
                    checked.append(f"{module.name}:{target.id}")
                    assert isinstance(value, str), f"{module.name}:{target.id} is not a string"
                    assert value.startswith("/"), (
                        f"{module.name}:{target.id} = {value!r} is relative. LceClient._build_url "
                        f"concatenates it onto {LCE_BASE_PATH!r} with no separator, so it must "
                        f"start with '/'"
                    )

        # And guard against the pattern matching nothing, which would also pass vacuously.
        assert len(checked) >= 2, f"expected at least the two known constants, found {checked}"

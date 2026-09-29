"""
SL1 Client Tests

This module tests ``powerpack_mcp.sl1_client``: the REST and GraphQL transport, error translation,
the outbound response size cap, and path safety.

It mirrors ``test_lce_client``'s harness: every test uses ``httpx.MockTransport``, so the default
run needs no appliance, no credential and no network. The substitutable transport is also what makes
"the request was never issued to SL1" assertable.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import SecretStr

from powerpack_mcp.config import Config
from powerpack_mcp.credentials import LceCredential
from powerpack_mcp.errors import (
    Sl1EmptyResponse,
    Sl1GraphQlError,
    Sl1HttpError,
    Sl1MalformedResponse,
    Sl1ResponseTooLarge,
    Sl1Unreachable,
    ValidationBlocked,
)
from powerpack_mcp.sl1_client import (
    GRAPHQL_PATH,
    SL1_API_BASE_PATH,
    Sl1Client,
    is_safe_relative_path,
)


def _client_with(
    config: Config, handler: Callable[[httpx.Request], httpx.Response]
) -> tuple[Sl1Client, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = Sl1Client(config)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(recording))
    return client, seen


def _cred() -> LceCredential:
    return LceCredential(SecretStr("Basic dXNlcjpwYXNz"))


def _ok(body: Any) -> Callable[[httpx.Request], httpx.Response]:
    return lambda _r: httpx.Response(200, json=body)


class TestRestHappyPath:
    @pytest.mark.anyio
    async def test_returns_the_parsed_body(self, config: Config) -> None:
        client, seen = _client_with(config, _ok({"result": [1, 2]}))
        body = await client.request(credential=_cred(), method="GET", path="device")
        assert body == {"result": [1, 2]}
        assert len(seen) == 1

    @pytest.mark.anyio
    async def test_the_url_is_composed_structurally(self, config: Config) -> None:
        """The URL is https, on the configured host, with the path under the API base.

        The configuration key holds a host, and the scheme comes from the client rather than from
        configuration, so there is no string to concatenate.
        """
        client, seen = _client_with(config, _ok({}))
        await client.request(credential=_cred(), method="GET", path="device/1")
        url = seen[0].url
        assert url.scheme == "https"
        assert url.host == config.SL1_DEFAULT_TARGET_HOST
        assert str(url.path) == f"{SL1_API_BASE_PATH}/device/1"

    @pytest.mark.anyio
    async def test_the_credential_is_sent_on_every_request(self, config: Config) -> None:
        """The credential is forwarded per request, never bound into the client."""
        client, seen = _client_with(config, _ok({}))
        await client.request(credential=_cred(), method="GET", path="device")
        await client.request(credential=_cred(), method="GET", path="device")
        assert all("authorization" in r.headers for r in seen)

    @pytest.mark.anyio
    async def test_query_parameters_go_through_the_encoder(self, config: Config) -> None:
        client, seen = _client_with(config, _ok({}))
        await client.request(
            credential=_cred(), method="GET", path="device", query={"limit": "5 &x"}
        )
        assert seen[0].url.params["limit"] == "5 &x"


class TestRestErrorTranslation:
    """SL1 failures must not present as LCE failures."""

    @pytest.mark.anyio
    async def test_non_2xx_raises_sl1_http_error_not_the_lce_one(self, config: Config) -> None:
        client, _ = _client_with(config, lambda _r: httpx.Response(404, json={"msg": "nope"}))
        with pytest.raises(Sl1HttpError) as exc:
            await client.request(credential=_cred(), method="GET", path="device/9")
        assert exc.value.status_code == 404
        assert "SL1 returned HTTP 404" in str(exc.value)

    @pytest.mark.anyio
    async def test_a_non_json_error_body_still_reports_the_status(self, config: Config) -> None:
        """A non-JSON error body is common and is not a second, separate failure.

        Reporting ``Sl1MalformedResponse`` here would replace a useful 404 with a confusing parse
        complaint; the status is what the caller can act on.
        """
        client, _ = _client_with(config, lambda _r: httpx.Response(500, text="<html>oops"))
        with pytest.raises(Sl1HttpError) as exc:
            await client.request(credential=_cred(), method="GET", path="device")
        assert exc.value.status_code == 500

    @pytest.mark.anyio
    async def test_a_transport_failure_raises_sl1_unreachable(self, config: Config) -> None:
        def boom(_r: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused")

        client, _ = _client_with(config, boom)
        with pytest.raises(Sl1Unreachable) as exc:
            await client.request(credential=_cred(), method="GET", path="device")
        assert "refused" not in str(exc.value), "no library exception text in the error"

    @pytest.mark.anyio
    async def test_unparseable_success_body_raises_malformed(self, config: Config) -> None:
        client, _ = _client_with(config, lambda _r: httpx.Response(200, text="not json"))
        with pytest.raises(Sl1MalformedResponse):
            await client.request(credential=_cred(), method="GET", path="device")


class TestOutboundSizeCap:
    """Response bodies over ``MAX_RESPONSE_BODY_BYTES`` are refused while streaming."""

    @pytest.mark.anyio
    async def test_a_body_over_the_cap_is_refused(self, config: Config) -> None:
        oversized = Config(**{**config.model_dump(), "MAX_RESPONSE_BODY_BYTES": 64})
        client, _ = _client_with(oversized, _ok({"pad": "x" * 500}))
        with pytest.raises(Sl1ResponseTooLarge) as exc:
            await client.request(credential=_cred(), method="GET", path="device")
        assert exc.value.limit_bytes == 64

    @pytest.mark.anyio
    async def test_a_body_under_the_cap_passes(self, config: Config) -> None:
        client, _ = _client_with(config, _ok({"small": True}))
        assert await client.request(credential=_cred(), method="GET", path="device") == {
            "small": True
        }

    @pytest.mark.anyio
    async def test_no_partial_body_is_returned(self, config: Config) -> None:
        """The caller gets an error, never a truncated payload it might trust."""
        tight = Config(**{**config.model_dump(), "MAX_RESPONSE_BODY_BYTES": 16})
        client, _ = _client_with(tight, _ok({"items": list(range(200))}))
        with pytest.raises(Sl1ResponseTooLarge):
            await client.request(credential=_cred(), method="GET", path="device")

    @pytest.mark.anyio
    async def test_the_cap_applies_to_the_graphql_path_too(self, config: Config) -> None:
        """The arbitrary-query path is the least bounded of the three, so it most needs the cap."""
        tight = Config(**{**config.model_dump(), "MAX_RESPONSE_BODY_BYTES": 32})
        client, _ = _client_with(tight, _ok({"data": {"pad": "y" * 400}}))
        with pytest.raises(Sl1ResponseTooLarge):
            await client.graphql(credential=_cred(), query="{ devices { id } }")

    @pytest.mark.anyio
    async def test_the_reader_streams_rather_than_reading_then_measuring(
        self, config: Config
    ) -> None:
        """Distinguish a streaming reader from one that reads the whole body, then measures it.

        A read-then-measure version would raise the same error, so asserting the error alone is not
        enough. Here the response is served in chunks and the cap is far
        below the total: the mock's iterator is only advanced as far as the cap allows, so if the
        implementation had buffered everything first, `served` would show every chunk consumed.
        """
        served: list[int] = []

        def chunked(_r: httpx.Request) -> httpx.Response:
            async def gen() -> AsyncIterator[bytes]:
                # An async generator: ``AsyncClient`` requires an async byte stream. A sync one
                # fails inside httpx, with an error that points at httpx's internals rather than at
                # the fixture.
                for i in range(100):
                    served.append(i)
                    yield b"x" * 100

            return httpx.Response(200, content=gen())

        tight = Config(**{**config.model_dump(), "MAX_RESPONSE_BODY_BYTES": 250})
        client, _ = _client_with(tight, chunked)
        with pytest.raises(Sl1ResponseTooLarge):
            await client.request(credential=_cred(), method="GET", path="device")

        assert len(served) < 100, "the whole body was consumed before the cap was applied"


class TestGraphQl:
    """GraphQL over HTTP: a 200 response can still carry errors."""

    @pytest.mark.anyio
    async def test_it_posts_the_envelope_to_the_gql_path(self, config: Config) -> None:
        client, seen = _client_with(config, _ok({"data": {"devices": []}}))
        await client.graphql(credential=_cred(), query="{ devices { id } }", variables={"a": 1})
        assert seen[0].method == "POST"
        assert str(seen[0].url.path) == GRAPHQL_PATH

    @pytest.mark.anyio
    async def test_variables_are_omitted_when_empty(self, config: Config) -> None:
        """Sending `"variables": null` is not the same as omitting the key, and some GraphQL
        servers reject the former."""
        client, seen = _client_with(config, _ok({"data": {}}))
        await client.graphql(credential=_cred(), query="{ a }")
        assert b"variables" not in seen[0].content

    @pytest.mark.anyio
    async def test_errors_inside_a_200_raise_sl1_graphql_error(self, config: Config) -> None:
        """Errors inside a 200 raise ``Sl1GraphQlError``, the reason that error type exists.

        The transport succeeded, so ``sl1_http_error`` is wrong, and the caller's input was not
        refused by this service, so ``validation_blocked`` is wrong. Without this raise the error
        type would be one no code can emit.
        """
        client, _ = _client_with(
            config, _ok({"data": None, "errors": [{"message": "Cannot query field 'nope'"}]})
        )
        with pytest.raises(Sl1GraphQlError) as exc:
            await client.graphql(credential=_cred(), query="{ nope }")
        assert exc.value.messages == ("Cannot query field 'nope'",)

    @pytest.mark.anyio
    async def test_an_empty_errors_array_is_success(self, config: Config) -> None:
        """`"errors": []` is not a failure, and treating it as one would reject valid responses."""
        client, _ = _client_with(config, _ok({"data": {"a": 1}, "errors": []}))
        assert await client.graphql(credential=_cred(), query="{ a }") == {
            "data": {"a": 1},
            "errors": [],
        }

    @pytest.mark.anyio
    async def test_an_oddly_shaped_error_entry_is_stringified_not_dropped(
        self, config: Config
    ) -> None:
        """SL1 authors these strings, so the shape is not ours to guarantee. Dropping would be
        worse than an ugly string: the caller would see "N errors" with nothing to act on."""
        client, _ = _client_with(config, _ok({"errors": ["plain", {"no_message": 1}]}))
        with pytest.raises(Sl1GraphQlError) as exc:
            await client.graphql(credential=_cred(), query="{ a }")
        assert len(exc.value.messages) == 2


class TestTlsRelaxationWarning:
    """Turning TLS verification off logs a warning on the SL1 path too."""

    @pytest.mark.anyio
    async def test_a_warning_is_emitted_on_the_sl1_path_when_verification_is_off(
        self, config: Config, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The two backends share one ``LCE_VERIFY_TLS`` flag, so without this the warning would
        hold for LCE and silently not for SL1."""
        relaxed = Config(**{**config.model_dump(), "LCE_VERIFY_TLS": False})
        client, _ = _client_with(relaxed, _ok({}))
        with caplog.at_level(logging.WARNING):
            await client.request(credential=_cred(), method="GET", path="device")
        assert any("SL1" in r.getMessage() for r in caplog.records)

    @pytest.mark.anyio
    async def test_no_warning_when_verification_is_on(
        self, config: Config, caplog: pytest.LogCaptureFixture
    ) -> None:
        client, _ = _client_with(config, _ok({}))
        with caplog.at_level(logging.WARNING):
            await client.request(credential=_cred(), method="GET", path="device")
        assert caplog.records == []


class TestNoPerCallerState:
    """The client holds no per-caller state: one transport, whatever the credential."""

    @pytest.mark.anyio
    async def test_one_transport_serves_both_accessors(self, config: Config) -> None:
        """Two accessors over one transport. A second ``AsyncClient`` would double the pool
        against ``MemoryMax=512M`` for no gain."""
        client, seen = _client_with(config, _ok({"data": {}}))
        transport_before = client._client
        await client.request(credential=_cred(), method="GET", path="device")
        await client.graphql(credential=_cred(), query="{ a }")
        assert client._client is transport_before
        assert len(seen) == 2

    @pytest.mark.anyio
    async def test_differing_credentials_do_not_create_client_structure(
        self, config: Config
    ) -> None:
        """A client cached per credential would be one pool per human under credential forwarding,
        unbounded and never evicted."""
        client, _ = _client_with(config, _ok({}))
        before = client._client
        for token in ("Basic aaa", "Basic bbb", "Basic ccc"):
            await client.request(
                credential=LceCredential(SecretStr(token)), method="GET", path="device"
            )
        assert client._client is before

    @pytest.mark.anyio
    async def test_aclose_is_idempotent(self, config: Config) -> None:
        client, _ = _client_with(config, _ok({}))
        await client.aclose()
        await client.aclose()


class TestPathSafety:
    """Caller-supplied paths must stay relative to the API base.

    No tool takes a ``target_host``, so no parameter can redirect a call. But ``path`` is still a
    caller input, and an absolute URL there would reach an arbitrary host by another door.
    """

    @pytest.mark.parametrize(
        "path",
        [
            "//evil.example.com/x",  # protocol-relative -- looks like a path
            "https://evil.example.com/x",
            "HTTPS://evil.example.com/x",  # case
            "http://evil.example.com",
            "../../etc/passwd",
            "device/../../secret",
            "\\\\evil.example.com\\x",  # backslash as a // disguise
            "file:/etc/passwd",
            "device\nGET /admin",  # request splitting / log forging
            "device 1",
            "",
        ],
    )
    @pytest.mark.anyio
    async def test_unsafe_paths_are_refused_before_any_request(
        self, config: Config, path: str
    ) -> None:
        """Refused before the call is made: reject before spending."""
        client, seen = _client_with(config, _ok({}))
        with pytest.raises(ValidationBlocked):
            await client.request(credential=_cred(), method="GET", path=path)
        assert seen == [], "an unsafe path must never reach the transport"

    @pytest.mark.parametrize(
        "path",
        [
            "device",
            "device/1",
            "device/1/interface",
            "device?limit=5",
            "my..device",  # NOT traversal -- a legal SL1 resource name
            "..foo",
            "device/x:y",  # a colon after the first slash is legitimate
        ],
    )
    def test_legitimate_paths_are_accepted(self, path: str) -> None:
        """Over-rejection in a passthrough is a bug, not a security win, which is why the ``..``
        check is segment-wise rather than a substring match."""
        assert is_safe_relative_path(path) is True

    def test_the_rejection_never_echoes_the_offending_value(self) -> None:
        """A rejected path is caller-supplied content, and quoting it into a log record is the
        log-forging vector this check exists to close."""
        from powerpack_mcp.sl1_client import ensure_relative_path

        marker = "https://attacker.invalid/canary"
        with pytest.raises(ValidationBlocked) as exc:
            ensure_relative_path(marker)
        assert marker not in str(exc.value)
        assert all(marker not in f.message for f in exc.value.findings)


class TestPathSafetyProperty:
    """Path safety is a universally quantified property, so it is tested as one.

    An example table tests the cases someone thought of. This tests the claim actually being made:
    for any input, a path that escapes its prefix is refused.
    """

    @given(
        prefix=st.sampled_from(["//", "https://", "http://", "\\\\", "file:"]),
        rest=st.text(
            alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=12
        ),
    )
    @settings(max_examples=60, deadline=None)
    def test_no_generated_absolute_or_protocol_relative_path_is_accepted(
        self, prefix: str, rest: str
    ) -> None:
        assert is_safe_relative_path(prefix + rest) is False

    @given(
        head=st.text(
            alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=8
        ),
        tail=st.text(
            alphabet=st.characters(min_codepoint=97, max_codepoint=122), min_size=1, max_size=8
        ),
    )
    @settings(max_examples=60, deadline=None)
    def test_no_generated_traversal_segment_is_accepted(self, head: str, tail: str) -> None:
        assert is_safe_relative_path(f"{head}/../{tail}") is False


class TestBoundedReadEdgeShapes:
    """``bounded_read``'s three rejections, each one a shape no tool could use."""

    @pytest.mark.anyio
    async def test_an_empty_body_is_malformed(self, config: Config) -> None:
        """An empty body is not JSON, and for a ``200`` it is malformed.

        An empty body raises ``Sl1EmptyResponse``, a subclass of ``Sl1MalformedResponse``. A
        ``200 OK`` promises a representation, so an empty one really is malformed; this is why only
        ``202`` and ``204`` accept an empty body, not any 2xx.
        """
        client, _ = _client_with(config, lambda _r: httpx.Response(200, content=b""))
        with pytest.raises(Sl1MalformedResponse):
            await client.request(credential=_cred(), method="GET", path="device")

    @pytest.mark.anyio
    async def test_a_bare_scalar_is_malformed(self, config: Config) -> None:
        """``42`` is valid JSON and still unusable. It is treated as malformed rather than
        wrapped, because wrapping would invent structure the API did not send."""
        client, _ = _client_with(config, lambda _r: httpx.Response(200, content=b"42"))
        with pytest.raises(Sl1MalformedResponse):
            await client.request(credential=_cred(), method="GET", path="device")

    @pytest.mark.anyio
    async def test_a_graphql_response_that_is_a_list_is_malformed(self, config: Config) -> None:
        """A GraphQL response is a JSON object by specification; a list is not something to
        interpret."""
        client, _ = _client_with(config, _ok([1, 2, 3]))
        with pytest.raises(Sl1MalformedResponse):
            await client.graphql(credential=_cred(), query="{ a }")


class TestAnEmptyBodyOnAnAcceptedStatus:
    """``202``/``204`` with an empty body is correct REST, not a malformed response.

    SL1 answers ``sl1_clear_event``'s DELETE and ``sl1_run_discovery_session``'s async POST with
    ``202``, an empty body, and an explicit ``x-em7-status-message``. Treating that as malformed
    would report every successful write as a failure.
    """

    @pytest.mark.anyio
    async def test_a_202_with_an_empty_body_is_accepted(self, config: Config) -> None:
        """The response shape SL1 returns for a successful event DELETE."""
        client, _ = _client_with(
            config,
            lambda _r: httpx.Response(
                202, content=b"", headers={"x-em7-status-message": "event seq:8854 deleted"}
            ),
        )
        result = await client.request(credential=_cred(), method="DELETE", path="event/8854")
        assert result == {
            "status": "accepted",
            "http_status": 202,
            "message": "event seq:8854 deleted",
        }

    @pytest.mark.anyio
    async def test_a_204_with_an_empty_body_is_accepted(self, config: Config) -> None:
        """``204`` is defined as bodyless, so it cannot be excluded on any principle that
        admits ``202``.
        """
        client, _ = _client_with(config, lambda _r: httpx.Response(204, content=b""))
        result = await client.request(credential=_cred(), method="DELETE", path="event/1")
        assert result == {"status": "accepted", "http_status": 204, "message": ""}

    @pytest.mark.anyio
    async def test_a_202_carrying_json_still_parses(self, config: Config) -> None:
        """The fallback must not swallow a real body.

        ``202`` does not forbid one, so the accepted-result shape is reached only when the body is
        genuinely empty. Without this, a ``202`` with a payload would silently lose it.
        """
        client, _ = _client_with(config, lambda _r: httpx.Response(202, json={"id": 7}))
        assert await client.request(credential=_cred(), method="POST", path="x") == {"id": 7}

    @pytest.mark.anyio
    async def test_a_200_with_an_empty_body_is_still_malformed(self, config: Config) -> None:
        """The control for the status gate, and the reason it is not "any 2xx".

        Accepting any 2xx with an empty body would make this case a silent success: a false report
        pointed the other way.
        """
        client, _ = _client_with(config, lambda _r: httpx.Response(200, content=b""))
        with pytest.raises(Sl1MalformedResponse):
            await client.request(credential=_cred(), method="GET", path="device")

    @pytest.mark.anyio
    async def test_an_error_status_with_an_empty_body_still_raises_the_http_error(
        self, config: Config
    ) -> None:
        """The ``>= 400`` path is untouched: the status is what the caller needs, not a parse
        verdict.
        """
        client, _ = _client_with(config, lambda _r: httpx.Response(404, content=b""))
        with pytest.raises(Sl1HttpError) as exc:
            await client.request(credential=_cred(), method="GET", path="device/9")
        assert exc.value.status_code == 404

    def test_the_empty_response_error_is_a_malformed_response(self) -> None:
        """``Sl1EmptyResponse`` must stay a subclass of ``Sl1MalformedResponse``.

        That is what lets the ``>= 400`` path's ``except Sl1MalformedResponse`` keep catching it,
        and ``pytest.raises(Sl1MalformedResponse)`` assertions keep passing. Re-parenting it to a
        sibling would change error handling silently.
        """
        assert issubclass(Sl1EmptyResponse, Sl1MalformedResponse)


class TestTheStatusMessageIsTreatedAsForeignContent:
    """``x-em7-status-message`` reaches a tool result and the journal, so it is untrusted text."""

    @pytest.mark.anyio
    async def test_control_characters_are_dropped_not_escaped(self, config: Config) -> None:
        """A newline here would forge a log record, as it would in a correlation ID (see
        ``sanitize_correlation_id``). Dropped rather than escaped: nothing a control character
        conveys in a status message is worth preserving.
        """
        client, _ = _client_with(
            config,
            lambda _r: httpx.Response(
                202,
                content=b"",
                headers={"x-em7-status-message": "ok\r\nevent: forged log line"},
            ),
        )
        result = await client.request(credential=_cred(), method="DELETE", path="event/1")
        assert isinstance(result, dict)
        message = result["message"]
        assert isinstance(message, str)
        assert "\n" not in message
        assert "\r" not in message
        assert "forged" in message, "the text survives; only the control characters go"

    @pytest.mark.anyio
    async def test_an_overlong_message_is_truncated_rather_than_rejected(
        self, config: Config
    ) -> None:
        """A merely long header is still evidence of what happened. Refusing the whole response
        over it would report a successful call as a failure.
        """
        client, _ = _client_with(
            config,
            lambda _r: httpx.Response(
                202, content=b"", headers={"x-em7-status-message": "z" * 5000}
            ),
        )
        result = await client.request(credential=_cred(), method="DELETE", path="event/1")
        assert isinstance(result, dict)
        message = result["message"]
        assert isinstance(message, str)
        assert len(message) == 200

    @pytest.mark.anyio
    async def test_a_missing_header_yields_an_empty_message_not_a_failure(
        self, config: Config
    ) -> None:
        """SL1 is not contractually obliged to send it, and its absence is not an error."""
        client, _ = _client_with(config, lambda _r: httpx.Response(202, content=b""))
        result = await client.request(credential=_cred(), method="DELETE", path="event/1")
        assert isinstance(result, dict)
        assert result["message"] == ""

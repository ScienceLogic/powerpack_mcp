"""
Bounded Response Reading

This module provides ``read_json_within_limit``, the single helper every SL1 accessor uses to read
a response body under a hard byte cap. The inbound request-size limit does not bound what SL1
sends back, and a passthrough request, an extended fetch or a caller-authored GraphQL query can all
return very large bodies against the service's ``MemoryMax=512M``. The body is streamed and the
read aborts mid-stream, so peak memory is the cap plus one chunk.

The byte cap is only safe alongside the request deadline enforced around the whole ASGI call.
Every chunk resets httpx's read timeout, so a byte limit without a time limit turns a memory risk
into an unbounded-duration one. Do not remove one and keep the other.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from powerpack_mcp.errors import (
    Sl1EmptyResponse,
    Sl1MalformedResponse,
    Sl1ResponseTooLarge,
)

if TYPE_CHECKING:
    import httpx

__all__ = ["read_json_within_limit"]


async def read_json_within_limit(
    response: httpx.Response, *, limit_bytes: int
) -> dict[str, Any] | list[Any]:
    """Read a streaming response, aborting past ``limit_bytes``, and parse it as JSON.

    The caller must have opened ``response`` with ``client.stream(...)``, not
    ``client.request(...)``. A non-streaming response has already been read in full by httpx, so
    the cap would be enforced after the memory was spent.

    :param response: A streaming httpx response.
    :param limit_bytes: The maximum body size to read.
    :return: The parsed JSON object or array.
    :raises Sl1ResponseTooLarge: If the body exceeds ``limit_bytes``.
    :raises Sl1EmptyResponse: If the body is empty.
    :raises Sl1MalformedResponse: If the body is not a JSON object or array.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        total += len(chunk)
        if total > limit_bytes:
            # Abort before appending, so peak memory stays at the cap plus the chunk in hand.
            # Abandoning the ``aiter_bytes`` generator closes the response and releases the
            # connection.
            raise Sl1ResponseTooLarge(limit_bytes)
        chunks.append(chunk)

    body = b"".join(chunks)
    if not body:
        # Raise the ``Sl1MalformedResponse`` subclass so the caller can decide from the status
        # code: an empty body is expected for ``202 Accepted`` and ``204 No Content``, which this
        # function cannot see. ``client.py`` makes that call.
        raise Sl1EmptyResponse
    try:
        parsed: object = json.loads(body)
    except ValueError as exc:
        # The parse error text is deliberately not propagated: it quotes the offending bytes,
        # which are foreign content this service does not control.
        raise Sl1MalformedResponse from exc
    if not isinstance(parsed, dict | list):
        # SL1 returning a bare scalar is not a shape any tool can use. Treated as malformed rather
        # than wrapped, because wrapping would invent structure the API did not send.
        raise Sl1MalformedResponse
    return parsed

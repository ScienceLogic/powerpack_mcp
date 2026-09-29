"""
LCE Destination Host Validation

This module provides ``TargetHost``, the validated LCE destination type, and
``is_valid_target_host``, its pure predicate. ``TargetHost`` is the single definition of the
allowed host pattern. It is enforced twice: pydantic rejects a bad value at the tool signature, and
``LceClient.request()`` checks again before building the URL, so neither layer is the only defence.

IPv6 literals are rejected. The systemd unit sets ``RestrictAddressFamilies=AF_INET AF_UNIX``, so
the process cannot open an IPv6 socket, and accepting one would surface as a confusing connection
failure. A port is rejected for its own reason: it would let a caller redirect a write at an
arbitrary listener on an otherwise legitimate host.
"""

from __future__ import annotations

import re
from typing import Annotated, Final

from pydantic import StringConstraints

__all__ = ["MAX_TARGET_HOST_LENGTH", "TARGET_HOST_PATTERN", "TargetHost", "is_valid_target_host"]

# RFC-1123: dot-separated labels of 1 to 63 characters, alphanumeric at each end, hyphens interior
# only. A dotted-quad IPv4 literal satisfies this pattern too, which is why one expression covers
# both accepted forms. Deliberately anchored and free of lookahead so pydantic's Rust regex engine
# accepts it unchanged.
TARGET_HOST_PATTERN: Final[str] = (
    r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)

MAX_TARGET_HOST_LENGTH: Final[int] = 253

_TARGET_HOST_RE: Final[re.Pattern[str]] = re.compile(TARGET_HOST_PATTERN)

TargetHost = Annotated[
    str,
    StringConstraints(pattern=TARGET_HOST_PATTERN, max_length=MAX_TARGET_HOST_LENGTH),
]


def is_valid_target_host(value: str) -> bool:
    """Return whether ``value`` is an acceptable LCE destination.

    Accepts RFC-1123 hostnames and IPv4 literals. Rejects every string containing ``:``, ``/``,
    ``?``, ``#``, ``@``, whitespace or ``%``; each is excluded by the pattern's character class
    rather than by a separate check, so there is no ordering between them to get wrong. A trailing
    dot is rejected: it is valid DNS but doubles the representation of every hostname.

    The predicate never raises for any ``str`` input, including the empty string, and is
    case-insensitive, as hostnames are.

    :param value: The candidate host.
    :return: ``True`` if the host is acceptable.
    """
    if not value or len(value) > MAX_TARGET_HOST_LENGTH:
        return False
    # ``fullmatch``, not ``match``: in Python's ``re``, ``$`` also matches before a trailing
    # newline, so ``match()`` would accept "host\n". Pydantic's Rust regex engine rejects it, which
    # is why the two validation layers are both kept.
    return _TARGET_HOST_RE.fullmatch(value) is not None

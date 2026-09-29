"""
Caller-Supplied Path Safety

This module validates the ``path`` argument that SL1 passthrough tools accept. The destination
host, username and password are fixed by configuration and are never tool parameters, but ``path``
is still caller input, and an absolute or protocol-relative URL there would reach an arbitrary
host. This check closes that route.
"""

from __future__ import annotations

from powerpack_mcp.errors import FindingCode, ValidationBlocked, ValidationFinding

__all__ = ["ensure_relative_path", "is_safe_relative_path"]

# A scheme, a protocol-relative prefix, or anything that could re-target the request.
_ABSOLUTE_PREFIXES: tuple[str, ...] = ("//", "http://", "https://")


def is_safe_relative_path(path: str) -> bool:
    """Return whether ``path`` is a relative path that cannot escape the SL1 base.

    Rejects, in order of how easily each is missed:

    * ``//host``, a protocol-relative URL. It looks like a path and starts with a slash, but
      ``urljoin`` treats it as a new authority.
    * ``http://`` / ``https://``, an absolute URL, in any case combination.
    * ``..`` in any segment, which traverses above the base.
    * A backslash, which some servers normalise to ``/``, so ``\\\\host`` is ``//host`` in
      disguise.
    * A control character or whitespace, a request-splitting and log-forging vector, on the same
      reasoning ``credentials.contains_control_characters`` applies to header values.
    * A scheme prefix such as ``file:``, refused by position rather than by enumerating schemes. A
      denylist of schemes is a list someone must remember to extend.

    :param path: The caller-supplied path.
    :return: ``True`` if the path is safe to join to the SL1 base URL.
    """
    if not path:
        return False
    lowered = path.lower()
    if lowered.startswith(_ABSOLUTE_PREFIXES):
        return False
    if "\\" in path:
        return False
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
        return False
    # A colon before the first slash is a scheme (``file:x``, ``mailto:x``). A colon *after* one is
    # legitimate in a query or a matrix parameter, so the position matters rather than the
    # character.
    head = path.split("/", 1)[0]
    if ":" in head:
        return False
    # Segment-wise, so ``..`` is caught while ``..foo`` and ``foo..bar`` -- which are legal SL1
    # resource names -- are not. A substring check would reject those, and over-rejection in a
    # passthrough is a bug report, not a security win.
    return ".." not in path.split("?", 1)[0].split("/")


def ensure_relative_path(path: str) -> str:
    """Return ``path`` unchanged, or raise naming the offending field.

    The message names the rule and never echoes the value: a rejected path is caller-supplied
    content, and quoting it into a log record is the log-forging vector this check exists to close.

    :param path: The caller-supplied path.
    :return: ``path``, unchanged.
    :raises ValidationBlocked: If the path is not a safe relative path.
    """
    if not is_safe_relative_path(path):
        raise ValidationBlocked(
            [
                ValidationFinding(
                    path="path",
                    rule=FindingCode.FILTER_CONSTRAINT,
                    message=(
                        "must be a relative path within the SL1 API -- no scheme, no "
                        "protocol-relative '//' prefix, no '..' segment, no backslash and no "
                        "whitespace or control characters. The destination host is fixed by "
                        "configuration and cannot be supplied per call."
                    ),
                )
            ]
        )
    return path

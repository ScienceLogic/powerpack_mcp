"""
Security Invariant Tests

This module pins security-weighted constants by importing them, so a reformat of the source
cannot break the check. The rationale for each value lives here because nothing else in the code
explains why it must not drift. The nginx fragment and RPM spec are checked separately, since a
config file has no import path.
"""

from __future__ import annotations

from powerpack_mcp.config import DEFAULT_ENV_FILE_PATH
from powerpack_mcp.mcp_app.correlation import FORWARDED_ACTOR_HEADERS


def test_forwarded_actor_headers_is_exactly_x_user_id() -> None:
    """Widening this tuple is a security regression, and it fails silently.

    nginx sets only ``x-user-id``. Any other header name in this tuple is passed through from the
    client unchanged, so a caller sending ``X-Remote-User: admin`` would be recorded as admin in
    audit records. The nginx fragment also blanks the legacy names ``x-remote-user``,
    ``x-forwarded-user`` and ``x-authenticated-user`` as defence in depth, but that is a second
    line, not a reason to relax this one.
    """
    assert FORWARDED_ACTOR_HEADERS == (b"x-user-id",)


def test_env_file_path_is_inside_the_service_directory() -> None:
    """The env file stays inside the versioned service directory.

    Moving it to a version-independent location, so operator edits survive a version bump, was
    considered and rejected. The accepted consequence: a release bump preserves the file, a version
    bump does not. Treat a change here as a design decision, not a refactor.
    """
    assert DEFAULT_ENV_FILE_PATH == "/opt/em7/services/powerpack-mcp/powerpack-mcp.env"

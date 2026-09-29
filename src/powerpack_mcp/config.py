"""
Service Configuration

This module provides the ``Config`` model and the functions that load it from the environment.
Each field is read from the environment variable of the same name, which is why field names are
upper case, and every value is converted and validated by the pydantic model. Credentials are not
configured here; each request carries its own (see ``credentials``).

Configuration precedence, highest first:

1. Real environment variables.
2. The env file. It is loaded with ``override=False``, so it only fills gaps.
3. The field default.

There is no module-level configuration singleton: loading at import time would break test
collection for any invalid value. ``load_config()`` is called at startup after logging is
configured, so a configuration failure is itself logged.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import stat
from pathlib import Path
from typing import Final

from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError, field_validator

from powerpack_mcp.errors import ConfigurationError

__all__ = [
    "DEFAULT_ENV_FILE_PATH",
    "LOG_FORMAT",
    "MAX_CONCURRENT_REQUESTS_CEILING",
    "MIN_CONCURRENT_REQUESTS",
    "POOL_KEEPALIVE_EXPIRY_SECONDS",
    "POOL_MAX_CONNECTIONS",
    "POOL_MAX_KEEPALIVE_CONNECTIONS",
    "READ_TIMEOUT_CEILING_SECONDS",
    "TOOL_SET_FLAG_KEYS",
    "Config",
    "load_config",
    "load_env_file",
    "load_logging",
]

logger = logging.getLogger(__name__)

# The env file the RPM installs, loaded only from this exact path. ``powerpack-mcp`` is a symlink to
# a versioned directory, so a version upgrade installs a fresh file. That is acceptable: every key
# has a default, and there is no credential in the file, so a lost file degrades to defaults rather
# than to a service that will not start.
DEFAULT_ENV_FILE_PATH: Final[str] = "/opt/em7/services/powerpack-mcp/powerpack-mcp.env"

# The standard log line format of ScienceLogic appliance services. Appliance log parsers split on
# ``::`` and ``:::``, so it must stay byte for byte as it is.
LOG_FORMAT: Final[str] = (
    "%(asctime)s::%(levelname)s::%(process)d::%(name)s.%(lineno)d:::%(message)s"
)

# Overriding the env-file location is itself an environment variable, so it cannot come from the env
# file.
ENV_FILE_PATH_VAR: Final[str] = "POWERPACK_MCP_ENV_FILE"

_VALID_LOG_LEVELS: Final[frozenset[str]] = frozenset(
    {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
)


# The read timeout is also the shutdown drain bound, and systemd's default ``TimeoutStopSec`` is
# 90s; 5s of margin absorbs process teardown. Above this, systemd would SIGKILL the process
# mid-drain and cancel in-flight writes.
READ_TIMEOUT_CEILING_SECONDS: Final[float] = 85.0

# Pool sizes are code constants, not configuration keys: there is no correct operator-facing value
# to document.
POOL_MAX_CONNECTIONS: Final[int] = 10
POOL_MAX_KEEPALIVE_CONNECTIONS: Final[int] = 5
POOL_KEEPALIVE_EXPIRY_SECONDS: Final[float] = 30.0


# The validated range for ``MAX_CONCURRENT_REQUESTS``. Code constants rather than configuration,
# because the range is an engineering fact while the value is site policy.
MIN_CONCURRENT_REQUESTS: Final[int] = 1
MAX_CONCURRENT_REQUESTS_CEILING: Final[int] = 64

# ---- Strict boolean parsing for the ENABLE_* tool-set flags and LCE_VERIFY_TLS -----------------
#
# The accepted spellings, and nothing else. ``_check_strict_bool`` refuses anything outside these
# two sets rather than falling back to the default; see its docstring for why.
_TRUE_LITERALS: Final[frozenset[str]] = frozenset({"true", "1", "yes", "on"})
_FALSE_LITERALS: Final[frozenset[str]] = frozenset({"false", "0", "no", "off"})

# The tool-set flag field names, in one place so the validator and the tests cannot drift from each
# other. The ``lce`` tool set has no flag; it is always registered.
TOOL_SET_FLAG_KEYS: Final[tuple[str, ...]] = (
    "ENABLE_SL1_REST_TOOLS",
    "ENABLE_SL1_GRAPHQL_TOOLS",
    "ENABLE_DB_TOOLS",
    "ENABLE_DB_WRITE_TOOLS",
    "ENABLE_OPS_TOOLS",
    "ENABLE_STANDARDS_TOOLS",
)
# Every boolean field, parsed by ``_check_strict_bool``. ``LCE_VERIFY_TLS`` is not a tool-set flag,
# but a lax parser would let a typo decide whether TLS is verified, so it gets the same strict rule.
_STRICT_BOOL_KEYS: Final[tuple[str, ...]] = (*TOOL_SET_FLAG_KEYS, "LCE_VERIFY_TLS")


class Config(BaseModel):
    """The service configuration. Constructed once at startup and immutable thereafter.

    Read the key set from ``Config.model_fields`` rather than from prose; a test asserts the exact
    key set. There is no ``API_V1_PREFIX``: the service exposes MCP only, not a REST API.
    """

    # ``allow_inf_nan`` is off because every comparison with NaN is false, so a ``nan`` timeout
    # would pass each range check below, and ``inf`` would pass the positivity check.
    model_config = {"frozen": True, "allow_inf_nan": False}

    LOG_LEVEL: str = "INFO"
    LISTEN_HOST: str = "127.0.0.1"
    LISTEN_PORT: int = 8000
    LCE_DEFAULT_TARGET_HOST: str = "localhost"
    # ---- The SL1 destination --------------------------------------------------------------------
    #
    # A host, not a base URL. The URL is composed structurally rather than by concatenating the
    # host into a string, and ``is_valid_target_host`` rejects a scheme, so a base URL would need
    # validation logic nothing here could consume safely.
    #
    # Defaults to the appliance-local host because SL1 REST and ``/gql`` are treated as
    # appliance-local. If SL1 ever becomes remote, revisit that assumption and the shared
    # ``LCE_VERIFY_TLS`` below with it.
    SL1_DEFAULT_TARGET_HOST: str = "localhost"
    # There is no credential key. Each request carries the caller's own ``Authorization`` header
    # (see ``credentials``) and a request without one is refused, so every key has a safe default
    # and the service starts with no configuration file at all.
    #
    # The next three keys also govern SL1 traffic, although their names do not say so:
    #
    # * ``LCE_VERIFY_TLS``: ``_build_url`` uses ``https`` to the same appliance-local host for both
    #   backends, so LCE and SL1 present the same self-signed appliance certificate. A separate
    #   ``SL1_VERIFY_TLS`` would describe a distinction that does not exist.
    # * The two timeouts: reusing them keeps one validated mechanism and inherits the 85s ceiling,
    #   which the shutdown drain depends on (see ``mcp_app.concurrency``).
    #
    # So raising ``LCE_READ_TIMEOUT_SECONDS`` to troubleshoot LCE also slows every SL1 call, and
    # disabling ``LCE_VERIFY_TLS`` disables verification for both backends.
    LCE_VERIFY_TLS: bool = True
    LCE_CONNECT_TIMEOUT_SECONDS: float = 2.0
    LCE_READ_TIMEOUT_SECONDS: float = 30.0
    MAX_REQUEST_BODY_BYTES: int = 10485760
    # ---- The outbound body cap -------------------------------------------------------------------
    #
    # ``MAX_REQUEST_BODY_BYTES`` above applies to inbound requests only (``pipeline.py``). Reading
    # an SL1 response reads the whole body into memory against ``MemoryMax=512M``, and a
    # passthrough request, an extended fetch or a caller-authored GraphQL query can return a lot.
    # The default matches the inbound limit.
    #
    # This cap does not cover the LCE client. A reader seeing this key would reasonably assume it
    # covers every outbound call; it does not.
    #
    # No ceiling validator: ``MemoryMax=512M`` is the real bound and systemd enforces it.
    MAX_RESPONSE_BODY_BYTES: int = 10485760
    # Bounds inbound concurrency. Each in-flight maximum-size request costs about 46 MiB of RSS
    # across the transformation passes, and a request queued on the outbound pool already holds
    # its fully parsed payload, because the body and validation guards run before the LCE call. So
    # the ten-slot pool does not protect memory: ``MemoryMax=512M`` was breached at about 8
    # concurrent maximum-size requests. Operator-tunable because appliance memory varies.
    MAX_CONCURRENT_REQUESTS: int = 6
    # ---- Tool-set flags --------------------------------------------------------------------------
    #
    # ``ENABLE_*`` is a new key prefix, so no operator habit guards against a typo in these, which
    # is one reason an unparseable value is fatal rather than defaulted.
    #
    # Every flag defaults to enabled. That is the shipped default, and it is bounded by the service
    # itself shipping disabled: the tools are only reachable once an operator enables the unit.
    #
    # The ``lce`` tool set has no flag and is always registered; there is deliberately no
    # ``ENABLE_LCE_TOOLS``. ``ENABLE_DB_WRITE_TOOLS`` is nested under ``ENABLE_DB_TOOLS``. That
    # nesting is resolved in ``tool_sets``, not here: this model parses values, and the
    # relationship between two values is a decision.
    ENABLE_SL1_REST_TOOLS: bool = True
    ENABLE_SL1_GRAPHQL_TOOLS: bool = True
    ENABLE_DB_TOOLS: bool = True
    ENABLE_DB_WRITE_TOOLS: bool = True
    ENABLE_OPS_TOOLS: bool = True
    ENABLE_STANDARDS_TOOLS: bool = True

    @field_validator(*_STRICT_BOOL_KEYS, mode="before")
    @classmethod
    def _check_strict_bool(cls, value: object) -> bool:
        """Parse a boolean key strictly, failing startup on an unrecognised value.

        Applies to the tool-set flags and ``LCE_VERIFY_TLS``. "Strict" is about the failure mode,
        not about accepting fewer spellings: the eight conventional spellings are accepted, and
        everything else is refused rather than falling back to the default. With every tool-set
        flag defaulting to enabled, a permissive parser would make a typo indistinguishable from a
        deliberate enable, and the set being enabled may include database writes. For
        ``LCE_VERIFY_TLS``, pydantic's permissive parser would accept spellings such as ``t`` and
        ``y`` that nothing documents, so which spellings decide TLS verification would be unclear.

        Runs ``mode="before"`` so the raw string arrives here before pydantic's permissive bool
        coercion. A ``bool`` is passed through; that is the path taken when the key is absent and
        the field default applies.

        :raises ValueError: If the value is not a recognised boolean spelling.
        """
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            candidate = value.strip().lower()
            if candidate in _TRUE_LITERALS:
                return True
            if candidate in _FALSE_LITERALS:
                return False
        raise ValueError(
            f"must be a boolean -- one of {', '.join(sorted(_TRUE_LITERALS))} for enabled or "
            f"{', '.join(sorted(_FALSE_LITERALS))} for disabled (case-insensitive). got {value!r}. "
            "An unrecognised value is refused rather than defaulted, because a typo must not be "
            "indistinguishable from a deliberate setting"
        )

    @field_validator("LOG_LEVEL")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        upper = value.strip().upper()
        if upper not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"must be one of {', '.join(sorted(_VALID_LOG_LEVELS))} (case-insensitive), "
                f"got {value!r}"
            )
        return upper

    @field_validator("LISTEN_HOST")
    @classmethod
    def _check_listen_host_is_loopback(cls, value: str) -> str:
        """Require a loopback listen address.

        The service must never bind a routable interface, so this is a validation rule rather than
        a default an operator could edit. Contrast ``LCE_VERIFY_TLS``, which may be relaxed
        explicitly.

        :raises ValueError: If the value is not ``localhost`` or a loopback IP address.
        """
        candidate = value.strip()
        if candidate.lower() == "localhost":
            return candidate
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            raise ValueError(
                "must be a loopback address -- 127.0.0.0/8, ::1, or the literal 'localhost'. "
                f"got {candidate!r}, which is not an IP address. The service must not "
                "bind a routable interface"
            ) from None
        if not address.is_loopback:
            raise ValueError(
                f"must be a loopback address -- 127.0.0.0/8, ::1, or 'localhost'. {candidate!r} is "
                "routable, and the service must not bind a routable interface"
            )
        return candidate

    @field_validator("LISTEN_PORT")
    @classmethod
    def _check_listen_port(cls, value: int) -> int:
        if not 1024 <= value <= 65535:
            raise ValueError(
                f"must be in the unprivileged range 1024-65535, got {value}. A port below 1024 "
                "would "
                "require CAP_NET_BIND_SERVICE, which the systemd unit deliberately does not grant"
            )
        return value

    @field_validator("LCE_DEFAULT_TARGET_HOST")
    @classmethod
    def _check_default_target_host(cls, value: str) -> str:
        """Validate the LCE host at startup rather than at request time.

        Without this check a malformed host surfaces only at request time, as ``LceUnreachable``,
        so the operator sees "LCE is unreachable" when the truth is "your configuration is
        malformed". There is no per-call override, so a bad value would fail every tool call, and
        the value is written into every log record. The check reuses ``is_valid_target_host``
        rather than adding validation logic.

        :raises ValueError: If the value is not a valid target host.
        """
        # Imported here to break an import cycle: importing ``lce_client.target_host`` runs the
        # ``lce_client`` package ``__init__``, which imports ``client``, which imports this module
        # before ``Config`` is defined.
        from powerpack_mcp.lce_client.target_host import (
            MAX_TARGET_HOST_LENGTH,
            is_valid_target_host,
        )

        candidate = value.strip()
        if not is_valid_target_host(candidate):
            # Name the rule and what would be valid. This is operator-supplied configuration, not
            # caller input, so quoting the value is safe; every other validator here does the same.
            raise ValueError(
                "must be an RFC-1123 hostname or an IPv4 literal, at most "
                f"{MAX_TARGET_HOST_LENGTH} characters, with no scheme, port, path, userinfo or "
                f"trailing dot -- got {candidate!r}. IPv6 literals are not accepted, because the "
                "systemd unit removes AF_INET6 from RestrictAddressFamilies"
            )
        return candidate

    @field_validator("SL1_DEFAULT_TARGET_HOST")
    @classmethod
    def _check_sl1_default_target_host(cls, value: str) -> str:
        """Validate the SL1 host at startup, reusing ``is_valid_target_host``.

        A second host validator would be a second rule to keep in step. Validating at startup
        avoids an invalid value surfacing as "SL1 is unreachable". The function-local import breaks
        the same cycle described in ``_check_default_target_host``.

        :raises ValueError: If the value is not a valid target host.
        """
        from powerpack_mcp.lce_client.target_host import (
            MAX_TARGET_HOST_LENGTH,
            is_valid_target_host,
        )

        candidate = value.strip()
        if not is_valid_target_host(candidate):
            # Operator-supplied configuration, not caller input, so quoting the value is safe.
            raise ValueError(
                "must be an RFC-1123 hostname or an IPv4 literal, at most "
                f"{MAX_TARGET_HOST_LENGTH} characters, with no scheme, port, path, userinfo or "
                f"trailing dot -- got {candidate!r}. A scheme is rejected deliberately: "
                "the URL is composed structurally rather than concatenated, "
                "so this key holds a host and the scheme is supplied by the client. IPv6 literals "
                "are not accepted, because the systemd unit removes AF_INET6 from "
                "RestrictAddressFamilies"
            )
        return candidate

    @field_validator("LCE_CONNECT_TIMEOUT_SECONDS")
    @classmethod
    def _check_connect_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError(f"must be greater than 0, got {value}")
        if value > 60.0:
            raise ValueError(f"must be at most 60 seconds, got {value}")
        return value

    @field_validator("LCE_READ_TIMEOUT_SECONDS")
    @classmethod
    def _check_read_timeout(cls, value: float) -> float:
        if value <= 0:
            raise ValueError(f"must be greater than 0, got {value}")
        if value > READ_TIMEOUT_CEILING_SECONDS:
            raise ValueError(
                f"must be at most {READ_TIMEOUT_CEILING_SECONDS} seconds, got {value}. This "
                "value is "
                "the shutdown drain bound, and systemd's default TimeoutStopSec is "
                "90s -- a "
                "higher value would let systemd SIGKILL the process mid-drain and cancel an "
                "in-flight "
                "write"
            )
        return value

    @field_validator("MAX_REQUEST_BODY_BYTES", "MAX_RESPONSE_BODY_BYTES")
    @classmethod
    def _check_max_body(cls, value: int) -> int:
        """Validate both body caps, inbound and outbound.

        One validator for both because the rule is identical. Pydantic reports which field
        failed, so the message needs no key name.
        """
        if value <= 0:
            raise ValueError(f"must be greater than 0, got {value}")
        return value

    @field_validator("MAX_CONCURRENT_REQUESTS")
    @classmethod
    def _check_max_concurrent_requests(cls, value: int) -> int:
        """Fail startup if the concurrency bound is out of range, rather than clamping it.

        One is meaningful: it serialises tool traffic, a legitimate choice on a memory-constrained
        appliance. The upper bound leaves room for a larger ``MemoryMax``. The two are coupled:
        raising this without raising ``MemoryMax`` lets concurrent requests exceed the memory
        limit again.
        """
        if not MIN_CONCURRENT_REQUESTS <= value <= MAX_CONCURRENT_REQUESTS_CEILING:
            raise ValueError(
                f"must be between {MIN_CONCURRENT_REQUESTS} and "
                f"{MAX_CONCURRENT_REQUESTS_CEILING} inclusive, got {value}"
            )
        return value

    def model_post_init(self, context: object, /) -> None:
        """Require the connect timeout not to exceed the read timeout."""
        del context
        if self.LCE_CONNECT_TIMEOUT_SECONDS > self.LCE_READ_TIMEOUT_SECONDS:
            raise ValueError(
                "LCE_CONNECT_TIMEOUT_SECONDS must not exceed LCE_READ_TIMEOUT_SECONDS "
                f"({self.LCE_CONNECT_TIMEOUT_SECONDS} > {self.LCE_READ_TIMEOUT_SECONDS})"
            )

    @classmethod
    def from_env(cls) -> Config:
        """Read every field from the environment, then validate through pydantic.

        Values reach the model as the raw strings from the environment, so pydantic is the single
        place each one is converted and checked. An absent key takes the field default.

        :return: The validated configuration.
        :raises ConfigurationError: If a value is missing or invalid.
        """
        values: dict[str, object] = {}
        for field, info in cls.model_fields.items():
            raw = os.environ.get(field)
            if raw is not None:
                values[field] = raw
            elif info.is_required():
                raise ConfigurationError(
                    f"{field} is not set and has no default. {_remedy_for(field)}"
                )
        try:
            # ``model_validate`` rather than ``cls(**values)``: the values arrive as
            # ``dict[str, object]``, and unpacking that into typed keyword parameters is not
            # type-checkable.
            return cls.model_validate(values)
        except ValidationError as exc:
            raise ConfigurationError(_format_validation_error(exc)) from exc


def _remedy_for(field: str) -> str:
    """Return the actionable half of a missing-key message."""
    return f"Set {field} in the env file or the service environment"


def _format_validation_error(exc: ValidationError) -> str:
    """Render a pydantic error as an actionable message naming each failing key."""
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"]) or "<config>"
        message = error["msg"].removeprefix("Value error, ")
        parts.append(f"{location} {message}")
    return "Invalid configuration: " + "; ".join(parts)


def _resolve_env_file_path() -> Path:
    return Path(os.environ.get(ENV_FILE_PATH_VAR, DEFAULT_ENV_FILE_PATH))


def _check_env_file_permissions(path: Path) -> None:
    """Refuse to start on a group- or world-accessible, or wrong-owner, env file.

    This enforces the RPM's 0600 file mode at runtime, as ``LISTEN_HOST`` is enforced. Ownership is
    compared against the effective uid rather than a named account, so the check does not depend
    on the service account's name.

    :raises ConfigurationError: If the file mode or owner is wrong.
    """
    info = path.stat()
    if info.st_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
        raise ConfigurationError(
            f"The configuration file {path} is group- or world-accessible (mode "
            f"{stat.S_IMODE(info.st_mode):04o}). It configures this service and must be mode "
            "0600. "
            f"Run: chmod 0600 {path}"
        )
    if info.st_uid != os.geteuid():
        raise ConfigurationError(
            f"The configuration file {path} is not owned by the account running this service "
            f"(file uid {info.st_uid}, process euid {os.geteuid()}). It must be owned by the "
            "service account. "
            f"Run: chown <service-account> {path}"
        )


def load_env_file(path: Path | None = None) -> Path | None:
    """Load the env file into ``os.environ``, or report that there is none.

    Only the exact path is read, and only after its mode and owner are checked; nothing searches
    other directories for a file of the same name, where a planted file could bypass the 0600
    check. Values already in the environment are never overwritten, and ``$`` in a value is taken
    literally rather than expanded, so a secret containing ``$`` survives intact.

    A missing file is not fatal: every key has a default.

    :param path: The env file to load; defaults to ``POWERPACK_MCP_ENV_FILE`` or
        ``DEFAULT_ENV_FILE_PATH``.
    :return: The path loaded, or ``None`` if there was no file.
    :raises ConfigurationError: If the file's mode or owner is wrong, or if it cannot be read or
        is not valid UTF-8.
    """
    target = path if path is not None else _resolve_env_file_path()
    if not target.is_file():
        logger.info(
            "No configuration file at %s; using environment variables and defaults.", target
        )
        return None
    _check_env_file_permissions(target)
    # Without this, a read failure escapes as a non-``ConfigurationError`` and the process exits 1
    # rather than 78, so systemd restarts it in a loop instead of stopping.
    try:
        load_dotenv(target, override=False, interpolate=False, encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigurationError(
            f"The configuration file {target} is not valid UTF-8 (byte {exc.start}). Re-save it "
            "as UTF-8"
        ) from exc
    except OSError as exc:
        raise ConfigurationError(
            f"The configuration file {target} could not be read ({exc.strerror or exc}). Check "
            "that it is a readable regular file owned by the service account"
        ) from exc
    logger.info("Loaded configuration file %s", target)
    return target


def load_config(env_file: Path | None = None) -> Config:
    """Read and validate configuration.

    Called at startup after logging is configured.

    :param env_file: The env file to load; see ``load_env_file``.
    :return: The validated configuration.
    :raises ConfigurationError: If any value is invalid or missing.
    """
    load_env_file(env_file)
    return Config.from_env()


def load_logging(config: Config) -> None:
    """Install ``LOG_FORMAT`` at the configured level.

    A thin shim for the template's entry point. ``mcp_app.configure_logging`` is the real startup
    path and adds the filter chain this function does not. The configuration object is
    deliberately not logged: logging a whole config object is the wrong habit.
    """
    logging.basicConfig(format=LOG_FORMAT, level=config.LOG_LEVEL)

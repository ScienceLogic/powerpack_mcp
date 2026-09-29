"""
Configuration Tests

This module tests ``powerpack_mcp.config``: every validation rule and failure mode, env file
loading and its permission checks, the tool-set flags, and the rule that only the credentials
module reads a secret value.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from pathlib import Path

import pytest

from powerpack_mcp import config as config_module
from powerpack_mcp.config import (
    READ_TIMEOUT_CEILING_SECONDS,
    TOOL_SET_FLAG_KEYS,
    Config,
    load_config,
    load_env_file,
)
from powerpack_mcp.errors import ConfigurationError


def _write_env(path: Path, body: str, mode: int = 0o600) -> Path:
    path.write_text(body)
    path.chmod(mode)
    return path


class TestImportIsSideEffectFree:
    def test_importing_config_does_not_require_a_credential(self) -> None:
        """There is no import-time ``Config`` singleton.

        An import-time load would make importing the module raise when configuration is bad, which
        breaks pytest collection. The module is already imported at the top of this file with no
        credential set by the autouse isolation fixture.
        """
        assert not hasattr(config_module, "config"), (
            "a module-level Config singleton would reintroduce the import-time load"
        )


class TestListenHost:
    """Loopback-only is a prohibition, not a default."""

    @pytest.mark.parametrize("value", ["127.0.0.1", "127.0.0.53", "localhost", "::1"])
    def test_loopback_accepted(self, value: str) -> None:
        assert value == Config(LISTEN_HOST=value).LISTEN_HOST

    @pytest.mark.parametrize("value", ["0.0.0.0", "10.1.2.3", "192.168.1.5", "example.com", ""])
    def test_routable_or_unparseable_rejected(self, value: str) -> None:
        with pytest.raises(ValueError, match="loopback"):
            Config(LISTEN_HOST=value)

    def test_message_names_the_requirement(self) -> None:
        """Name which key was wrong and what would be valid."""
        with pytest.raises(ValueError, match=re.escape("127.0.0.0/8")) as exc:
            Config(LISTEN_HOST="0.0.0.0")
        assert "routable" in str(exc.value)


class TestDefaultTargetHost:
    """The default LCE target host is validated at startup.

    Without a startup check a malformed value surfaces at request time as `LceUnreachable`, which
    reads as "LCE is unreachable" when the configuration is at fault. There is no per-call override,
    so a bad value has no workaround, and the value is written into every log record.
    """

    def test_default_is_localhost_and_is_valid(self) -> None:
        config = Config()
        assert config.LCE_DEFAULT_TARGET_HOST == "localhost"

    @pytest.mark.parametrize(
        "value", ["localhost", "192.0.2.44", "lce-01.example.internal", "LCE-01.Example.COM"]
    )
    def test_hostnames_and_ipv4_accepted(self, value: str) -> None:
        config = Config(LCE_DEFAULT_TARGET_HOST=value)
        assert value == config.LCE_DEFAULT_TARGET_HOST

    @pytest.mark.parametrize(
        "value",
        [
            "http://host",  # scheme
            "host:8080",  # port
            "user:pass@host",  # userinfo
            "host/path",  # path
            "host?q=1",  # query
            "::1",  # IPv6, rejected
            "host.",  # trailing dot
            "has space",
            # An interior control character, which is the case that matters: a trailing one is
            # stripped as surrounding whitespace (see `test_trailing_newline_is_normalised`), while
            # an interior one would be a log-forging and header-injection vector.
            "ho\nst",
            "",
        ],
    )
    def test_malformed_values_fail_startup(self, value: str) -> None:
        with pytest.raises(ValueError, match="RFC-1123"):
            Config(LCE_DEFAULT_TARGET_HOST=value)

    def test_message_names_the_requirement(self) -> None:
        """Name which key was wrong and what would be valid."""
        with pytest.raises(ValueError, match="RFC-1123") as exc:
            Config(LCE_DEFAULT_TARGET_HOST="host:8080")
        message = str(exc.value)
        assert "RFC-1123" in message
        assert "port" in message

    def test_surrounding_whitespace_is_stripped(self) -> None:
        config = Config(LCE_DEFAULT_TARGET_HOST="  host  ")
        assert config.LCE_DEFAULT_TARGET_HOST == "host"

    def test_trailing_newline_is_normalised(self) -> None:
        """A trailing newline is stripped, not rejected, like the other string keys.

        The credential rejects control characters outright because it is sent in an outbound header
        verbatim. Here the stripped value is what is used and validated, so normalising a plausible
        env-file artifact is safe. An interior control character is still rejected.
        """
        config = Config(LCE_DEFAULT_TARGET_HOST="host\n")
        assert config.LCE_DEFAULT_TARGET_HOST == "host"


class TestListenPort:
    @pytest.mark.parametrize("value", [1024, 8000, 65535])
    def test_unprivileged_accepted(self, value: int) -> None:
        assert value == Config(LISTEN_PORT=value).LISTEN_PORT

    @pytest.mark.parametrize("value", [0, 80, 443, 1023, 65536, -1])
    def test_outside_unprivileged_range_rejected(self, value: int) -> None:
        with pytest.raises(ValueError, match="1024-65535"):
            Config(LISTEN_PORT=value)


class TestTimeouts:
    def test_defaults_are_the_designed_values(self, config: Config) -> None:
        """Other modules rely on these values, so they must not drift."""
        assert config.LCE_CONNECT_TIMEOUT_SECONDS == 2.0
        assert config.LCE_READ_TIMEOUT_SECONDS == 30.0

    def test_read_timeout_ceiling_is_enforced(self) -> None:
        """Above 85 s systemd would SIGKILL the service mid-drain, defeating graceful shutdown."""
        with pytest.raises(ValueError, match=re.escape("85.0")):
            Config(LCE_READ_TIMEOUT_SECONDS=85.5)

    def test_read_timeout_at_the_ceiling_accepted(self) -> None:
        cfg = Config(
            LCE_READ_TIMEOUT_SECONDS=READ_TIMEOUT_CEILING_SECONDS,
        )
        assert cfg.LCE_READ_TIMEOUT_SECONDS == READ_TIMEOUT_CEILING_SECONDS

    def test_ceiling_message_explains_why(self) -> None:
        with pytest.raises(ValueError, match="TimeoutStopSec"):
            Config(LCE_READ_TIMEOUT_SECONDS=300.0)

    @pytest.mark.parametrize("value", [0.0, -1.0])
    def test_non_positive_rejected(self, value: float) -> None:
        with pytest.raises(ValueError, match="greater than 0"):
            Config(LCE_READ_TIMEOUT_SECONDS=value)

    @pytest.mark.parametrize("key", ["LCE_CONNECT_TIMEOUT_SECONDS", "LCE_READ_TIMEOUT_SECONDS"])
    @pytest.mark.parametrize("raw", ["nan", "NaN", "inf", "-inf", "infinity"])
    def test_non_finite_values_refuse_to_start(
        self, monkeypatch: pytest.MonkeyPatch, key: str, raw: str
    ) -> None:
        """Every comparison with NaN is false, so ``nan`` would pass each range check."""
        monkeypatch.setenv(key, raw)
        with pytest.raises(ConfigurationError, match=f"{key} .*finite"):
            load_config()

    def test_connect_may_not_exceed_read(self) -> None:
        with pytest.raises(ValueError, match="must not exceed"):
            Config(
                LCE_CONNECT_TIMEOUT_SECONDS=40.0,
                LCE_READ_TIMEOUT_SECONDS=10.0,
            )


class TestLogLevel:
    @pytest.mark.parametrize(("given", "expected"), [("debug", "DEBUG"), ("Info", "INFO")])
    def test_case_insensitive(self, given: str, expected: str) -> None:
        assert expected == Config(LOG_LEVEL=given).LOG_LEVEL

    def test_unknown_level_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRITICAL, DEBUG"):
            Config(LOG_LEVEL="LOUD")


class TestStartsWithoutACredential:
    """Startup succeeds with no credential available anywhere; the credential is per request."""

    def test_load_config_succeeds_with_no_credential_in_the_environment(self) -> None:
        """The autouse fixture strips every LCE_* variable and points the env file at a missing
        path, so this runs with nothing available.
        """
        config = load_config()
        assert config.LCE_DEFAULT_TARGET_HOST == "localhost"
        assert not hasattr(config, "LCE_CREDENTIAL")


class TestEnvFileLoading:
    """Env file loading: no ancestor search, and strict mode and owner checks."""

    def test_ancestor_directory_search_never_runs(self, tmp_path: Path) -> None:
        """A missing file must not fall back to a same-named file in an ancestor directory.

        A planted file there would bypass the 0600 check.
        """
        planted = _write_env(tmp_path / "powerpack-mcp.env", 'LCE_CREDENTIAL="Bearer PLANTED"\n')
        assert planted.is_file()
        nested = tmp_path / "a" / "b" / "c"
        nested.mkdir(parents=True)

        loaded = load_env_file(nested / "powerpack-mcp.env")

        assert loaded is None, "a missing file must not fall back to an ancestor"
        assert "LCE_CREDENTIAL" not in os.environ, (
            "the planted ancestor file was read -- the upward search escaped"
        )

    def test_missing_file_is_not_fatal(self, tmp_path: Path) -> None:
        """A missing file is logged at INFO and startup continues."""
        assert load_env_file(tmp_path / "nothing-here.env") is None

    def test_missing_file_logs_at_info(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.INFO, logger="powerpack_mcp.config"):
            load_env_file(tmp_path / "nothing-here.env")
        assert any(r.levelno == logging.INFO for r in caplog.records)

    def test_present_file_is_loaded_and_logged(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        env = _write_env(tmp_path / "powerpack-mcp.env", 'LCE_CREDENTIAL="Bearer FROM-FILE"\n')
        with caplog.at_level(logging.INFO, logger="powerpack_mcp.config"):
            loaded = load_env_file(env)
        assert loaded == env
        assert os.environ["LCE_CREDENTIAL"] == "Bearer FROM-FILE"
        assert str(env) in caplog.text

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666])
    def test_group_or_world_accessible_file_fails_startup(self, tmp_path: Path, mode: int) -> None:
        """The packaging installs the file as 0600; this enforces that at runtime too."""
        env = _write_env(tmp_path / "powerpack-mcp.env", "LOG_LEVEL=INFO\n", mode=mode)
        with pytest.raises(ConfigurationError, match="must be mode 0600"):
            load_env_file(env)

    def test_mode_0600_owned_by_the_effective_uid_succeeds(self, tmp_path: Path) -> None:
        """Uses `os.geteuid()`, so the service account name is not needed."""
        env = _write_env(tmp_path / "powerpack-mcp.env", "LOG_LEVEL=WARNING\n", mode=0o600)
        assert env.stat().st_uid == os.geteuid()
        assert load_env_file(env) == env

    def test_environment_variables_win_over_the_env_file(self, tmp_path: Path) -> None:
        """The env file fills gaps and never overwrites a value already in the environment."""
        os.environ["LCE_CREDENTIAL"] = "Bearer FROM-ENVIRONMENT"
        env = _write_env(tmp_path / "powerpack-mcp.env", 'LCE_CREDENTIAL="Bearer FROM-FILE"\n')
        load_env_file(env)
        assert os.environ["LCE_CREDENTIAL"] == "Bearer FROM-ENVIRONMENT"

    def test_unquoted_value_keeps_its_spaces(self, tmp_path: Path) -> None:
        """An unquoted value is read as written, not tokenised."""
        env = _write_env(tmp_path / "powerpack-mcp.env", "LCE_CREDENTIAL=Bearer spaced\n")
        load_env_file(env)
        assert os.environ["LCE_CREDENTIAL"] == "Bearer spaced"

    def test_dollar_signs_are_not_expanded(self, tmp_path: Path) -> None:
        """A secret containing ``$`` must survive intact, so ``${VAR}`` is never interpolated."""
        os.environ["POWERPACK_MCP_TEST_EXPANSION"] = "EXPANDED"
        try:
            env = _write_env(
                tmp_path / "powerpack-mcp.env",
                "LCE_CREDENTIAL=pa$$word${POWERPACK_MCP_TEST_EXPANSION}\n",
            )
            load_env_file(env)
            assert os.environ["LCE_CREDENTIAL"] == "pa$$word${POWERPACK_MCP_TEST_EXPANSION}"
        finally:
            del os.environ["POWERPACK_MCP_TEST_EXPANSION"]

    def test_comments_quotes_and_blank_lines_are_handled(self, tmp_path: Path) -> None:
        env = _write_env(
            tmp_path / "powerpack-mcp.env",
            "# a comment\n\nLOG_LEVEL=\"DEBUG\"\nLCE_CREDENTIAL='Bearer quoted'\n",
        )
        load_env_file(env)
        assert os.environ["LOG_LEVEL"] == "DEBUG"
        assert os.environ["LCE_CREDENTIAL"] == "Bearer quoted"

    def test_a_non_utf8_file_is_a_configuration_error(self, tmp_path: Path) -> None:
        """A decode failure must exit 78 like any other configuration error, not crash-loop."""
        env = tmp_path / "powerpack-mcp.env"
        env.write_bytes(b"LISTEN_HOST=caf\xe9\n")
        env.chmod(0o600)
        assert env.stat().st_uid == os.geteuid()
        with pytest.raises(ConfigurationError, match="UTF-8") as caught:
            load_env_file(env)
        assert str(env) in str(caught.value)
        assert isinstance(caught.value.__cause__, UnicodeDecodeError)

    def test_an_unreadable_file_is_a_configuration_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`load_dotenv` is patched because a test run as root could read a mode-0000 file."""
        env = _write_env(tmp_path / "powerpack-mcp.env", "LOG_LEVEL=INFO\n")

        def _refuse(*_args: object, **_kwargs: object) -> bool:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr(config_module, "load_dotenv", _refuse)
        with pytest.raises(ConfigurationError, match="could not be read") as caught:
            load_env_file(env)
        assert str(env) in str(caught.value)
        assert isinstance(caught.value.__cause__, PermissionError)


class TestLoadConfig:
    def test_spaced_credential_does_not_warn(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("LCE_CREDENTIAL", "Bearer token")
        with caplog.at_level(logging.WARNING, logger="powerpack_mcp.config"):
            load_config()
        assert "contains no space" not in caplog.text

    def test_invalid_value_raises_configuration_error_not_validation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An invalid explicit value fails; no default is substituted for it."""
        monkeypatch.setenv("LCE_CREDENTIAL", "Bearer x")
        monkeypatch.setenv("LISTEN_HOST", "0.0.0.0")
        with pytest.raises(ConfigurationError, match="LISTEN_HOST"):
            load_config()


class TestSecretIsolationInvariant:
    def test_no_module_outside_config_calls_get_secret_value(self) -> None:
        """Walks the shipped source, so the invariant is checked rather than left to review."""
        src = Path(config_module.__file__).parent
        offenders: list[str] = []
        for path in src.rglob("*.py"):
            if path.name == "credentials.py":
                continue
            if "get_secret_value" in path.read_text():
                offenders.append(str(path.relative_to(src)))
        assert not offenders, f"get_secret_value() called outside credentials: {offenders}"


class TestPoolConstantsAreNotConfigurable:
    def test_pool_sizes_are_not_configuration_keys(self) -> None:
        """Pool sizes are code constants; there is no correct operator-facing value for them."""
        assert not any("POOL" in field for field in Config.model_fields)


class TestConfigSurface:
    def test_exactly_the_seventeen_designed_keys(self) -> None:
        """The count is pinned so an unintended extra key is visible in review.

        The ``ENABLE_*`` flags use a key prefix no other key uses, which is one reason an
        unparseable value is refused instead of defaulted. There is deliberately no
        ``ENABLE_LCE_TOOLS``: the LCE set has no flag and is always registered. SL1 reuses the LCE
        TLS and timeout keys rather than adding its own. Rename the test with its assertion if the
        count changes.
        """
        assert set(Config.model_fields) == {
            "LOG_LEVEL",
            "LISTEN_HOST",
            "LISTEN_PORT",
            "LCE_DEFAULT_TARGET_HOST",
            "SL1_DEFAULT_TARGET_HOST",
            "LCE_VERIFY_TLS",
            "LCE_CONNECT_TIMEOUT_SECONDS",
            "LCE_READ_TIMEOUT_SECONDS",
            "MAX_REQUEST_BODY_BYTES",
            "MAX_RESPONSE_BODY_BYTES",
            "MAX_CONCURRENT_REQUESTS",
            *TOOL_SET_FLAG_KEYS,
        }
        assert len(Config.model_fields) == 17

    def test_every_key_has_a_default(self) -> None:
        """No key is required, so the service starts with no configuration file at all.

        Failing closed is still guaranteed: any request without a credential is refused, per call
        rather than once at boot.
        """
        required = {name for name, f in Config.model_fields.items() if f.is_required()}
        assert required == set()

    def test_tls_verification_defaults_on(self, config: Config) -> None:
        """Settable, unlike LISTEN_HOST: TLS verification may be relaxed explicitly."""
        assert config.LCE_VERIFY_TLS is True

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [("false", False), ("0", False), ("no", False), ("off", False), ("true", True)],
    )
    def test_tls_verification_parses_common_spellings(
        self, monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
    ) -> None:
        monkeypatch.setenv("LCE_VERIFY_TLS", raw)
        assert load_config().LCE_VERIFY_TLS is expected

    @pytest.mark.parametrize("raw", ["ture", "flase", "disabled", "t", "y", "f", "n"])
    def test_a_misspelt_tls_setting_is_refused(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        """A typo must stop startup rather than silently turn TLS verification off.

        ``t`` and ``y`` are accepted by pydantic's permissive bool parser but not by the strict
        one the tool-set flags use, which this key shares.
        """
        monkeypatch.setenv("LCE_VERIFY_TLS", raw)
        with pytest.raises(ConfigurationError, match="LCE_VERIFY_TLS"):
            load_config()

    def test_config_is_immutable(self, config: Config) -> None:
        """Constructed once, immutable for the process lifetime."""
        with pytest.raises(ValueError, match=r"frozen|immutable"):
            config.LISTEN_PORT = 9999  # type: ignore[misc]


def test_env_file_default_path_is_the_service_root() -> None:
    """The env file lives in the service root, not a nested ``etc/``.

    A release bump preserves the file; a version bump does not, so the operator must re-supply its
    values.
    """
    assert (
        config_module.DEFAULT_ENV_FILE_PATH == "/opt/em7/services/powerpack-mcp/powerpack-mcp.env"
    )


def test_load_logging_does_not_log_the_config_object(
    config: Config, caplog: pytest.LogCaptureFixture
) -> None:
    """Logging ``str(config)`` would log the whole configuration object, secrets included."""
    with caplog.at_level(logging.DEBUG):
        config_module.load_logging(config)
    assert "test-token" not in caplog.text


def test_owner_check_rejects_a_file_owned_by_another_uid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`geteuid` is patched because a test cannot chown to another user."""
    env = _write_env(tmp_path / "powerpack-mcp.env", "LOG_LEVEL=INFO\n", mode=0o600)
    monkeypatch.setattr(config_module.os, "geteuid", lambda: env.stat().st_uid + 1)
    with pytest.raises(ConfigurationError, match="not owned by"):
        load_env_file(env)


def test_permission_check_reports_the_actual_mode(tmp_path: Path) -> None:
    env = _write_env(tmp_path / "powerpack-mcp.env", "LOG_LEVEL=INFO\n", mode=0o644)
    with pytest.raises(ConfigurationError) as exc:
        load_env_file(env)
    assert f"{stat.S_IMODE(env.stat().st_mode):04o}" in str(exc.value)


class TestToolSetFlags:
    """The six ``ENABLE_*`` tool-set keys."""

    def test_all_six_keys_exist_and_default_to_enabled(self) -> None:
        """Enabled is the shipped default, not a development posture."""
        config = Config()
        assert len(TOOL_SET_FLAG_KEYS) == 6
        for key in TOOL_SET_FLAG_KEYS:
            assert getattr(config, key) is True, key

    def test_there_is_no_flag_for_the_lce_set(self) -> None:
        """The LCE tools are always registered and have no key.

        Adding ``ENABLE_LCE_TOOLS`` looks like a symmetry improvement but contradicts that.
        """
        assert not hasattr(Config(), "ENABLE_LCE_TOOLS")
        assert all("LCE_TOOLS" not in key for key in TOOL_SET_FLAG_KEYS)

    @pytest.mark.parametrize("key", TOOL_SET_FLAG_KEYS)
    @pytest.mark.parametrize("raw", ["false", "FALSE", "False", "0", "no", "off", "  off  "])
    def test_every_false_spelling_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, key: str, raw: str
    ) -> None:
        monkeypatch.setenv(key, raw)
        assert getattr(load_config(), key) is False

    @pytest.mark.parametrize("key", TOOL_SET_FLAG_KEYS)
    @pytest.mark.parametrize("raw", ["true", "TRUE", "1", "yes", "on"])
    def test_every_true_spelling_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, key: str, raw: str
    ) -> None:
        monkeypatch.setenv(key, raw)
        assert getattr(load_config(), key) is True

    @pytest.mark.parametrize("key", TOOL_SET_FLAG_KEYS)
    @pytest.mark.parametrize("raw", ["maybe", "", "2", "trueish", "disabled", "null", "-1"])
    def test_an_unparseable_value_refuses_to_start_and_names_the_key(
        self, monkeypatch: pytest.MonkeyPatch, key: str, raw: str
    ) -> None:
        """With sets on by default, a permissive parser would make a typo look like an enable.

        The set being enabled may include ``master.*`` writes, so the value is refused rather than
        defaulted.
        """
        monkeypatch.setenv(key, raw)
        with pytest.raises(ConfigurationError) as caught:
            load_config()
        assert key in str(caught.value)

    def test_an_unparseable_flag_is_refused(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unrecognised value must be refused, never silently read as a default."""
        monkeypatch.setenv("ENABLE_OPS_TOOLS", "definitely-not-a-bool")
        with pytest.raises(ConfigurationError):
            load_config()

    def test_flags_are_independent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Turning one set off must not disturb another.

        The nesting rule lives in `tool_sets`; this model parses values and does not relate them.
        """
        monkeypatch.setenv("ENABLE_DB_TOOLS", "false")
        config = load_config()
        assert config.ENABLE_DB_TOOLS is False
        assert config.ENABLE_SL1_REST_TOOLS is True
        # `config` records the raw value; `tool_sets.resolve` applies the nesting rule.
        assert config.ENABLE_DB_WRITE_TOOLS is True


class TestSl1DefaultTargetHost:
    """The default SL1 target host, validated like the LCE one."""

    def test_defaults_to_the_appliance_local_value(self, config: Config) -> None:
        """SL1 REST is appliance-local, so the default is."""
        assert config.SL1_DEFAULT_TARGET_HOST == "localhost"

    def test_it_is_a_separate_key_from_the_lce_host(self) -> None:
        """Sharing one key would let a future LCE change silently redirect SL1 traffic."""
        assert "SL1_DEFAULT_TARGET_HOST" in Config.model_fields
        assert "LCE_DEFAULT_TARGET_HOST" in Config.model_fields

    @pytest.mark.parametrize(
        "value",
        [
            "https://sl1.example.com",  # a scheme
            "http://localhost",
            "localhost:443",  # a port
            "localhost/gql",  # a path
            "user@localhost",  # userinfo
            "localhost.",  # trailing dot
            "::1",  # IPv6: RestrictAddressFamilies removes AF_INET6
            "not a host",
            "",
        ],
    )
    def test_rejects_anything_that_is_not_a_bare_host(self, value: str) -> None:
        """The scheme cases matter most: the URL is composed structurally, so a scheme is refused.

        This is why the key is a host, not a base URL.
        """
        with pytest.raises(ValueError, match=r"RFC-1123|hostname"):
            Config(SL1_DEFAULT_TARGET_HOST=value)

    def test_the_error_explains_why_a_scheme_is_refused(self) -> None:
        """A bare "invalid hostname" would not tell an operator the scheme was the problem."""
        with pytest.raises(ValueError, match="composed structurally"):
            Config(SL1_DEFAULT_TARGET_HOST="https://localhost")

    def test_accepts_a_hostname_and_an_ipv4_literal(self) -> None:
        assert Config(SL1_DEFAULT_TARGET_HOST="sl1.example.com").SL1_DEFAULT_TARGET_HOST == (
            "sl1.example.com"
        )
        assert Config(SL1_DEFAULT_TARGET_HOST="127.0.0.1").SL1_DEFAULT_TARGET_HOST == "127.0.0.1"


class TestMaxResponseBodyBytes:
    """The cap on SL1 response bodies."""

    def test_defaults_symmetric_with_the_inbound_limit(self, config: Config) -> None:
        """The inbound limit already states a reasonable body size for this service."""
        assert config.MAX_RESPONSE_BODY_BYTES == 10485760
        assert config.MAX_RESPONSE_BODY_BYTES == config.MAX_REQUEST_BODY_BYTES

    @pytest.mark.parametrize("value", [0, -1])
    def test_rejects_a_non_positive_cap(self, value: int) -> None:
        with pytest.raises(ValueError, match="greater than 0"):
            Config(MAX_RESPONSE_BODY_BYTES=value)


class TestSharedLceKeysGovernSl1Too:
    """Three ``LCE_*`` keys deliberately govern both backends.

    The key names misdescribe their scope, so these assertions record that the absence of
    ``SL1_*`` equivalents is deliberate.
    """

    def test_there_is_no_separate_sl1_tls_flag(self) -> None:
        """Both backends are the same host presenting the same certificate."""
        assert "SL1_VERIFY_TLS" not in Config.model_fields

    def test_there_are_no_separate_sl1_timeout_keys(self) -> None:
        """SL1 calls reuse the LCE timeouts."""
        assert "SL1_CONNECT_TIMEOUT_SECONDS" not in Config.model_fields
        assert "SL1_READ_TIMEOUT_SECONDS" not in Config.model_fields

    def test_the_shared_read_timeout_still_carries_the_ceiling(self) -> None:
        """Reuse means the 85 s ceiling applies to SL1 by construction.

        Separate SL1 timeout fields would need the ceiling re-asserted, and a missing validator
        would silently break the shutdown budget that the request deadline depends on.
        """
        with pytest.raises(ValueError, match=re.escape("at most 85.0")):
            Config(LCE_READ_TIMEOUT_SECONDS=READ_TIMEOUT_CEILING_SECONDS + 0.1)

# powerpack-mcp

An MCP Server for PowerPack development.

A remote **streamable-HTTP** FastMCP server for Skylar One. It runs as a systemd unit on a loopback
listener and is reverse-proxied by nginx at `/mcp`, which enforces the existing Skylar One
authentication scheme before proxying and **fails closed**.

It reaches Skylar One over **four** backends: the **LCE** Dynamic Application API, SL1's **REST** API,
SL1's **GraphQL** API, and the appliance's **MariaDB** via the platform's own connection. Which of
those a given tool uses is a property of that tool, not of the caller.


## Status

**Implemented and shipping.** The RPM, systemd unit and nginx fragments are installable, and the
service has run on appliance hardware.

**55 tools register** when a database is available, **47 without**: a missing platform database
driver, `libem7` or `silo.conf` disables the DB-backed sets **with a stated reason** rather than
failing to start.

| Route | Exposure |
|---|---|
| `/mcp` | The MCP transport mount. Behind perimeter authentication, which fails closed |
| `/health` | **Public.** Process liveness only — never contacts a backend, discloses no version |

> There is no `/ready` route. With no service-held credential there is nothing for a readiness probe
> to authenticate *with*. Backend reachability surfaces as an error on a real tool call instead of as
> a probe.

## Authentication

**The service holds no credential of its own.** Each caller presents their own Skylar One credential
in the `Authorization` header, which the service forwards, so the backend applies **that caller's**
permissions. A request arriving without one is refused per-request with `credential_missing` — never
at startup.

Two schemes work, and the distinction matters:

| Scheme | Works? | Notes |
|---|---|---|
| `Authorization: Basic <base64>` | Yes | A Skylar One user's own username and password |
| `Authorization: Bearer <api-key>` | Yes | An **SL1 API key**, which is a JWT. Suited to automation |
| `X-API-Key: <api-key>` | No | The platform authenticator is handed this header and **ignores it**, so a valid key 401s exactly like a bogus one |

An SL1 API key **is an account** (`auth_method = 6`), so it carries its own entitlements rather than
its owner's — which is the point: mint it narrowly. See `docs/client-setup.md`.

## Authorization

Perimeter authentication proves the caller is *some* authenticated Skylar One principal. It does not
say what they may do. Two mechanisms cover that:

**For the LCE, REST and GraphQL tools — the backend decides.** Their calls travel with the caller's
own credential, so LCE returns `403 Forbidden (insufficient access hooks)` and SL1 returns
`RESTRICTED_ACCESS` for a caller who is not entitled. Nothing here needs to duplicate that.

**For the DB-backed tools — this service decides**, because MariaDB sees one platform account for
every caller and so cannot tell them apart. A per-caller **access-hook gate** resolves the caller's
granted hooks from `GET /api/account/_self/access_hooks` using their own credential, caches them for
60 s per principal, and permits a call only if the tool's required `hook_id` set is present. It is
**deny-by-default**: an unmapped tool, an absent hook, an unresolvable caller or a failed lookup all
refuse, and a refusal names the **required** hook without disclosing what the caller does hold.

`sl1_fetch_collection_output` additionally requires that the collection job **belongs to the caller**.

## Configuration

All configuration is read from environment variables and validated by a pydantic model.
Precedence, highest first:

1. Environment variables
2. The env file — `/opt/em7/services/powerpack-mcp/powerpack-mcp.env`, mode `0600`
3. The field default

The env file is read **only** from that exact path. Set `POWERPACK_MCP_ENV_FILE` to override it. **A
missing file is not an error, and there are no required keys** — every setting below has a safe
default, so the service starts with no configuration file at all.

**There is no credential key.** There is no `LCE_CREDENTIAL` or `LCE_CREDENTIAL_HEADER`: the
outbound header name is fixed at `Authorization`, and the credential arrives per request.

### Service

| Key | Default | Notes |
|---|---|---|
| `LOG_LEVEL` | `INFO` | |
| `LISTEN_HOST` | `127.0.0.1` | **Loopback only.** A routable value refuses to start |
| `LISTEN_PORT` | `8000` | 1024–65535 |
| `MAX_CONCURRENT_REQUESTS` | `6` | 1–64. **Coupled to the unit's `MemoryMax`** — raising one without the other risks an OOM kill under load |

### Backends

| Key | Default | Notes |
|---|---|---|
| `LCE_DEFAULT_TARGET_HOST` | `localhost` | Hostname or IPv4 literal. No port, scheme or path. Server-side only — **not a tool parameter** |
| `SL1_DEFAULT_TARGET_HOST` | `localhost` | Same rules. No per-call override |
| `LCE_VERIFY_TLS` | `true` | Governs **both** LCE and SL1 — same host, same certificate. Disabling logs a WARNING on **every affected request** |
| `LCE_CONNECT_TIMEOUT_SECONDS` | `2.0` | |
| `LCE_READ_TIMEOUT_SECONDS` | `30.0` | Capped at `85.0`; also the shutdown drain bound |
| `MAX_REQUEST_BODY_BYTES` | `10485760` | 10 MiB inbound |
| `MAX_RESPONSE_BODY_BYTES` | `10485760` | 10 MiB outbound, streamed and aborted at the cap |

### Tool sets — the operator's surface controls

Each flag switches a whole set off at **registration**, so a disabled tool does not exist rather than
failing when called. **All default `true`**, and an unparseable value **fails startup** naming the key
— a typo must not be indistinguishable from a deliberate enable.

| Key | Default | Set |
|---|---|---|
| `ENABLE_SL1_REST_TOOLS` | `true` | SL1 REST |
| `ENABLE_SL1_GRAPHQL_TOOLS` | `true` | SL1 GraphQL |
| `ENABLE_DB_TOOLS` | `true` | DB reads. **Also the parent of the write flag** |
| `ENABLE_DB_WRITE_TOOLS` | `true` | DB writes, including `master.*`. Nested under `ENABLE_DB_TOOLS` |
| `ENABLE_OPS_TOOLS` | `true` | Health, capability and discovery |
| `ENABLE_STANDARDS_TOOLS` | `true` | Content standards |

> **The seven LCE tools have no flag and are always registered.** That is deliberate, not an
> omission.

> **Quote any value containing ` #`.** In an unquoted value a space followed by `#` starts a
> comment, so `LOG_LEVEL=INFO # verbose` is read as `INFO`.

The service refuses to start on any **invalid** value, naming the key and what would be valid. It
never starts in a degraded mode. Note the distinction: an invalid value is fatal, a *missing* one is
not.

> On an appliance with the stock self-signed certificate you will need `LCE_VERIFY_TLS=false`, or
> every tool call fails with `lce_unreachable`. With a real CA-issued certificate leave it at the
> default. See `docs/operations.md` §2.

## Response shaping — empty fields

**Both tool surfaces drop empty fields, and they use the same rule.** SL1 itself returns empty
values such as `"supportedVersions": ""`; the SL1 tools drop them just as the LCE tools do.

**Dropped:** `null`, the empty string `""`, the empty array `[]`, the empty object `{}`. Removal is
recursive and bottom-up, so a container left empty by the removal of its members is dropped too.

**Kept — and this is the part that matters:**

| value | kept | why |
|---|---|---|
| `0`, `0.0` | Yes | A number. `numeric_range_low: 0` is real threshold data |
| `false` | Yes | The *opposite* of absent, not a synonym for it |
| `"   "` | Yes | Judging whitespace empty is a judgement about *content*, and some fields legitimately hold it |

A truthiness check would drop all three, which is why the rule is written as an explicit test in
one place (`shaping.drop_empty`) and reused everywhere rather than reimplemented.

**Turning it off.** The two passthrough tools — `sl1_rest_request` and `sl1_graphql` — take
`prune: bool = True`. Set it `false` to see the literal shape, where an empty value and an absent
one are distinguishable. The typed tools always prune; use a passthrough when you need the raw
document.

**Not pruned:** payloads this service *constructs* rather than relays — a collection's `lines`, a
`server_health` verdict, an audit record. There an empty value is a measurement, not noise.

## Running locally

`main()` starts a real server. **No credential is needed to start it** — callers supply their own per
request:

```bash
uv sync
uv run powerpack_mcp
```

The default test suite needs **no appliance, no credential and no network**:

```bash
uv run pytest                              # unit + property tests
HYPOTHESIS_PROFILE=ci uv run pytest        # 500 examples per property instead of 50
```


## Building the RPM

The RPM installs into `/opt/em7` and hooks into the appliance's nginx, so it is only useful on a
Skylar One appliance. It is built on Oracle Linux 8, the appliance's OS family, and the version comes
from the latest `v*` git tag through setuptools-scm, so build from a clone with its tags.
`--platform linux/amd64` matters on Apple silicon: appliances are x86_64.

```bash
docker run --rm --platform linux/amd64 -v "$PWD:/src" -w /src oraclelinux:8 bash -c '
  set -euo pipefail
  dnf -y install rpm-build systemd-rpm-macros python3.12 git tar gzip findutils which >/dev/null
  curl -LsSf https://astral.sh/uv/install.sh | sh && export PATH="$HOME/.local/bin:$PATH"
  git config --global --add safe.directory /src
  mkdir -p /opt/em7/bin && ln -sf /usr/bin/python3.12 /opt/em7/bin/python3.12
  rm -rf dist && uv build --sdist
  SDIST=$(ls dist/*.tar.gz); VER=$(basename "$SDIST" .tar.gz); VER=${VER#powerpack_mcp-}
  TOP=/root/rpmbuild; mkdir -p "$TOP/SPECS" "$TOP/SOURCES"
  cp "$SDIST" "$TOP/SOURCES/"; cp packaging/rpm/powerpack-mcp.spec "$TOP/SPECS/"
  rpmbuild -bb --define "_topdir $TOP" --define "service_build_version ${VER//-/.}" \
    "$TOP/SPECS/powerpack-mcp.spec"
  mkdir -p /src/rpmbuild && cp -r "$TOP/RPMS" /src/rpmbuild/'
```

The build runs inside the container's own filesystem, because a bind-mounted build directory can
break rpmbuild (on macOS every file appears executable). Only the finished RPM is copied back, to
`rpmbuild/RPMS/x86_64/`. Installing and upgrading it is covered in
[docs/operations.md](docs/operations.md).


## Development

### Host workflow (`uv`)

Install uv: https://docs.astral.sh/uv/getting-started/installation

```bash
uv lock
uv sync --dev
uv run powerpack_mcp
```

### Docker Compose workflow

Docker is used for **tests only** — it is not a deployment path for this service.

```bash
make dev-up
make dev-shell
make dev-test
```

## Linting & Testing

```bash
make lint        # ruff format --check, ruff check, mypy, pyright
make typecheck   # mypy, pyright
make test        # pytest
make prek        # run every check via prek (ruff, mypy, pyright, pytest)
```

To format and auto-fix linting issues, you can run:

```bash
uv run ruff check --fix
uv run ruff format
```

Or, in docker:
```bash
make dev-exec CMD='uv run ruff check --fix'
make dev-exec CMD='uv run ruff format'
```

### Pre-commit hooks (prek)

This project ships a [prek](https://prek.j178.dev) config (`prek.toml`). Install the git hooks
once so ruff autofix and formatting run automatically on every commit:

```bash
uv run prek install
```

The heavier checks (ruff, mypy, pyright, pytest) run in the `manual` stage -- the same set CI runs
and what `make prek` invokes:

```bash
uv run prek --all-files --stage=manual
```

> **`pyright` needs the venv interpreter.** A bare `pyright` run here reports import errors for
> `pytest` and similar — an environment artifact, not a real failure. `make lint` and CI pass the
> right interpreter; if you invoke it directly, use
> `uv run pyright --pythonpath .venv/bin/python src tests`.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

# PowerPack MCP Server — Operator Guide

The MCP server exposes the Skylar One LCE Dynamic Application API as MCP tools, over streamable
HTTP at **`/mcp`**.

This document is the operator-facing surface of the package. There is no UI.

---

## 1. Install, then enable. There is no credential step.

**The package is installed disabled and stopped.** Installation deliberately neither starts nor
enables the service; those are separate operator decisions.

```bash
# 1. Install.  A file, not a repository name -- see the note below.
sudo rpm -i -vh /tmp/powerpack-mcp-1.0-<version>-1.el8.x86_64.rpm

# 2. Enable and start.  That is all.
systemctl enable --now powerpack-mcp
systemctl status powerpack-mcp
```

> **Install from the RPM file.** No repository serves this package, so `dnf install
> powerpack-mcp-1.0` cannot succeed. Use `rpm -i` on a fresh appliance and `rpm -U` for an upgrade.
>
> **`rpm` exits 0 even when a scriptlet fails**, so read the output rather than the exit status. The
> failure it produces is *"installed successfully, `/mcp` never works"*.
>
> **The package name is `powerpack-mcp-1.0`.** `rpm -q powerpack-mcp`, without the `-1.0`, reports
> *"not installed"* on an appliance where it **is** installed, which reads exactly like a missing
> deployment.

There is no configured credential and no `LCE_CREDENTIAL` key. The service starts successfully with
no configuration file at all.

### How authentication works

**Each user authenticates as themselves.** Every MCP request must carry that user's own Skylar One
credential in the `Authorization` header; the service forwards it verbatim to `/lce`, so **LCE applies
that user's own permissions**. There is no shared service account, so an authenticated caller cannot
invoke tools, including the writes, beyond what their own account allows.

A request with no usable credential is refused before any LCE call, with `credential_missing`. There is
no fallback and no service account to fall back to.

Configure your MCP client with a Basic header, for example:

```
Authorization: Basic <base64 of user:password>
```

`Basic` is the scheme verified against LCE 3.1.0. The service is scheme-agnostic and forwards whatever
you send.

> **An SL1 API key works, presented as `Bearer`.** An opaque bearer token is rejected, because the
> platform has no authorization server (all seven OAuth/OIDC discovery paths return 404). But an SL1
> API key is a JWT, and the platform accepts it as `Bearer`: `POST /mcp` returns **200** with an
> `mcp-session-id`, `tools/list` returns the full tool surface, and the no-credential control returns
> **401**.
>
> **`X-API-Key` does not work.** The platform authenticator is handed that header and ignores it, so a
> real key sent that way gets a 401 exactly like a bogus one.
>
> [`client-setup.md`](client-setup.md) covers API keys in full, including two caveats: an API key
> resolves to its own entitlements, not its owner's, and keys expire.

**Full client-side setup instructions, including how to handle the appliance TLS certificate, are in
[`client-setup.md`](client-setup.md).** Hand that document to anyone configuring a client; this guide
covers the server side only.

### A 401 issues a challenge — expect a browser credential dialog

A 401 carries the header RFC 7235 requires:

```
WWW-Authenticate: Basic realm="Skylar One MCP", charset="UTF-8"
```

A browser that reaches a 401 on `/mcp` shows a native username/password dialog. That is correct, and
it is what lets an MCP client discover which scheme to use. The platform itself omits the header; the
fragment deliberately does not.

> **Read this before rolling out widely.**
>
> **Every MCP client configuration holds a live Skylar One password in plaintext.** Basic
> credentials do not expire, cannot be revoked individually, and are replayable. The secret lives in
> a configuration file on every machine running an MCP client, none of which this package controls.
>
> This is accepted deliberately for a **development-only All-in-One** deployment. It is **not a GA
> posture**. The intended GA path is OAuth 2.1 resource-server authentication.

### The credential is forwarded explicitly

The service expects nginx to forward the caller's `Authorization` header, and **the shipped fragment
does so explicitly**, in `location /mcp`:

```
proxy_set_header Authorization $http_authorization;
```

It does not rely on nginx passing unknown headers through by default.
`tests/unit/test_nginx_fragment.py` pins the line so it cannot be dropped.

**The forwarding is fail-safe, not fail-open.** nginx omits a header whose variable is empty, so a
credential-less request forwards **no** `Authorization` at all and the service answers
`credential_missing`; there is nothing to fall back to. And it cannot disturb
`auth_request /auth_user`: that location is `internal` and sets its own `Authorization` from the
client request, so the subrequest and this upstream are independent.

### Verifying it worked

```bash
curl -s http://127.0.0.1:8000/health              # {"status":"ok"} — process liveness only
# There is no /ready route.  With no configured credential there is nothing for a readiness
# probe to authenticate with.  LCE reachability surfaces as an lce_unreachable error on an
# actual tool call.
journalctl -u powerpack-mcp -n 50                 # startup records
tail -n 50 /var/log/sl1/powerpack_mcp.log         # the durable log — see §4
```

If the service refuses to start, the error names the exact problem, such as an env file with the
wrong permissions, an invalid value, or a non-loopback listener address. It **fails closed**: it will
not start in a degraded state.

---

## 2. The configuration file

**`/opt/em7/services/powerpack-mcp/powerpack-mcp.env`**, mode `0600`, owned by `s-em7-core`.

The service **checks that mode at every startup** and refuses to start if the file is group- or
world-accessible. If you change ownership or permissions, the service will tell you.

| Key | Required | Notes |
|---|---|---|
| **`LCE_VERIFY_TLS`** | No | Default `true`. **Set `false` on a self-signed appliance — see the warning below.** **Governs SL1 too** — see §2.1 |
| `LCE_CONNECT_TIMEOUT_SECONDS` | No | **Governs SL1 too** — see §2.1 |
| `LCE_READ_TIMEOUT_SECONDS` | No | **Governs SL1 too, and bounds the request deadline** — see §2.1 |
| `SL1_DEFAULT_TARGET_HOST` | No | Default `localhost`. The SL1 host the tools address. **Appliance-local by design; no tool takes a host** |
| `MAX_RESPONSE_BODY_BYTES` | No | Default `10485760` (10 MiB). Largest SL1 response read, enforced **during** the read |
| `LOG_LEVEL` | No | `DEBUG`…`CRITICAL`. Default `INFO`. **Leave at `INFO`** — see §4 |
| `MAX_CONCURRENT_REQUESTS` | No | **See the warning below** |

### 2.1 The `LCE_*` keys are not LCE-only — they govern SL1 as well

**This is the most surprising thing about this file, so it is stated before the details.**
`LCE_CONNECT_TIMEOUT_SECONDS`, `LCE_READ_TIMEOUT_SECONDS` and `LCE_VERIFY_TLS` apply to **every**
outbound call the service makes: to LCE, to the SL1 REST API, and to SL1's GraphQL endpoint at
`/gql`. There is deliberately **no** `SL1_VERIFY_TLS` and **no** `SL1_*_TIMEOUT_SECONDS`.

**Why.** All three targets are the **same appliance-local host over https**, so they present the
**same certificate**. A separate `SL1_VERIFY_TLS` would describe a distinction that does not exist,
and an operator who set one and forgot the other would end up with a posture they did not choose.

**What this means in practice:**

| If you… | Then… |
|---|---|
| set `LCE_VERIFY_TLS=false` | verification is relaxed for **SL1 traffic too**, not just LCE. The service logs a **WARNING on the SL1 path** when it does, so it is visible in the log and not only in this file |
| lower `LCE_READ_TIMEOUT_SECONDS` | you also shorten the **concurrency gate's request deadline**, so a slow SL1 call holds a gate slot for less time. **One value, three jobs** |
| look for an SL1 timeout key | there isn't one. Tune the `LCE_*` keys, knowing they are shared |

### `LCE_VERIFY_TLS` — depends on which certificate your appliance uses

**Check before changing anything. Skylar One appliances may present either a real CA-issued
certificate or the stock self-signed one. That is the customer's choice, and it decides this
setting.**

```bash
openssl s_client -connect localhost:443 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName
```

| What you have | Setting |
|---|---|
| **A real certificate** whose `subjectAltName` covers the host you connect to | **Leave `LCE_VERIFY_TLS=true`.** Verification works; no workaround needed |
| **The stock self-signed certificate** (no `subjectAltName`) | **Set `LCE_VERIFY_TLS=false`** — see below. This is the workaround, not the default posture |

**With `true` against a stock self-signed appliance the service cannot reach LCE**, and no credential
fixes it. The log shows:

```
SSLCertVerificationError('[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed:
                          self signed certificate')
```

Two things fail at once: the appliance certificate is **self-signed** and therefore untrusted, and its
**CN is the appliance IP** while the default target host is `localhost`, a hostname mismatch even if it
were trusted.

```bash
LCE_VERIFY_TLS=false
```

**This is a considered trade-off, not a shortcut.** The target is **loopback**. Setting it `false` keeps
the connection **encrypted** and drops only **peer authentication**, and anyone positioned to intercept
`127.0.0.1` already has root, at which point they can read this file anyway. Encryption in transit is
retained.

There is currently **no option to supply a CA bundle.**

> #### Trusting the stock certificate does not work
>
> Adding the stock self-signed certificate to the system trust store, and setting the target host to
> match its CN, **cannot succeed**.
>
> TLS makes **two independent checks**: is the certificate *trusted*, and does the *name* on it match
> what you connected to. Adding it to a trust store fixes only the first. **The stock certificate has
> no `subjectAltName` at all**, and modern runtimes do not consult CN for an IP connection, so the
> name check can never pass, however well the certificate is trusted. Against a live appliance with
> the certificate installed as a trusted CA:
>
> ```
> Python 3.12:  SSLCertVerificationError [CERTIFICATE_VERIFY_FAILED]
>               IP address mismatch, certificate is not valid for '192.0.2.44'
> Node.js 24:   ERR_TLS_CERT_ALTNAME_INVALID
>               IP: 192.0.2.44 is not in the cert's list:
> ```
>
> **So on a stock appliance there are exactly two options**: `LCE_VERIFY_TLS=false` (the workaround
> above), or **replace the certificate with one carrying a proper `subjectAltName`**, which is the
> real fix and the same change that lets clients verify too. If your appliance already has a real
> certificate, none of this applies: leave verification on.

Configuration precedence, highest first: **environment variable → this file → built-in default.**

### `MAX_CONCURRENT_REQUESTS` is not an independent knob

Raising it without also raising `MemoryMax` **and** `MemoryHigh` in the systemd unit will get the
service OOM-killed under load. This is measured, not theoretical: without the concurrency gate,
`MemoryMax=512M` was breached at roughly **8 concurrent maximum-size requests**, below the
service's own connection pool size of 10.

If you raise one, raise all three, and re-measure.

### Tool-set flags — `ENABLE_*`

Six optional keys decide **which groups of tools the server offers**. All six default to **enabled**,
so a file that mentions none of them gets the full tool surface.

| Key | Tool set | Default |
|---|---|---|
| *(none — there is no key)* | The **LCE** tools. Always offered | always on |
| `ENABLE_SL1_REST_TOOLS` | **22 SL1 tools — 6 REST and 16 GraphQL.** See the warning below | enabled |
| `ENABLE_SL1_GRAPHQL_TOOLS` | **2** generic GraphQL tools — *not* all GraphQL traffic. See below | enabled |
| `ENABLE_DB_TOOLS` | Database **read** tools | enabled |
| `ENABLE_DB_WRITE_TOOLS` | Database **write** tools | enabled |
| `ENABLE_OPS_TOOLS` | Operations, capability and discovery tools | enabled |
| `ENABLE_STANDARDS_TOOLS` | Content-standards tools | enabled |

Accepted values are `true`/`1`/`yes`/`on` and `false`/`0`/`no`/`off`, case-insensitive.

**A flag decides whether a tool exists, not whether a call succeeds.** A disabled set's tools are
absent from `tools/list` entirely: a client never sees them, rather than seeing them and getting an
error. Changing a flag needs a restart, which is already how every configuration change is applied.

#### `ENABLE_SL1_GRAPHQL_TOOLS=false` does not disable GraphQL

**The two SL1 flag names do not describe the transports.** Of the 22 tools under
`ENABLE_SL1_REST_TOOLS`, **only 6 are REST**: the four arbitrary-request passthroughs plus two
Dynamic Application readers. **Sixteen are GraphQL.**

So `ENABLE_SL1_GRAPHQL_TOOLS=false` removes **two** tools and leaves sixteen GraphQL tools running
under the other flag. **If your intent is "no GraphQL at all", set both keys to `false`.**

**The names are deliberately left as they are**, because renaming a flag silently changes what an
existing `.env` file switches off: an upgrade would alter a deployed tool surface with no operator
action.

#### SL1 applies the caller's permissions to GraphQL queries, but not to introspection

On a live appliance, **SL1 applies the caller's own permissions to a GraphQL query**: a deliberately
narrow account was refused data that `em7admin` was granted, on the identical query over the
identical endpoint. That is what makes these tools safe to ship.

**It does not extend to introspection.** The same narrow account read the **entire schema**,
including the very field it was forbidden to query. Schema **shape** is readable by any authenticated
caller; schema **data** is not. That is SL1's behaviour, not this service's, and it is not a
privilege-escalation path, because *shape* discloses no records. But if exposing the shape is
unacceptable in your environment, `sl1_graphql_introspect` is the tool that exposes it, and
`ENABLE_SL1_GRAPHQL_TOOLS=false` is how you remove it.

#### `ENABLE_DB_WRITE_TOOLS` is nested under `ENABLE_DB_TOOLS`

`ENABLE_DB_TOOLS=false` turns off **all** database tools, writes included, whatever the write key
says. That is not an error and the service still starts, but the startup log will say the write set
was *disabled by nesting* rather than *disabled by configuration*, so you can see that it was a
consequence of the read flag rather than something you set directly.

#### A misspelled value stops the service, on purpose

`ENABLE_DB_TOOLS=maybe` does **not** fall back to the default. The service refuses to start and names
the key:

```text
Invalid configuration: ENABLE_DB_TOOLS must be a boolean -- one of 1, on, true, yes for enabled ...
```

This is deliberate. Because the flags default to *enabled*, you are usually editing them to turn
something **off**, and if a typo silently fell back to the default, a mistyped
`ENABLE_DB_WRITE_TOOLS=flase` would leave database **writes on** while looking like it had turned
them off. Refusing to start is the safe direction.

#### What you will see when a flag is wrong

The unit sets `RestartPreventExitStatus=78`, so a configuration mistake goes **straight to `failed`
and stays there** instead of restarting every five seconds:

```bash
systemctl status powerpack-mcp
#   Active: failed (Result: exit-code)
#  Process: ... status=78
grep powerpack_mcp /var/log/sl1/powerpack_mcp.log | grep startup_failed
```

**Exit status 78 means "configuration error"** (`EX_CONFIG`). Any other non-zero status is treated as
a crash and *is* restarted automatically. Fix the file and `systemctl start powerpack-mcp`.

> **Not yet verified on an appliance.** This behaviour follows from systemd's documented defaults. If
> you find `systemctl status` reporting something other than the above, that is worth reporting.

### The file survives uninstall

**Deliberately.** It holds settings you chose, and deleting it silently would destroy your state and
prevent a reinstall from resuming. **If you want it gone, remove it deliberately:**

```bash
rm /opt/em7/services/powerpack-mcp-1.0/powerpack-mcp.env
```

---

## 3. Upgrades

The service version is part of the package name, `powerpack-mcp-1.0`, matching the platform
convention used by `lce`, `slsctl` and others.

**Only one version may be installed at a time.** The symlink, the nginx zone file and the nginx
include line are single-instance resources that two concurrently-installed versions would conflict
over.

| Kind of upgrade | Command | Your env file |
|---|---|---|
| **Release bump** — same version line, e.g. `1.0-1` → `1.0-2` | `dnf upgrade powerpack-mcp-1.0` | **Preserved** |
| **Version bump** — e.g. `1.0` → `1.1` | erase, then install | **Fresh file**; re-apply your edits |

A version bump installs a fresh directory with a fresh env file. Nothing must be re-supplied for the
service to start, because the env file holds no credential and every key has a safe default. Do
re-apply any settings you had changed, in particular `LCE_VERIFY_TLS=false` on a self-signed
appliance: without it the service starts and every tool call fails with `lce_unreachable`.

An upgrade restarts a running service onto the new code. A stopped service stays stopped.

## 4. Logs and retention

Records go to **rsyslog**, not journald, matching every other em7 Python service:

```
the service writes stdout/stderr
  → systemd, SyslogIdentifier=silo.powerpack_mcp
  → rsyslog
  → /var/log/sl1/powerpack_mcp.log      (rotated by the existing /etc/logrotate.d/sl1)
```

`journalctl -u powerpack-mcp` also works and is convenient for startup problems, but **journald on
this appliance is volatile**: it stores nothing under `/var/log/journal`, so **its records are lost
on every reboot.** For anything that must survive, use the file.

### Retention depends on your log volume, and may not reach 90 days

The platform's `sl1` logrotate rule is `daily`, `rotate 10`, **`minsize 5M`**. Because of `minsize`,
rotation is **volume-driven rather than time-driven**:

| Sustained volume | Approximate retention | Meets a 90-day requirement? |
|---|---|---|
| **≤ ~0.6 MB/day** | **≥ 90 days** | Yes |
| ~5 MB/day | ~11 days | No |
| ≥ 30 MB/day | < 2 days | No |

Roughly **1,500–3,000 records/day**, about one to two tool calls per minute sustained, is the
threshold. **Above it, audit records for write operations will not survive 90 days.**

Neither this package nor the service can change that: `/etc/logrotate.d/sl1` is platform-owned. If
you need a guarantee, raise that policy or ship records off-box.

### Monitoring

Alert on the stable **`event`** field, **never on message text**. The vocabulary is closed:

`startup_failed` · `unhandled_exception` · `tls_verification_relaxed` · `validation_blocked` ·
`lce_auth_denied` · `write_committed` · `concurrency_limited` · `tool_sets_registered`

Sustained `concurrency_limited` means the bound is too low for real traffic, or a client is
misbehaving.

#### `tool_sets_registered` — what the server decided to offer, at every startup

One record per tool set, the always-on LCE set included, so the log is a complete inventory rather
than a list of the optional parts. Each record carries `set_id`, `registered`, `tool_count`, the
`flag` that gates it (absent for the LCE set, which is how "always on" is marked), and, when a set is
off, a `reason` of `disabled_by_configuration`, `disabled_by_nesting` or `prerequisite_missing`.

```text
event=tool_sets_registered set_id=db_write registered=False
  flag=ENABLE_DB_WRITE_TOOLS reason=disabled_by_nesting tool_count=0
```

**Worth an alert, not just a log line.** An upgrade can widen the tool surface without anyone editing
the configuration file, because a newly shipped set defaults to enabled. These records are the only
place that becomes visible. Comparing them across restarts tells you whether an upgrade added tools
you had not asked for.

The three reasons are deliberately distinct: *configuration* means you turned it off, *nesting* means
`ENABLE_DB_TOOLS=false` turned it off for you, and *prerequisite missing* means the set cannot run on
this appliance. Those need different responses, which is why "disabled" alone is not reported.

---

## 5. nginx integration

The package installs two nginx files, at two different levels, because `limit_req_zone` is only valid
at `http` level while `location` blocks are only valid inside a `server`:

| File | Location |
|---|---|
| `powerpack-mcp-zone.conf` | `/opt/em7/share/config/nginx.d/` — picked up by an existing wildcard |
| `powerpack-mcp.fragment` | `/opt/em7/services/powerpack-mcp/nginx/` — activated by an include line |

`%post` adds that include line to `/opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment`.

### After any Skylar One platform upgrade, verify `/mcp` is still routed

**This is the most important operational check in this document.**

`em7ngx_web_ui.fragment` is owned by the `sl-php-ui` package and is **not** a configuration file, so
a platform upgrade **overwrites it and silently removes our include line.** No `.rpmsave`, nothing
in any log. **`/mcp` returns 404 while the service is running and reporting healthy.**

```bash
# Check
grep -c powerpack-mcp /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment    # expect 1

# Repair
dnf reinstall powerpack-mcp-1.0     # %posttrans re-adds the line idempotently
# or add it by hand inside the server block, then:
nginx -t && systemctl reload nginx
```

A future platform release providing a server-level wildcard include hook would remove this problem
entirely, and is worth requesting.

### Routes

| Route | Authentication |
|---|---|
| `/mcp` | **Required.** Rate-limited. `POST`, `GET`, `DELETE` only |
| `/health` | **Anonymous.** The only public route. Discloses process liveness and nothing else |

**There is no `/ready` route.** With no configured credential there is nothing for a readiness probe
to authenticate with. The path falls through to the platform and returns `404 text/html`. LCE
reachability surfaces as an `lce_unreachable` error on a real tool call instead.

Authentication uses the existing Skylar One scheme via nginx `auth_request`, and **fails closed**:
if the authenticator is unavailable or misconfigured, requests are **denied**, never proxied.

### Authorization — each caller gets their own permissions

The caller's own credential is forwarded per request, and LCE applies **that caller's**
permissions. No tool runs as a shared service account.

**The mechanism is worth knowing precisely, because it is not what it looks like.** The
`Authorization` header does *not* reach LCE. The platform's own `/lce` location does not forward it;
LCE acts on `X-User-ID`, which nginx derives from the `auth_request` subrequest:

```
caller's Authorization
  -> /mcp                  nginx forwards it explicitly
  -> this service          holds no credential of its own
  -> https://localhost/lce/api
  -> nginx /lce            auth_request /auth_user resolves the credential to an identity
  -> LCE                   receives X-User-ID and applies that user's permissions
```

**Consequence for troubleshooting**: if the `Authorization` header goes missing anywhere in that
chain, identity resolution never happens, so the symptom is an authorization failure, not a
transport error. That is why the fragment forwards it explicitly rather than relying on nginx's
default pass-through.

> **A limitation**: authorization is exactly as granular as LCE's own model. If a caller has broad
> LCE rights, they have broad rights here. This layer adds no per-tool restriction of its own for
> the LCE tools; it stops every caller being *escalated* to a shared account, which is a narrower
> claim than per-tool access control.

---

## 6. Uninstall

```bash
systemctl disable --now powerpack-mcp
dnf remove powerpack-mcp-1.0
```

Removal stops and disables the service, deletes both nginx files, removes the include line, and
**verifies `nginx -t` passes afterwards** before reloading. If validation fails it does **not**
reload; nginx keeps serving its last known-good configuration.

**Your `powerpack-mcp.env` is left in place** (§2).

---

## 7. Troubleshooting

| Symptom | Cause |
|---|---|
| Service refuses to start, complains about permissions | `powerpack-mcp.env` is group- or world-readable. `chmod 0600` |
| `/mcp` returns **404** while `systemctl status` is healthy | **The include line was removed by a platform upgrade** (§5) |
| `/mcp` returns **401**/**403** with a JSON body | Authentication was enforced and denied — working as designed |
| `/mcp` returns **500** `"Failed to identify user"` | The authenticator itself failed. Fail-closed behaviour |
| Every tool call fails `lce_unreachable`, service otherwise healthy | Almost always `LCE_VERIFY_TLS` against a self-signed certificate (§2). **This is how LCE unreachability surfaces**; there is no readiness probe to consult |
| Service OOM-killed under load | `MAX_CONCURRENT_REQUESTS` raised without `MemoryMax`/`MemoryHigh` (§2) |
| Upgraded the RPM but behaviour did not change | Builds **before `dev14`** did not restart the service on upgrade: every file was replaced while the old process kept serving. Check `systemctl show -p ExecMainStartTimestamp powerpack-mcp`; if it predates the upgrade, `systemctl restart powerpack-mcp` |
| Install reported success but `/mcp` never worked | **`nginx -t` failed and the configuration self-removed.** `rpm` cannot report a scriptlet failure — re-read the install output |

**On that last row**: a failing RPM scriptlet does not abort an installation, and `rpm` exits 0
regardless. **Read the install output rather than trusting the exit status.**

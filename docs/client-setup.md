# PowerPack MCP Server — MCP Client Setup Guide

How to point an MCP client at a deployed server. This is the **client-side** counterpart to
[`operations.md`](operations.md), which covers installing and running the service itself.

Worked examples use Claude Code and the appliance address `192.0.2.44`. Substitute your own.
OpenAI Codex is covered separately in §7; §1–§3 apply to it too.

Two things have to be solved: the **`Authorization` header** the service requires, and the
appliance's **self-signed TLS certificate**.

---

## 1. Prerequisite — the server must actually be reachable

Before configuring a client, confirm the service is installed, enabled and routed
(`operations.md` §1 and §5):

```bash
curl -sk https://192.0.2.44/health
```

A JSON body means the service is up and nginx is routing `/mcp`. A 404 usually means the nginx
fragment is missing — see `operations.md` §5.

> **The credential is forwarded.** The shipped nginx fragment forwards your `Authorization` header
> to the service **explicitly**: `proxy_set_header Authorization $http_authorization;` in
> `location /mcp`. **Nothing extra is needed on your side:** send the header as §2 describes and it
> arrives intact. See `operations.md` §1.
>
> Send no credential and nginx forwards none: you get an authentication failure, never anonymous
> access.

---

## 2. Build the `Authorization` header

Each user authenticates as themselves; the service forwards the credential verbatim to LCE, so
**LCE applies that user's own permissions** (`operations.md` §1). There is no service account.

Use **your own** Skylar One credentials:

```bash
printf 'YOUR_USER:YOUR_PASSWORD' | base64
```

Use `printf`, **not** `echo`. `echo` appends a newline, which corrupts the header and yields a
401 that looks exactly like a wrong password.

`Basic` is the scheme verified against LCE 3.1.0. The service is scheme-agnostic and forwards
whatever you send.

> **An SL1 API key works, presented as `Bearer`.** An **opaque bearer token** is rejected, because
> the platform has no authorization server at all (all seven OAuth/OIDC discovery paths return 404,
> and so does `/api/v2/tokens`). But **an SL1 API key is a JWT, and the platform accepts it as
> `Bearer`.** `POST /mcp` with `Authorization: Bearer <api-key>` returns **HTTP/2 200** with an
> `mcp-session-id`, and `tools/list` returns the full tool surface. The no-credential control
> returns **401**.
>
> `X-API-Key` does **not** work: the platform authenticator is handed that header and ignores it,
> so a real key sent that way gets a 401 exactly like a bogus one.

## Authenticating with an SL1 API key

Suited to automation, because it avoids putting a human's password on a client machine (the
hazard described below). Create the key in SL1 (it becomes an account with its own
entitlements), then send it as a bearer token:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**The key's own access hooks are what authorize it**, not its owner's. An API key is an SL1
account (`auth_method = 6`), so it resolves to its own entitlement set — which is the point: mint
it narrowly. A key granted nothing is refused every gated tool, by design.

**Keys expire.** The `expiration` is recorded in SL1 and enforced by the platform, so a client
using one needs a renewal path. A key that has expired returns 401 at the perimeter and never
reaches this service.

> **Basic authentication puts a live, non-expiring password on every client machine.**
>
> Basic credentials do not expire, cannot be revoked individually, and are replayable. Base64 is
> *encoding, not encryption* — trivially reversible. In Claude Code the header lands in
> `~/.claude.json` in plaintext-equivalent form. **Never commit that file; never paste the header
> into a ticket or chat.**
>
> Accepted deliberately for **development-only All-in-One** deployments. **Not a GA posture** — the
> intended GA path is OAuth 2.1 resource-server authentication.

---

## 3. Check the appliance certificate — this decides everything below

**Do this before touching any TLS setting.**

```bash
openssl s_client -connect 192.0.2.44:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -dates -ext subjectAltName
```

| What you see | Take |
|---|---|
| A `subjectAltName` listing your appliance's IP or hostname | **Path A** — clean, nothing global weakened |
| `No extensions in certificate`, or an empty SAN list | **Path B** — verification must be disabled |

A stock appliance is **Path B**. A typical stock certificate reads
`subject=C=US, ST=Silo, L=Reston, O=Silo, CN=192.0.2.44`: self-signed, `CA:TRUE`, valid to 2036,
**no extensions at all**.

### Why trusting the certificate is not enough

TLS makes **two independent checks**: *is the certificate trusted*, and *does the name on it match
what I connected to*. Installing a self-signed cert as a trusted CA fixes only the first.

**A certificate with no `subjectAltName` can never match an IP address**, no matter how thoroughly
it is trusted, because CN is not consulted for IP connections. In both runtimes, with the cert
installed as a trusted CA and connecting to the exact IP in its CN:

```
Node.js 24:   ERR_TLS_CERT_ALTNAME_INVALID
              Hostname/IP does not match certificate's altnames:
              IP: 192.0.2.44 is not in the cert's list:

Python 3.12:  SSLCertVerificationError [CERTIFICATE_VERIFY_FAILED]
              IP address mismatch, certificate is not valid for '192.0.2.44'
```

Setting the target host to match the CN does not help either, because CN is not consulted. The only
real fix is reissuing the certificate (see "The durable fix" under Path B).

---

## Path A — certificate has a `subjectAltName`

Trust it as an extra CA. Nothing global is weakened.

```bash
mkdir -p ~/.claude/certs
openssl s_client -connect 192.0.2.44:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > ~/.claude/certs/sl1-192.0.2.44.pem
chmod 600 ~/.claude/certs/sl1-192.0.2.44.pem
```

In `~/.claude/settings.json`:

```json
{
  "env": {
    "NODE_EXTRA_CA_CERTS": "/Users/YOUR_USERNAME/.claude/certs/sl1-192.0.2.44.pem"
  }
}
```

Must be an **absolute path** — `~` is not expanded. Continue at §4.

---

## Path B — certificate has no `subjectAltName` (stock appliance)

There is no targeted fix. Certificate verification must be switched off, in
`~/.claude/settings.json`:

```json
{
  "env": {
    "NODE_TLS_REJECT_UNAUTHORIZED": "0"
  }
}
```

> **Read this before pasting it: the blast radius is larger than `LCE_VERIFY_TLS=false`'s.**
>
> **This is process-global, not per-server.** The client will make **every** TLS connection without
> verifying certificates — every other MCP server configured in it, and its calls to its own
> vendor API. Node.js offers no per-host scoping, and Claude Code exposes no per-server TLS option
> for HTTP-transport servers (checked: `claude mcp add --help`, `claude mcp add-json --help`).
>
> **Do not reason by analogy with `LCE_VERIFY_TLS=false`.** That trade-off is defensible because its
> target is **loopback** — anyone positioned to intercept `127.0.0.1` already has root
> (`operations.md` §2). **Neither half of that argument holds here.** This connection crosses a real
> network, so peer authentication is doing genuine work, and the setting degrades *unrelated*
> connections rather than one loopback hop. It is strictly weaker than `LCE_VERIFY_TLS=false`.
> Treat it as **lab-only**.
>
> **Do not pair it with `NODE_EXTRA_CA_CERTS` and assume the CA entry earns its keep.** It does not:
> the bypass is what makes the connection succeed, and the CA line is decorative and misleading to
> the next reader.

### The durable fix

Reissue the appliance certificate with an IP SAN:

```
subjectAltName = IP:192.0.2.44
```

Then switch to **Path A** and delete `NODE_TLS_REJECT_UNAUTHORIZED`. Trust comes from the CA entry,
hostname matching from the SAN. **If you administer the appliance, do this instead of Path B.** It
also fixes the server side, letting `LCE_VERIFY_TLS` stay `true`.

---

## 4. Register the server

```bash
claude mcp add --transport http --scope user sl1-powerpack https://192.0.2.44/mcp \
  --header "Authorization: Basic PASTE_BASE64_HERE"
```

* `--scope user` writes to `~/.claude.json`, so it works in every project. **The default is
  `local`** — omit the flag and you get a project-scoped entry that silently isn't there from a
  different directory.
* Re-adding an existing name does not cleanly replace it. Remove first:
  `claude mcp remove sl1-powerpack --scope user`

---

## 5. Restart, then verify

`~/.claude/settings.json` `env` values are read at **startup** — restart the client after editing
them, or the TLS setting will appear to have no effect.

```bash
claude mcp list
```

Expect:

```
sl1-powerpack: https://192.0.2.44/mcp (HTTP) - ✔ Connected
```

The seven LCE tools should then be available. There is no readiness endpoint to check: there is
**no `/ready` route**, and LCE reachability surfaces as an `lce_unreachable` error on an actual tool
call, not as a probe (`operations.md` §1).

---

## 6. Troubleshooting

| Symptom | Cause |
|---|---|
| `DEPTH_ZERO_SELF_SIGNED_CERT` | Certificate not trusted — §3 not applied, or the client wasn't restarted |
| `ERR_TLS_CERT_ALTNAME_INVALID` / `IP address mismatch` | No matching `subjectAltName`. Path A **cannot** work; use Path B or reissue the cert |
| `401 Unauthorized` | Wrong credentials — or a newline in the base64 from using `echo` instead of `printf` |
| `401` with correct credentials | nginx may not be forwarding `Authorization` — see §1 |
| `credential_missing` | Request carried no usable credential; the header never arrived |
| `request_deadline_exceeded` (HTTP 504) | The request hit the server's time limit before it replied. Retry a read, ideally narrower; check whether a write took effect before retrying it |
| `404` on `/mcp` | nginx fragment missing or clobbered by a platform upgrade — `operations.md` §5 |
| `lce_unreachable` on every tool call | Server-side, not client-side: usually `LCE_VERIFY_TLS` — `operations.md` §2 |
| Works in one project, absent in another | Registered at `local` scope instead of `--scope user` |
| Cert setting ignored, `ENOENT` | `NODE_EXTRA_CA_CERTS` used `~` instead of an absolute path |

---

## 7. OpenAI Codex

> **Untested.** This section is written from the Codex documentation and source (Codex CLI
> 0.158), not from a run against an appliance. Treat it as a starting point, and report what you
> find.

The Codex CLI, the Codex IDE extension and the ChatGPT desktop app share one configuration, so the
steps below cover all three. §1 (reachability), §2 (building the header) and §3 (checking the
certificate) apply unchanged. The TLS and registration steps differ.

### The certificate: a stock appliance does not work

**Codex has no setting that disables certificate verification**, globally or per server. There is
no equivalent of `NODE_TLS_REJECT_UNAUTHORIZED=0`, so **there is no Path B for Codex.** Its TLS
stack also checks the name against the `subjectAltName` only, and it refuses a server certificate
marked `CA:TRUE`. A stock appliance certificate has no extensions and is marked `CA:TRUE`, so it
fails both checks, however it is trusted.

Check both properties:

```bash
openssl s_client -connect 192.0.2.44:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -ext subjectAltName,basicConstraints
```

Codex needs a certificate with a `subjectAltName` for the appliance's IP or hostname and
`CA:FALSE`. The reliable route is to issue it from a private CA and give Codex that CA. Reissuing the
certificate is the same fix as "The durable fix" under Path B, and it lets `LCE_VERIFY_TLS` stay
`true` on the server as well.

Point Codex at the CA with an **absolute path**, in the environment Codex starts from:

```bash
export CODEX_CA_CERTIFICATE=/Users/YOUR_USERNAME/.codex/certs/sl1-ca.pem
```

Codex falls back to `SSL_CERT_FILE` when `CODEX_CA_CERTIFICATE` is unset. The system trust store
stays trusted alongside it, so other connections are unaffected.

### Register the server

`codex mcp add` has no option for arbitrary headers, and it probes the URL before saving, so edit
the configuration file by hand. Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.sl1-powerpack]
url = "https://192.0.2.44/mcp"
env_http_headers = { "Authorization" = "SL1_MCP_AUTH" }
```

`env_http_headers` maps a header name to the **name of an environment variable**, and the variable
holds the whole header value, scheme included. Set it without putting the password in your shell
history:

```bash
read -rs -p 'Skylar One password: ' P; echo
export SL1_MCP_AUTH="Basic $(printf '%s:%s' YOUR_USER "$P" | base64 | tr -d '\n')"; unset P
```

`tr -d '\n'` matters on Linux, where `base64` wraps long output onto a new line. For an SL1 API key,
set `SL1_MCP_AUTH="Bearer eyJhbGciOi..."` instead, or use `bearer_token_env_var = "SL1_MCP_JWT"`
with the variable holding the raw key, since that option adds `Bearer ` itself.

* **The variable must be in Codex's own environment.** An IDE extension launched from the desktop
  may not inherit variables exported in your shell profile.
* **A project-level `.codex/config.toml` is ignored unless the project is trusted.** The user file
  above applies everywhere.
* `http_headers = { "Authorization" = "Basic ..." }` also works, but it writes the credential into
  `config.toml` in plaintext-equivalent form, with the hazard described in §2.

### Verify

```bash
codex mcp list
codex mcp get sl1-powerpack
```

In the terminal UI, `/mcp` lists the connected servers and their tools. In the IDE extension, use
the gear menu's **MCP servers**.

### Codex troubleshooting

| Symptom | Cause |
|---|---|
| Certificate or name-mismatch error | Stock appliance certificate. It cannot work with Codex; reissue it (see above) |
| Certificate error after setting `CODEX_CA_CERTIFICATE` | Relative path, or the certificate is still `CA:TRUE` or has no `subjectAltName` |
| `401 Unauthorized`, no other error | `SL1_MCP_AUTH` not set in Codex's environment. A missing `env_http_headers` variable is **silently skipped**, and the request goes out with no credential |
| Startup error that a variable "is not set" | `bearer_token_env_var` names a variable missing from Codex's environment |
| Server missing in one project | It was added to that project's `.codex/config.toml` and the project isn't trusted |

References: [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp),
[custom CA certificates](https://learn.chatgpt.com/docs/auth).

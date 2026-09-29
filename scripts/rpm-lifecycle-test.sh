#!/bin/bash
# =============================================================================================
# RPM lifecycle test.
#
# Builds the RPM from an sdist and exercises install -> relocation -> release-bump upgrade ->
# include-line self-heal -> erase -> idempotent re-erase, asserting nginx -t at every step.
#
# Usage, from the submodule root:
#
#     rm -rf dist && uv build --sdist      # dist/ must hold exactly one sdist: the harness aborts
#                                          # on more than one rather than guess, and on one that
#                                          # does not match the tree.  Build from a clean tree, or
#                                          # the version carries a .d<date> marker.
#     docker build -f - -t rpmtest:ol8 . <<'EOF'
#     FROM oraclelinux:8
#     RUN dnf -y install rpm-build systemd-rpm-macros nginx python3.12 git tar gzip findutils \
#      && dnf clean all
#     RUN curl -LsSf https://astral.sh/uv/install.sh | sh
#     EOF
#     docker run --rm \
#         -e EXPECTED_SDIST_VERSION="$(uv run --no-project --with setuptools-scm \
#                                      python -m setuptools_scm 2>/dev/null)" \
#         -v "$PWD:/src:ro" \
#         -v "$PWD/scripts/rpm-lifecycle-test.sh:/bt.sh:ro" rpmtest:ol8 bash /bt.sh
#
# EXPECTED_SDIST_VERSION is mandatory and has to come from the host.  It is the only input to
# the staleness check below, and the harness refuses to run without it.  It cannot be derived
# inside the container, so do not try to fix that by installing git in the image:
#   1. Only the submodule directory is mounted, at /src.  Nothing above it is visible.
#   2. This repo is a submodule, so /src/.git is a gitfile reading
#      `gitdir: ../.git/modules/powerpack_mcp`, and that target is outside the mount.
#      `git -C <dir> describe --tags` exits 128 with
#      `fatal: not a git repository: <dir>/../.git/modules/powerpack_mcp`.
#   3. /src is mounted :ro, and a checkout owned by another user trips git's safe.directory
#      dubious-ownership refusal regardless.
#
# Use `python -m setuptools_scm`, not `git describe`.  pyproject.toml declares
# `dynamic = ["version"]` with `build-backend = "setuptools.build_meta"` and `setuptools-scm` in
# `requires`, so setuptools-scm names the sdist, and its answer is not git describe's.  On one
# commit, `git describe --tags` gives `v1.1.0-46-gf4a1ece` and setuptools-scm gives
# `1.1.1.dev46+gf4a1ece21`: a different next-version guess and a different abbreviation length.
# Only the latter appears in `powerpack_mcp-1.1.1.dev46+gf4a1ece21.tar.gz`, byte for byte.  A dirty
# tree's `.d<date>` marker survives into the filename verbatim too (for example
# `powerpack_mcp-1.0.1.dev16+g775c04c14.d20260811.tar.gz`), which is why the check below is a
# plain string equality.  `--no-project` skips installing this project into the throwaway
# environment, and `2>/dev/null` drops uv's progress output, which goes to stderr.
#
# Compute it inline rather than exporting it.  An `export EXPECTED_SDIST_VERSION=...` left over
# from before a commit gives a stale expectation that agrees with a stale sdist.  Computing it in
# the `docker run` line means the expectation can never be older than the invocation.
#
# Build the image first and separately.  Running dnf inside the test run makes a slow repository
# fetch indistinguishable from a hang.
#
# What this does not verify: appliance behaviour.  It verifies RPM's and nginx's semantics, which
# is what the packaging depends on.  The systemd hardening directives have no precedent on the
# appliance and remain untested until manual acceptance.
#
# EXIT CODES.  A test failure exits 0: read the trailing "RESULT: N failure(s)" line and the
# PASS/FAIL markers, not $?.  A run that cannot start at all exits non-zero: 2 when the sdist in
# /src/dist is missing or ambiguous, 2 when it does not match EXPECTED_SDIST_VERSION or
# EXPECTED_SDIST_VERSION was not supplied, and 1 when rpmbuild itself fails (step 1).
# =============================================================================================
set -uo pipefail
FAIL=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; FAIL=$((FAIL+1)); }
# Not named `head`: a function called head() shadows /usr/bin/head and silently breaks every
# `... | head -1` and log-truncating pipe in this script.
hdr()  { echo; echo "======== $* ========"; }

hdr "0. Environment"
dnf -y -q install rpm-build systemd-rpm-macros nginx python3.12 git tar gzip findutils >/dev/null 2>&1
curl -LsSf https://astral.sh/uv/install.sh >/tmp/uvi 2>/dev/null && sh /tmp/uvi >/dev/null 2>&1
export PATH="$HOME/.local/bin:$PATH"
echo "  arch=$(uname -m)  rpm=$(rpm --version | awk '{print $3}')  nginx=$(nginx -v 2>&1 | sed 's/.*\///')"
echo "  uv=$(uv --version 2>&1 | awk '{print $2}')  python3.12=$(/usr/bin/python3.12 --version)"

# Mirror the appliance: /opt/em7/bin/python3.12 is a symlink to /usr/bin/python3.12, and
# s-em7-core is the platform service account.
mkdir -p /opt/em7/bin
ln -sf /usr/bin/python3.12 /opt/em7/bin/python3.12
groupadd -r s-em7-core 2>/dev/null || :
useradd -r -l -g s-em7-core -d /opt/em7 -s /sbin/nologin -c "EM7 System" s-em7-core 2>/dev/null || :
echo "  /opt/em7/bin/python3.12 -> $(readlink /opt/em7/bin/python3.12)"

# ---- The sdist must be unambiguous.  Do not select it with `ls ... | head -1`. ----
#
# `SDIST=$(ls /src/dist/*.tar.gz | head -1)` is wrong: `ls` sorts lexicographically, so
# `powerpack_mcp-1.1.1.dev1+...tar.gz` sorts before `...dev32+...tar.gz`, and a stale sdist left in
# dist/ gets built and tested while every assertion below honestly reports PASS about the wrong
# artifact.  Smarter selection does not help: newest-by-mtime would still choose silently.
# Ambiguity is unrecoverable, so the harness aborts and names what it found.
#
# It aborts instead of calling bad() because nothing downstream can run without the right sdist;
# recording a failure and carrying on would produce a page of meaningless assertions.  Step 1
# exits on an rpmbuild failure for the same reason.
#
# The glob goes into an array rather than through `head` (see hdr() above).  A glob plus
# ${var##*/} needs no external command and nothing a later edit could shadow.
shopt -s nullglob
SDISTS=(/src/dist/*.tar.gz)
shopt -u nullglob
if [ "${#SDISTS[@]}" -eq 0 ]; then
  echo
  echo "######################################################################"
  echo "ABORT (sdist count): no *.tar.gz in /src/dist -- there is nothing to build."
  echo "  From the submodule root, on a CLEAN tree:"
  echo "      rm -rf dist && uv build --sdist"
  echo "######################################################################"
  exit 2
elif [ "${#SDISTS[@]}" -gt 1 ]; then
  echo
  echo "######################################################################"
  echo "ABORT (sdist count): ${#SDISTS[@]} sdists in /src/dist -- refusing to guess which."
  for sd in "${SDISTS[@]}"; do echo "      ${sd##*/}"; done
  echo "  Picking one would test a possibly-stale artifact and report PASS for it."
  echo "  Clean dist/ and rebuild, from the submodule root:"
  echo "      rm -rf dist && uv build --sdist"
  echo "######################################################################"
  exit 2
fi
SDIST="${SDISTS[0]}"
VER=$(basename "$SDIST" | sed 's/^powerpack_mcp-//; s/\.tar\.gz$//')
echo "  sdist=$(basename $SDIST)"
echo "  version=$VER"

# ---- The one sdist must also be the current one. ----
#
# The count check above cannot catch exactly one stale sdist: it passes the check, gets built, and
# every assertion below reports PASS about the wrong artifact.  So the sdist's version is compared
# with EXPECTED_SDIST_VERSION, which the host supplies (see the usage header for why it cannot be
# computed in here).
#
# An unset value aborts rather than skipping the check.  A check that only runs when someone
# remembered to pass a variable is off in exactly the circumstances that produce a stale build, and
# an unknown expectation leaves every PASS below unattributable to any commit.  That is the same
# unrecoverable state as an ambiguous sdist, so it gets the same exit 2.
#
# There is deliberately no bypass value.  To test an sdist built elsewhere, set
# EXPECTED_SDIST_VERSION to the version you believe you are testing; that lands in the run log.
#
# Whitespace is stripped before comparing, and nothing else is normalised.  The two strings are
# byte-identical when correct, so a looser comparison could only make a real mismatch compare
# equal.  The strip is there because `-e VAR="$(...)"` copied out of a document, or run through a
# shell with CRLF habits, can carry an invisible trailing CR.
EXPECTED_VER=$(printf '%s' "${EXPECTED_SDIST_VERSION-}" | tr -d '[:space:]')
if [ -z "$EXPECTED_VER" ]; then
  echo
  echo "######################################################################"
  echo "ABORT (sdist version): EXPECTED_SDIST_VERSION is unset -- cannot tell if this sdist is current."
  echo "      sdist version:    $VER"
  echo "      expected version: <not supplied>"
  echo "  A stale sdist is one file, so it passes the sdist count check, and every"
  echo "  assertion below would report PASS for the wrong artifact.  Not running blind."
  echo "  Re-run passing the version this tree builds, from the submodule root:"
  echo "      -e EXPECTED_SDIST_VERSION=\"\$(uv run --no-project --with setuptools-scm \\"
  echo "                                   python -m setuptools_scm 2>/dev/null)\""
  echo "######################################################################"
  exit 2
elif [ "$VER" != "$EXPECTED_VER" ]; then
  echo
  echo "######################################################################"
  echo "ABORT (sdist version): the sdist in /src/dist is not what this tree builds -- it is stale."
  echo "      sdist version:    $VER"
  echo "      expected version: $EXPECTED_VER"
  echo "  Exactly one sdist is present, so the sdist count check passed it, and every"
  echo "  assertion below would have reported PASS for a stale artifact."
  echo "  Clean dist/ and rebuild, from the submodule root:"
  echo "      rm -rf dist && uv build --sdist"
  echo "######################################################################"
  exit 2
fi
echo "  matches EXPECTED_SDIST_VERSION -- sdist is current"

mkdir -p /root/rpmbuild/{SPECS,SOURCES,BUILD,RPMS,SRPMS}
cp "$SDIST" /root/rpmbuild/SOURCES/
tar xzf "$SDIST" -C /tmp
cp "/tmp/powerpack_mcp-$VER/packaging/rpm/powerpack-mcp.spec" /root/rpmbuild/SPECS/

# The one modification made to the spec for the main test: the spec hardcodes
# `BuildArch: x86_64` (correct, since the appliance is x86_64), but this container may be aarch64,
# where an x86_64 package cannot be installed.  Everything else is tested as written.
sed -i 's/^BuildArch:.*/BuildArch: %{_arch}/' /root/rpmbuild/SPECS/powerpack-mcp.spec
echo "  NOTE: BuildArch overridden x86_64 -> %{_arch} for this container only"

hdr "1. rpmbuild -- does the spec build at all?"
if rpmbuild -bb --define "service_build_version $VER" \
      /root/rpmbuild/SPECS/powerpack-mcp.spec >/tmp/build.log 2>&1; then
  ok "rpmbuild succeeded"
  RPM=$(find /root/rpmbuild/RPMS -name '*.rpm' | head -1)
  echo "        $(basename "$RPM")"
else
  bad "rpmbuild FAILED"
  tail -25 /tmp/build.log | sed 's/^/        /'
  echo; echo "RESULT: FAIL=$FAIL"; exit 1
fi

hdr "2. In-%build assertions fired"
# Two independent tests, not one `A || B && C || D` chain: shell parses that as
# `((A||B) && C) || D`, which reports a FAIL when `relocatable = true` is found.
if grep -q "FATAL" /tmp/build.log; then
  bad "a %build assertion tripped"; grep "FATAL" /tmp/build.log | head -3 | sed 's/^/          /'
else ok "no %build assertion tripped"; fi
if grep -qs "relocatable = true" /root/rpmbuild/BUILD/venv/pyvenv.cfg; then
  ok "venv pyvenv.cfg marks relocatable = true"
else
  echo "        NOTE: no pyvenv.cfg at /root/rpmbuild/BUILD/venv -- not asserted here."
  echo "              Relocation is proven for real from the INSTALLED path in step 7."
fi

hdr "3. Payload -- exclusions and expected contents"
rpm -qlp "$RPM" > /tmp/files.txt 2>/dev/null
echo "  payload has $(wc -l < /tmp/files.txt) entries"
for want in "/opt/em7/services/powerpack-mcp" \
            "/opt/em7/services/powerpack-mcp-1.0/venv/bin/python" \
            "/opt/em7/services/powerpack-mcp-1.0/nginx/powerpack-mcp.fragment" \
            "/opt/em7/share/config/nginx.d/powerpack-mcp-zone.conf" \
            "/usr/lib/systemd/system/powerpack-mcp.service" \
            "/opt/em7/services/powerpack-mcp-1.0/docs/operations.md"; do
  grep -qx "$want" /tmp/files.txt && ok "present: $want" || bad "MISSING: $want"
done
# The exclusions are about the project's own tests/ and packaging/ directories.  The bundled venv
# legitimately contains matches (`certifi/tests/`, `jeepney/io/tests/`, and the `packaging` PyPI
# dependency), so third-party site-packages content is left out of the check.
grep -v "/site-packages/" /tmp/files.txt > /tmp/files.own.txt
echo "  $(wc -l < /tmp/files.own.txt) entries outside the bundled venv's site-packages"
for bad_pat in "Dockerfile" "docker-compose" "/tests/" "/packaging/" "\.github"; do
  if grep -q "$bad_pat" /tmp/files.own.txt; then
    bad "payload exclusion violated -- payload contains '$bad_pat':"; grep "$bad_pat" /tmp/files.own.txt | head -3 | sed 's/^/          /'
  else ok "excluded: $bad_pat"; fi
done
echo "  --- is the env file a %ghost? ---"
# Read the file flags directly.  `rpm -qlp --ghost` is not a valid rpm 4.14 query flag (the flag
# is --noghost), and %ghost files do appear in a plain `rpm -ql`, so neither answers the question.
rpm -qp --qf '[%{FILENAMES} %{FILEFLAGS:fflags}\n]' "$RPM" 2>/dev/null > /tmp/fflags.txt
ENVLINE=$(grep "powerpack-mcp\.env" /tmp/fflags.txt | head -1)
echo "        flags: ${ENVLINE:-<env file absent from payload>}"
case "$ENVLINE" in
  *g*) ok "env file carries the %ghost flag, at: ${ENVLINE%% *}" ;;
  "")  bad "env file absent from the payload entirely" ;;
  *)   bad "env file present but NOT flagged %ghost" ;;
esac

hdr "4. Version (must not be 0.0.0+unknown)"
PV=$(rpm -qp --qf '%{VERSION}' "$RPM" 2>/dev/null)
echo "  package version = $PV"
[ "$PV" = "0.0.0+unknown" ] && bad "version is the unknown fallback" || ok "version preserved from the sdist"

hdr "5. nginx scaffolding (stands in for the appliance's server block)"
mkdir -p /opt/em7/share/config/nginx.d
cat > /opt/em7/share/config/nginx.d/security_headers.fragment <<'EOF'
add_header X-Content-Type-Options nosniff always;
add_header Strict-Transport-Security "max-age=31536000" always;
EOF
# Stands in for em7ngx_web_ui.fragment, the platform-owned file %post edits.
cat > /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment <<'EOF'
    client_max_body_size 256M;
    include /opt/em7/share/config/nginx.d/security_headers.fragment;
    location = /auth_user { internal; return 200; }
    location / { return 404; }
EOF
cat > /etc/nginx/conf.d/em7.conf <<'EOF'
server {
    listen 8443;
    server_name _;
    include /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment;
}
EOF
# The appliance's /etc/nginx/nginx.conf carries, at http level (line 31):
#     include /opt/em7/share/config/nginx.d/*.conf;
# That wildcard is what makes powerpack-mcp-zone.conf's `limit_req_zone` visible; limit_req_zone
# is valid only in the http context, which is why the zone file is separate from the fragment.
# Without it the fragment's `limit_req zone=powerpack_mcp` references an undeclared zone and nginx
# rejects a correct fragment.  conf.d/*.conf is itself included from inside http{}, so this
# reproduces the appliance's context.
cat > /etc/nginx/conf.d/em7-nginxd-wildcard.conf <<'EOF'
include /opt/em7/share/config/nginx.d/*.conf;
EOF
nginx -t >/dev/null 2>&1 && ok "baseline nginx config is valid before install" || bad "baseline nginx invalid"
grep -q "nginx.d/\*.conf" /etc/nginx/conf.d/em7-nginxd-wildcard.conf \
  && ok "http-level nginx.d/*.conf wildcard in place (mirrors appliance nginx.conf:31)" \
  || bad "http-level wildcard missing -- zone file would be invisible"

hdr "6. INSTALL  (%post, %posttrans)"
rpm -i "$RPM" >/tmp/inst.log 2>&1; RC=$?
echo "  rpm -i exit=$RC"; sed 's/^/        /' /tmp/inst.log | head -12
[ "$RC" = 0 ] && ok "install returned 0" || bad "install returned $RC"

# `rpm -i exit=0` proves almost nothing: rpm exits 0 even when a scriptlet fails.  A run that
# asserted only the exit code printed
#
#     /var/tmp/rpm-tmp.XXXX: line 80: unexpected EOF while looking for matching `'
#     warning: %posttrans(...) scriptlet failed, exit status 2
#
# and still reported "RESULT: 0 failure(s)", although the broken %posttrans meant no nginx
# validation, no include self-heal and no service restart.  So scan for scriptlet failure
# explicitly, on every rpm invocation that runs one.
assert_no_scriptlet_failure() {
  local log="$1" label="$2"
  if grep -qE "scriptlet failed|syntax error|unexpected EOF|command not found" "$log" 2>/dev/null; then
    bad "$label -- A SCRIPTLET FAILED (rpm still exited 0; see below)"
    grep -E "scriptlet failed|syntax error|unexpected EOF|command not found" "$log" \
      | head -4 | sed 's/^/          /'
  else
    ok "$label -- no scriptlet errors in rpm output"
  fi
}
assert_no_scriptlet_failure /tmp/inst.log "install scriptlets"
rpm -q powerpack-mcp-1.0 >/dev/null 2>&1 && ok "package registered" || bad "package not registered"

echo "  --- the symlink ---"
[ -L /opt/em7/services/powerpack-mcp ] \
  && ok "symlink -> $(readlink /opt/em7/services/powerpack-mcp)" || bad "symlink missing"

echo "  --- the env file ---"
if [ -f /opt/em7/services/powerpack-mcp/powerpack-mcp.env ]; then
  ok "created: $(stat -c 'mode=%a owner=%U:%G' /opt/em7/services/powerpack-mcp/powerpack-mcp.env)"
  # The env file must not contain a credential key.  There is no LCE_CREDENTIAL: each caller
  # presents their own credential in the Authorization header, so there is nothing for the
  # operator to paste.
  if grep -qE '^#?[[:space:]]*LCE_CREDENTIAL=' /opt/em7/services/powerpack-mcp/powerpack-mcp.env; then
    bad "a credential key is present in the env file; the service has none (has it crept back?)"
    grep -nE '^#?[[:space:]]*LCE_CREDENTIAL=' /opt/em7/services/powerpack-mcp/powerpack-mcp.env \
      | sed 's/^/          /'
  else
    ok "no credential key in the env file -- nothing for the operator to supply"
  fi
else bad "env file was NOT created by %post"; fi

echo "  --- install must NOT enable the service ---"
grep -q "systemctl enable" /tmp/inst.log && bad "install tried to enable" || ok "no enable attempted"
[ -L /etc/systemd/system/multi-user.target.wants/powerpack-mcp.service ] \
  && bad "service IS enabled by install" || ok "service not enabled"

echo "  --- the include line %post adds ---"
grep -c "powerpack-mcp/nginx/powerpack-mcp.fragment" \
  /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment | grep -qx 1 \
  && ok "include line added exactly once" \
  || bad "include line count = $(grep -c powerpack-mcp/nginx /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment)"

echo "  --- nginx -t with the real fragment in place ---"
# Check the fragment is actually included first.  If %posttrans's nginx -t failed, its clean-up has
# already removed the fragment and include line, and a bare nginx -t here would validate a config
# without the fragment and report a false pass.
if ! grep -q "powerpack-mcp/nginx/powerpack-mcp.fragment" \
       /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment; then
  bad "CANNOT ASSERT nginx -t -- the fragment is not included (self-cleaned or never added)"
elif nginx -t >/tmp/ngx.log 2>&1; then
  ok "nginx -t PASSES, and the shipped fragment IS in the config"
else
  bad "nginx -t FAILED with the shipped fragment"; sed 's/^/        /' /tmp/ngx.log | head -6
fi

hdr "6b. Behavioural nginx checks -- real requests, not just nginx -t"
# ---------------------------------------------------------------------------------------------
# Every nginx assertion before this point is `nginx -t`, which checks only that the config is
# valid.  Some defects produce a valid config:
#
#   * the caller's Authorization reaching the service only through nginx's default pass-through
#     of unknown headers;
#   * a duplicate Content-Type on the @mcp_* envelopes, where the body is still valid JSON, so
#     only the response headers show it.
#
# So this starts nginx for real and makes requests through it.  It still does not verify
# appliance behaviour: /auth_user here is a stub, not the platform's authenticator.
# ---------------------------------------------------------------------------------------------

# This section must be driven over TLS.  `location /mcp` opens with the HTTPS guard
#     if ($scheme = http) { return 308 https://$host$request_uri; }
# so a plain-HTTP probe gets a 308 HTML page instead of reaching the fragment's logic, and checks
# such as "exactly one Content-Type" or "security headers survive" are true of that page too.
# Every check below is therefore gated on the expected status code before it inspects anything.

# A self-signed cert so $scheme is https, matching the appliance.  Throwaway, 1 day, never shipped.
openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/bt-tls.key -out /tmp/bt-tls.crt \
  -subj "/CN=localhost" -days 1 >/dev/null 2>&1

# A header-echoing upstream on the port the fragment proxies to.  Pure nginx -- it interpolates
# variables into `return` bodies, so no extra process or language runtime is needed.
# Plain HTTP is correct here: the fragment proxies to http://127.0.0.1:8000.
cat > /etc/nginx/conf.d/zz-echo-upstream.conf <<'EOF'
server {
    listen 127.0.0.1:8000;
    location / {
        default_type application/json;
        return 200 '{"authorization":"$http_authorization","user_id":"$http_x_user_id","remote_user":"$http_x_remote_user"}';
    }
}
EOF

# A TLS vhost on a SEPARATE port, so the existing 8443 plain stub other sections rely on is
# untouched.  Same fragment, included the same way.
cat > /etc/nginx/conf.d/zz-tls-vhost.conf <<'EOF'
server {
    listen 127.0.0.1:8444 ssl;
    server_name localhost;
    ssl_certificate     /tmp/bt-tls.crt;
    ssl_certificate_key /tmp/bt-tls.key;
    include /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment;
}
EOF

B="https://127.0.0.1:8444"

if ! nginx -t >/tmp/ngx-echo.log 2>&1; then
  bad "the behavioural scaffolding made the config invalid -- checks skipped"
  sed 's/^/        /' /tmp/ngx-echo.log | head -5
else
  nginx >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1
  sleep 1
  if [ "$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "$B/health" 2>/dev/null)" != 200 ]; then
    bad "nginx did not serve TLS on 8444 -- behavioural checks skipped"
  else
    ok "TLS vhost up; /health reachable anonymously over https"
    CRED='Basic dXNlcjpwYXNzd29yZA=='      # synthetic: base64 of user:password.  Never a real one.

    echo "  --- does the caller's Authorization actually REACH the upstream? ---"
    CODE=$(curl -sk -o /tmp/b1 -w '%{http_code}' --max-time 5 -X POST \
             -H "Authorization: $CRED" "$B/mcp" 2>/dev/null)
    if [ "$CODE" != 200 ]; then
      bad "Authorization forwarding -- expected 200 from the echo upstream, got $CODE (not testing what was intended)"
      head -c 160 /tmp/b1 | sed 's/^/        /'
    elif grep -qF "$CRED" /tmp/b1; then
      ok "Authorization arrived at the upstream intact"
    else
      bad "Authorization did NOT arrive. Upstream saw: $(head -c 160 /tmp/b1)"
    fi

    echo "  --- a forged identity header must NOT survive ---"
    CODE=$(curl -sk -o /tmp/b2 -w '%{http_code}' --max-time 5 -X POST \
             -H "Authorization: $CRED" -H "X-Remote-User: admin" "$B/mcp" 2>/dev/null)
    if [ "$CODE" != 200 ]; then
      bad "forgery check -- expected 200, got $CODE (assertion skipped rather than faked)"
    elif grep -q '"remote_user":""' /tmp/b2; then
      ok "X-Remote-User was blanked -- the attribution-forgery vector stays closed"
    else
      bad "X-Remote-User SURVIVED to the upstream: $(head -c 160 /tmp/b2)"
    fi

    echo "  --- /ready must be gone, and must NOT 502 ---"
    CODE=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 \
             -H "Authorization: $CRED" "$B/ready" 2>/dev/null)
    case "$CODE" in
      404) ok "/ready returns 404 -- the route is gone and falls through, as designed" ;;
      502) bad "/ready returned 502 -- the location still proxies to a route the service dropped" ;;
      *)   bad "/ready returned unexpected $CODE (expected 404)" ;;
    esac

    echo "  --- the WWW-Authenticate challenge and a single Content-Type, on a REAL 401 ---"
    # Force the auth subrequest to fail so error_page 401 -> @mcp_401 is exercised.
    sed -i 's|location = /auth_user { internal; return 200; }|location = /auth_user { internal; return 401; }|' \
      /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment
    if ! nginx -s reload >/dev/null 2>&1; then
      bad "could not reload nginx to exercise the 401 path"
    else
      sleep 1
      CODE=$(curl -sk -D /tmp/h401 -o /tmp/b401 -w '%{http_code}' --max-time 5 -X POST \
               -H "Authorization: $CRED" "$B/mcp" 2>/dev/null)

      # GATE: everything below is meaningless unless this really is the @mcp_401 envelope.
      if [ "$CODE" != 401 ]; then
        bad "expected 401 from a denying authenticator, got $CODE -- ALL @mcp_401 assertions SKIPPED"
        echo "        (skipped rather than asserted, so nothing here can report a false pass)"
        head -1 /tmp/h401 | sed 's/^/        /'
      else
        ok "401 returned when the authenticator denies (fail-closed)"

        grep -qi '^www-authenticate:.*Basic' /tmp/h401 \
          && ok "WWW-Authenticate: Basic present on a real 401" \
          || bad "no WWW-Authenticate on the 401 (is the 'always' flag missing?)"

        grep -qi '^www-authenticate:.*realm=' /tmp/h401 \
          && ok "challenge carries a realm" || bad "challenge has no realm"

        CT=$(grep -ci '^content-type:' /tmp/h401)
        if [ "$CT" = 1 ]; then
          ok "exactly ONE Content-Type on the 401 envelope -- duplicate-header defect fixed"
        else
          bad "Content-Type appears $CT times (RFC 9110 s5.5 singleton violation)"
          grep -i '^content-type:' /tmp/h401 | sed 's/^/        /'
        fi

        grep -qi '^content-type:.*application/json' /tmp/h401 \
          && ok "the single Content-Type is application/json (default_type applies to a return body)" \
          || bad "Content-Type is not application/json: $(grep -i '^content-type:' /tmp/h401)"

        grep -qi '^strict-transport-security:' /tmp/h401 \
          && ok "security headers survive on the 401 envelope" \
          || bad "security headers MISSING from the 401"

        grep -q '"error"' /tmp/b401 \
          && ok "401 body is the nested MCP error envelope" \
          || bad "401 body is not the expected envelope: $(head -c 120 /tmp/b401)"
      fi
    fi

    echo "  --- the HTTPS guard itself: plain HTTP must 308, not proxy ---"
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST \
             -H "Authorization: $CRED" http://127.0.0.1:8443/mcp 2>/dev/null)
    [ "$CODE" = 308 ] \
      && ok "plain HTTP to /mcp returns 308 -- the credential is never sent in clear" \
      || bad "plain HTTP to /mcp returned $CODE, expected 308"

    # Restore the permissive stub so later sections are unaffected.
    sed -i 's|location = /auth_user { internal; return 401; }|location = /auth_user { internal; return 200; }|' \
      /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment
    nginx -s reload >/dev/null 2>&1
  fi
  nginx -s stop >/dev/null 2>&1
  rm -f /etc/nginx/conf.d/zz-echo-upstream.conf /etc/nginx/conf.d/zz-tls-vhost.conf \
        /tmp/bt-tls.crt /tmp/bt-tls.key
  nginx -t >/dev/null 2>&1 \
    && ok "config still valid after removing the behavioural scaffolding" \
    || bad "config invalid after behavioural checks -- later sections are unreliable"
fi

hdr "7. RELOCATION from the INSTALLED path"
# Run as s-em7-core, as systemd does.  Run as root, the app refuses the env file owned by
# s-em7-core ("file uid 997, process euid 0"), and a correct refusal looks like a failure.
#
# Every config key is optional, so the service starts and serves for ever; $(...) would wait for
# an EOF that never comes and hang the harness.  Hence the `timeout`, and it must go inside the su
# command, wrapping python directly.  Outside (`timeout 10 su -c '...'`) it kills `su` but can
# leave the python child holding the pipe, so the command substitution still blocks.  -k 2
# escalates to KILL if the server ignores TERM.
#
# Exit 124 (killed by timeout while serving) is the pass: a service that starts and serves shows
# the venv relocated.  "bad interpreter" and ModuleNotFoundError are the relocation failures.
AS_SVC="su -s /bin/bash s-em7-core -c"
OUT=$($AS_SVC 'timeout -k 2 10 /opt/em7/services/powerpack-mcp/venv/bin/python -m powerpack_mcp' 2>&1)
RC=$?
if   echo "$OUT" | grep -q "bad interpreter";   then bad "venv not relocatable (bad interpreter)"
elif echo "$OUT" | grep -q "ModuleNotFoundError"; then bad "editable install (ModuleNotFoundError)"
elif echo "$OUT" | grep -q "not owned by the account running this service"; then
  bad "still an ownership error -- the test is not running as s-em7-core"; echo "$OUT" | tail -3 | sed 's/^/        /'
elif [ "$RC" = 124 ]; then
  ok "started and kept serving until timeout -- venv relocated"
elif echo "$OUT" | grep -q "LCE_CREDENTIAL is not set"; then
  ok "ConfigurationError for a missing credential -- accepted for older builds that required one"
else bad "unrecognised output (rc=$RC):"; echo "$OUT" | tail -4 | sed 's/^/        /'; fi
echo "  --- and the console script ---"
# Capture the output into a variable, then match; do not pipe it straight into grep.  This script
# runs under `set -o pipefail`, and when the command exits non-zero (killed by timeout, or an older
# build refusing to start), `cmd | grep -q "expected"` returns that status even when grep matched.
# systemd's ExecStart uses `python -m powerpack_mcp`, not this console script, so a failure here
# does not affect the service, but the console script should still work.
CS=/opt/em7/services/powerpack-mcp/venv/bin/powerpack_mcp
if [ ! -e "$CS" ]; then
  bad "console script absent at $CS"
  ls -la /opt/em7/services/powerpack-mcp/venv/bin/ 2>&1 | grep -iE "powerpack|python" | sed 's/^/          /'
else
  echo "        shebang: $(head -1 "$CS" 2>/dev/null)"
  echo "        perms:   $(stat -c '%a %U:%G' "$CS")"
  # The same timeout as above, for the same reason.
  CSOUT=$($AS_SVC "timeout -k 2 10 $CS" 2>&1)
  CSRC=$?
  if   echo "$CSOUT" | grep -q "bad interpreter";   then bad "console script -- bad interpreter"
  elif echo "$CSOUT" | grep -q "ModuleNotFoundError"; then bad "console script -- ModuleNotFoundError"
  elif [ "$CSRC" = 124 ]; then ok "console script started and served until timeout"
  elif echo "$CSOUT" | grep -q "LCE_CREDENTIAL is not set"; then ok "console script also works (older build)"
  else bad "console script broken (rc=$CSRC):"; echo "$CSOUT" | tail -5 | sed 's/^/          /'; fi
fi

hdr "8. UPGRADE, release bump (scriptlet guards, config preserved)"

# --- does the package ask systemd to restart a running service on upgrade? ---
#
# This is a static check and cannot prove runtime behaviour.  systemd is not usable in this
# container ("System has not been booted with systemd as init system"), so try-restart cannot run
# here, and every systemctl call in the scriptlets is swallowed by `|| :`.  This asserts that the
# directive is present in the shipped %posttrans; without it, `rpm -U` replaces every file and
# leaves the old process serving.  Runtime proof needs an appliance.
if rpm -qp --scripts "$RPM" 2>/dev/null | awk '/^posttrans/,0' | grep -q 'try-restart powerpack-mcp.service'; then
  ok "%posttrans asks systemd to try-restart the service (static check)"
else
  bad "REGRESSION -- no try-restart in %posttrans; an upgrade would leave old code running"
fi
# The inverse matters just as much: install must still not START or ENABLE anything.
# try-restart is a no-op on an inactive unit, so `start` or `enable` appearing here would be a
# different and worse defect.
if rpm -qp --scripts "$RPM" 2>/dev/null | grep -qE '^\s*%?\{?_bindir\}?/?systemctl (start|enable) '; then
  bad "a scriptlet STARTS or ENABLES the unit; install must do neither"
else
  ok "no scriptlet starts or enables the unit"
fi
printf 'LCE_CREDENTIAL="Bearer OPERATOR SUPPLIED VALUE"\n' > /opt/em7/services/powerpack-mcp/powerpack-mcp.env
chmod 0600 /opt/em7/services/powerpack-mcp/powerpack-mcp.env
sed 's/^Release:        1/Release:        2/' /root/rpmbuild/SPECS/powerpack-mcp.spec > /root/rpmbuild/SPECS/v2.spec
# Clear build 1's tree, or build 2's `uv venv` finds an existing venv and fails with
# "Use the --clear flag ...".
rm -rf /root/rpmbuild/BUILD/* /root/rpmbuild/BUILDROOT/* 2>/dev/null
rpmbuild -bb --define "service_build_version $VER" /root/rpmbuild/SPECS/v2.spec >/tmp/b2.log 2>&1 \
  && ok "release-2 built" || { bad "release-2 build failed"; tail -8 /tmp/b2.log | sed 's/^/        /'; }
RPM2=$(find /root/rpmbuild/RPMS -name '*-2*.rpm' | head -1)
if [ -n "$RPM2" ]; then
  rpm -U "$RPM2" >/tmp/up.log 2>&1; echo "  rpm -U exit=$?"; sed 's/^/        /' /tmp/up.log | head -8
  # A silently broken %posttrans is worst here: no restart and no nginx validation, with rpm
  # reporting success.
  assert_no_scriptlet_failure /tmp/up.log "upgrade scriptlets"
  grep -q "OPERATOR SUPPLIED VALUE" /opt/em7/services/powerpack-mcp/powerpack-mcp.env \
    && ok "operator's env file PRESERVED across the release bump" \
    || bad "operator's env file contents lost on upgrade"
  ls /opt/em7/services/powerpack-mcp/powerpack-mcp.env.rpmnew >/dev/null 2>&1 \
    && bad "an .rpmnew appeared -- %ghost not working" || ok "no .rpmnew (%ghost working)"
  grep -c "powerpack-mcp/nginx/powerpack-mcp.fragment" \
    /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment | grep -qx 1 \
    && ok "include line still exactly once -- NOT duplicated, NOT deleted" \
    || bad "include line count wrong after upgrade: $(grep -c powerpack-mcp/nginx /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment)"
  nginx -t >/dev/null 2>&1 && ok "nginx -t still passes after upgrade" || bad "nginx -t broken after upgrade"
fi

hdr "9. Self-heal (%posttrans re-adds a removed include line)"
sed -i '/# PowerPack MCP Server/,+1d' /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment
grep -q "powerpack-mcp/nginx" /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment \
  && bad "line not actually removed" || echo "        simulated a platform upgrade wiping the line"
rpm -U --force "$RPM2" >/tmp/heal.log 2>&1
grep -c "powerpack-mcp/nginx/powerpack-mcp.fragment" \
  /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment | grep -qx 1 \
  && ok "%posttrans re-added the include line" \
  || bad "self-heal did not restore the include line"

hdr "10. ERASE (env file survives, nginx stays valid)"
rpm -e powerpack-mcp-1.0 >/tmp/er.log 2>&1; echo "  rpm -e exit=$?"; sed 's/^/        /' /tmp/er.log | head -8
echo "  --- the operator's env file must SURVIVE ---"
if [ -f /opt/em7/services/powerpack-mcp-1.0/powerpack-mcp.env ]; then
  ok "env file survived: $(stat -c 'mode=%a owner=%U:%G' /opt/em7/services/powerpack-mcp-1.0/powerpack-mcp.env)"
  grep -q "OPERATOR SUPPLIED VALUE" /opt/em7/services/powerpack-mcp-1.0/powerpack-mcp.env \
    && ok "contents intact -- a reinstall would resume" || bad "file survived but contents lost"
else
  bad "env file DELETED on erase"
  ls -a /opt/em7/services/powerpack-mcp-1.0/ 2>&1 | sed 's/^/        /'
fi
echo "  --- nginx must be VALID AFTER REMOVAL ---"
grep -q "powerpack-mcp/nginx" /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment \
  && bad "include line NOT removed -- dangling include" || ok "include line removed"
nginx -t >/tmp/ngx2.log 2>&1 && ok "nginx -t PASSES after removal (the forgotten direction)" \
  || { bad "nginx -t FAILS after removal"; sed 's/^/        /' /tmp/ngx2.log | head -6; }
[ -f /opt/em7/share/config/nginx.d/powerpack-mcp-zone.conf ] \
  && bad "zone file left behind" || ok "zone file removed"

hdr "11. Idempotent re-erase"
rpm -e powerpack-mcp-1.0 >/tmp/er2.log 2>&1 && ok "second erase returned 0" || ok "second erase refused cleanly (expected: not installed)"
nginx -t >/dev/null 2>&1 && ok "nginx still valid" || bad "nginx broken by re-erase"

# =============================================================================================
hdr "12. The single-version-at-a-time constraint"
# Version-in-the-package-name does not allow parallel installs, because two versions each want to
# own three single-instance resources:
#   1. the symlink  /opt/em7/services/powerpack-mcp                      -- RPM-OWNED
#   2. the zone file  nginx.d/powerpack-mcp-zone.conf                    -- RPM-OWNED
#   3. the include line in em7ngx_web_ui.fragment                        -- NOT rpm-owned; %post/%postun
# Resource 3 is the root of it: %posttrans does not run on a pure erase, so removal must live in
# %postun, which cannot see whether a sibling remains.
#
# This section checks that RPM enforces the constraint.  If resources 1 and 2 make RPM abort
# before any scriptlet runs, the constraint is self-enforcing and resource 3 is never reached by a
# supported operation.
#
# One more test-only spec change: `%global service_version 1.0` is unconditional, so a
# command-line --define cannot override it.  The sibling is made by rewriting that one line, as
# BuildArch and Release are rewritten above.  Nothing else is changed.

sed -e 's/^%global service_version .*/%global service_version 1.1/' \
    /root/rpmbuild/SPECS/powerpack-mcp.spec > /root/rpmbuild/SPECS/v11.spec
rm -rf /root/rpmbuild/BUILD/* /root/rpmbuild/BUILDROOT/* 2>/dev/null
if rpmbuild -bb --define "service_build_version $VER" /root/rpmbuild/SPECS/v11.spec >/tmp/b11.log 2>&1; then
  ok "sibling powerpack-mcp-1.1 built"
else
  bad "sibling 1.1 build failed"; tail -8 /tmp/b11.log | sed 's/^/        /'
fi
RPM11=$(find /root/rpmbuild/RPMS -name 'powerpack-mcp-1.1-*.rpm' | head -1)
echo "        sibling: $(basename "${RPM11:-<none>}")"

if [ -z "$RPM11" ]; then
  bad "single-version constraint NOT TESTED -- no sibling package to install"
else
  echo "  --- reinstall 1.0 as the incumbent (steps 10/11 erased it) ---"
  rpm -i "${RPM2:-$RPM}" >/tmp/re1.log 2>&1
  rpm -q powerpack-mcp-1.0 >/dev/null 2>&1 && ok "1.0 reinstalled as incumbent" || bad "could not reinstall 1.0"
  BASE_LINK=$(readlink /opt/em7/services/powerpack-mcp 2>/dev/null)
  echo "        incumbent symlink -> $BASE_LINK"

  echo "  --- THE TEST: install 1.1 alongside 1.0. RPM must REFUSE. ---"
  rpm -i "$RPM11" >/tmp/par.log 2>&1; PRC=$?
  echo "  rpm -i (sibling) exit=$PRC"; sed 's/^/        /' /tmp/par.log | head -10
  if [ "$PRC" != 0 ]; then
    ok "RPM REFUSED the parallel install -- the constraint is enforced by RPM, not just documented"
    grep -qiE "conflicts with|file .* from install" /tmp/par.log \
      && ok "refusal is a FILE CONFLICT (fires before any scriptlet runs)" \
      || echo "        NOTE: refused, but not via a file conflict -- see the log above"
    for res in "/opt/em7/services/powerpack-mcp" "/opt/em7/share/config/nginx.d/powerpack-mcp-zone.conf"; do
      grep -q "$res" /tmp/par.log && ok "conflict names $res" \
        || echo "        NOTE: conflict did not name $res"
    done
  else
    bad "RPM ALLOWED a parallel install -- the single-version constraint is NOT enforced"
  fi

  echo "  --- and the incumbent must be UNTOUCHED (a blocked install must leave nothing half-done) ---"
  rpm -q powerpack-mcp-1.1 >/dev/null 2>&1 && bad "1.1 registered despite the refusal" || ok "1.1 not registered"
  [ "$(readlink /opt/em7/services/powerpack-mcp 2>/dev/null)" = "$BASE_LINK" ] \
    && ok "symlink still -> $BASE_LINK" || bad "symlink CHANGED to $(readlink /opt/em7/services/powerpack-mcp)"
  [ -f /opt/em7/share/config/nginx.d/powerpack-mcp-zone.conf ] \
    && ok "zone file still present" || bad "zone file lost"
  grep -c "powerpack-mcp/nginx/powerpack-mcp.fragment" /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment \
    | grep -qx 1 && ok "include line still exactly once (resource 3 untouched)" \
    || bad "include line count = $(grep -c powerpack-mcp/nginx /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment)"
  grep -q "OPERATOR SUPPLIED VALUE" /opt/em7/services/powerpack-mcp/powerpack-mcp.env 2>/dev/null \
    && ok "incumbent env file intact" || bad "incumbent env file contents lost"
  nginx -t >/dev/null 2>&1 && ok "nginx -t still passes" || bad "nginx -t broken by the refused install"

  echo "  --- now the DOCUMENTED path: erase-then-install (the version-bump model) ---"
  rpm -e powerpack-mcp-1.0 >/tmp/e10.log 2>&1
  rpm -i "$RPM11" >/tmp/i11.log 2>&1; IRC=$?
  [ "$IRC" = 0 ] && ok "erase-then-install succeeded (exit 0)" || { bad "erase-then-install FAILED exit=$IRC"; sed 's/^/        /' /tmp/i11.log | head -6; }
  [ "$(readlink /opt/em7/services/powerpack-mcp 2>/dev/null)" = "powerpack-mcp-1.1" ] \
    && ok "symlink now -> powerpack-mcp-1.1" || bad "symlink wrong: $(readlink /opt/em7/services/powerpack-mcp)"
  grep -c "powerpack-mcp/nginx/powerpack-mcp.fragment" /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment \
    | grep -qx 1 && ok "include line exactly once after the swap" \
    || bad "include line count = $(grep -c powerpack-mcp/nginx /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment)"
  nginx -t >/dev/null 2>&1 && ok "nginx -t passes on 1.1" || bad "nginx -t fails on 1.1"

  # Characterisation, not a contract test.  `rpm -i --force` bypasses conflict detection, so it can
  # reach the unsupported dual-installed state.  It is the only route to resource 3's %postun
  # sibling-blindness, and an operator who forces an install should know what it costs.  A bad
  # outcome here is not counted as a failure; forced installs are outside the contract.
  echo "  --- characterising the FORCED (unsupported) state: rpm -i --force ---"
  if rpm -i --force "${RPM2:-$RPM}" >/tmp/force.log 2>&1; then
    echo "        --force DID create the dual-installed state RPM otherwise blocks"
    echo "        rpm -qa: $(rpm -qa 'powerpack-mcp-*' | tr '\n' ' ')"
    rpm -e powerpack-mcp-1.1 >/tmp/f11.log 2>&1
    FL=$(grep -c "powerpack-mcp/nginx/powerpack-mcp.fragment" /opt/em7/share/config/nginx.d/em7ngx_web_ui.fragment)
    if [ "$FL" = 0 ]; then
      echo "        NOTE (expected, documented): erasing one sibling REMOVED the shared include line."
      echo "              This is resource 3's %postun sibling-blindness, as predicted above,"
      echo "              and exactly why single-version-at-a-time is the supported model."
    else
      echo "        NOTE: include line survived the sibling erase (count=$FL)"
    fi
    nginx -t >/dev/null 2>&1 && echo "        nginx -t still valid in the forced state" \
                             || echo "        NOTE: nginx -t INVALID in the forced state"
  else
    echo "        --force also refused; the dual state was not reachable here"
  fi
  rpm -e powerpack-mcp-1.1 powerpack-mcp-1.0 >/dev/null 2>&1
  nginx -t >/dev/null 2>&1 && ok "nginx -t valid after cleanup" || bad "nginx -t invalid after cleanup"
fi

echo; echo "================ RESULT: $FAIL failure(s) ================"
exit 0

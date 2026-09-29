#!/bin/bash
# =============================================================================================
# PowerPack MCP Server -- post-install verification.  Run this after `rpm -i` and after
# `systemctl enable --now powerpack-mcp`.
#
# Answers the question `rpm` cannot: "is this actually working?"  A failing %post or %posttrans
# scriptlet does not abort the transaction, and `rpm -i` exits 0 regardless, so the install's exit
# status is not evidence of anything.  This script checks the effects instead.
#
# See docs/operations.md for the install procedure.  Run scripts/mcp-preflight.sh before the
# install.
#
# ---------------------------------------------------------------------------------------------
# Usage -- on the appliance, as root (see mcp-preflight.sh for why there is no --host mode):
#
#     scp scripts/mcp-verify.sh em7admin@<appliance>:/tmp/
#     ssh -t em7admin@<appliance> 'sudo bash /tmp/mcp-verify.sh'
#
# The full surface check needs a Skylar One credential.  Supply it in the environment, not argv:
#
#     ssh -t em7admin@<appliance>
#     read -rs -p 'password: ' MCP_PASS; export MCP_PASS MCP_USER=em7admin
#     sudo -E bash /tmp/mcp-verify.sh
#
# The credential is deliberately never put in argv.  `curl -u user:pass` is visible to every user
# on the box in `ps` for the life of the request.  This script hands it to curl through a `-K -`
# config on stdin instead, so it never appears in the process table, in your shell history, or in
# this script's output.  Any credential you can authenticate with will do; the checks it drives
# are all read-only.
#
# Without root it still runs and reports the privileged checks as SKIP.  A SKIP is not a PASS.
# Without a credential it still runs; the two checks that need one report SKIP, and those are the
# only two that prove the service is really serving MCP.
#
# EXIT CODES:  0 = every executed check passed.  1 = at least one FAIL.  2 = cannot run at all.
# =============================================================================================

set -uo pipefail

FAIL=0; WARN=0; SKIP=0
ok()    { echo "  PASS   $*"; }
bad()   { echo "  FAIL   $*"; FAIL=$((FAIL+1)); }
warn()  { echo "  WARN   $*"; WARN=$((WARN+1)); }
skip()  { echo "  SKIP   $*"; SKIP=$((SKIP+1)); }
# Fixed-width banner: "=== title " padded out to 92 columns.  A fixed suffix made the long
# section titles wrap in an 80-column terminal, which is where these actually get read.
_FILL='============================================================================================'
head1() { local t="=== $* "; printf '\n%s%s\n' "$t" "${_FILL:${#t}}"; }

MCP_URL="https://127.0.0.1/mcp"
WAITED=0
MCP_USER="${MCP_USER:-}"; MCP_PASS="${MCP_PASS:-}"
EXPECT_TOOLS="${EXPECT_TOOLS:-55}"
while [ $# -gt 0 ]; do
  case "$1" in
    --url)   MCP_URL="${2:-}"; shift 2 ;;
    --user)  MCP_USER="${2:-}"; shift 2 ;;
    --tools) EXPECT_TOOLS="${2:-}"; shift 2 ;;
    -h|--help) sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1  (try --help)" >&2; exit 2 ;;
  esac
done

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
SVC=/opt/em7/services/powerpack-mcp
NGINX_D=/opt/em7/share/config/nginx.d
WEB_FRAGMENT="$NGINX_D/em7ngx_web_ui.fragment"
ENV_FILE="$SVC/powerpack-mcp.env"
TMP=$(mktemp -d /tmp/mcp-verify.XXXXXX) || exit 2
trap 'rm -rf "$TMP"' EXIT
RESP="$TMP/resp"; HDR="$TMP/hdr"

echo "PowerPack MCP verification -- $(hostname) -- $(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ "$IS_ROOT" -eq 1 ] || echo "NOTE: not running as root.  Privileged checks will report SKIP."

# =============================================================================================
head1 "1. The package, and what it put on disk"

if RPMV=$(rpm -q powerpack-mcp-1.0 2>/dev/null); then
  ok "installed: $RPMV"
  # Query the name with -1.0.  Plain `rpm -q powerpack-mcp` reports "not installed" even here,
  # because the service version is part of the package name.
  PKGVER=$(rpm -q --qf '%{VERSION}' powerpack-mcp-1.0 2>/dev/null)
  case "$PKGVER" in
    0.0.0*) bad "version is 0.0.0+unknown -- indistinguishable from a broken install" ;;
    *dev*)  warn "development version $PKGVER from an untagged commit -- not a release" ;;
  esac
else
  bad "powerpack-mcp-1.0 is NOT installed.  Nothing below can pass; stop here."
  echo; echo "RESULT: FAIL=$FAIL"; exit 1
fi

# The unit, the include line and the env path all reference the symlink and never the versioned
# directory, which keeps them version-independent.
if [ -L "$SVC" ]; then
  tgt=$(readlink "$SVC")
  [ "$tgt" = powerpack-mcp-1.0 ] && ok "symlink $SVC -> $tgt" \
    || bad "symlink points at '$tgt', expected powerpack-mcp-1.0"
else
  bad "$SVC is not a symlink -- the version indirection is broken"
fi

# %ghost + %config(noreplace) + %attr(0600).  The service also checks the mode at every startup,
# refusing to start if the file is group- or world-accessible.
if [ -e "$ENV_FILE" ]; then
  perm=$(stat -c '%a %U:%G' "$ENV_FILE")
  [ "$perm" = "600 s-em7-core:s-em7-core" ] \
    && ok "env file is 0600 s-em7-core:s-em7-core" \
    || bad "env file is '$perm', expected '600 s-em7-core:s-em7-core' -- the service will refuse to start"
else
  bad "env file $ENV_FILE is MISSING -- %post's creation step did not run"
fi
for f in "$SVC/nginx/powerpack-mcp.fragment" "$NGINX_D/powerpack-mcp-zone.conf" \
         /usr/lib/systemd/system/powerpack-mcp.service "$SVC/docs/operations.md"; do
  [ -f "$f" ] && ok "present: $f" || bad "MISSING: $f"
done
# `rpm -V` catches a file the package owns having been changed or removed since install.  The env
# file legitimately differs (it is %ghost, rpm carries no content for it) so it is filtered out.
if [ "$IS_ROOT" -eq 1 ]; then
  vout=$(rpm -V powerpack-mcp-1.0 2>&1 | grep -v 'powerpack-mcp\.env' || true)
  [ -z "$vout" ] && ok "rpm -V clean -- no owned file altered or missing since install" \
    || { warn "rpm -V reports differences:"; echo "$vout" | head -6 | sed 's/^/           /'; }
else
  skip "rpm -V needs root"
fi

# =============================================================================================
head1 "2. The nginx wiring -- where a healthy service still returns 404"
# em7ngx_web_ui.fragment is owned by sl-php-ui and is not a %config file, so any platform upgrade
# overwrites it and silently deletes our include line, with no .rpmsave and nothing in any log.
# /mcp then returns 404 while the service runs and reports healthy.  This is the check to repeat.
if [ -f "$WEB_FRAGMENT" ]; then
  n=$(grep -c 'powerpack-mcp/nginx/powerpack-mcp.fragment' "$WEB_FRAGMENT" 2>/dev/null || true)
  case "${n:-0}" in
    1) ok "include line present exactly once in $(basename "$WEB_FRAGMENT")" ;;
    0) bad "include line is ABSENT -- /mcp will 404 while the service reports healthy."
       echo  "         Repair: rpm -i again over the top (%posttrans re-adds it idempotently),"
       echo  "         or add it by hand inside the server block, then nginx -t && systemctl reload nginx" ;;
    *) bad "include line appears $n times -- nginx will load the fragment more than once" ;;
  esac
else
  bad "$WEB_FRAGMENT is missing entirely"
fi
if [ "$IS_ROOT" -eq 1 ]; then
  nginx -t >"$TMP/ngx.log" 2>&1 \
    && ok "nginx -t PASSES with our configuration loaded" \
    || { bad "nginx -t FAILS:"; tail -5 "$TMP/ngx.log" | sed 's/^/           /'; }
else
  skip "nginx -t needs root"
fi

# =============================================================================================
head1 "3. The unit"

en=$(systemctl is-enabled powerpack-mcp 2>&1); ac=$(systemctl is-active powerpack-mcp 2>&1)
[ "$en" = enabled ] && ok "is-enabled: enabled" \
  || warn "is-enabled: $en -- install leaves it disabled on purpose; run
           systemctl enable --now powerpack-mcp when you are ready"
if [ "$ac" = active ]; then
  ok "is-active: active"
else
  bad "is-active: $ac"
  if [ "$IS_ROOT" -eq 1 ]; then
    echo "         last 12 log lines:"
    journalctl -u powerpack-mcp -n 12 --no-pager 2>/dev/null | sed 's/^/           /'
  fi
fi
# Without a restart, `rpm -U` replaces every file on disk while the old process keeps serving,
# with MainPID and ExecMainStartTimestamp unchanged and rpm exiting 0.  %posttrans runs
# try-restart; this checks it worked.  On a fresh install try-restart is a deliberate no-op, so a
# process older than the package means someone started it from elsewhere.
if [ "$ac" = active ]; then
  started=$(systemctl show -p ExecMainStartTimestamp --value powerpack-mcp 2>/dev/null)
  instd=$(rpm -q --qf '%{INSTALLTIME}' powerpack-mcp-1.0 2>/dev/null)
  s_epoch=$(date -d "$started" +%s 2>/dev/null || echo 0)
  if [ "${s_epoch:-0}" -gt 0 ] && [ -n "${instd:-}" ]; then
    if [ "$s_epoch" -ge "$instd" ]; then
      ok "the running process started AFTER the package was installed ($started)"
    else
      bad "the running process PREDATES the package install -- old code is still serving."
      echo  "         started $started, package installed $(date -d "@$instd" 2>/dev/null)."
      echo  "         Fix: systemctl restart powerpack-mcp"
    fi
  else
    skip "could not compare process start time against install time"
  fi
fi

# =============================================================================================
head1 "4. The venv -- the two defects that ship a package which cannot start"
# A venv built without --relocatable bakes the buildroot path into 37 console-script shebangs (LCE
# 3.1.0's venv ships with that defect), and one built without --no-editable has a .pth pointing at
# the build directory.  Both produce a package that installs cleanly and then will not run.
# Importing the module tests both at once, and also proves the base-interpreter symlink resolves.
PY="$SVC/venv/bin/python"
if [ -x "$PY" ]; then
  if vv=$("$PY" -c 'import powerpack_mcp;print(powerpack_mcp.__version__)' 2>"$TMP/py.err"); then
    if [ "$vv" = "0.0.0+unknown" ]; then
      bad "the venv imports but reports 0.0.0+unknown -- dist-info metadata is missing"
    elif [ "$vv" = "$PKGVER" ]; then
      ok "venv reports $vv, matching the installed package"
    else
      warn "venv reports $vv but rpm says $PKGVER -- these should agree"
    fi
  else
    bad "the venv cannot import powerpack_mcp:"
    head -3 "$TMP/py.err" | sed 's/^/           /'
    grep -q 'bad interpreter' "$TMP/py.err" 2>/dev/null \
      && echo "         ^ 'bad interpreter' means the venv was built without --relocatable"
  fi
else
  bad "$PY is missing or not executable"
fi
# Section 6 parses JSON with $PY.  If the venv's interpreter is the very thing that is broken, fall
# back to a platform one so the wire checks still run; a broken venv should cost you one check,
# not the two that actually prove MCP is serving.
if ! "$PY" -c '' >/dev/null 2>&1; then
  PY=$(command -v python3.12 || command -v python3 || true)
  [ -n "$PY" ] && warn "falling back to $PY for JSON parsing" \
                || warn "no usable python found -- section 6 cannot parse responses"
fi

# =============================================================================================
head1 "5. Over the wire -- and the one check that distinguishes 401 from 404"
# With the service not running at all, an unauthenticated /mcp returns 401 and not 502, because
# the authentication gate is evaluated before proxying.  401, 404 and 502 mean completely
# different things, so they are separated here.

# LISTEN_PORT defaults to 8000, but an operator may have moved it, in which case probing 8000
# reports a failure that is really just the wrong port.  Read the setting when we can.
PORT=8000
if [ -r "$ENV_FILE" ]; then
  p=$(grep -E '^\s*LISTEN_PORT\s*=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d ' "' || true)
  case "${p:-}" in ''|*[!0-9]*) : ;; *) PORT="$p"; echo "  NOTE   env file sets LISTEN_PORT=$PORT" ;; esac
fi
# Retry for up to 30 seconds.  Straight after `rpm -U`, %posttrans's try-restart has just
# restarted the service, and startup takes several seconds, so a single probe reports a false
# FAIL on a healthy upgrade.  A checker that cries wolf stops being believed.  Retrying rather
# than sleeping unconditionally keeps a healthy box fast.
DEADLINE=$(( $(date +%s) + 30 ))
hc=000
while :; do
  hc=$(curl -s -m 5 -o "$RESP" -w '%{http_code}' "http://127.0.0.1:$PORT/health" 2>/dev/null || true)
  hc=${hc:-000}
  { [ "$hc" = 200 ] || [ "$(date +%s)" -ge "$DEADLINE" ]; } && break
  [ "$WAITED" -eq 0 ] && echo "  ....   /health not up yet; waiting for startup"
  WAITED=$((WAITED+1)); sleep 2
done
if [ "$hc" = 200 ] && grep -q '"status":"ok"' "$RESP" 2>/dev/null; then
  [ "$WAITED" -gt 0 ] && ok "/health came up after ~$((WAITED*2))s of waiting -- startup latency, not a fault"
  ok "/health on loopback:$PORT -> 200 {\"status\":\"ok\"}"
  echo  "  NOTE   that is PROCESS LIVENESS ONLY.  It carries no version and says nothing about"
  echo  "         LCE reachability.  There is no /ready route."
else
  bad "/health on 127.0.0.1:$PORT still '$hc' after 30s of retries"
  [ "$hc" = 000 ] && echo "         Nothing is listening there, and it is not startup latency --"
  [ "$hc" = 000 ] && echo "         30s is well past normal startup.  Check LISTEN_PORT in the env"
  [ "$hc" = 000 ] && echo "         file, and journalctl -u powerpack-mcp for a bind failure."
fi

code=$(curl -sk -m 10 -o "$RESP" -D "$HDR" -w '%{http_code}' -X POST "$MCP_URL" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' -d '{}' 2>/dev/null || true)
code=${code:-000}
case "$code" in
  401) ok "unauthenticated POST $MCP_URL -> 401.  The perimeter denies by default"
       # RFC 7235 requires a WWW-Authenticate challenge on a 401.  The platform omits it; the
       # fragment deliberately does not.  A browser shows a credential dialog.
       if grep -qi '^www-authenticate:' "$HDR"; then
         ok "  and it carries $(grep -i '^www-authenticate:' "$HDR" | tr -d '\r')"
       else
         warn "  but WITHOUT a WWW-Authenticate header -- RFC 7235 requires one; clients cannot"
         echo  "         discover the scheme, and this suggests an older fragment is loaded"
       fi ;;
  404) bad "unauthenticated POST $MCP_URL -> 404.  /mcp IS NOT ROUTED."
       echo  "         The include line is missing or nginx has not reloaded.  See section 2." ;;
  502|503) bad "-> $code.  nginx is routing but the service is not reachable behind it."
       echo  "         A 502 also means auth was NOT evaluated before proxying -- which would be"
       echo  "         a fragment defect, not just a service outage.  Check both." ;;
  200) bad "-> 200 for an UNAUTHENTICATED request.  THE PERIMETER IS OPEN.  Stop and investigate." ;;
  000) bad "no response from $MCP_URL at all -- is nginx listening on 443?" ;;
  *)   warn "-> $code, which is none of the expected answers.  Investigate before proceeding." ;;
esac

# =============================================================================================
head1 "6. The full surface -- needs a credential"
# This is the only check that proves the new code is serving.  rpm -q tells you what is on disk,
# and /health carries no version.  serverInfo.version is fastmcp's version, which makes it a
# clean signal that a specific build is live.
if [ -z "$MCP_USER" ] || [ -z "$MCP_PASS" ]; then
  skip "no credential supplied -- set MCP_USER and MCP_PASS (see --help) and re-run."
  echo  "         Everything above can pass on a box where MCP still does not work.  This is"
  echo  "         the check that closes that gap, along with the LCE probe in section 7."
else
  INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"mcp-verify","version":"1.0"}}}'
  printf '%s' "$INIT" > "$TMP/init.json"
  # `-K -` reads curl options from STDIN, so the credential never enters argv and never shows up
  # in `ps`.  Basic is the scheme verified against LCE 3.1.0; Bearer is rejected by the platform.
  mcp_post() {
    local jf="$1"; shift
    curl -sk -m 30 -K - -o "$RESP" -D "$HDR" -w '%{http_code}' -X POST "$MCP_URL" \
      -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
      --data "@$jf" "$@" <<CURLCFG
user = "$MCP_USER:$MCP_PASS"
CURLCFG
  }
  jq_field() {   # $1 = python expression over the parsed first `data:` payload
    sed -n 's/^data: //p' "$RESP" | head -1 | "$PY" -c \
      "import sys,json;d=json.load(sys.stdin);print($1)" 2>/dev/null
  }
  code=$(mcp_post "$TMP/init.json" || true); code=${code:-000}
  if [ "$code" = 200 ]; then
    ok "authenticated initialize -> 200"
    sv=$(jq_field 'd["result"]["serverInfo"]["version"]')
    [ -n "${sv:-}" ] && ok "serverInfo.version = $sv" \
      || warn "could not parse serverInfo.version from the response"
    SID=$(tr -d '\r' < "$HDR" | awk 'tolower($1)=="mcp-session-id:"{print $2}')
    if [ -n "${SID:-}" ]; then
      printf '%s' '{"jsonrpc":"2.0","method":"notifications/initialized"}' > "$TMP/n.json"
      mcp_post "$TMP/n.json" -H "mcp-session-id: $SID" >/dev/null
      printf '%s' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' > "$TMP/l.json"
      if [ "$(mcp_post "$TMP/l.json" -H "mcp-session-id: $SID")" = 200 ]; then
        tc=$(jq_field 'len(d["result"]["tools"])')
        if [ "${tc:-0}" = "$EXPECT_TOOLS" ]; then
          ok "tools/list -> $tc tools, as expected"
        elif [ "${tc:-0}" = 46 ]; then
          warn "tools/list -> 46 tools.  The 8 DB tools were withheld: the platform Python tree"
          echo  "         is not importable.  The service is otherwise healthy."
        elif [ -n "${tc:-}" ]; then
          warn "tools/list -> $tc tools, expected $EXPECT_TOOLS.  Check the ENABLE_* keys in the"
          echo  "         env file and the per-set tool_sets_registered records (section 7)."
        else
          warn "could not parse the tool count from tools/list"
        fi
      else
        warn "tools/list did not return 200"
      fi
    else
      warn "no mcp-session-id header returned -- cannot enumerate tools"
    fi
  else
    bad "authenticated initialize -> $code"
    [ "$code" = 401 ] && echo "         The credential was rejected by the Skylar One authenticator."
    [ "$code" = 500 ] && echo "         'Failed to identify user' means the authenticator itself failed. Fail-closed."
  fi
fi

# =============================================================================================
head1 "7. The service's own record -- tool sets, and the LCE_VERIFY_TLS cross-check"

if [ "$IS_ROOT" -eq 1 ]; then
  # Records go stdout -> systemd (SyslogIdentifier=silo.powerpack_mcp) -> rsyslog -> this file,
  # rotated by the platform's /etc/logrotate.d/sl1.  journald on these appliances is volatile
  # (nothing under /var/log/journal), so its records are lost on every reboot.
  LOG=/var/log/sl1/powerpack_mcp.log
  [ -f "$LOG" ] && ok "durable log present: $LOG ($(stat -c %s "$LOG") bytes)" \
    || warn "$LOG does not exist.  This stack's rsyslog rules may differ; journalctl still works,
           but journald here is volatile and loses everything on reboot"

  sets=$(journalctl -u powerpack-mcp --no-pager 2>/dev/null | grep -c tool_sets_registered || true)
  if [ "${sets:-0}" -gt 0 ]; then
    ok "tool_sets_registered records found -- the inventory the service decided to offer:"
    journalctl -u powerpack-mcp --no-pager 2>/dev/null | grep tool_sets_registered \
      | tail -8 | sed 's/^/           /'
  else
    warn "no tool_sets_registered record in the journal -- has the service ever started?"
  fi
  grep -qi 'PREREQUISITE_MISSING' <(journalctl -u powerpack-mcp --no-pager 2>/dev/null) \
    && warn "PREREQUISITE_MISSING appears in the journal -- a tool set was withheld for want of
           a platform prerequisite (usually the DB driver).  Expected on a box without it."

  # ---- the LCE_VERIFY_TLS cross-check.  This is the highest-value check in the script. --------
  # A fresh install writes the env template with every key commented out, so the box takes the code
  # default LCE_VERIFY_TLS=true.  Against the stock self-signed certificate that means every tool
  # call fails lce_unreachable while systemctl status and /health both read perfectly healthy.
  if [ -r "$ENV_FILE" ]; then
    setting=$(grep -E '^\s*LCE_VERIFY_TLS\s*=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d ' "' || true)
    eff="${setting:-true (code default -- the key is commented out or absent)}"
    echo "  LCE_VERIFY_TLS is effectively: $eff"
    cert=$(openssl s_client -connect 127.0.0.1:443 </dev/null 2>/dev/null || true)
    san=$(printf '%s' "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
          | grep -E 'DNS:|IP Address:' || true)
    case "${setting:-true}" in
      false|False|FALSE|0|no|off)
        [ -z "$san" ] && ok "false, against a certificate with no subjectAltName -- correct" \
                      || warn "false, but this certificate HAS a subjectAltName.  Verification might
           have worked; you are dropping peer authentication you could have kept" ;;
      *)
        if [ -z "$san" ]; then
          bad "TRUE against a certificate with NO subjectAltName.  This is the"
          echo  "         SILENT failure: the service starts, /health says ok, and EVERY tool call"
          echo  "         fails lce_unreachable.  Set LCE_VERIFY_TLS=false in $ENV_FILE and"
          echo  "         systemctl restart powerpack-mcp."
        else
          ok "true, and the certificate has a subjectAltName -- verification can work, provided"
          echo  "         that SAN covers LCE_DEFAULT_TARGET_HOST (default localhost)"
        fi ;;
    esac
    # The service's own evidence beats both of the above: it logs which server_health probe failed
    # and why, rather than only reporting `reachable: false`.
    if grep -q 'CERTIFICATE_VERIFY_FAILED\|SSLCertVerificationError' "$LOG" 2>/dev/null; then
      bad "the log contains CERTIFICATE_VERIFY_FAILED -- TLS verification is already failing on this box:"
      grep -h 'CERTIFICATE_VERIFY_FAILED\|SSLCertVerificationError' "$LOG" 2>/dev/null \
        | tail -2 | cut -c1-160 | sed 's/^/           /'
    fi
    # Anchor on the actual log format, logger.warning("server_health's %s probe failed: ...") and
    # ("server_health's %s probe answered but reads as unreachable: ...").  A bare
    # `grep server_health` also matches the tool schema, which LOG_LEVEL=DEBUG dumps into the log
    # as part of full response bodies.
    if grep -qE "server_health's [a-z]+ probe" "$LOG" 2>/dev/null; then
      echo "  most recent server_health PROBE records (the REASON lives here, not in the tool's"
      echo "  own output):"
      grep -hE "server_health's [a-z]+ probe" "$LOG" 2>/dev/null | tail -3 | cut -c1-200 \
        | sed 's/^/           /'
    else
      echo "  NOTE   no server_health probe FAILURES in the log -- either it has not been called,"
      echo "         or every probe succeeded.  Neither is recorded, so this is not evidence."
    fi
    # DEBUG is not a neutral setting.
    case "$(grep -E '^\s*LOG_LEVEL\s*=' "$ENV_FILE" | tail -1 | cut -d= -f2- | tr -d ' "')" in
      DEBUG|debug)
        warn "LOG_LEVEL=DEBUG.  This logs full response bodies -- tens of MB/day, which under the
           platform's minsize 5M logrotate rule rotates the audit trail away in a day or two.
           INFO is the running default." ;;
    esac
  else
    skip "cannot read $ENV_FILE (mode 0600) -- the LCE_VERIFY_TLS cross-check needs root"
  fi
else
  skip "the journal, the durable log and the LCE_VERIFY_TLS cross-check all need root."
  echo  "         The TLS cross-check is the highest-value check here.  Re-run under sudo."
fi

# =============================================================================================
echo
echo "============================================================================="
echo "RESULT: FAIL=$FAIL  WARN=$WARN  SKIP=$SKIP"
if [ "$FAIL" -gt 0 ]; then
  echo "NOT READY.  Work the FAIL lines above."
else
  echo "No failures in the checks that ran."
  [ "$SKIP" -gt 0 ] && echo "But $SKIP check(s) were SKIPPED.  A SKIP IS NOT A PASS -- re-run as root," \
    && echo "and with MCP_USER/MCP_PASS set, for the checks that actually prove MCP is serving."
fi
cat <<'CLOSING'
Two things to remember regardless of the result above:
  * After ANY Skylar One platform upgrade, re-run this script.  em7ngx_web_ui.fragment is owned
    by sl-php-ui and is not a %config file, so an upgrade silently deletes our include line and
    /mcp returns 404 while the service reports healthy.
  * Authentication is not authorization.  nginx proves the caller is SOME authenticated
    principal.  LCE and SL1 then apply that caller's own permissions, and the service's
    access-hook gate decides for the DB-backed tools.
CLOSING
echo "============================================================================="
[ "$FAIL" -gt 0 ] && exit 1
exit 0

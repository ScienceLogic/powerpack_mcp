#!/bin/bash
# =============================================================================================
# PowerPack MCP Server -- appliance preflight.  Run this before `rpm -i`.
#
# Answers one question: "will the first install of this package onto this box work, and what will
# I have to do by hand afterwards?"  It changes nothing.  Every check is a read, and the only
# privileged operations are `nginx -t`, reading the env file, and the optional `rpm -i --test`.
#
# See docs/operations.md for the install procedure.  Run scripts/mcp-verify.sh after the
# install.
#
# ---------------------------------------------------------------------------------------------
# Usage -- copy it to the appliance and run it there.
#
#     scp scripts/mcp-preflight.sh em7admin@<appliance>:/tmp/
#     ssh -t em7admin@<appliance> 'sudo bash /tmp/mcp-preflight.sh'
#
# Optionally hand it the RPM as well, and it will verify the artifact and dry-run the transaction:
#
#     scp scripts/mcp-preflight.sh powerpack-mcp-1.0-*.rpm em7admin@<appliance>:/tmp/
#     ssh -t em7admin@<appliance> 'sudo bash /tmp/mcp-preflight.sh --rpm /tmp/powerpack-mcp-1.0-*.rpm'
#
# Why `ssh -t` and `sudo` on the box, rather than a `--host` flag that runs ssh for you:
# `em7admin` has no passwordless sudo on these appliances, and `sudo` requires a terminal.  A
# remote mode would have to either pipe the password in, which is how it ends up in a shell
# history, a CI log or an agent transcript, or run without sudo and silently skip the checks that
# matter.  Copying the script over and running it in your own terminal has neither problem.  A
# `sudo` over a non-interactive ssh fails with `sudo: a terminal is required`, and an `|| echo`
# fallback would print a line that reads exactly like success.
#
# ---------------------------------------------------------------------------------------------
# Without root it still runs, and reports the privileged checks as SKIP rather than guessing.
# A SKIP is not a pass.  Re-run under sudo before you rely on the result.
#
# EXIT CODES:  0 = no blockers.  1 = at least one BLOCK.  2 = cannot run at all.
# WARN never affects the exit code -- a WARN is something to know, not something to fix first.
# =============================================================================================

set -uo pipefail

BLOCK=0; WARN=0; SKIP=0
ok()    { echo "  PASS   $*"; }
block() { echo "  BLOCK  $*"; BLOCK=$((BLOCK+1)); }
warn()  { echo "  WARN   $*"; WARN=$((WARN+1)); }
skip()  { echo "  SKIP   $*"; SKIP=$((SKIP+1)); }
# Fixed-width banner: "=== title " padded out to 92 columns.  A fixed suffix made the long
# section titles wrap in an 80-column terminal, which is where these actually get read.
_FILL='============================================================================================'
head1() { local t="=== $* "; printf '\n%s%s\n' "$t" "${_FILL:${#t}}"; }

# The remote shell expands the glob before this script runs.
# `ssh host 'sudo bash /tmp/mcp-preflight.sh --rpm /tmp/powerpack-mcp-1.0-*.rpm'` arrives here as
# --rpm plus one path per match, so bare paths after the flag are collected rather than rejected;
# "unknown argument" would be a confusing way to report "you have two RPMs in /tmp".
RPM_FILES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --rpm) [ -n "${2:-}" ] && { RPM_FILES+=("$2"); shift 2; } || { echo "--rpm needs a path" >&2; exit 2; } ;;
    -h|--help) sed -n '2,37p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option: $1  (try --help)" >&2; exit 2 ;;
    *) RPM_FILES+=("$1"); shift ;;
  esac
done

IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1
echo "PowerPack MCP preflight -- $(hostname) -- $(date -u +%Y-%m-%dT%H:%M:%SZ)"
[ "$IS_ROOT" -eq 1 ] || echo "NOTE: not running as root.  Privileged checks will report SKIP."

# =============================================================================================
head1 "0. Is this actually a first install?"
# A first install and an upgrade are different procedures.  `rpm -i` over an existing install
# fails, and `rpm -U` in the wrong version direction needs `--oldpackage` or is refused: rpm ranks
# `1.1.1.dev46+g...` above `1.1.1`, because it compares segments left to right with no concept of
# PEP 440's `dev` as a pre-release.
#
# On an upgrade several later checks would be false in first-install framing: port 8000 held by
# the service itself, the live env file, the installed paths, and `rpm -i --test` failing on file
# conflicts.  So the mode is recorded once here and the affected checks below branch on it.
INSTALLED=0
if rpm -q powerpack-mcp-1.0 >/dev/null 2>&1; then
  INSTALLED=1
  block "ALREADY INSTALLED: $(rpm -q powerpack-mcp-1.0)"
  echo "         THIS IS AN UPGRADE, AND THIS IS THE WRONG TOOL FOR IT.  See the Upgrades"
  echo "         section of docs/operations.md, and check the version direction before using"
  echo "         --oldpackage -- rpm ranks 1.1.1.dev46+g... ABOVE 1.1.1."
  echo "         Everything below is still checked, but reported in UPGRADE framing."
else
  ok "powerpack-mcp-1.0 is not installed -- the first-install path applies"
fi
# `rpm -q powerpack-mcp` (no -1.0) says "not installed" even on a box where it is running, because
# the service version is part of the package name.  Catch other names too, in case a future build
# renames: a rename silently turns an upgrade into a parallel install, which cannot work because
# both versions would own the same symlink, zone file and include line.
other=$(rpm -qa 'powerpack-mcp*' 2>/dev/null | grep -v '^powerpack-mcp-1\.0-' || true)
[ -n "$other" ] && warn "another powerpack-mcp package is installed: $other  (only one version can be installed)"

# =============================================================================================
head1 "1. Hard requirements -- the install fails without these"

arch=$(uname -m)
[ "$arch" = x86_64 ] && ok "arch is x86_64" \
  || block "arch is $arch, not x86_64 -- the venv ships compiled wheels; this package is not noarch"

# The spec's only two Requires.  python3.12 because `uv venv --relocatable` does not relocate the
# base-interpreter symlink, so venv/bin/python3.12 is an absolute link to /usr/bin/python3.12.
# nginx because the location fragment is the only route to the service and the only thing that
# authenticates a caller.
for req in python3.12 nginx; do
  if rpm -q "$req" >/dev/null 2>&1; then
    ok "Requires: $req -> $(rpm -q "$req")"
  else
    block "Requires: $req is NOT installed -- rpm -i will refuse on an unresolved dependency"
  fi
done
# Assert the interpreter the symlink actually points at, not just that a package owns it.
if [ -x /usr/bin/python3.12 ]; then
  ok "/usr/bin/python3.12 -> $(/usr/bin/python3.12 -V 2>&1)"
else
  block "/usr/bin/python3.12 is missing or not executable -- every console script will fail"
fi

# The package creates no account.  s-em7-core belongs to the platform.
id s-em7-core >/dev/null 2>&1 \
  && ok "user s-em7-core exists ($(id -u s-em7-core):$(id -g s-em7-core))" \
  || block "user s-em7-core does NOT exist -- the unit runs as it and the package creates no account"
getent group s-em7-core >/dev/null 2>&1 \
  && ok "group s-em7-core exists" \
  || block "group s-em7-core does NOT exist -- the env file is owned by it"

NGINX_D=/opt/em7/share/config/nginx.d
[ -d "$NGINX_D" ] && ok "$NGINX_D exists -- both nginx files land here or under the service dir" \
  || block "$NGINX_D does NOT exist -- the zone file has nowhere to go and /mcp will never route"

# %post appends the include line to this file.  If it is absent, %post's `[ -f ]` guard skips
# silently, the fragment is installed but never included, and /mcp returns 404 while the service
# reports perfectly healthy.  rpm still exits 0.
WEB_FRAGMENT="$NGINX_D/em7ngx_web_ui.fragment"
if [ -f "$WEB_FRAGMENT" ]; then
  ok "$(basename "$WEB_FRAGMENT") exists -- %post has somewhere to add the include line"
  if grep -q 'powerpack-mcp/nginx/powerpack-mcp.fragment' "$WEB_FRAGMENT" 2>/dev/null; then
    if [ "$INSTALLED" -eq 1 ]; then
      ok "include line already present, as it should be for an installed package"
    else
      warn "an include line for us is ALREADY present, with the package NOT installed."
      echo "         Left over from a previous erase.  %post's grep guard will skip re-adding it,"
      echo "         which is harmless -- %files installs the fragment it points at either way."
    fi
  fi
else
  block "$WEB_FRAGMENT is MISSING -- %post's [ -f ] guard skips silently and /mcp will 404"
fi

# =============================================================================================
head1 "2. nginx must be VALID BEFORE you install"
# %posttrans validates and reloads nginx once per transaction.  On a box whose nginx config is
# already broken, %posttrans removes our config again and reports CRITICAL about a pre-existing
# problem, so you get a package installed, unroutable, and rpm exit 0.  Establish the baseline.
if [ "$IS_ROOT" -eq 1 ]; then
  if nginx -t >/tmp/mcp-preflight-ngx.log 2>&1; then
    ok "nginx -t PASSES right now -- this is the baseline %posttrans will be judged against"
    w=$(grep -c '\[warn\]' /tmp/mcp-preflight-ngx.log || true)
    [ "${w:-0}" -gt 0 ] && warn "nginx -t emits $w pre-existing [warn] line(s).  Record them NOW so"
    [ "${w:-0}" -gt 0 ] && echo  "         you do not later attribute them to our fragment:" \
      && grep '\[warn\]' /tmp/mcp-preflight-ngx.log | head -4 | sed 's/^/           /'
  else
    block "nginx -t FAILS right now.  FIX NGINX BEFORE INSTALLING."
    tail -4 /tmp/mcp-preflight-ngx.log | sed 's/^/           /'
  fi
  rm -f /tmp/mcp-preflight-ngx.log
else
  skip "nginx -t needs root (it opens the error log).  Re-run under sudo -- this is not optional"
fi
systemctl is-active nginx >/dev/null 2>&1 && ok "nginx is active" \
  || warn "nginx is not active -- %posttrans's reload will be a no-op and /mcp will not answer"

# =============================================================================================
head1 "3. Room, and a free port"

avail=$(df -Pk /opt 2>/dev/null | awk 'NR==2{print $4}')
if [ -n "${avail:-}" ]; then
  # Measured footprint on a test appliance: 5,222 files, ~75 MB under the versioned directory.
  if [ "$avail" -ge 204800 ]; then
    ok "/opt has $((avail/1024)) MB free (payload is ~75 MB)"
  elif [ "$avail" -ge 102400 ]; then
    warn "/opt has only $((avail/1024)) MB free.  The payload is ~75 MB -- tight"
  else
    block "/opt has only $((avail/1024)) MB free.  The payload is ~75 MB"
  fi
else
  skip "could not read free space on /opt"
fi

# LISTEN_PORT defaults to 8000 on loopback.  Something else already holding it means the service
# starts, fails to bind and never serves -- discovered at `systemctl enable --now`, not at install.
if command -v ss >/dev/null 2>&1; then
  if ss -ltn 2>/dev/null | grep -qE '127\.0\.0\.1:8000|\[::1\]:8000|0\.0\.0\.0:8000'; then
    # On an upgrade the listener is our own running service.  Calling that a conflict would tell
    # an operator to free a port they must not free, on a box where nothing is wrong.
    if [ "$INSTALLED" -eq 1 ] && [ "$(systemctl is-active powerpack-mcp 2>/dev/null)" = active ]; then
      ok "port 8000 is held by the running powerpack-mcp service -- expected on an upgrade"
    else
      block "something is ALREADY listening on port 8000 -- the service will fail to bind."
      echo  "         Either free it or set LISTEN_PORT in the env file AND edit the nginx"
      echo  "         fragment's proxy_pass to match.  The fragment does not follow the key."
    fi
  else
    ok "port 8000 is free (the default LISTEN_PORT)"
  fi
else
  skip "ss not available -- could not check whether port 8000 is free"
fi

# =============================================================================================
head1 "4. The DB tool sets -- advisory, never a blocker"
# The 8 DB tools import the platform's sl_mysql and MySQLdb through
# /usr/lib/python3.12/site-packages/silo.pth, which runs site.addsitedir('/opt/em7/lib/python3.12').
# That is why the venv is built --system-site-packages.  An absent platform tree reduces what the
# service offers but does not stop the install: the service starts, reports PREREQUISITE_MISSING
# and registers 46 of 54 tools.  Hence WARN, deliberately.
if [ -d /opt/em7/lib/python3.12 ]; then
  ok "/opt/em7/lib/python3.12 present -- expect the full 54-tool surface"
  [ -f /usr/lib/python3.12/site-packages/silo.pth ] \
    && ok "silo.pth present -- this is the mechanism that makes the tree importable" \
    || warn "silo.pth is ABSENT from /usr/lib/python3.12/site-packages.  The tree exists but
           nothing puts it on sys.path, so sl_mysql stays unimportable and the 8 DB tools are
           withheld anyway.  Expect 46 tools, not 54."
else
  warn "/opt/em7/lib/python3.12 is ABSENT.  Not a blocker: expect 46 of 54 tools, the 8 DB"
  echo  "         tools withheld with PREREQUISITE_MISSING.  The service starts normally."
fi
# The DB tools reach only this box's database: every cursor comes from the platform's local_db(),
# and there is no host, port, user or password in config at all, so another host cannot be
# supplied by accident.  On a distributed stack this is a topology decision, and no configuration
# changes it after the fact.
echo  "  NOTE   the DB tools read only THIS box's database.  On a distributed stack, which"
echo  "         appliance you install on decides what they can see."

# =============================================================================================
head1 "5. The certificate -- decides LCE_VERIFY_TLS"
# This is the one manual step a fresh install leaves you: %post writes the env template with every
# key commented out, including #LCE_VERIFY_TLS=false, so the box takes the code default `true`.
# Against the stock self-signed certificate that means every tool call fails lce_unreachable while
# systemctl status and /health both read perfectly healthy.
cert=$(openssl s_client -connect 127.0.0.1:443 </dev/null 2>/dev/null || true)
if [ -z "$cert" ]; then
  skip "could not retrieve a certificate from 127.0.0.1:443 -- is nginx serving TLS?"
  echo  "         Decide LCE_VERIFY_TLS by hand.  On a dev box, set it false."
else
  subj=$(printf '%s' "$cert" | openssl x509 -noout -subject 2>/dev/null | sed 's/^subject= *//')
  issu=$(printf '%s' "$cert" | openssl x509 -noout -issuer  2>/dev/null | sed 's/^issuer= *//')
  san=$( printf '%s' "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
         | grep -E 'DNS:|IP Address:' || true)
  echo "  subject: ${subj:-<unreadable>}"
  echo "  issuer:  ${issu:-<unreadable>}"
  if [ -n "$san" ]; then
    echo "  SAN:    $(echo "$san" | tr -s ' ')"
    ok "the certificate HAS a subjectAltName"
    if [ "$subj" = "$issu" ]; then
      warn "...but it is SELF-SIGNED (subject == issuer), so it is still untrusted."
      echo  "         VERDICT: set LCE_VERIFY_TLS=false unless this CA is in the trust store."
    else
      echo  "  VERDICT: LEAVE LCE_VERIFY_TLS at its default true, PROVIDED the SAN above covers"
      echo  "           the host the service connects to (LCE_DEFAULT_TARGET_HOST, default"
      echo  "           localhost).  If it does not, the name check fails and you need false."
    fi
  else
    warn "the certificate has NO subjectAltName -- this is the stock appliance certificate"
    echo  "         VERDICT: you MUST set LCE_VERIFY_TLS=false after installing."
    echo  "         Adding this certificate to the trust store CANNOT fix it: with no SAN the"
    echo  "         NAME check can never pass, however well the certificate is trusted."
    echo  "         The durable fix is a certificate carrying a proper subjectAltName."
  fi
fi

# =============================================================================================
head1 "6. Leftovers from a previous install"
# The env file is %ghost + %config(noreplace) and survives erase by design.  That is a feature on
# a reinstall and also a trap: %post's `if [ ! -f ]` guard means a fresh install will not rewrite
# the template over a surviving file, so the box silently keeps whatever settings, and whatever
# missing keys, the old file had.
ENV_FILE=/opt/em7/services/powerpack-mcp/powerpack-mcp.env
if [ -e "$ENV_FILE" ]; then
  if [ "$INSTALLED" -eq 1 ]; then
    # On an upgrade this is the live configuration of a running install, not debris.
    ok "env file present -- the live configuration.  %config(noreplace) PRESERVES it across"
    echo  "         rpm -U; back it up anyway, and expect no .rpmnew/.rpmsave afterwards."
  else
    warn "an env file ALREADY EXISTS at $ENV_FILE with the package NOT installed"
    echo  "         It survived a previous erase, by design.  %post will NOT overwrite it, so the"
    echo  "         new template's keys will be ABSENT and its defaults will apply silently."
    echo  "         Read it before you install, and consider moving it aside to get a fresh one:"
    echo  "             mv $ENV_FILE /root/powerpack-mcp.env.\$(date +%F)"
  fi
  if [ "$IS_ROOT" -eq 1 ]; then
    echo  "         current non-comment settings:"
    grep -vE '^\s*(#|$)' "$ENV_FILE" 2>/dev/null | sed 's/^/           /' || echo "           (none)"
  else
    skip "reading its contents needs root (mode 0600)"
  fi
else
  ok "no leftover env file -- %post will write the current template"
fi
# Only "leftover" if nothing owns them.  On an upgrade these are the installed payload,
# and rpm -V (in mcp-verify.sh) is the right check for them, not this one.
if [ "$INSTALLED" -eq 0 ]; then
  for stale in /opt/em7/services/powerpack-mcp /opt/em7/services/powerpack-mcp-1.0 \
               "$NGINX_D/powerpack-mcp-zone.conf" /usr/lib/systemd/system/powerpack-mcp.service; do
    [ -e "$stale" ] && warn "leftover path present with the package not installed: $stale"
  done
else
  echo  "  NOTE   the service paths belong to the installed package, so they are not leftovers."
fi

# =============================================================================================
if [ "${#RPM_FILES[@]}" -gt 0 ]; then
  head1 "7. The artifact itself"
  if [ "${#RPM_FILES[@]}" -gt 1 ]; then
    block "${#RPM_FILES[@]} RPM paths given.  Name exactly one -- verifying the wrong file and"
    echo  "         then installing the other is precisely the mistake this section prevents:"
    printf '           %s\n' "${RPM_FILES[@]}"
  elif [ ! -f "${RPM_FILES[0]}" ]; then
    block "no such file: ${RPM_FILES[0]}"
  else
    F="${RPM_FILES[0]}"
    echo "  file:    $F"
    echo "  size:    $(stat -c %s "$F") bytes"
    echo "  sha256:  $(sha256sum "$F" | cut -d' ' -f1)"
    echo "           ^ COMPARE THIS against the digest you computed where you downloaded it."
    echo "             Transfer corruption is the failure this catches, and nothing else here will."
    rpm -qp --qf '  package: %{NAME} %{VERSION} %{RELEASE} %{ARCH}\n' "$F" 2>/dev/null

    # `digests OK` on an UNSIGNED package is the correct result: these hosts set
    # _pkgverify_level = digest, so rpm enforces digests and not signatures.  The package is not
    # signed yet.  --nogpgcheck is not an rpm option (it belongs to dnf/yum), and passing it just
    # produces `unknown option`.
    kout=$(rpm -K "$F" 2>&1)
    case "$kout" in
      *"digests OK"*|*"digests signatures OK"*) ok "rpm -K: $kout" ;;
      *) block "rpm -K did not report digests OK: $kout" ;;
    esac
    a=$(rpm -qp --qf '%{ARCH}' "$F" 2>/dev/null)
    [ "$a" = "$arch" ] && ok "package arch $a matches this box" \
      || block "package arch is $a but this box is $arch"
    n=$(rpm -qp --qf '%{NAME}' "$F" 2>/dev/null)
    [ "$n" = powerpack-mcp-1.0 ] && ok "package NAME is powerpack-mcp-1.0, as expected" \
      || block "package NAME is '$n', not powerpack-mcp-1.0 -- the service version is part of the name"
    case "$(rpm -qp --qf '%{VERSION}' "$F" 2>/dev/null)" in
      0.0.0*) block "version is 0.0.0+unknown -- git history was unavailable to setuptools-scm."
              echo  "         That is the SAME literal a BROKEN install produces." ;;
      *dev*)  warn "this is a DEVELOPMENT version from an untagged commit." ;;
    esac
    if [ "$IS_ROOT" -eq 1 ]; then
      # `-i` against an installed package fails on a file conflict for every file in the payload,
      # which tests nothing.  `-U` is the verb that matches the operation.
      VERB=-i; [ "$INSTALLED" -eq 1 ] && VERB=-U
      if rpm "$VERB" --test -vh "$F" >/tmp/mcp-preflight-test.log 2>&1; then
        ok "rpm $VERB --test: dependencies satisfied, no file conflicts"
      else
        block "rpm $VERB --test FAILED:"
        sed 's/^/           /' /tmp/mcp-preflight-test.log | head -12
        # rpm emits the same "is already installed" string for a downgrade and for re-installing
        # the build already on the box.  Compare the versions to say which it actually is, rather
        # than wrongly telling an operator it is a downgrade.
        if [ "$INSTALLED" -eq 1 ] && grep -q 'is already installed' /tmp/mcp-preflight-test.log; then
          _have=$(rpm -q --qf '%{VERSION}-%{RELEASE}' powerpack-mcp-1.0 2>/dev/null)
          _file=$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$F" 2>/dev/null)
          if [ "$_have" = "$_file" ]; then
            echo "         ^ SAME VERSION already installed ($_have).  Not a downgrade, and nothing"
            echo "           to do -- this box already runs this exact build.  Use \`rpm -U --force\`"
            echo "           only if you deliberately want to re-lay the payload."
          else
            echo "         ^ a DOWNGRADE: installed $_have is ranked ABOVE the file's $_file."
            echo "           rpm has no PEP 440 notion of 'dev' as a pre-release, so check the"
            echo "           direction before reaching for --oldpackage."
          fi
        fi
      fi
      rm -f /tmp/mcp-preflight-test.log
    else
      skip "rpm --test needs root (it takes the transaction lock)"
    fi
  fi
fi

# =============================================================================================
echo
echo "============================================================================="
echo "RESULT: BLOCK=$BLOCK  WARN=$WARN  SKIP=$SKIP"
if [ "$BLOCK" -gt 0 ]; then
  echo "DO NOT INSTALL until the BLOCK lines above are resolved."
elif [ "$SKIP" -gt 0 ] && [ "$IS_ROOT" -eq 0 ]; then
  echo "No blockers found, but $SKIP check(s) were skipped for want of root."
  echo "A SKIP IS NOT A PASS.  Re-run as: sudo bash $0"
else
  echo "No blockers.  Proceed with the install -- and read the rpm -i output: a failing"
  echo "scriptlet cannot abort the transaction and rpm exits 0 regardless."
fi
echo "Review every WARN line: they are what you will have to do by hand afterwards."
echo "============================================================================="
[ "$BLOCK" -gt 0 ] && exit 1
exit 0

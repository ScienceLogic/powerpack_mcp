# =============================================================================================
# Skylar One PowerPack MCP Server -- RPM spec.
#
# Built by CI in the powerpack_mcp repository, in a container, from an sdist.
#
# The service version is in the package name, matching the scheme used on the appliance: lce
# ships as Name: lce-3.1.0, Version: 3.12.2.
#
# Only one version may be installed at a time.  Putting the version in the name does not allow
# parallel installs, because two versions would each want to own three single-instance shared
# resources:
#     - the /opt/em7/services/powerpack-mcp symlink
#     - /opt/em7/share/config/nginx.d/powerpack-mcp-zone.conf
#     - the include line in em7ngx_web_ui.fragment
# LCE has the same limitation: rpm -qf on its symlink returns the versioned package.  Supporting
# parallel installs would mean managing all three through %ghost entries and scriptlets, which is
# the kind of imperative scriptlet logic this spec keeps to a minimum.  An upgrade is therefore
# `rpm -U` within a version line, or erase-then-install across lines.
# =============================================================================================

%global service_version 1.0
%global service_root     /opt/em7/services
%global versioned_dir    %{service_root}/powerpack-mcp-%{service_version}
%global symlink_path     %{service_root}/powerpack-mcp
%global env_file         %{symlink_path}/powerpack-mcp.env
%global nginx_d          /opt/em7/share/config/nginx.d
%global em7_web_fragment %{nginx_d}/em7ngx_web_ui.fragment
%global build_python     /opt/em7/bin/python3.12

# `Version:` comes from the sdist's PKG-INFO, which setuptools-scm populated in a git-aware step
# upstream.  Building from a .git-less tree yields 0.0.0+unknown, the same literal that
# __init__.py's PackageNotFoundError fallback produces, so a version-less build is
# indistinguishable from a broken install.
#
# Release builds must come from a tagged commit.  An untagged build yields a PEP 440 local version
# such as 1.0.1.dev3+g0582d99ca; rpm accepts `+` but not `-`, so CI substitutes any `-` for `.`
# before passing it in.
%{!?service_build_version: %global service_build_version 0.0.0}

Name:           powerpack-mcp-%{service_version}
Version:        %{service_build_version}
Release:        1%{?dist}
Summary:        Skylar One PowerPack MCP Server (remote HTTP MCP server over the LCE Dynamic Application API)
License:        Apache-2.0
URL:            https://github.com/ScienceLogic/powerpack_mcp
# The spelling the platform's own packages use, so rpm queries and inventory tools group this one
# with them.  There is no Packager: this spec is public, and a hard-coded one would put
# ScienceLogic's name on anyone's build.  An internal build can pass --define "packager ...".
Vendor:         ScienceLogic, Inc.
Source0:        powerpack_mcp-%{version}.tar.gz
BuildArch:      x86_64

# Not noarch: the venv contains compiled wheels for this architecture.
%global _build_id_links none
%global debug_package %{nil}

# ---------------------------------------------------------------------------------------------
# Requires -- explicit and minimal.
#
# The venv is not fully self-contained.  Every pip dependency comes from the committed uv.lock
# with hashes verified, and %build asserts that they were installed inside the venv rather than
# inherited.  But sl_mysql and MySQLdb are resolved at runtime from /opt/em7/lib/python3.12 via
# silo.pth, outside the venv and outside uv.lock's hashes.  For those two, the trust anchor is the
# platform's own signed packaging rather than our lockfile.
#
# No Requires: on the platform Python tree.  The RPM that owns /opt/em7/lib/python3.12 has not
# been identified, and without that tree the service still starts, reports PREREQUISITE_MISSING
# for the DB tools and serves 47 of 55 tools, so a hard Requires: would turn a working install
# into an uninstallable package.  The cost is that a missing tree is not caught at install time.
#
# python3.12 is required: the venv's bin/python3.12 is an absolute symlink to /usr/bin/python3.12,
# because `uv venv --relocatable` does not relocate the base-interpreter symlink.  The appliance
# ships Python 3.12.13 there.
#
# nginx is required: the fragment is useless without it.  This makes the package uninstallable
# on an appliance type that does not run nginx; all three target appliance types do.
# ---------------------------------------------------------------------------------------------
Requires:       python3.12
Requires:       nginx
%{?systemd_requires}

BuildRequires:  systemd-rpm-macros

%description
A remote HTTP MCP (Model Context Protocol) server exposing the Skylar One LCE Dynamic
Application API as MCP tools, over streamable HTTP at /mcp.

Ships a self-contained Python 3.12 virtualenv, a systemd unit that is disabled by default, and
an nginx location fragment that enforces the existing Skylar One authentication scheme and fails
closed.

No credential configuration is required. Each MCP caller presents their own Skylar One
credential in the Authorization header, which the service forwards, so LCE applies that
caller's own permissions. There is no service account and no credential at rest.

Install, then "systemctl enable --now powerpack-mcp". On an appliance with a self-signed
certificate you will also need LCE_VERIFY_TLS=false in %{env_file}. See
%{symlink_path}/docs/operations.md, and %{symlink_path}/docs/client-setup.md for
configuring a client -- including how to authenticate with an SL1 API key.

# =============================================================================================
%prep
%setup -q -n powerpack_mcp-%{version}

# =============================================================================================
%build
# ---------------------------------------------------------------------------------------------
# The venv build.  Every flag prevents a specific failure:
#
#   --relocatable       without it, all 37 console-script shebangs bake in the buildroot path and
#                       fail with "bad interpreter".  LCE 3.1.0's venv ships with that defect.
#   --no-editable       uv sync installs the project editable by default, leaving a .pth file
#                       pointing at the build directory, which gives ModuleNotFoundError on the
#                       appliance.
#   --python <path>     the base-interpreter symlink is not relocated, so the build host's
#                       interpreter path is baked in regardless.
#   --frozen            fails if uv.lock and pyproject.toml have drifted apart, which is itself
#                       a supply-chain check.
#   --no-dev            keeps test and lint tooling off the appliance.
#
#   --system-site-packages
#                       the DB tools reach the platform's sl_mysql and MySQLdb through
#                       /usr/lib/python3.12/site-packages/silo.pth, which runs
#                       site.addsitedir('/opt/em7/lib/python3.12').  An isolated venv never
#                       executes that .pth, so `import sl_mysql` fails and the 8 DB tools are
#                       disabled.  An A/B test confirmed the flag is what makes the difference
#                       (sl_mysql also needs libem7 at import time).
#
# --relocatable and --no-editable are independent and both required: one fixes the interpreter
# path, the other the module path.  Either alone still ships a package that will not start.
#
# --relocatable and --system-site-packages coexist.  On uv 0.8.15 one pyvenv.cfg carries both
# `relocatable = true` and `include-system-site-packages = true`; both are asserted below.
#
# The venv is built here, at RPM build time.  Nothing is built, downloaded or resolved at install
# time, and no lifecycle operation touches the network.
# ---------------------------------------------------------------------------------------------
uv venv --relocatable --system-site-packages %{_builddir}/venv --python %{build_python}
VIRTUAL_ENV=%{_builddir}/venv uv sync --frozen --no-dev --no-editable --active

# Assert what the build actually produced, rather than trusting the flags.
#
# The site-packages check is two-sided on purpose: a venv that silently stopped inheriting system
# site-packages would disable the DB tools on the appliance with nothing failing at build time.
test "$(grep -c 'include-system-site-packages = true' %{_builddir}/venv/pyvenv.cfg)" -eq 1 \
  || { echo "FATAL: venv does not inherit system site-packages -- include-system-site-packages=true is required, or sl_mysql is unimportable and the DB tools are disabled"; exit 1; }
grep -q '^relocatable = true' %{_builddir}/venv/pyvenv.cfg \
  || { echo "FATAL: venv is not relocatable -- console-script shebangs would point at the buildroot"; exit 1; }
! find %{_builddir}/venv -name '__editable__*' -print -quit | grep -q . \
  || { echo "FATAL: editable install detected -- the package would import from the build directory"; exit 1; }

# With the system tree inherited, a locked dependency that also exists there could in principle be
# treated as satisfied and never installed into the venv, shipping an incomplete venv that passes
# every other check here.  On uv 0.8.15 `uv sync --frozen` installs every locked distribution into
# the venv's own site-packages with the flag on; this is asserted anyway because a future uv could
# behave differently.
for _pkg in fastmcp httpx pydantic; do
  test -d "%{_builddir}/venv/lib/python3.12/site-packages/${_pkg}" \
    || { echo "FATAL: locked dependency ${_pkg} is NOT in the venv -- it may have been satisfied from the inherited system tree, which would ship an incomplete venv"; exit 1; }
done

# The loop above is not enough for fastmcp.  fastmcp 3.x is an ~8 kB meta-package plus
# `fastmcp-slim`, which owns all the code: on 3.4.7 the `fastmcp` distribution ships no files
# outside its own dist-info, and all 269 entries under `site-packages/fastmcp/` belong to
# `fastmcp-slim`.  So `test -d site-packages/fastmcp` passes with the `fastmcp` distribution
# absent, which is exactly the case it exists to catch.
#
# A dist-info directory shows that a distribution was installed here, and unlike an
# import-package directory it exists for a meta-package too.  Both halves of the split are
# checked, because either one missing ships a broken venv.
for _dist in fastmcp fastmcp_slim; do
  find "%{_builddir}/venv/lib/python3.12/site-packages" -maxdepth 1 -type d \
       -name "${_dist}-*.dist-info" -print -quit | grep -q . \
    || { echo "FATAL: locked distribution ${_dist} has no dist-info in the venv -- it may have been satisfied from the inherited system tree, which would ship an incomplete venv"; exit 1; }
done

# =============================================================================================
%install
rm -rf %{buildroot}

install -d -m 0755 %{buildroot}%{versioned_dir}
install -d -m 0755 %{buildroot}%{versioned_dir}/nginx
install -d -m 0755 %{buildroot}%{versioned_dir}/docs

cp -a %{_builddir}/venv %{buildroot}%{versioned_dir}/venv

# The version symlink.  The unit file, the nginx include line and the env file path all
# reference this and never the versioned directory, which keeps them version-independent.
ln -s powerpack-mcp-%{service_version} %{buildroot}%{symlink_path}

install -D -m 0644 packaging/systemd/powerpack-mcp.service \
        %{buildroot}%{_unitdir}/powerpack-mcp.service

# The fragment lives in a directory this package owns, activated by the include line %post adds.
# The zone file has to be in nginx.d/ to be picked up by the existing http-level wildcard.
install -m 0640 packaging/nginx/powerpack-mcp.fragment \
        %{buildroot}%{versioned_dir}/nginx/powerpack-mcp.fragment
install -D -m 0640 packaging/nginx/powerpack-mcp-zone.conf \
        %{buildroot}%{nginx_d}/powerpack-mcp-zone.conf

# Every doc the %description points at must be installed here and listed in %files;
# tests/unit/test_rpm_spec.py checks this.  `docs/release-notes.md` is deliberately not shipped,
# and the %description does not mention it.
install -m 0644 docs/operations.md   %{buildroot}%{versioned_dir}/docs/operations.md
install -m 0644 docs/client-setup.md %{buildroot}%{versioned_dir}/docs/client-setup.md

# ---------------------------------------------------------------------------------------------
# Payload exclusions.
#
# The sdist contains Dockerfile, docker-compose*.yml, CI configuration, tests/ and packaging/
# itself, so it cannot be relied on to have excluded anything.  The exclusion happens at the RPM
# payload level: %files below lists only what is wanted, and this guard asserts it.
# ---------------------------------------------------------------------------------------------
for forbidden in Dockerfile docker-compose.yml docker-compose.editable.yml .github tests packaging; do
    if [ -e "%{buildroot}%{versioned_dir}/${forbidden}" ]; then
        echo "FATAL: ${forbidden} leaked into the payload"; exit 1
    fi
done

# =============================================================================================
%files
%dir %{versioned_dir}
%dir %{versioned_dir}/nginx
%dir %{versioned_dir}/docs
%{versioned_dir}/venv
%{symlink_path}
%{_unitdir}/powerpack-mcp.service
%attr(0640,root,s-em7-core) %{versioned_dir}/nginx/powerpack-mcp.fragment
%attr(0640,root,s-em7-core) %{nginx_d}/powerpack-mcp-zone.conf
%doc %{versioned_dir}/docs/operations.md
%doc %{versioned_dir}/docs/client-setup.md
%license LICENSE

# ---------------------------------------------------------------------------------------------
# The operator's config file.  All three flags are needed.
#
#   %ghost              RPM carries no content for this path.  Without it, RPM ships a file: an
#                       upgrade drops a .rpmnew alongside, and an erase renames the operator's file
#                       to .rpmsave, so it is gone from its own path and a reinstall does not
#                       resume.
#
#   %config(noreplace)  Not redundant; do not remove it.  It looks redundant, since RPM ships no
#                       content for a %ghost path, but it is what makes the file survive erase.
#                       Verified on RPM 4.14.3: without %config, the %ghost file and its parent
#                       directory are deleted on erase.
#
#   %attr(0600,...)     The service also checks the mode at startup and refuses to start if the
#                       file is group- or world-accessible.
#
# The path is inside the versioned directory.  A release bump preserves the file; a version bump
# installs a fresh directory, and any operator edits must be re-applied.  Every key is optional,
# so the service starts normally with the fresh file.  The one edit that matters is
# LCE_VERIFY_TLS=false on a self-signed appliance, and forgetting it is not loud: the service
# starts and every tool call fails with lce_unreachable.  See docs/operations.md section 2.
# ---------------------------------------------------------------------------------------------
%ghost %attr(0600,s-em7-core,s-em7-core) %config(noreplace) %{env_file}

# =============================================================================================
# SCRIPTLETS
#
# Every lifecycle action is guarded on the scriptlet argument, using this table (verified on
# RPM 4.14.3):
#
#   transaction      %pre   %post   %preun   %postun   %posttrans
#   fresh install      1      1       -         -          1
#   upgrade            2      2       1(old)    1(old)     1
#   erase              -      -       0         0          -        <-- no %posttrans on erase
#
# The guards are required because %preun and %postun also run on upgrade, for the old package.
# An unguarded "stop and disable the service" or "delete the nginx fragment" would fire on every
# upgrade.  Worse, the old package's %postun runs after the new package's files are installed, so
# an unguarded delete removes the new fragment and rpm -V reports a file the package owns as
# missing.
#
# The platform has this bug: em7-platform-core's %preuninstall runs `groupdel s-em7-core || :`
# unguarded, so it fires on every upgrade.  It is harmless only because groupdel refuses while the
# group is in use.
#
# A failing %post or %posttrans does not abort the transaction: `rpm -i` exits 0, the package
# stays installed, and the failure is only a warning.  So the scriptlets clean up after themselves,
# and no CI step may treat rpm's exit status as evidence that a lifecycle operation succeeded.
#
# There is no %pre: no account is created (s-em7-core belongs to the platform), and there is no
# check that it exists.
# =============================================================================================

%post
# --- the operator's config file, created only if absent ---------------------------------------
# The file holds only optional settings; there is no credential in it.  The existence guard is
# needed: without it, every upgrade would overwrite the operator's edited settings.
# %config(noreplace) at the %files entry covers the packaged case; this covers the %ghost one.
if [ ! -f "%{env_file}" ]; then
    cat > "%{env_file}" <<'ENVFILE'
# Skylar One PowerPack MCP Server configuration.
#
# Every key below is optional and shipped commented out, showing its default.  There is no
# credential to supply: each MCP caller sends its own Skylar One credential in the Authorization
# header of its requests.
#
# Boolean keys accept true or false (also 1/0, yes/no, on/off), case-insensitive.
# Quote any value containing " #" -- in an unquoted value it starts a comment.
#
# To start the service:            systemctl enable --now powerpack-mcp
# After editing this file:         systemctl restart powerpack-mcp

# The address the service binds.  Loopback only: 127.0.0.0/8, ::1 or localhost.
# Default: 127.0.0.1.
#
# A routable value such as 0.0.0.0 is refused at startup.  nginx is the only route to this service
# and nginx is what authenticates the caller, so a routable bind would leave the service reachable
# directly, with no authentication in front of it.
#LISTEN_HOST=127.0.0.1

# The loopback port the service binds.  An integer from 1024 to 65535.  Default: 8000.
# The nginx fragment proxies to this port, so changing it means editing that fragment to match.
#LISTEN_PORT=8000

# Verify the TLS certificate of the appliance this service calls.  Default: true.
#
# Set this to false only if the appliance still presents the stock self-signed certificate, which
# cannot be verified.  If you leave it at true in that case the service starts and looks healthy,
# but every tool call fails with lce_unreachable.  The permanent fix is to install a certificate
# with a proper subjectAltName instead.  This setting also covers SL1 traffic, not just LCE.
#LCE_VERIFY_TLS=false

# Log verbosity: DEBUG, INFO, WARNING, ERROR or CRITICAL.  Default: INFO.
#
# Leave this at INFO for normal running.  DEBUG logs full response bodies and can write tens of MB
# a day, which rotates older logs away within a day or two and loses the audit trail.
#LOG_LEVEL=INFO

# Maximum concurrent in-flight MCP requests.  An integer from 1 to 64.  Default: 6.
#
# Raising this also requires raising MemoryHigh and MemoryMax in the systemd unit; the service was
# measured breaching its 512M limit at about 8 concurrent maximum-size requests.
#MAX_CONCURRENT_REQUESTS=6

# Seconds to wait for a connection to the appliance.  Greater than 0, at most 60.  Default: 2.0.
# Must not exceed LCE_READ_TIMEOUT_SECONDS; the service refuses to start if it does.
#LCE_CONNECT_TIMEOUT_SECONDS=2.0

# Seconds to wait for a response from the appliance.  Greater than 0, at most 85.0.  Default: 30.0.
#
# The 85.0 ceiling is enforced at startup because this value is also how long shutdown waits for
# in-flight requests to drain, and systemd gives up at 90s.  Like LCE_VERIFY_TLS it governs SL1
# traffic too, so raising it to troubleshoot LCE also slows every SL1 call.
#LCE_READ_TIMEOUT_SECONDS=30.0

# The LCE host the LCE tools address.  A host name or IPv4 address, not a URL.  Default: localhost.
# As with SL1_DEFAULT_TARGET_HOST below, this is the only place the host is set.
#LCE_DEFAULT_TARGET_HOST=localhost

# The SL1 host the SL1 tools address.  A host name or IP address, not a URL.  Default: localhost.
# This is the only place the host is set -- no tool accepts a host as a parameter.
#SL1_DEFAULT_TARGET_HOST=localhost

# Maximum bytes accepted in an inbound request payload.  A positive integer.  Default: 10485760
# (10 MiB).  This is the INBOUND cap; MAX_RESPONSE_BODY_BYTES below is the OUTBOUND one.
# A larger payload is refused with an actionable message; split it into smaller batches.
#MAX_REQUEST_BODY_BYTES=10485760

# Maximum bytes read from any single SL1 response.  A positive integer.  Default: 10485760 (10 MiB).
# A larger response is refused with sl1_response_too_large rather than truncated; narrow the query.
#MAX_RESPONSE_BODY_BYTES=10485760

# Register the 22 tools of the sl1_rest set.  Default: true.
#
# Despite the name, 16 of these 22 use GraphQL, so setting ENABLE_SL1_GRAPHQL_TOOLS=false on its own
# does not stop GraphQL traffic -- set both keys to false for that.  This set also includes a
# general-purpose SL1 request tool; what it can reach is limited to whatever the calling user's own
# SL1 account permits, and every call is audit-logged.  Set this to false to withhold the whole set.
#ENABLE_SL1_REST_TOOLS=true

# Register the 2 generic GraphQL tools of the sl1_graphql set.  Default: true.
#
# SL1 applies the calling user's own permissions to GraphQL queries, but NOT to schema
# introspection: one of these two tools lets any authenticated caller read the entire schema shape,
# including fields whose data their account cannot query.  Set this to false to withhold that.
#ENABLE_SL1_GRAPHQL_TOOLS=true

# Register the 3 tools of the db_read set, which read the appliance database directly.
# Default: true.
#
# Setting this to false also withholds the db_write set, whatever ENABLE_DB_WRITE_TOOLS says.
# Both DB sets need the platform database driver; without it neither is registered even at true.
#ENABLE_DB_TOOLS=true

# Register the 5 tools of the db_write set, which write directly to the appliance database.
# Default: true.
#
# The platform database connection runs with autocommit on, so these writes CANNOT be rolled back.
# A tool that fails part-way through a multi-statement change has already committed the statements
# before the failure, leaving inconsistent data that nothing in this service can undo.  Set this to
# false to withhold the whole set.
#ENABLE_DB_WRITE_TOOLS=true

# Register the 14 tools of the ops set -- events, discovery, icons, health and capability checks.
# Default: true.  These use the supported SL1 REST and GraphQL paths, not the database, so they are
# unaffected by the two DB keys above.
#ENABLE_OPS_TOOLS=true

# Register the 1 tool of the standards set, which returns the PowerPack content standards from an
# in-memory catalog.  Default: true.  It reads no appliance data and makes no network call.
#ENABLE_STANDARDS_TOOLS=true
ENVFILE
    chown s-em7-core:s-em7-core "%{env_file}" >/dev/null 2>&1 || :
    chmod 0600 "%{env_file}" >/dev/null 2>&1 || :
fi

# --- register the unit, without enabling it --------------------------------------------------
# Installing must never enable or start the service.  `%%systemd_post` enables units passed to
# it, so it is deliberately not used.  A bare daemon-reload registers the unit and leaves it
# disabled and stopped.
#
# Keep the `%%`.  RPM expands defined macros inside `#` comments, and written unescaped this
# comment expanded into a live `systemctl --no-reload preset ...` in %post, with the prose
# swallowed as arguments.  It never failed visibly (garbage unit names make `preset` a no-op, and
# `|| :` hides the exit status), but `preset` is exactly the enable-adjacent operation to avoid.
%{_bindir}/systemctl daemon-reload >/dev/null 2>&1 || :

# --- the nginx include line ------------------------------------------------------------------
# Points at the symlink path, so a version bump never needs to re-edit this platform-owned file.
#
# This file is owned by sl-php-ui and is not a %config file, so any platform upgrade overwrites
# it and silently deletes this line.  %posttrans re-adds it on our next upgrade, but nothing of
# ours runs at the moment the platform removes it.  See docs/operations.md.
if [ -f "%{em7_web_fragment}" ] \
   && ! grep -q 'powerpack-mcp/nginx/powerpack-mcp.fragment' "%{em7_web_fragment}"; then
    printf '\n    # PowerPack MCP Server\n    include %s/nginx/powerpack-mcp.fragment;\n' \
        "%{symlink_path}" >> "%{em7_web_fragment}"
fi

%preun
# $1 = 0 only.  On an upgrade this argument is 1 and nothing below may run.
if [ "$1" = 0 ]; then
    %{_bindir}/systemctl --no-reload disable powerpack-mcp.service >/dev/null 2>&1 || :
    %{_bindir}/systemctl stop powerpack-mcp.service >/dev/null 2>&1 || :
fi

%postun
# $1 = 0 only -- see %preun.  This scriptlet also runs on upgrade, after the new package's files
# are in place, so an unguarded delete here would remove the new files.
if [ "$1" = 0 ]; then
    # Remove our include line from the platform's fragment.  nginx must be valid after removal: a
    # broken uninstall takes the appliance's entire web surface down, not just this service, and
    # a dangling include of a file we just deleted is exactly that failure.
    if [ -f "%{em7_web_fragment}" ]; then
        sed -i '/# PowerPack MCP Server/,+1d' "%{em7_web_fragment}" >/dev/null 2>&1 || :
    fi

    # %posttrans does not run on erase, so validate and reload here.
    if %{_sbindir}/nginx -t >/dev/null 2>&1; then
        %{_bindir}/systemctl reload nginx >/dev/null 2>&1 || :
    else
        echo "WARNING: nginx -t failed after removing the PowerPack MCP fragment." >&2
        echo "         nginx was NOT reloaded and is still serving its last good config." >&2
        echo "         Inspect %{em7_web_fragment}." >&2
    fi

    %{_bindir}/systemctl daemon-reload >/dev/null 2>&1 || :
fi

%posttrans
# ---------------------------------------------------------------------------------------------
# nginx is validated and reloaded exactly once per transaction, from %posttrans and nowhere else
# (except %postun on erase, when %posttrans does not run).
#
# %posttrans runs last, after the old package's %postun, so it is the only point at which the
# filesystem is in its final state.  A reload issued from %post happens before the old package's
# %postun, so any change that scriptlet makes lands after nginx has re-read its configuration,
# leaving nginx serving a config that no longer matches disk, and nothing detects that.
#
# %posttrans cannot distinguish install from upgrade (its argument is 1 for both), and it does not
# need to, because validate-then-reload is correct either way.
# ---------------------------------------------------------------------------------------------

# Re-add the include line if a platform upgrade removed it.  Idempotent.
if [ -f "%{em7_web_fragment}" ] && [ -f "%{symlink_path}/nginx/powerpack-mcp.fragment" ] \
   && ! grep -q 'powerpack-mcp/nginx/powerpack-mcp.fragment' "%{em7_web_fragment}"; then
    printf '\n    # PowerPack MCP Server\n    include %s/nginx/powerpack-mcp.fragment;\n' \
        "%{symlink_path}" >> "%{em7_web_fragment}"
    echo "NOTE: re-added the PowerPack MCP nginx include line, which had been removed." >&2
fi

if %{_sbindir}/nginx -t >/dev/null 2>&1; then
    %{_bindir}/systemctl reload nginx >/dev/null 2>&1 || :
else
    # Clean up and report.
    #
    # A failing scriptlet cannot abort the install or signal failure through its exit status:
    # `rpm -i` exits 0 regardless (verified for both %post and %posttrans).  So this scriptlet
    # leaves the system in a state that needs no signal: remove what we added, confirm the
    # appliance is back as we found it, and do not reload.  nginx keeps serving its last
    # known-good configuration, so the web surface is never degraded, even on failure.
    #
    # The cost is that the service is installed but unroutable while rpm reports success.  The
    # alternative, leaving an invalid fragment on disk so the failure is discoverable, would make
    # any later unrelated nginx reload fail, turning this service's problem into the appliance's.
    sed -i '/# PowerPack MCP Server/,+1d' "%{em7_web_fragment}" >/dev/null 2>&1 || :
    rm -f "%{nginx_d}/powerpack-mcp-zone.conf" >/dev/null 2>&1 || :
    if %{_sbindir}/nginx -t >/dev/null 2>&1; then
        echo "ERROR: the PowerPack MCP nginx configuration was REJECTED by nginx -t." >&2
        echo "       It has been removed and the appliance is as it was before installation." >&2
        echo "       nginx was NOT reloaded.  /mcp is NOT available." >&2
        echo "       The package remains installed; rpm cannot report this failure itself." >&2
    else
        echo "CRITICAL: nginx -t still fails after removing the PowerPack MCP configuration." >&2
        echo "          The pre-existing nginx configuration may already have been invalid." >&2
        echo "          DO NOT RELOAD NGINX until this is resolved." >&2
    fi
fi

# ---------------------------------------------------------------------------------------------
# Restart a running service on upgrade.  Without this, `rpm -U` replaces every file on disk and
# exits 0 while the old process keeps running the old code.
#
# Nothing else restarts it.  %post does a bare daemon-reload (`%%systemd_post` would enable the
# unit), and %preun and %postun are guarded to `$1 = 0`, so neither runs on an upgrade.
#
# Keep the `%%` above.  RPM expands defined macros inside `#` comments, and a multi-line expansion
# escapes the comment into live shell code.  An unescaped macro name here once injected an
# `if ... fi` block and an unmatched backtick, bash rejected the scriptlet with "unexpected EOF
# while looking for matching backtick", and the restart below silently never ran while `rpm -U`
# still exited 0.  The mentions of %post, %preun, %postun and %posttrans are safe unescaped
# because those are section names, not defined macros.
#
# try-restart acts only on a unit that is currently active, which gives the three behaviours
# wanted with no branching:
#     fresh install    -> unit inactive and disabled, so this is a no-op; install still neither
#                         enables nor starts anything.
#     upgrade, running -> restarted onto the new code.
#     upgrade, stopped -> stays stopped; an operator who stopped it is not overruled.
#
# It lives in %posttrans rather than %postun because %postun is guarded to erase only, and
# %posttrans is already the single point where the filesystem is in its final state.
# daemon-reload has already run in %post, after the new unit file was installed.
#
# Startup takes 7-27 seconds while the tools register.  A health check issued immediately after
# this returns will see a refused connection; that is startup latency, not failure.  Poll /health
# rather than sleeping once and probing.
%{_bindir}/systemctl try-restart powerpack-mcp.service >/dev/null 2>&1 || :

%changelog
* Tue Aug 11 2026 ScienceLogic Solutions <solutions@sciencelogic.com> - 1.0.1-1
- nginx forwards the caller's Authorization header explicitly instead of relying on default
  pass-through.
- /ready removed.  nginx sends a WWW-Authenticate challenge on 401.
- Fixed a duplicate Content-Type header on all four @mcp_* error envelopes (RFC 9110 s5.5).
- Fixed: an upgrade now restarts a running service.  It previously did not, leaving the
  old code running with every file on disk replaced.
- Corrected %description and the env-file comments: there is no credential key.
* Thu Aug 06 2026 ScienceLogic Solutions <solutions@sciencelogic.com> - 1.0.0-1
- Initial packaging.

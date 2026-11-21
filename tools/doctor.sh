#!/bin/sh
# Source-checkout diagnostics only: never provision, compile or print env values.
set -u
export GOTOOLCHAIN=local
failures=0
pass() { printf 'PASS %s: %s\n' "$1" "$2"; }
fix() { printf 'FIX  %s: %s\n' "$1" "$2"; failures=$((failures + 1)); }
skip() { printf 'SKIP %s: %s\n' "$1" "$2"; }
has() { command -v "$1" >/dev/null 2>&1; }

printf '%s\n' 'Pomar source prerequisites (read-only; no environment values printed)'
for tool in git make awk sed grep find cmp mktemp sh go gofmt swift xcode-select codesign shasum file curl tar; do
    if has "$tool"; then pass "$tool" 'available'; else fix "$tool" 'provide the documented toolchain through your host owner; no automatic install'; fi
done

if [ "$(uname -s)" = Darwin ] && [ "$(uname -m)" = arm64 ]; then
    pass platform 'Apple silicon macOS host'
else
    fix platform 'the full native gate and Swift VM host require Apple silicon macOS; use an admitted native builder'
fi
if has sw_vers; then
    os_major=$(sw_vers -productVersion 2>/dev/null | awk -F. '{print $1}')
    case "$os_major" in ''|*[!0-9]*) fix macOS 'cannot determine version; macOS 26 or newer is required' ;;
        *) if [ "$os_major" -ge 26 ]; then pass macOS '26 or newer'; else fix macOS 'use macOS 26 or newer'; fi ;;
    esac
else
    fix macOS 'sw_vers unavailable; use the documented native builder'
fi

go_min=$(awk '$1 == "go" {print $2; exit}' go.mod 2>/dev/null)
go_line=$(printf '%s\n' "$go_min" | awk -F. '{print $1 "." $2}')
go_version=''
if has go; then go_version=$(go version 2>/dev/null | awk '{print $3}'); fi
case "$go_version" in
    "go$go_line".[0-9]*) pass Go "module toolchain line $go_line.x (minimum $go_min; local toolchain only)" ;;
    *) fix Go "provide the go.mod toolchain line $go_line.x (minimum $go_min); GOTOOLCHAIN is kept local" ;;
esac

swift_min=$(sed -n 's|^// swift-tools-version: *||p' host/Package.swift 2>/dev/null)
swift_version=''
if has swift; then swift_version=$(swift --version 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i == "version") {print $(i+1); exit}}'); fi
if awk -v got="$swift_version" -v need="$swift_min" 'BEGIN {
    if (got !~ /^[0-9]+\.[0-9]+/ || need !~ /^[0-9]+\.[0-9]+/) exit 1;
    split(got,g,"."); split(need,n,"."); exit !(g[1]>n[1] || (g[1]==n[1] && g[2]>=n[2]));
}'; then pass Swift "meets Package.swift tools version $swift_min"; else fix Swift "provide Swift $swift_min or newer from the approved developer tools"; fi

developer_dir=''
if has xcode-select; then developer_dir=$(xcode-select -p 2>/dev/null); fi
if [ -n "$developer_dir" ] && [ -d "$developer_dir" ]; then pass developer-tools 'selected directory exists'; else fix developer-tools 'have the host owner select an installed Xcode or Command Line Tools directory'; fi

container_pin=$(awk '/"identity"[[:space:]]*:[[:space:]]*"containerization"/ {pin=1}
    pin && /"version"[[:space:]]*:/ {line=$0; sub(/.*:[[:space:]]*"/,"",line); sub(/".*/,"",line); print line; exit}' host/Package.resolved 2>/dev/null)
if [ "$container_pin" = 0.45.0 ] && grep -q 'exact: "0.45.0"' host/Package.swift; then
    pass dependency-lock 'Containerization 0.45.0 pinned; builds use --force-resolved-versions'
else
    fix dependency-lock 'restore the reviewed host/Package.swift and host/Package.resolved pins; do not update dependencies to repair this check'
fi
if [ -f host/pomar-host.entitlements ] && grep -q com.apple.security.virtualization host/pomar-host.entitlements; then pass entitlement 'Virtualization entitlement input present'; else fix entitlement 'restore host/pomar-host.entitlements'; fi
if [ ! -e /var/run/docker.sock ]; then pass no-docker 'no Docker socket exposed'; else fix no-docker 'use the approved builder without a Docker socket'; fi

common=''
if has git; then common=$(git rev-parse --git-common-dir 2>/dev/null); fi
if [ -n "$common" ] && [ -d "$common" ] && [ -w "$common" ] && [ -w . ]; then
    pass checkout 'worktree and Git directory have OS write access; sandbox writes still require their normal policy'
else
    fix checkout 'restore the owner-approved writable worktree and Git metadata; do not widen permissions'
fi
hooks_path=''
if has git; then hooks_path=$(git config --get core.hooksPath 2>/dev/null || :); fi
if { [ "$hooks_path" = .githooks ] || [ "$hooks_path" = "$(pwd)/.githooks" ]; } && [ -x .githooks/pre-push ]; then
    pass hooks 'committed main-push guard installed (no heavy pre-push gate)'
else
    fix hooks 'run make hooks in your own clone to install the main-push guard'
fi

if [ "${HYGIENE_REQUIRE:-0}" != 0 ] && [ "${HYGIENE_REQUIRE:-0}" != 1 ]; then
    fix HYGIENE_REQUIRE 'use 0 for generic checks or 1 to require the private deny-list'
fi
if [ -n "${HYGIENE_DENYLIST:-}" ]; then
    if [ -f "$HYGIENE_DENYLIST" ] && [ -r "$HYGIENE_DENYLIST" ]; then pass HYGIENE_DENYLIST 'set and readable (value withheld)'; else fix HYGIENE_DENYLIST 'set but unreadable; obtain the private input from its owner'; fi
elif [ "${HYGIENE_REQUIRE:-0}" = 1 ]; then
    fix HYGIENE_DENYLIST 'required but unset; obtain the private input from its owner'
else
    skip HYGIENE_DENYLIST 'unset; generic contributor checks apply; maintainers require the private input'
fi
if [ -n "${POMAR_DEV_ROOT:-}" ]; then
    case "$POMAR_DEV_ROOT" in
        /*) if [ -d "$POMAR_DEV_ROOT" ] && [ ! -L "$POMAR_DEV_ROOT" ] && [ -w "$POMAR_DEV_ROOT" ]; then pass POMAR_DEV_ROOT 'set, present, not a symlink and writable (value withheld)'; else fix POMAR_DEV_ROOT 'set but not a usable directory; use the approved preparation route without moving a live environment'; fi ;;
        *) fix POMAR_DEV_ROOT 'must name an explicit absolute private directory' ;;
    esac
else
    skip POMAR_DEV_ROOT 'unset; only prepare/kernel/run need it; no volume or root is guessed'
fi
if [ -n "${POMAR_KERNEL_SHA256:-}" ]; then
    if printf '%s\n' "$POMAR_KERNEL_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then pass POMAR_KERNEL_SHA256 'set with valid digest shape; bytes still verified at launch'; else fix POMAR_KERNEL_SHA256 'set the exact digest from the approved kernel step'; fi
else
    skip POMAR_KERNEL_SHA256 'unset; make run requires the actual prepared kernel digest'
fi
if [ -n "${POMAR_SOCKET:-}" ]; then
    if [ ! -S "$POMAR_SOCKET" ]; then
        fix POMAR_SOCKET 'set but not a socket; obtain the correct binding from the host owner'
    elif has pomar; then
        if pomar doctor -json >/dev/null 2>&1; then pass POMAR_SOCKET 'installed client reports the explicit manager binding usable'; else fix POMAR_SOCKET 'read-only client doctor failed; ask the manager owner; never change socket permissions'; fi
    else
        fix POMAR_SOCKET 'set; an installed pomar client is needed to check manager reachability'
    fi
else
    skip POMAR_SOCKET 'unset; source tasks need no manager; job clients must receive this binding from the owner'
fi

if has curl && curl -q --head --fail --silent --output /dev/null --connect-timeout 2 --max-time 5 https://github.com/apple/containerization; then
    pass network 'dependency-source HTTPS reachable; this does not prove Git authentication or job admission'
else
    fix network 'dependency-source HTTPS unavailable; use the approved network/cache route; no fetch or install attempted'
fi
if [ "$failures" -ne 0 ]; then
    printf 'Doctor found %s prerequisite issue(s); no repairs made.\n' "$failures"
    exit 1
fi
printf '%s\n' 'Doctor prerequisites PASS; this is not a build, gate, VM qualification or job-admission receipt.'

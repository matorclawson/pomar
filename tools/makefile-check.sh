#!/bin/sh
# Compiler-free behavior checks in an isolated Git fixture. No network or push.
set -eu
repo=$(pwd)
make_bin=$(command -v make)
scratch=$(mktemp -d "${TMPDIR:-/tmp}/pomar-makefile.XXXXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
fixture="$scratch/repo"
fake="$scratch/bin"
mkdir -p "$fixture/.githooks" "$fixture/tools" "$fixture/host" "$fake" "$scratch/developer-tools"
cp Makefile "$fixture/Makefile"
cp .githooks/pre-push "$fixture/.githooks/pre-push"
cp tools/doctor.sh "$fixture/tools/doctor.sh"
cp go.mod "$fixture/go.mod"
cp host/Package.swift host/Package.resolved host/pomar-host.entitlements "$fixture/host/"
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
git -C "$fixture" init -q
fail() { printf 'FAIL makefile-check: %s\n' "$1" >&2; exit 1; }

export POMAR_FIXTURE_SENTINEL="$scratch/heavy-command"
export POMAR_FIXTURE_DEVELOPER_DIR="$scratch/developer-tools"
for tool in go swift xcode-select make; do
    cat > "$fake/$tool" <<'STUB'
#!/bin/sh
printf '%s\n' unexpected-heavy-command > "$POMAR_FIXTURE_SENTINEL"
exit 97
STUB
    chmod +x "$fake/$tool"
done
fixture_make() { (cd "$fixture" && PATH="$fake:/usr/bin:/bin" "$make_bin" --no-print-directory "$@"); }
fixture_make help help-all help-check > "$scratch/help.log" 2>&1 || fail 'discovery failed'
[ ! -e "$POMAR_FIXTURE_SENTINEL" ] || fail 'discovery launched a toolchain probe'
grep -q 'make help-all' "$scratch/help.log" || fail 'curated guide omits help-all'
printf '\nundocumented:\n\t@:\n' >> "$fixture/Makefile"
if fixture_make help-check > "$scratch/undocumented.log" 2>&1; then fail 'undocumented target accepted'; fi
cp "$repo/Makefile" "$fixture/Makefile"

hook="$fixture/.githooks/pre-push"
for row in \
    'refs/heads/work a refs/heads/main b' \
    '(delete) 0000000000000000000000000000000000000000 refs/heads/main b'; do
    if printf '%s\n' "$row" | sh "$hook" > "$scratch/hook.log" 2>&1; then fail 'main update or deletion allowed'; fi
done
if printf '%s\n' 'refs/heads/work a refs/heads/work b' 'refs/heads/work a refs/heads/main b' | sh "$hook" > "$scratch/hook.log" 2>&1; then fail 'mixed-ref main push allowed'; fi
printf '%s\n' 'refs/heads/work a refs/heads/work b' 'refs/tags/main a refs/tags/main b' | sh "$hook" || fail 'work branch or unrelated tag refused'
if printf '%s\n' 'malformed' | sh "$hook" > "$scratch/hook.log" 2>&1; then fail 'malformed hook input accepted'; fi
[ ! -e "$POMAR_FIXTURE_SENTINEL" ] || fail 'hook launched a heavy command'
fixture_make hooks > "$scratch/hooks.log" 2>&1 || fail 'hook installation failed'
[ "$(git -C "$fixture" config --local --get core.hooksPath)" = .githooks ] || fail 'hook configuration missing'
[ ! -e "$POMAR_FIXTURE_SENTINEL" ] || fail 'installing hooks launched heavy work'

# Replace tool probes with exact fixture versions, never actual compilers.
cat > "$fake/go" <<'STUB'
#!/bin/sh
if [ "$*" = version ]; then printf 'go version %s darwin/arm64\n' "${POMAR_FIXTURE_GO:-go1.27.3}"; else printf unexpected > "$POMAR_FIXTURE_SENTINEL"; exit 97; fi
STUB
cat > "$fake/swift" <<'STUB'
#!/bin/sh
if [ "$*" = --version ]; then printf 'Apple Swift version %s\n' "${POMAR_FIXTURE_SWIFT:-6.2.1}"; else printf unexpected > "$POMAR_FIXTURE_SENTINEL"; exit 97; fi
STUB
cat > "$fake/uname" <<'STUB'
#!/bin/sh
case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) exit 1 ;; esac
STUB
cat > "$fake/sw_vers" <<'STUB'
#!/bin/sh
echo 26.0
STUB
cat > "$fake/xcode-select" <<'STUB'
#!/bin/sh
printf '%s\n' "$POMAR_FIXTURE_DEVELOPER_DIR"
STUB
cat > "$fake/curl" <<'STUB'
#!/bin/sh
[ "${POMAR_FIXTURE_NETWORK:-up}" = up ]
STUB
for tool in gofmt codesign shasum file; do
    printf '#!/bin/sh\nexit 0\n' > "$fake/$tool"
done
chmod +x "$fake/"*
snapshot() { find "$fixture" -type f -exec cksum {} \; | sort; }
snapshot > "$scratch/before"
HYGIENE_DENYLIST= HYGIENE_REQUIRE=0 POMAR_SOCKET= POMAR_DEV_ROOT= POMAR_KERNEL_SHA256= \
    fixture_make doctor > "$scratch/doctor.log" 2>&1 || { cat "$scratch/doctor.log"; fail 'healthy fixture doctor failed'; }
snapshot > "$scratch/after"
cmp "$scratch/before" "$scratch/after" >/dev/null || fail 'doctor changed checkout or Git files'
grep -q 'PASS hooks' "$scratch/doctor.log" || fail 'doctor missed installed hook'
if POMAR_FIXTURE_GO=go1.26.0 fixture_make doctor > "$scratch/wrong-go.log" 2>&1; then fail 'wrong Go line accepted'; fi
grep -q 'FIX  Go:' "$scratch/wrong-go.log" || fail 'wrong Go line lacks repair guidance'
if POMAR_FIXTURE_SWIFT=6.1.0 fixture_make doctor > "$scratch/wrong-swift.log" 2>&1; then fail 'old Swift accepted'; fi
grep -q 'FIX  Swift:' "$scratch/wrong-swift.log" || fail 'old Swift lacks repair guidance'
sed 's/0.45.0/0.44.0/g' "$repo/host/Package.resolved" > "$fixture/host/Package.resolved"
if fixture_make doctor > "$scratch/wrong-pin.log" 2>&1; then fail 'changed dependency pin accepted'; fi
grep -q 'FIX  dependency-lock:' "$scratch/wrong-pin.log" || fail 'changed pin lacks repair guidance'
cp "$repo/host/Package.resolved" "$fixture/host/Package.resolved"
if POMAR_FIXTURE_NETWORK=down fixture_make doctor > "$scratch/network.log" 2>&1; then fail 'network refusal hidden'; fi
grep -q 'FIX  network:' "$scratch/network.log" || fail 'network refusal lacks repair guidance'
secret_marker=DO_NOT_PRINT_PRIVATE_ENV_VALUE
if HYGIENE_REQUIRE=1 HYGIENE_DENYLIST="$scratch/$secret_marker" POMAR_SOCKET="$scratch/$secret_marker" \
    POMAR_DEV_ROOT="$scratch/$secret_marker" POMAR_KERNEL_SHA256="$secret_marker" \
    fixture_make doctor > "$scratch/private.log" 2>&1; then fail 'invalid private inputs accepted'; fi
if grep -q "$secret_marker" "$scratch/private.log"; then fail 'doctor printed an environment value'; fi
git -C "$fixture" config --local --unset core.hooksPath
if fixture_make doctor > "$scratch/missing-hook.log" 2>&1; then fail 'missing hook ignored'; fi
grep -q 'FIX  hooks:' "$scratch/missing-hook.log" || fail 'missing hook lacks repair guidance'
if VERSION= RELEASE_OUT= fixture_make release-candidate > "$scratch/candidate-inputs.log" 2>&1; then fail 'candidate without explicit inputs accepted'; fi
if VERSION=v0.1.0 RELEASE_OUT="$scratch/candidate" fixture_make release-candidate > "$scratch/candidate-version.log" 2>&1; then fail 'final version accepted as a candidate'; fi
if VERSION=v0.1.0-rc.1 RELEASE_OUT=relative-output fixture_make release-candidate > "$scratch/candidate-output.log" 2>&1; then fail 'relative candidate output accepted'; fi
if VERSION=v0.1.0 RELEASE_OUT="$scratch/candidate" fixture_make release > "$scratch/release.log" 2>&1; then fail 'unconfigured final publication accepted'; fi
grep -q 'Release promotion is not configured' "$scratch/release.log" || fail 'release refusal omits the missing route'
if POMAR_DEV_ROOT= POMAR_KERNEL_SHA256= fixture_make run > "$scratch/run.log" 2>&1; then fail 'run without explicit inputs accepted'; fi
mkdir "$scratch/preserved-build"
printf retained > "$scratch/preserved-build/marker"
ln -s "$scratch/preserved-build" "$fixture/.build"
if fixture_make clean > "$scratch/clean.log" 2>&1; then fail 'clean accepted a redirected build directory'; fi
[ "$(cat "$scratch/preserved-build/marker")" = retained ] || fail 'clean affected another directory'
[ ! -e "$POMAR_FIXTURE_SENTINEL" ] || fail 'read-only/refusal checks launched heavy work'
printf '%s\n' 'PASS makefile-check: help; hook install/refusals; read-only doctor; pins/network/env refusals; candidate inputs and promotion refusal; explicit run inputs; clean redirect refusal'

#!/usr/bin/env bash
# sow: pomar-SOW-87
# Exercise the ACTUAL candidate hook in a private Git fixture. No push/network,
# production hook installation, credentials or source-worktree mutation.
set -euo pipefail
source_root=$(git rev-parse --show-toplevel)
hook=$source_root/.githooks/pre-push
scratch=$(mktemp -d "${TMPDIR:-/tmp}/zeo-wip-hook.XXXXXX")
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/home" "$scratch/tools"
export HOME="$scratch/home" XDG_CONFIG_HOME="$scratch/home" GIT_CONFIG_NOSYSTEM=1
fixture=$scratch/repo
git clone -q --shared --no-checkout "$source_root" "$fixture"
git -C "$fixture" checkout -q -b fixture-source 3a36b259ab1cdac8c4c3e56a81cbee077732bfe1
git -C "$fixture" remote remove origin
git -C "$fixture" config user.name Fixture
git -C "$fixture" config user.email fixture@example.invalid
url=git@github.com:matorclawson/pomar.git
git -C "$fixture" remote add origin "$url"
cd "$fixture"
head=$(git rev-parse HEAD)
local_ref=$(git symbolic-ref HEAD)
zero=0000000000000000000000000000000000000000
ref=refs/heads/zeo-site-maintainer/wip/creator-verification-20261024
export ZMAIL_INSTANCE=zeroemployee
export TEST_MAKE_LOG="$scratch/make.log"
cat > "$scratch/tools/make" <<'MAKE'
#!/usr/bin/env bash
printf '%s
' "$*" >> "$TEST_MAKE_LOG"
exit 47
MAKE
chmod +x "$scratch/tools/make"
export PATH="$scratch/tools:$PATH"
printf '%s %s %s %s
' "$local_ref" "$head" "$ref" "$zero" > "$scratch/valid"
run() {
    local name=$1 want=$2 input=$3 destination=${4:-$url} code
    if "$hook" origin "$destination" < "$input" > "$scratch/stdout" 2> "$scratch/stderr"; then code=0; else code=$?; fi
    if [[ "$want" == pass ]]; then
        [[ "$code" == 0 ]] || { echo "FAIL expected backup: $name" >&2; exit 1; }
    else
        [[ "$code" != 0 ]] || { echo "FAIL exception admitted: $name" >&2; exit 1; }
    fi
}
run own-fork-owner-backup pass "$scratch/valid"
run_guard() {
    local name=$1 input=$2 expected=$3
    run "$name" refuse "$input"
    case "$(cat "$scratch/stderr")" in
        *"$expected"*) ;;
        *) echo "FAIL wrong refusal boundary: $name" >&2; exit 1 ;;
    esac
}
# A newline-terminated allowed update must never hide an unterminated suffix.
# Each alone must also fail, before authorization can return success.
for suffix in mixed tag delete malformed valid; do
    case "$suffix" in
        mixed) printf '%s %s refs/heads/main %s' "$local_ref" "$head" "$zero" > "$scratch/partial" ;;
        tag) printf '%s %s refs/tags/wip/backup %s' "$local_ref" "$head" "$zero" > "$scratch/partial" ;;
        delete) printf '%s %s %s %s' "$local_ref" "$zero" "$ref" "$head" > "$scratch/partial" ;;
        malformed) printf 'malformed' > "$scratch/partial" ;;
        valid) printf '%s %s %s %s' "$local_ref" "$head" "$ref" "$zero" > "$scratch/partial" ;;
    esac
    run_guard "partial-alone-$suffix" "$scratch/partial" 'partial or unreadable update record'
    cat "$scratch/valid" "$scratch/partial" > "$scratch/valid-and-partial"
    run_guard "valid-then-partial-$suffix" "$scratch/valid-and-partial" 'partial or unreadable update record'
done
# A closed input descriptor must fail capture, not look like clean EOF.
if "$hook" origin "$url" <&- > "$scratch/stdout" 2> "$scratch/stderr"; then
    echo 'FAIL unreadable input admitted' >&2; exit 1
fi
case "$(cat "$scratch/stderr")" in
    *'update stream read failed'*) ;;
    *) echo 'FAIL unreadable input missed capture guard' >&2; exit 1 ;;
esac
# Inject only config-query failures; other Git operations still use the actual
# installed Git. This fixture cannot become an installed credential/tool route.
export TEST_REAL_GIT
TEST_REAL_GIT=$(command -v git)
cat > "$scratch/tools/git" <<'GIT'
#!/usr/bin/env bash
if [[ "${1:-}" == config ]]; then
    case "${TEST_GIT_CONFIG_FAULT:-}:${2:-}" in
        rewrite:--name-only|mirror:--bool|push:--get-all) exit 3 ;;
    esac
fi
exec "$TEST_REAL_GIT" "$@"
GIT
chmod +x "$scratch/tools/git"
for fault in rewrite mirror push; do
    case "$fault" in
        rewrite) expected='URL rewrite configuration unreadable' ;;
        mirror) expected='mirror configuration unreadable' ;;
        push) expected='push refspec configuration unreadable' ;;
    esac
    TEST_GIT_CONFIG_FAULT=$fault run_guard "config-read-error-$fault" "$scratch/valid" "$expected"
done
git config remote.origin.mirror not-a-boolean
run_guard malformed-mirror-boolean "$scratch/valid" 'mirror configuration unreadable'
git config --unset remote.origin.mirror
git config remote.origin.mirror false
run explicit-nonmirror pass "$scratch/valid"
git config --add remote.origin.mirror false
run_guard ambiguous-mirror "$scratch/valid" 'mirror configured or ambiguous'
git config --unset-all remote.origin.mirror
run absent-config-still-valid pass "$scratch/valid"
printf '%s %s %s %s
' "$local_ref" "$head" "$ref" "$head" > "$scratch/ff"
run idempotent-fast-forward pass "$scratch/ff"
: > "$scratch/empty"
run empty refuse "$scratch/empty"
printf 'malformed
' > "$scratch/bad"
run malformed refuse "$scratch/bad"
printf '%s %s %s %s
' "$local_ref" "$zero" "$ref" "$head" > "$scratch/delete"
run delete refuse "$scratch/delete"
printf '%s %s refs/tags/wip/backup %s
' "$local_ref" "$head" "$zero" > "$scratch/tag"
run tag refuse "$scratch/tag"
cp "$scratch/valid" "$scratch/mixed"
printf '%s %s refs/heads/main %s
' "$local_ref" "$head" "$zero" >> "$scratch/mixed"
run mixed-all-or-nothing refuse "$scratch/mixed"
cat "$scratch/valid" "$scratch/valid" > "$scratch/duplicate"
run duplicate-destination-ref refuse "$scratch/duplicate"
printf '%s %s refs/heads/foreign/wip/backup %s
' "$local_ref" "$head" "$zero" > "$scratch/foreign"
run foreign-owner-ref refuse "$scratch/foreign"
ZMAIL_INSTANCE=foreign run foreign-context refuse "$scratch/valid"
ZMAIL_INSTANCE= run missing-context refuse "$scratch/valid"
git remote set-url origin git@github.com:zeroemployeeorg/pomar.git
run gold refuse "$scratch/valid" git@github.com:zeroemployeeorg/pomar.git
git remote set-url origin git@github.com:foreign/pomar.git
run foreign-fork refuse "$scratch/valid" git@github.com:foreign/pomar.git
git remote set-url origin "$url"
run mismatched-actual-argument refuse "$scratch/valid" https://github.com/foreign/pomar.git
git config --add remote.origin.pushurl "$url"
git config --add remote.origin.pushurl "$url"
run duplicate-push-destination refuse "$scratch/valid"
git config --unset-all remote.origin.pushurl
git config remote.origin.mirror true
run mirror-config refuse "$scratch/valid"
git config --unset remote.origin.mirror
git config remote.origin.push 'refs/heads/*:refs/heads/*'
run implicit-refspec refuse "$scratch/valid"
git config --unset remote.origin.push
git config url."$url".pushInsteadOf 'fixture-prefix:'
run rewrite refuse "$scratch/valid"
git config --unset-all url."$url".pushInsteadOf
unrelated=$(printf 'unrelated fixture
' | git commit-tree "$(git rev-parse HEAD^{tree})")
printf '%s %s %s %s
' "$local_ref" "$head" "$ref" "$unrelated" > "$scratch/force"
run non-fast-forward refuse "$scratch/force"
printf '%s %s %s %s
' "$local_ref" "$head" "$ref" ffffffffffffffffffffffffffffffffffffffff > "$scratch/unknown"
run missing-ancestry refuse "$scratch/unknown"
printf '%s %s refs/heads/main %s
' "$local_ref" "$head" "$zero" > "$scratch/ordinary"
run ordinary-still-gated refuse "$scratch/ordinary"
[[ -f "$TEST_MAKE_LOG" ]] && grep -qx verify "$TEST_MAKE_LOG" || { echo "ordinary make verify guard bypassed" >&2; exit 1; }
printf '%s
' 'PASS actual hook backup/refusal fixture; no network push or live adoption'

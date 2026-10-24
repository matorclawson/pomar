#!/usr/bin/env bash
# sow: pomar-SOW-87
# Exercise the ACTUAL candidate hook in a private Git fixture. No push/network,
# production hook installation, credentials or source-worktree mutation.
set -euo pipefail
source_root=$(git rev-parse --show-toplevel)
hook=${WIP_HOOK_UNDER_TEST:-$source_root/.githooks/pre-push}
test_base_path=$PATH
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
    local name=$1 want=$2 input=$3 destination=${4:-$url} expected=${5:-} code
    if "$hook" origin "$destination" < "$input" > "$scratch/stdout" 2> "$scratch/stderr"; then code=0; else code=$?; fi
    if [[ "$want" == pass ]]; then
        [[ "$code" == 0 ]] || { echo "FAIL expected backup: $name" >&2; exit 1; }
        grep -Fxq 'UNQUALIFIED WIP BACKUP ONLY: no gate, PR, merge or release acceptance.' "$scratch/stderr" || { echo "FAIL backup success marker missing: $name" >&2; exit 1; }
    else
        [[ "$code" != 0 ]] || { echo "FAIL exception admitted: $name" >&2; exit 1; }
        if [[ "$name" == ordinary-still-gated ]]; then
            [[ "$code" == 47 && -f "$TEST_MAKE_LOG" ]] && grep -qx verify "$TEST_MAKE_LOG" || { echo "FAIL ordinary gate boundary: $name" >&2; exit 1; }
            return
        fi
        if [[ -z "$expected" ]]; then
            case "$name" in
                empty) expected='empty update stream' ;;
                malformed) expected='malformed update' ;;
                delete) expected='deletion' ;;
                tag|mixed-all-or-nothing|foreign-owner-ref) expected='ref outside exact owning acceptance' ;;
                duplicate-destination-ref) expected='duplicate destination ref' ;;
                foreign-context|missing-context) expected='owner mapping unavailable' ;;
                gold|foreign-fork) expected='not the accepted own fork' ;;
                mismatched-actual-argument|duplicate-push-destination) expected='extra or mismatched destination' ;;
                mirror-config) expected='mirror configured or ambiguous' ;;
                implicit-refspec) expected='implicit push refspec configured' ;;
                rewrite) expected='URL rewrite configured' ;;
                non-fast-forward) expected='non-fast-forward backup' ;;
                missing-ancestry) expected='remote ancestry unavailable' ;;
                *) echo "FAIL no intended refusal bound: $name" >&2; exit 1 ;;
            esac
        fi
        grep -Fxq "WIP BACKUP REFUSED: $expected" "$scratch/stderr" || { echo "FAIL wrong refusal boundary: $name" >&2; exit 1; }
    fi
}
run own-fork-owner-backup pass "$scratch/valid"
run_guard() {
    local name=$1 input=$2 expected=$3
    run "$name" refuse "$input" "$url" "$expected"
    case "$(cat "$scratch/stderr")" in
        *"$expected"*) ;;
        *) echo "FAIL wrong refusal boundary: $name" >&2; exit 1 ;;
    esac
}
# Source identity failures must reach their own guard, not merely fail setup.
printf '%s %s %s %s\n' refs/heads/other-source "$head" "$ref" "$zero" > "$scratch/wrong-local-ref"
run_guard wrong-local-ref "$scratch/wrong-local-ref" 'source mapping is not current branch'
printf '%s %s %s %s\n' "$local_ref" ffffffffffffffffffffffffffffffffffffffff "$ref" "$zero" > "$scratch/wrong-local-oid"
run_guard wrong-local-oid "$scratch/wrong-local-oid" 'source mapping is not current branch'
changed_head=$(printf 'different private source fixture\n' | git commit-tree "$(git rev-parse HEAD^{tree})" -p "$head")
git update-ref "$local_ref" "$changed_head" "$head"
printf '%s %s %s %s\n' "$local_ref" "$changed_head" "$ref" "$zero" > "$scratch/changed-selected-head"
run_guard changed-selected-head "$scratch/changed-selected-head" 'owner-selected source changed'
git update-ref "$local_ref" "$head" "$changed_head"

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
    cat "$scratch/valid" "$scratch/partial" > "$scratch/valid-and-partial"
    run_guard "valid-then-partial-$suffix" "$scratch/valid-and-partial" 'partial or unreadable update record'
    run_guard "partial-alone-$suffix" "$scratch/partial" 'partial or unreadable update record'
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
# Optional paths below are fixture-only; production hooks never read these
# variables. Child runs avoid recursive mutation and restore the actual source.
if [[ "${WIP_HOOK_MUTATION_CHILD:-0}" != 1 ]]; then
    for mutation in eof config; do
        mutant=$scratch/hook-$mutation
        awk -v target="$mutation" '
            target == "eof" && index($0, "partial or unreadable update record") { print "        :"; changed++; next }
            target == "config" && index($0, "[[ \"$config_status\" == 1 ]]") { print "        :"; changed++; next }
            { print }
            END { if ((target == "eof" && changed != 1) || (target == "config" && changed != 3)) exit 2 }
        ' "$hook" > "$mutant" || { echo "FAIL mutant source mismatch: $mutation" >&2; exit 1; }
        chmod +x "$mutant"
        if (cd "$source_root" && PATH="$test_base_path" WIP_HOOK_MUTATION_CHILD=1 WIP_HOOK_UNDER_TEST="$mutant" "$BASH" "$source_root/tests/wip-backup-pre-push.sh") > "$scratch/mutant-$mutation.log" 2>&1; then
            echo "FAIL mutant survived: $mutation" >&2; exit 1
        fi
        case "$mutation" in
            eof) assertion='FAIL exception admitted: valid-then-partial-mixed' ;;
            config) assertion='FAIL exception admitted: config-read-error-rewrite' ;;
        esac
        grep -Fxq "$assertion" "$scratch/mutant-$mutation.log" || { echo "FAIL unrelated mutant failure: $mutation" >&2; exit 1; }
        (cd "$source_root" && PATH="$test_base_path" WIP_HOOK_MUTATION_CHILD=1 WIP_HOOK_UNDER_TEST="$hook" "$BASH" "$source_root/tests/wip-backup-pre-push.sh") > "$scratch/fixed-$mutation.log" 2>&1 || { echo "FAIL fixed source after mutant: $mutation" >&2; exit 1; }
    done
fi
printf '%s
' 'PASS actual hook backup/refusal fixture; no network push or live adoption'

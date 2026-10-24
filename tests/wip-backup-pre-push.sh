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

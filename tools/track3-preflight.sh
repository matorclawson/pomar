#!/bin/sh
# Track 3 (pomar-SOW-87 / zeo-rt-sched-SOW-04 / zeocore-SOW-41): a read-only
# preflight for the ENG-UK job re-running zeocore's same source revision
# 155d8b9a, after the environment correction. This script never installs,
# modifies or executes any part of the job itself -- it only inspects the
# already-present environment and reports facts, so the scheduler's
# allocation can carry real preflight evidence instead of a plan.
#
# Usage: sh tools/track3-preflight.sh <zeocore-repo-path> <scratch-path> <pandoc-job-target>
#
# <zeocore-repo-path> is a local checkout of zeroemployeeorg/zeocore, read
# only to learn its OWN pandoc floor (src/zeo_core/integrations/pandoc/
# _runner.py's MIN_PANDOC_VERSION) and CI pin (tools/install-pandoc.sh) and
# Python requirement (pyproject.toml) -- never hardcoded here, so this
# script tracks whatever the repo currently states, not a copy that can
# drift. <scratch-path> is the job's own scratch directory, checked (not
# created) for the store's ancestor rule: no ancestor directory may be
# writable by group or others unless it also carries the sticky bit (the
# /tmp pattern). <pandoc-job-target> is the council/Architect-set minimum
# THIS job's run requires (settled at 3.11 for golden-reproducibility with
# where they were recorded) -- it is operational policy, not a repo fact,
# so it is never read from the repo or defaulted; the caller must supply
# it explicitly (Architect's msg-architect-architect-pandoc-settled-2156).
#
# Output is the report followed by its own sha256 (a receipt over the
# report text itself, computed after capture, so the two can never drift).
set -eu

repo=${1:-}
scratch=${2:-}
job_target=${3:-}
usage='usage: sh tools/track3-preflight.sh <zeocore-repo-path> <scratch-path> <pandoc-job-target>'
[ -n "$repo" ] && [ -d "$repo" ] || { echo "$usage" >&2; exit 2; }
[ -n "$scratch" ] || { echo "$usage" >&2; exit 2; }
[ -n "$job_target" ] || { echo "$usage" >&2; exit 2; }

preflight() {
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  host=$(hostname)
  uid=$(id -u)
  user=$(id -un)

  echo "=== Track3 preflight (read-only) ==="
  echo "timestamp: $ts"
  echo "host: $host"
  echo "uid: $uid ($user)"
  echo "argv: $0 $repo $scratch $job_target"

  # --- source identity of the inspected zeocore checkout ---
  source_head=NOT-INSPECTED
  source_remote=NOT-INSPECTED
  if git -C "$repo" rev-parse HEAD >/dev/null 2>&1; then
    source_head=$(git -C "$repo" rev-parse HEAD)
    source_remote=$(git -C "$repo" remote get-url origin 2>/dev/null || echo 'NOT-CONFIGURED')
  fi
  echo "zeocore source_head: $source_head"
  echo "zeocore source_remote: $source_remote"

  # --- 1. pandoc: three distinct, separately-sourced values (council's
  # settlement, msg-architect-architect-pandoc-settled-2156, after pomar-cc's
  # first version conflated the repo's own CI pin with the job's actual
  # requirement): the repo's floor (the oldest pandoc the code itself
  # requires), the repo's CI pin (what CI/release installs, newer than the
  # floor for an unrelated reason -- a slow mirror, see its own changelog),
  # and the job target (council/Architect operational policy, supplied by
  # the caller, checked for golden-reproducibility with the Mac mini where
  # the test goldens were recorded -- never read from the repo, which has
  # no 3.11 minimum of its own). The installed pandoc is checked against
  # the JOB TARGET, never the CI pin -- the two are unrelated requirements
  # that happen to both live in the one repo.
  floor_file="$repo/src/zeo_core/integrations/pandoc/_runner.py"
  floor_version=NOT-INSPECTED
  if [ -f "$floor_file" ]; then
    floor_version=$(sed -n 's/.*MIN_PANDOC_VERSION[^(]*(\([0-9][0-9]*\)[^0-9]*\([0-9][0-9]*\)).*/\1.\2/p' "$floor_file" | head -n 1)
    [ -n "$floor_version" ] || floor_version=DOES-NOT-EXIST
  else
    floor_version=DOES-NOT-EXIST
  fi
  echo "pandoc floor (code minimum, from $floor_file): $floor_version"

  pin_script="$repo/tools/install-pandoc.sh"
  ci_pin_version=NOT-INSPECTED
  if [ -f "$pin_script" ]; then
    ci_pin_version=$(awk -F'"' '/^VERSION=/{print $2; exit}' "$pin_script")
    [ -n "$ci_pin_version" ] || ci_pin_version=DOES-NOT-EXIST
  else
    ci_pin_version=DOES-NOT-EXIST
  fi
  echo "pandoc CI pin (from $pin_script): $ci_pin_version"
  echo "pandoc job target (council/Architect operational policy, not a repo fact): $job_target"

  pandoc_path=$(command -v pandoc 2>/dev/null || true)
  if [ -z "$pandoc_path" ]; then
    echo "pandoc on PATH: DOES-NOT-EXIST"
    pandoc_status=DOES-NOT-EXIST
  else
    installed_version=$(pandoc --version | head -n 1 | awk '{print $2}')
    echo "pandoc on PATH: $pandoc_path"
    echo "pandoc installed_version: $installed_version"
    newest=$(printf '%s\n%s\n' "$job_target" "$installed_version" | sort -V | tail -n 1)
    if [ "$newest" = "$installed_version" ]; then
      pandoc_status=VERIFIED
    else
      pandoc_status=NOT-CONFIGURED
    fi
  fi
  satisfies=does-not-satisfy
  [ "$pandoc_status" = VERIFIED ] && satisfies=satisfies
  echo "pandoc_status: $pandoc_status (job target >= required: installed $satisfies)"

  # --- 2. lock/project consistency (never `uv sync`, which installs).
  # pomar's review: `uv lock --check` proves ONLY that uv.lock is
  # consistent with pyproject.toml -- it does NOT prove the environment
  # this job will actually run in has those packages, extras or the
  # required Python version installed, and it can itself consult the
  # network or uv's own cache, so it is not a bounded offline check. Label
  # it precisely as what it is; a real installed-environment qualification
  # is a separate, not-yet-written check, out of this script's scope.
  uv_path=$(command -v uv 2>/dev/null || true)
  if [ -z "$uv_path" ]; then
    echo "uv on PATH: DOES-NOT-EXIST"
  else
    echo "uv on PATH: $uv_path ($("$uv_path" --version 2>&1))"
    required_python=$(awk -F'"' '/^requires-python/{print $2; exit}' "$repo/pyproject.toml" 2>/dev/null || echo NOT-INSPECTED)
    echo "zeocore requires-python: $required_python"
    lockcheck=$(mktemp)
    if (cd "$repo" && "$uv_path" lock --check >"$lockcheck" 2>&1); then
      lock_consistency=VERIFIED
    else
      lock_consistency=NOT-CONFIGURED
    fi
    echo "uv_lock_consistency_with_pyproject (uv lock --check; may consult network/cache, not a bounded offline check, and does not prove an installed environment): $lock_consistency"
    rm -f "$lockcheck"
  fi

  # --- 3. scratch path ancestry: no existing ancestor writable by others
  # unless sticky. The rule is about the already-existing directory chain,
  # not the scratch leaf itself (which the job creates later, and which this
  # preflight never creates). Report the leaf's own existence separately,
  # informationally, and always check every REAL (symlink-resolved) existing
  # ancestor regardless of whether the leaf exists yet.
  leaf_exists=NO
  [ -d "$scratch" ] && leaf_exists=YES

  nearest="$scratch"
  while [ ! -d "$nearest" ] && [ "$nearest" != "/" ] && [ -n "$nearest" ]; do
    nearest=$(dirname "$nearest")
  done
  # Canonicalize the nearest existing ancestor (cd -P/pwd -P is the portable
  # idiom) so a symlinked ancestor, e.g. /tmp -> /private/tmp, is walked by
  # its real path, reaching /private's own permissions too, not just /tmp's.
  walk=$(cd -P "$nearest" 2>/dev/null && pwd -P) || walk="$nearest"

  # pomar's review of pr#142 (two independently reproduced bugs):
  # (a) when both supported stat invocations fail, perm became an empty
  #     string via `|| true`, and an empty/unparseable permission string
  #     must never read as VERIFIED -- unknown metadata is UNKNOWN, not
  #     safe, so a failed or truncated stat now fails this ancestor closed.
  # (b) the receiving profile's actual safe-ancestor predicate examines
  #     BOTH group and other write bits (mode&0022); this only ever
  #     examined "others" (char 9) and silently accepted a group-writable,
  #     non-sticky ancestor (e.g. mode 0770) as safe.
  scratch_status=VERIFIED
  scratch_reason=""
  while [ -n "$walk" ]; do
    perm=$(stat -L -f '%Sp' "$walk" 2>/dev/null) || perm=$(stat -L -c '%A' "$walk" 2>/dev/null) || perm=""
    if [ -z "$perm" ] || [ ${#perm} -lt 10 ]; then
      scratch_status=NOT-CONFIGURED
      scratch_reason="$walk: could not read permission metadata (stat unavailable or unparseable)"
      break
    fi
    group_write=$(printf '%s' "$perm" | cut -c6)
    other_write=$(printf '%s' "$perm" | cut -c9)
    other_exec=$(printf '%s' "$perm" | cut -c10)
    sticky=false
    case "$other_exec" in t | T) sticky=true ;; esac
    if { [ "$group_write" = w ] || [ "$other_write" = w ]; } && [ "$sticky" = false ]; then
      scratch_status=NOT-CONFIGURED
      scratch_reason="$walk is group- or others-writable without the sticky bit ($perm)"
      break
    fi
    [ "$walk" = "/" ] && break
    walk=$(dirname "$walk")
  done
  echo "scratch_path: $scratch (leaf exists: $leaf_exists)"
  echo "scratch_ancestry_status: $scratch_status${scratch_reason:+ ($scratch_reason)}"

  # --- 4. keychain-dependent test capability: explicit, never silent ---
  echo "keychain_dependent_capability: NOT-INSPECTED (the specific keychain item/skip-reason contract is zeocore's to supply per the accepted gate; this preflight does not invent one)"

  echo "=== end Track3 preflight ==="
}

report=$(preflight)
printf '%s\n' "$report"
hash=$(printf '%s\n' "$report" | shasum -a 256 2>/dev/null | awk '{print $1}')
[ -n "$hash" ] || hash=$(printf '%s\n' "$report" | sha256sum 2>/dev/null | awk '{print $1}')
echo "receipt_sha256: $hash"

#!/bin/sh
# Track 3 (pomar-SOW-87 / zeo-rt-sched-SOW-04 / zeocore-SOW-41): a read-only
# preflight for the ENG-UK job re-running zeocore's same source revision
# 155d8b9a, after the environment correction. This script never installs,
# modifies or executes any part of the job itself -- it only inspects the
# already-present environment and reports facts, so the scheduler's
# allocation can carry real preflight evidence instead of a plan.
#
# Usage: sh tools/track3-preflight.sh <zeocore-repo-path> <scratch-path>
#
# <zeocore-repo-path> is a local checkout of zeroemployeeorg/zeocore, read
# only to learn its OWN pinned pandoc version (tools/install-pandoc.sh) and
# Python requirement (pyproject.toml) -- never hardcoded here, so this
# script tracks whatever the repo currently pins, not a copy that can drift.
# <scratch-path> is the job's own scratch directory, checked (not created)
# for the store's ancestor rule: no ancestor directory may be writable by
# others unless it also carries the sticky bit (the /tmp pattern).
#
# Output is the report followed by its own sha256 (a receipt over the
# report text itself, computed after capture, so the two can never drift).
set -eu

repo=${1:-}
scratch=${2:-}
[ -n "$repo" ] && [ -d "$repo" ] || { echo 'usage: sh tools/track3-preflight.sh <zeocore-repo-path> <scratch-path>' >&2; exit 2; }
[ -n "$scratch" ] || { echo 'usage: sh tools/track3-preflight.sh <zeocore-repo-path> <scratch-path>' >&2; exit 2; }

preflight() {
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  host=$(hostname)
  uid=$(id -u)
  user=$(id -un)

  echo "=== Track3 preflight (read-only) ==="
  echo "timestamp: $ts"
  echo "host: $host"
  echo "uid: $uid ($user)"
  echo "argv: $0 $repo $scratch"

  # --- source identity of the inspected zeocore checkout ---
  source_head=NOT-INSPECTED
  source_remote=NOT-INSPECTED
  if git -C "$repo" rev-parse HEAD >/dev/null 2>&1; then
    source_head=$(git -C "$repo" rev-parse HEAD)
    source_remote=$(git -C "$repo" remote get-url origin 2>/dev/null || echo 'NOT-CONFIGURED')
  fi
  echo "zeocore source_head: $source_head"
  echo "zeocore source_remote: $source_remote"

  # --- 1. pandoc, pinned by the repo's own tools/install-pandoc.sh ---
  pin_script="$repo/tools/install-pandoc.sh"
  pinned_version=NOT-INSPECTED
  if [ -f "$pin_script" ]; then
    pinned_version=$(awk -F'"' '/^VERSION=/{print $2; exit}' "$pin_script")
    [ -n "$pinned_version" ] || pinned_version=DOES-NOT-EXIST
  else
    pinned_version=DOES-NOT-EXIST
  fi
  echo "pandoc pinned_version (from repo): $pinned_version"

  pandoc_path=$(command -v pandoc 2>/dev/null || true)
  if [ -z "$pandoc_path" ]; then
    echo "pandoc on PATH: DOES-NOT-EXIST"
    pandoc_status=DOES-NOT-EXIST
  else
    installed_version=$(pandoc --version | head -n 1 | awk '{print $2}')
    echo "pandoc on PATH: $pandoc_path"
    echo "pandoc installed_version: $installed_version"
    if [ "$pinned_version" = NOT-INSPECTED ] || [ "$pinned_version" = DOES-NOT-EXIST ]; then
      pandoc_status=NOT-INSPECTED
    else
      newest=$(printf '%s\n%s\n' "$pinned_version" "$installed_version" | sort -V | tail -n 1)
      if [ "$newest" = "$installed_version" ]; then
        pandoc_status=VERIFIED
      else
        pandoc_status=NOT-CONFIGURED
      fi
    fi
  fi
  satisfies=does-not-satisfy
  [ "$pandoc_status" = VERIFIED ] && satisfies=satisfies
  echo "pandoc_status: $pandoc_status (pinned>=required: installed $satisfies)"

  # --- 2. the locked Python environment, read only (never `uv sync`, which installs) ---
  uv_path=$(command -v uv 2>/dev/null || true)
  if [ -z "$uv_path" ]; then
    echo "uv on PATH: DOES-NOT-EXIST"
  else
    echo "uv on PATH: $uv_path ($("$uv_path" --version 2>&1))"
    required_python=$(awk -F'"' '/^requires-python/{print $2; exit}' "$repo/pyproject.toml" 2>/dev/null || echo NOT-INSPECTED)
    echo "zeocore requires-python: $required_python"
    lockcheck=$(mktemp)
    if (cd "$repo" && "$uv_path" lock --check >"$lockcheck" 2>&1); then
      lock_status=VERIFIED
    else
      lock_status=NOT-CONFIGURED
    fi
    echo "uv.lock matches pyproject.toml (uv lock --check, read-only): $lock_status"
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

  scratch_status=VERIFIED
  scratch_reason=""
  while [ -n "$walk" ]; do
    perm=$(stat -L -f '%Sp' "$walk" 2>/dev/null || stat -L -c '%A' "$walk" 2>/dev/null || true)
    other_write=$(printf '%s' "$perm" | cut -c9)
    other_exec=$(printf '%s' "$perm" | cut -c10)
    if [ "$other_write" = w ] && [ "$other_exec" != t ] && [ "$other_exec" != T ]; then
      scratch_status=NOT-CONFIGURED
      scratch_reason="$walk is others-writable without the sticky bit ($perm)"
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

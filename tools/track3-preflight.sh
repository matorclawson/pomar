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

# pomar's review of pr#142 (9098c0b8): the previous bounded-wait sent TERM
# then called a plain `wait`, which is itself unbounded if the child traps
# or ignores TERM -- a child that outlives TERM can run (and "complete")
# indefinitely while the script still prints "killed". The watchdog below
# is the actual bounding primitive: it always escalates to the unmaskable
# KILL after a short fixed grace period, so the shell's own blocking `wait`
# on the real child is bounded by that escalation, not by the child's own
# cooperation. `wait` is never polled via kill -0 (a zombie still answers
# kill -0 until reaped, so that would not distinguish "still running" from
# "exited, awaiting reap"); it is called exactly once, and is what actually
# reaps the child and reports its true exit status. The one honest residual
# gap -- a process stuck in an unkillable kernel state even after KILL --
# is out of this fix's scope (no generic executor redesign); everything
# else must never silently read as the ordinary "completed" or "killed".
bounded_run() {
  budget=$1
  outfile=$2
  shift 2
  start=$(date +%s)
  "$@" >"$outfile" 2>&1 &
  pid=$!
  # The watchdog's own stdout/stderr must be redirected here, not inherited:
  # bounded_run is itself called inside a command substitution (`x=$(...)`),
  # which only sees EOF once every process holding its pipe's write end has
  # closed it. Killing the watchdog's own subshell process does not kill an
  # already-running `sleep` it has already forked as a plain foreground
  # child (the same orphaning this fix exists to handle for the real
  # command) -- that orphaned sleep would otherwise keep the inherited pipe
  # fd open for its own remaining duration, silently stalling the
  # substitution for up to budget+5 extra seconds even after bounded_run's
  # own bookkeeping has already finished. Redirecting to /dev/null here
  # means its children inherit that instead.
  (
    sleep "$budget"
    kill -TERM "$pid" 2>/dev/null || true
    sleep 5
    kill -KILL "$pid" 2>/dev/null || true
  ) >/dev/null 2>&1 &
  watchdog=$!
  # Under `set -e`, a bare failing `wait` would abort this function (and,
  # since this runs inside a command-substitution subshell, silently
  # truncate the caller's output) before the report below is ever printed --
  # the exit-status capture must stay inside an if-condition, exempt from -e.
  if wait "$pid" 2>/dev/null; then rc=0; else rc=$?; fi
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  end=$(date +%s)
  elapsed=$((end - start))
  if [ "$rc" -ge 128 ]; then
    echo "TIMED_OUT_KILLED $rc"
  elif [ "$elapsed" -gt "$budget" ]; then
    echo "TIMED_OUT_COMPLETED_BEFORE_TERMINATION $rc"
  else
    echo "COMPLETED $rc"
  fi
}

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
  uv_timeout_ok=false
  if [ -z "$uv_path" ]; then
    echo "uv on PATH: DOES-NOT-EXIST"
  else
    # pomar's review: TRACK3_UV_TIMEOUT must be a positive, bounded integer
    # -- not empty, not negative/zero, not non-numeric (which would make the
    # arithmetic comparisons below error out), and not an absurdly large
    # value that functions as "no timeout" in practice.
    uv_timeout=${TRACK3_UV_TIMEOUT:-30}
    case "$uv_timeout" in
      '' | *[!0-9]*)
        echo "uv on PATH: $uv_path (TRACK3_UV_TIMEOUT invalid: must be a positive integer, got '$uv_timeout')"
        ;;
      *)
        if [ "$uv_timeout" -ge 1 ] && [ "$uv_timeout" -le 3600 ]; then
          uv_timeout_ok=true
        else
          echo "uv on PATH: $uv_path (TRACK3_UV_TIMEOUT invalid: must be between 1 and 3600 seconds, got $uv_timeout)"
        fi
        ;;
    esac
  fi
  if [ "$uv_timeout_ok" = true ]; then
    # pomar's review: the preceding --version call is its own subprocess and
    # must not be claimed as covered by the lock-check's own timeout below
    # -- it gets its own short, separately-bounded run instead of an
    # unbounded direct call.
    versionfile=$(mktemp)
    version_report=$(bounded_run 10 "$versionfile" "$uv_path" --version)
    case "$version_report" in
      COMPLETED\ 0) echo "uv on PATH: $uv_path ($(cat "$versionfile"))" ;;
      *) echo "uv on PATH: $uv_path (version check: $version_report, bounded to 10s)" ;;
    esac
    rm -f "$versionfile"

    required_python=$(awk -F'"' '/^requires-python/{print $2; exit}' "$repo/pyproject.toml" 2>/dev/null || echo NOT-INSPECTED)
    echo "zeocore requires-python: $required_python"
    # pomar's review: this check may consult the network or uv's own cache,
    # so an unresponsive network/registry must not hang this (or any caller's
    # mandatory) run indefinitely. bounded_run's watchdog guarantees the
    # child is escalated to an unmaskable KILL, not merely sent a signal it
    # can ignore, so termination is genuinely bounded -- never report
    # "killed" without that escalation having actually confirmed it.
    lockcheck=$(mktemp)
    lock_report=$(cd "$repo" && bounded_run "$uv_timeout" "$lockcheck" "$uv_path" lock --check)
    case "$lock_report" in
      "COMPLETED 0")
        lock_consistency=VERIFIED
        lock_reason=""
        ;;
      COMPLETED\ *)
        lock_consistency=NOT-CONFIGURED
        lock_reason=""
        ;;
      TIMED_OUT_KILLED\ *)
        lock_consistency=NOT-CONFIGURED
        lock_reason=" (timed out after ${uv_timeout}s, killed)"
        ;;
      TIMED_OUT_COMPLETED_BEFORE_TERMINATION\ *)
        # Honest, not glossed over: the child outlived the timeout but
        # happened to finish on its own before our escalation reaped it --
        # this is still a timeout for this run's purposes (it did not
        # complete within budget), but it was not actually killed by us, and
        # saying so would be false.
        lock_consistency=NOT-CONFIGURED
        lock_reason=" (timed out after ${uv_timeout}s, completed on its own before termination was confirmed -- not killed by this check)"
        ;;
      *)
        # A supported primitive unavailable (bounded_run itself failed to
        # run, or produced an unrecognized report) must read as unknown, not
        # as a safe default in either direction.
        lock_consistency=UNKNOWN
        lock_reason=" (bounded execution unavailable or unrecognized: $lock_report)"
        ;;
    esac
    echo "uv_lock_consistency_with_pyproject (uv lock --check; may consult network/cache, not a bounded offline check, bounded to ${uv_timeout}s, and does not prove an installed environment): $lock_consistency$lock_reason"
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
    # pomar's re-review of pr#142 round 2: length alone is not parse
    # validation -- a 10-byte stream of e.g. "??????????" passes the old
    # `${#perm} -lt 10` check while carrying no real permission bits. Match
    # the actual ls-style grammar (file-type char, then three rwx triads,
    # each tolerating the usual s/S/t/T special-bit substitutions) before
    # trusting any character position below.
    case "$perm" in
      [-dlpscbD][-r][-w][-xsS][-r][-w][-xsS][-r][-w][-xtT]) ;;
      *)
        scratch_status=NOT-CONFIGURED
        scratch_reason="$walk: could not read permission metadata (stat unavailable or unparseable: $perm)"
        break
        ;;
    esac
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

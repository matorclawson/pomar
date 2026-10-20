sow: pomar-guest-SOW-01

# Delegated e667 task-control correction

Architect `ans_f36d05b4d9690441` delegates the correction and fixtures under
SOW-01. Runtime holds receiving while Pomar is unavailable; council reviews.
The issuer amendment has been requested and is not claimed received.

`entry.patch` applies only to the owner-supplied held task entry identified by
`bindings.json`. The complete private launcher, host paths and claim context
are not copied into this repository. This patch does not install an executor.
Pomar source base: `d1c552dbcdf2fea934c980fc483648d59ac40655`.
On an owned private copy, verify the input hash, use `git apply --unidiff-zero`
for this zero-context patch, then verify the corrected hash before review/use.

The change latches possible live-child custody immediately after `Popen`.
Fallible stdin and log I/O cannot skip bounded identity-safe cleanup. Failed
resource observations stay UNKNOWN independently of successful cleanup; known
positive ceiling violations remain distinct after proved reap/quiescence.
Unproved root identity never enters signal cleanup. Failed cleanup retains
UNKNOWN. Result persistence failure preserves the reserved UNKNOWN exit when
retention is required, including after an unacknowledged retain attempt.

Native preflight, inherited supervisor-only claim context, helper/guard/tool
bindings, source/head/tree/argv, resource ceilings, original identity, expired
start window and outer watchdog remain unchanged. The expired entry must not
be dispatched. A reviewed patch supplies neither an expiry renewal nor proof
of actual installed helper/broker retention semantics.

## Pure fixture check

Use an owned scratch directory for `TMPDIR`. Supply a privately retained copy
of the original or corrected entry whose bytes match `bindings.json`:

```sh
python3 -I -B tools/guest-smoke/e667-correction/test_controls.py --entry ENTRY_FILE
```

The fixture parses the exact entry and compiles only the AST suffix of
`execute` starting at its result initialization. All launch, kernel scope,
resource sampling, commands and retention operations are fake objects. No
owner module is imported, native preflight is run, process is spawned by the
fixture, signal is sent, socket is opened or real claim context is read.
Temporary files contain inert fixture bytes only. The harness is a targeted
task-body regression check, not a production executor or alternate admission
route. It intentionally does not test preflight or watchdog/native behavior.

Observed locally: 13 corrected fixtures PASS; the original has five assertion
failures and three errors under those same assertions. Cases cover RSS UNKNOWN
and observation I/O, live-child log digest/stat failure, stdin close failure,
failed/throwing cleanup, unknown identity, unacknowledged retain plus result
open/write failure, and positive/known-failure controls. Complete logs and
tool/environment evidence stay outside this public source tree.

Full committed-head `make verify`, native source qualification, actual helper
reply/broker mapping, independent council review, receiver adoption and the
usable Ubuntu guest remain outstanding. No push, installation, service act,
VM operation, candidate compile/test or renewed original follows here.

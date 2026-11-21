# Changelog

Notable changes to Pomar are recorded here in Keep a Changelog style. Entries
are grouped by month because the inspected Git history contains no release tags.
Monthly sections describe source changes, not published releases or deployments.

## Status

As of **2026-11-20**, Pomar is an **experimental** runner for isolated Linux jobs
and retained development environments on Apple silicon Macs. It combines a Go
manager and command-line tools with a Swift virtualization helper.

- **Latest meaningful source change in the inspected history:** 2026-11-11,
  completing the bounded artifact transport and cancellation checks below.
- **Current release:** no releases yet. The official repository has no release
  tags or published GitHub releases as of this status update.
- **Implemented in source:** owner-configured job classes, pinned source and
  images, controlled package access, signed results and logs, checked file
  outputs, interactive environments, terminal sessions, and release tooling.
  Running jobs requires a separately configured manager and authorized class.
- **Current limits:** the VM host requires macOS 26 or later on Apple silicon.
  Linux collection tools and the web deployment transaction model do not supply
  a Linux VM host or a working web deployment controller. Source integration of
  harness switching does not establish a qualified live provider round trip.
- **Check it yourself:** `make verify` is the full source gate on a supported
  Apple silicon builder; see CONTRIBUTING.md for its prerequisites. This
  changelog update does not establish a new gate result or successful deployment.

## [Unreleased]

### Added

- A documented Makefile guide, complete target listing, read-only prerequisite
  checks, and explicit setup/build/run/cleanup entry points help contributors
  discover the supported source workflow.
- A lightweight pre-push guard refuses updates and deletions of the main branch
  without starting a build. Full verification remains a separate required step
  on the admitted builder.

### Changed

- Distribution preparation moves to `make release-candidate` with an explicit
  release-candidate version. `make release` now refuses until the reviewed
  same-byte publication route is configured, preventing an implicit rebuild
  from being mistaken for promotion of an accepted candidate.

## 2026-11

### Added

- Opt-in artifact classes can return a bounded set of named files through a
  dedicated framed transport. The manager releases the set only after the job
  and every declared artifact succeed, so a partial export cannot look complete.
- `pomar attempt artifact-set` verifies the original signed result, independently
  supplied bindings, and every file in a set before returning a receiving
  receipt. A durable one-use claim preserves the original attempt across failed
  or interrupted transfers.
- Protected release-feed tooling binds publication to an approved policy and
  retained observations, allowing consumers to distinguish signed publication
  from an unverified file appearing in a directory.
- An internal web service transaction model describes fixed-port deployment,
  maintenance windows, readiness, and recovery after a known candidate failure.
  It retains the database identity and refuses ambiguous transitions. This is a
  tested model, without a deployment controller or persistent storage adapter.
- Qualification tooling can collect bounded Linux process inventories and
  journal native observations before an agent is allowed to receive model
  input. The checks distinguish process roles, cancellation, and incomplete
  cleanup rather than treating a command exit as sufficient evidence.
- An owner-bound, mail-only relay channel supports qualification without granting
  a general guest network connection.
- A host-wide disk-fill policy applies consistently to job admission and heavy
  preparation work. Invalid or unavailable policy data keeps conservative
  defaults rather than increasing available capacity.

### Changed

- Guest mail relays share bounded upstream concurrency and separate read and
  write budgets. A slow guest no longer occupies all upstream capacity, and busy
  responses are returned without automatically repeating writes.
- Qualification compares mail denials against a pinned, versioned template and
  binds input reads to their original owner-controlled files, making results
  comparable across repeated observations.
- Test fixtures supply their own disk measurements, so full-disk refusal checks
  remain meaningful without depending on the builder's available space.

### Fixed

- Artifact receiving rejects fragments returned after cancellation and reports
  success only through the complete command receipt. Staging paths and files
  are no longer presented as independent success signals.
- Artifact helpers use an explicit versioned command, so mismatched manager and
  helper versions refuse unsupported transfers instead of ignoring new limits.
- Qualification watchdogs preserve timeout outcomes even when a command handles
  termination or its diagnostic output cannot be written normally.
- The formatting gate propagates formatter failures, preventing a failed check
  from being reported as successful verification.
- Regression coverage verifies that staged image payloads retain their own bytes
  when the original source blobs change afterward.

### Security

- Tightened guest relay destination validation and shared resource accounting to
  preserve the configured network and capacity boundaries.
- Hardened release-feed and qualification input handling with bounded file reads
  and stable ownership checks.

## 2026-10

### Added

- Persistent, isolated coding environments can retain work across controller
  connections. Owner-selected project profiles bind source, launch policy, and
  execution scope to each environment.
- Codex and Claude Code adapters support explicit provider selection, sign-in
  operations, retained threads, and permission requests bound to actual tool
  calls. Adapter qualification and an actual successful model turn remain
  separate observations.
- Bounded controller requests and durable operation journals retain original
  replies after lost acknowledgements. Inspection remains available during
  delivery and after a failed resume.
- Verified candidate exports include source trees and commit proofs, allowing a
  receiver to check returned work against its declared source identity.
- Strict development-environment declarations and compare-and-set location
  records support listing, inspection, startup, attachment, and stopping through
  the command-line interface.
- A built-in terminal host provides framed attachment, a retained screen model,
  and explicit control ownership for interactive environments.
- `pomar session` runs programs independently of an attached terminal through a
  per-user service. It provides session listing, inspection, bounded sends,
  paste, stop readback, durable output logs, and scrollback.
- Session adapters can report readiness, input acceptance, and held operations.
  Callers can distinguish queued bytes from accepted input and fence writes on
  the observed session generation and control epoch.
- Passive session health reads combine the screen and recent scrollback to
  report possible problems without treating screen text as authoritative state.
- Structured attempt progress and read-only health reports expose current
  capacity, admission conditions, and bounded provisional output while a job is
  running.
- Installation-stall diagnostics report observed package-transfer and guest
  activity, with explicit time windows and unknown values, to support diagnosis
  without automatically retrying a job.
- Versioned distribution bundles, checksum-checked installation, and rollback
  tooling allow client installation without a source checkout.
- Service upgrade tooling checks signed payloads, retains the previous archive,
  and fences the running service before replacement or rollback.
- Durable completion intents and separately signed VM closure evidence support
  recovery of original results after an interrupted publication.
- Prepared executable invocations bind a session launch to its selected program
  and arguments before startup, with single-use operation identities.
- Read-only Linux metadata prechecks and bounded source preflight tools report
  prerequisite facts without claiming that a VM or application has run.
- `pomar actor-switch` selects an owner-configured harness after predecessor
  fencing while retaining the development environment and keeping provider
  histories separate. Original operation identities support inspection after
  an uncertain response; source integration does not qualify live switching.

### Changed

- Control-socket authorization uses the caller's kernel identity and configured
  job classes. Classes select their pinned images and package-lock locations;
  a retained class record alone does not grant caller access.
- Signed job results include admitted input hashes and output transport limits,
  making verification cover the files and limits actually selected at admission.
- Multiple classes and parallel jobs share measured host capacity. Current-fit
  diagnostics explain why work fits or must wait without promising fleet-wide
  scheduling.
- `run -wait` and `wait` report the job's exit code and distinguish wait timeout,
  class timeout, infrastructure failure, and requested stop. A wait timeout leaves
  the job running.
- Machine-readable help documents commands and exit codes. Environment listing
  remains noninteractive unless a menu is explicitly requested.
- Manager control calls, downloads, terminal operations, and diagnostic tails
  have explicit bounds, so a silent peer cannot hold a caller indefinitely.
- Terminal sessions replace the earlier terminal multiplexer integration.
  Programs survive client disconnection; sessions do not survive a service
  restart or reboot, while their durable logs remain available.
- Environment retirement explicitly records retained guest data and pending
  cleanup. Ambiguous launch, stop, continuation, or retirement outcomes retain
  their fences until reconciled instead of being repeated under a new identity.
- Release packaging includes the agent-environment tools and guides and removes
  private builder paths from packaged binaries.
- Contributor documentation explains source gates, ownership boundaries, and
  the distinction between source changes, installation, and deployment.

### Fixed

- Repeated operation identifiers return their original observations rather than
  redispatching work. Changed request bindings and stale adapter reports are
  refused, including after a controller disconnect or failed resume.
- Session stop waits for process reaping and reports remaining process-group
  state. Disconnects reset adapter state to unknown; refused readiness-based
  sends return their readiness claim for a later valid request.
- Sends and paste preserve partial or uncertain write outcomes. Held operations
  prevent further input unless the caller explicitly acknowledges uncertainty.
- Terminal screen reconstruction handles bounded combining characters, escaped
  control strings, and reattachment consistently. Retained history uses a ring
  rather than copying the full history on every scroll.
- Package-proxy diagnostics report short or failed transfers with the expected
  byte count and correct attribution instead of labeling them complete.
- Progress diagnostics keep terminal-attempt times fixed and apply their byte
  limits after JSON encoding, preserving valid bounded responses.
- Result publication recovers from its durable original intent and keeps
  supporting data until publication completes. VM object cleanup proceeds
  independently, with bounded recovery and explicit unavailable observations.
- Retained Git bundles are fetched using their own references instead of
  assuming they contain a reference named `HEAD`.
- A proven refusal before VM boot permits the first disk creation on a later
  valid start. Actor replacement still requires current predecessor evidence.
- Regression fixtures for task cleanup and result retention help detect failures
  that could otherwise be mistaken for completed execution.
- Source preflight timeouts terminate their process groups and report incomplete
  observations conservatively, including when diagnostic output is unavailable.

### Security

- Hardened source export validation and credential-output filtering so returned
  artifacts respect the configured export boundary.
- Bound provider permissions, controller capabilities, and session input to
  their selected execution identities, preventing stale observations from
  authorizing later work.
- Hardened retained-result publication, signed service upgrades, and executable
  launch validation against substituted inputs.
- Tightened terminal parsing and control ownership checks to keep hostile output
  bounded and prevent unintended cross-session input or state reuse.

## 2026-09

### Added

- Established the Go command-line and manager skeleton, the Swift VM host, and
  the `make verify` source gate, with pinned virtualization dependencies and
  entitlement checks for the host executable.
- Disposable Linux micro-VM jobs run through one VM-owning helper per attempt.
  A manager control socket supports starting, stopping, and inspecting jobs and
  reconciles retained attempts with live helper processes on startup.
- An explicit private data root tracks resource creation and cleanup in a ledger.
  Cleanup applies to recorded resources, while inspection reports unaccounted
  entries and VM services.
- Pinned kernels, guest initialization, cataloged images, and digest-checked
  base filesystems make job inputs inspectable. Each job gets its own writable
  clone of a verified read-only base.
- Configured source mirrors resolve an admitted reference to an exact commit and
  provide a per-job source snapshot. Jobs can name both head and base commits
  for an exact bundled source comparison.
- Job classes select memory, CPU, image, concurrency, output, and wall-clock
  limits. Host-wide budgets, capacity claims, cache eviction, and disk-fill
  refusal prevent admission from relying on nominal free space alone.
- Guests can receive named input files and return checked named outputs. Jobs
  run unprivileged where required and may use a read-only source tree.
- Controlled Go, Python, and npm package proxies support guest dependency access;
  Python and npm downloads are constrained by package locks and hashes.
- Signed immutable result documents, retained output logs, and result-verification
  commands let receivers check the original result and corresponding log bytes
  using an independently obtained public key.
- Per-attempt pin records and measured resource peaks describe the inputs and
  resources used by a job.
- Checked OCI image import supports images unavailable from a registry. Import
  verifies blobs and required file bytes before making an image available.
- Admission draining lets an owner stop new starts while existing jobs finish.

### Changed

- Guest root filesystems provide 16 GiB, and prepared bases are keyed by their
  pinned package set and image identity.
- Base verification runs at manager startup rather than repeatedly delaying job
  admission. Source resolution is completed before a start is admitted.
- Signed result bytes are served exactly as retained, so verification checks
  the original document rather than a reconstructed representation.

### Fixed

- Corrected the initial boot wait and Swift build/test sequence so the source
  gate preserves the signed host's virtualization entitlement.
- Image extraction applies checked whiteout handling and refuses replacement
  of an already installed image.
- Output logs obey per-class byte limits and are checked against their signed
  results when retrieved.

### Security

- Guest execution starts without host credentials and uses explicitly controlled
  communication channels. Source requests name configured mirrors rather than
  supplying arbitrary repository URLs.
- Resource creation is recorded before use, and cleanup stays within recorded
  ownership boundaries.

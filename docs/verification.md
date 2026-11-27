# Pomar verification and status

## Project status

| Area | Status as of 27 November 2026 |
| --- | --- |
| Latest release | [No binary release published](https://github.com/rodriveracom/pomar/releases). Build from source to try Pomar. |
| On `main` | Batch jobs, retained developer environments, and opt-in notification integration. The macOS service migration and rollback are in [#192](https://github.com/rodriveracom/pomar/pull/192). MIT licensing and notices in v3 bundles are in [#193](https://github.com/rodriveracom/pomar/pull/193). |
| In review | [#188](https://github.com/rodriveracom/pomar/pull/188) expands the changelog. [#189](https://github.com/rodriveracom/pomar/pull/189) adds Makefile workflows and prerequisite diagnostics. Both are drafts. |

## Measured results

| Scope and exact tested commit | Command | Host | Result | Receipt SHA-256 |
| --- | --- | --- | --- | --- |
| License and binary-notice changes, `8f4f6ca62072307b221ded352cdc6ec23f7a5ac7` ([#193](https://github.com/rodriveracom/pomar/pull/193)) | `make verify` | Apple silicon Mac | Exit 0 in 136 s | `3f191cddd59f76ad8b7723c05a10028f415c8c1faee1203285861d76aeb438e3` |
| Service migration and rollback source, `877390636d60a643d52ffd11050d6c039da6502f` ([#192](https://github.com/rodriveracom/pomar/pull/192)) | `make verify` | Apple silicon Mac | Exit 0 in 133 s | `a8edbb98e2d06eb9e144ab76ad6e7e4aa691c5a65ab17ca7721a6f654ff97070` |
| Workload benchmarks on current `main` | Pending | Pending | VM startup latency, job throughput, and capacity for concurrent development environments are unmeasured. | Pending |

The measured durations are for the build and test gate. Live installed
migration and rollback qualification is pending.

## Quick-start capture

The [terminal capture](images/pomar-quickstart.svg) shows the CLI commands
from the README run on an Apple silicon Mac at source commit
[`4b42373f47731536808d8468104ffe352a577fd4`](https://github.com/rodriveracom/pomar/commit/4b42373f47731536808d8468104ffe352a577fd4).
Both commands exited successfully. The original transcript SHA-256 is
`cc11b3a4b59f9bc85ea5b634427057ba024bb9e1ba51824e389e0b522cb4a011`.

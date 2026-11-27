# Pomar

Pomar runs Linux jobs in disposable micro-VMs on Apple silicon and hosts
retained development environments for interactive seats. Use it to run a
pinned command or repository build with controlled egress and without host
credentials in the guest. A signing-enabled manager returns a signed result
you can verify using its owner's public key.

## Quick start

On an Apple silicon Mac with macOS 26 or later, Go 1.27.x, Swift 6.2 or later,
and the Apple developer tools, clone the repository and inspect the CLI:

```sh
git clone https://github.com/rodriveracom/pomar.git
cd pomar
go run ./cmd/pomar help -json
```

To run your first local job, [build and install the bundle from source](docs/install.md#build-and-install-from-source),
then follow the [development manager quickstart](docs/operations.md#development-manager).
It starts a private manager and runs `/bin/echo hello` in a fresh Linux VM.
For an existing manager, get the control socket and job class from its owner.
See [AGENTS.md](AGENTS.md) for the CLI loop and result verification.

## Status

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
| Workload benchmarks on current `main` | Pending | Pending | VM startup latency, job throughput, and concurrent-seat capacity are unmeasured. | Pending |

The measured durations are for the build and test gate. Live installed
migration and rollback qualification is pending.

## Use a signed manager

If you already have access to a signing-enabled manager, get its approved control
socket, job class and independently pinned public key from its owner. Use the
[signed-manager workflow](docs/operations.md#submit-inspect-and-verify-a-job)
to submit work and verify its result and log. Explicit `-socket` overrides
`POMAR_SOCKET`; an explicit `-root` alone selects that root's owner socket.

For a repository job, pass the owner's configured mirror, ref and exact source
commit with `-mirror`, `-ref` and `-sha`. See
[health and diagnostics](docs/health-and-diagnostics.md) for capacity and progress.

## Develop Pomar

Start with [the standalone build and install guide](docs/install.md#build-and-install-from-source).
Contributors build from source on Apple silicon with the pinned Go and Swift
requirements. `make verify` is the native merge gate. This is separate from
using an installed release. See [CONTRIBUTING.md](CONTRIBUTING.md),
[release preparation](docs/releases.md), [manager classes](docs/manager-classes.md)
and [agent environments](docs/agent-environments.md).

Pomar is licensed under the [MIT License](LICENSE).

The unreleased [actor-switch integration](docs/harness-switching.md) selects an
owner-configured Claude or Codex harness on the same retained seat after fencing.
It preserves native histories separately; a launched replacement does not prove
login, model access or a successful inference turn. Native qualification and
owner deployment remain separate from source integration.

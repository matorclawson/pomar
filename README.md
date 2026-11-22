# Pomar

Run isolated Linux jobs and development seats on an Apple silicon Mac. Pomar
uses one disposable micro-VM per job, a Go coordinator and a Swift host built
on Apple's [Containerization](https://github.com/apple/containerization).
Guests run pinned inputs without host credentials; the host controls egress,
capacity and retained results.

**Agents and scripts:** start with [AGENTS.md](AGENTS.md), or `pomar help -json`.

**Status:** early prototype, macOS 26 or later, Apple silicon. The release
pipeline is prepared here; the first binary release has not yet been published.
To try Pomar now, use a [local source build](docs/install.md#build-and-install-from-source).

## Install a release

Users of a published release need no Git checkout, Go or Swift compiler. Choose
an explicit tag from [Releases](https://github.com/rodriveracom/pomar/releases),
download that tag's `install.sh` and `SHA256SUMS`, and verify the installer before
running it. For example, **after `v0.1.0` is published**:

```sh
VERSION=v0.1.0
URL="https://github.com/rodriveracom/pomar/releases/download/$VERSION"
curl -fL "$URL/install.sh" -o install.sh
curl -fL "$URL/SHA256SUMS" -o SHA256SUMS
awk '$2 == "install.sh" { print }' SHA256SUMS | shasum -a 256 -c -
sh install.sh "$VERSION"
export PATH="$HOME/.local/share/pomar/current/bin:$PATH"
pomar version
pomar help
```

The bundle includes the CLI, signed VM host, Linux shim, restricted clients and
these guides. Installation keeps versions side by side and activates only your
user tools. See [installation and rollback](docs/install.md).

## Run your first local job

After [building and installing from source](docs/install.md#build-and-install-from-source)
or installing a published release, follow the [development manager quickstart](docs/operations.md#development-manager).
It prepares a private development root, starts the manager in one terminal, and
runs `/bin/echo hello` from another. The manager returns an unsigned result for
this local smoke check.

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

Licensed under Apache-2.0.

The unreleased [actor-switch integration](docs/harness-switching.md) selects an
owner-configured Claude or Codex harness on the same retained seat after fencing.
It preserves native histories separately; a launched replacement does not prove
login, model access or a successful inference turn. Native qualification and
owner deployment remain separate from source integration.

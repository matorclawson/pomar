# Contributing to Pomar

## Propose a change

Open an issue in [the Pomar repository](https://github.com/rodriveracom/pomar/issues)
for a bug report or a substantial change. Describe the current behavior, the
expected behavior, affected callers and how to check it. Include a minimal
reproduction for a bug and remove credentials, local paths and private job
output. For changes to a public interface or security boundary, agree the
interface and compatibility plan with the maintainers before implementation.

Contributions can improve diagnostics, replay-safe APIs, bounded logs and
exports, capacity accounting, execution profiles, sessions and documentation.
Preserve explicit sockets and identities, pinned guest inputs, independent
result verification and account separation. A lost start response requires
inspection of the original attempt ID. It never authorizes a replacement job.

## Build and verify

Use an Apple silicon Mac with macOS 26 or later, Go from the 1.27.x line and
Swift 6.2 or later. Fork the repository, create a topic branch from `main`, and
work in a private checkout with sufficient space for compiler and test output.
Keep Go dependencies read-only and the Swift graph locked. Discuss new
dependencies and toolchain changes with the maintainers.

Run the full gate from the committed tree:

```sh
make verify
```

The gate checks versions and the exact commit, Docker socket absence, tracked
file hygiene, Go formatting, static analysis and race tests, the static Linux
ARM64 guest shim, and the locked Swift build, tests and Virtualization
entitlement. Maintainers can add a private hygiene denylist via
`HYGIENE_DENYLIST` and `HYGIENE_REQUIRE=1`. Keep the denylist outside Git.
Run `make hooks` to enable the repository's pre-push hook in your clone.

For disk-independent fixtures, use `venue.OpenWithOptions` with explicit fake
`Statfs` counters. Keep fake full-disk and read-error coverage alongside healthy
fixtures, and preserve production's host-wide disk checks. Exercise changed
failure boundaries with tests for mismatched bindings, concurrent requests or
lost acknowledgments as applicable. Keep qualification effects in isolated
fixtures or explicitly authorized development environments.

Preserve the CLI's documented compatibility. For example, `help -json` and
`doctor -json` expose structured output, and `run -wait` and `wait` propagate job
exits. The documented exit codes also distinguish a wait timeout, a class time
limit, an infrastructure failure and a requested stop. Update help and the
relevant guides when behavior changes.

## Submit a pull request

Sign each commit with `git commit -s` to certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
Open a pull request with the problem and behavior change, compatibility and
security implications, documentation changes, and the exact tested commit.
Include the toolchain, commands, outcomes and location of any sanitized gate
evidence. Retain failed results for diagnosis. Keep private logs, credentials
and deployment data outside the repository.

Maintainers review changes to signing, caller authorization, execution custody,
release packaging and service provisioning. Source review does not authorize
an install, account change, release publication or deployment. See
[release preparation](docs/releases.md) for artifact verification and
publication.

Contributions are licensed under [Apache 2.0](LICENSE). Section 6 of that
license describes the separate treatment of names and marks.

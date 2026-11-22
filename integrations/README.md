# Optional integrations

Pomar's batch jobs and retained environment APIs work with owner-provided
profiles and explicit sockets. The core packages do not depend on integrations.
The command binaries assemble optional features at their entry points.

- **Zeomessenger** provides an opt-in guest mailbox channel and a bounded
  owner notification sink. Configure the origin and workload binding on the
  owner side. The guest compatibility profile receives its fixed local
  endpoint only when the channel is enabled. Retries use the same original
  notification ID. A missing receipt leaves the delivery uncertain.
- **Signed release feed** verifies the requested producer and sequence and the
  exact original manifest using an independently pinned Ed25519 public key.
  The owner supplies the transport and chooses which release to inspect.
  Verification does not activate a release. The former Connect-specific feed
  commands and wire implementation have been retired.
- **Existing deployment and seat policy** remains available through the
  compatibility integration. It keeps the current seat commands, records and
  upgrades for installed deployments. Standalone workloads use the manager
  and environment commands. The installed runtime identifiers will have an
  explicit migration and rollback path.

The architecture test checks every Go import in the core, including its tests.
A new integration may depend on core packages. The reverse dependency fails
the test.

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
  The producer signs an issuance and expiry time. Owners supply the transport
  and select a release. `Read` verifies signed history, including expired
  entries. `Activate` uses an owner-provided clock to check the signed validity
  interval and persists a strictly increasing sequence before applying a
  release. Provision one private, durable admission directory per producer with
  `InitializeAdmission` on first adoption and retain it across restarts and
  key rotations. Repeats and rollbacks are refused, including repeats after an
  interrupted activation. Recover lost state and reconcile uncertain
  activations with the owner before proceeding. The former Connect-specific
  feed commands and wire implementation have been retired.
- **Existing deployment and seat policy** remains available through the
  compatibility integration. It keeps the current seat commands, records and
  upgrades for installed deployments. Standalone workloads use the manager
  and environment commands. The site qualification harness, including its
  process inventory and mail fixtures, lives alongside the deployment policy.
  Existing macOS services have an explicit
  [identifier migration and rollback path](../docs/service-upgrade.md#runtime-identifier-migration).

The architecture test checks Go files across the repository, including tests,
with exceptions for command entry points, integrations, and hidden build trees.
A new integration may depend on core packages. The reverse dependency fails
the test.

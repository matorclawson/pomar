# Changelog

## Unreleased

- Relicensed Dreamhuggers-owned Pomar code and documentation from Apache-2.0
  to MIT under the Pomar rights record dated 22 November 2026
  (SHA-256 `2ef5e29dbefd4db0cafd57f23277b6b5f77f44dbf5e75bdd4dc77d0a707dc45c`).
- Moved the Go module and release download links to `github.com/rodriveracom/pomar`.
- Added standalone setup and contribution instructions for people running Pomar on their own infrastructure.
- The mail relay retains the `X-Zmail-Instance` header for compatibility.
- Separate optional Messenger and organization policy from the workload core.
- Codex seats without a configured mail channel no longer receive `ZMAIL_URL`
  or `ZMAIL_INSTANCE`.
- Upgrade and roll back the Swift host, Go host and guest as one bundle so
  that the guest can interpret the host's `-notification-channel` flag.
- Provide an owner-pinned signed release feed interface for independent producers.
- Use the `io.github.rodriveracom.pomar` namespace for macOS binary signing
  and scratch Keychain probes. A manifest-bound service upgrade can switch
  existing launchd installs to the neutral label and restore the exact legacy
  plist and binaries on rollback.

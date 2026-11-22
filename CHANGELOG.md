# Changelog

## Unreleased

- Moved the Go module and release download links to `github.com/rodriveracom/pomar`.
- Added standalone setup and contribution instructions for people running Pomar on their own infrastructure.
- The mail relay retains the `X-Zmail-Instance` header for compatibility.
- Separate optional Messenger and organization policy from the workload core.
- Codex seats without a configured mail channel no longer receive `ZMAIL_URL`
  or `ZMAIL_INSTANCE`.
- Upgrade and roll back the Swift host, Go host and guest as one bundle so
  that the guest can interpret the host's `-notification-channel` flag.
- Provide an owner-pinned signed release feed interface for independent producers.

# Changelog

## Unreleased

- Moved the Go module and release download links to `github.com/rodriveracom/pomar`.
- Added standalone setup and contribution instructions for people running Pomar on their own infrastructure.
- Existing integrations retain the Connect release schemas and the mail relay's
  `X-Zmail-Instance` header for compatibility.
- Separate optional Messenger and organization policy from the workload core.
- Provide an owner-pinned signed release feed interface for independent producers.

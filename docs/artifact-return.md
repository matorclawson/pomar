# Artifact receiving component — source work in progress

The internal `artifactreturn` package implements the receiving component of
an explicit protected-class artifact return. It is not wired to manager
admission, guest copy-out, the HTTP client or a command. The historical 64 MiB
report limit and 32 MiB/16-file input limits remain unchanged. This document
must not be used as an installed command or class specification.

A reviewed receiver supplies the independent signing key, caller, original
attempt, class, source mirror/ref/commit/Git and access mode, base image,
derived package-set/rootfs hashes, command hash, and policy digest. The exact
original Ed25519 result bytes must bind those values, successful execution,
closed output names/count, individual lengths/hashes, and the protected
class's explicit per-file/count/aggregate/transfer-time ceilings. Signatures
never grant admission. The initial aggregate ceiling cannot exceed 1 GiB;
measured sizing records original attempt/result, actual bytes and the chosen
margin. Existing default results without the explicit policy are refused.

`Receive` checks free space against the entire class ceiling, then fetches
named files with one shared deadline. Acquisition must honor its context;
closing each returned stream must unblock its read. Each file uses an
exclusive create inside a fresh private `os.Root`. Lengths and hashes are
checked while streaming; an overrun byte is never written. Symlinks, paths,
case aliases, duplicate names and reserved metadata names are not outputs.
A receiving parent belongs to the consumer and is not supplied by a guest.
This does not protect against a hostile process with that same host UID.

Success is the function's **nil error return**, after all files and staging
metadata have been checked and synced. The returned confined staging path
can then be committed by the integrating consumer. No directory name or
READY file is a discoverable acceptance API. Consumers must not scan staged
paths to infer success. Any transfer, cap, digest, disk-write, sync or timeout
failure returns no accepted path; partial bytes stay fenced, with a failure
marker where writing one is possible. The same attempt cannot create its
staging directory twice, even after failure or a lost acknowledgement.
Reconcile original retained state instead of choosing another attempt name.
A free-space preflight is not a reservation; subsequent ENOSPC still fails
without accepting partial artifacts.

Remaining integration: protected class validation and signed policy/count;
bounded guest-to-manager transport rather than the existing unbounded
library copy-out; manager all-or-nothing result publication; context-bound
HTTP fetching and consumer acceptance; pinned offline layer/catalogue and
fixed build entry through the adopted protected base-build path. Those need
exact committed-tree `make verify`, independent source reviews, release and
one reviewed operator adoption before actual App qualification. This component
and its isolated race tests prove none of those receiving effects.

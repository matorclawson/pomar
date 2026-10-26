# Prepared executable integration for the Darwin Walking85 owner

sow: dt-animated-comics-SOW-01

Architect delegation `ans_cd3436515538f6b6`, base
`2761d89e82947289895323e9e824ba9f214c75af`. This adds an in-process preparation
path to the existing session lifecycle. It does not authenticate or admit a
native job, allocate a UID, change a service, or qualify walking playback.

The owner calls `PrepareExecutable(stagingRoot, originalCommand,
requiredNames, lookupPins)` with a canonical owned staging directory, an explicit
nonempty expected SHA256 and a complete bounded policy. For Walking85 the
required names are exactly `node`, `npm` and `git`, taken from the owner-selected
closure. Missing or duplicate roles refuse. Each pin includes canonical final
path, byte count and SHA256. No host environment is inherited.

Preparation makes the existing verified executable copy, renames it to its
selected lookup name **before** freezing the handle, and exposes the final path
and copied lookup identities. The owner now freezes the complete tool closure
and Product binding against this final Node path, calls the merged invocation
DATA adapter, and constructs `SessionSpec` with its opaque `Prepared` handle.
The final Command must still carry the exact nonempty expected SHA256 and the
handle's final Path. `PreservesInstallPath` may now describe that frozen final
location: there is no second relocation at Start. An original Command that
requires its original installation is still refused before preparation.

The ordinary session entry point remains unchanged, including its rejection of
ExpectedSHA256 together with PreservesInstallPath. A zero/forged handle refuses;
JSON cannot encode or construct the in-process handle. Copies of the handle
share the one-use state. A prepared session's replay fingerprint includes that
identity and the expected-pin declaration; exact replay returns the original
session, whereas a changed pin conflicts.

Immediately before Start, preparation verifies the private inode/mode, bytes
and size, then resolves the selected lookups in the actual explicit Command.Env
PATH. Empty, relative, duplicate, noncanonical or unbounded PATH entries refuse.
The first existing candidate must resolve to the selected canonical pinned file;
a shadow node/npm beside Git refuses. Verification uses no global PATH change.
A second verification pass detects a shadow introduced during the first pass's
hashing; this is not a guarantee against a privileged writer racing final
verification and exec. Owner-controlled immutable filesystem custody remains
mandatory. The policy declares every lookup the workload/descendants can use;
it is not discovery or a complete transitive native toolchain proof.

Preparations are bounded to64 selected lookups,512MiB per file and1GiB total.
The explicit staging root must be owned by the preparer and not writable by
group/others. New directories are traversable but not listable by other UIDs;
new copies never gain read/execute permissions beyond the original executable
and never gain group/other write permissions. Actual target-UID access and
immutable ownership must be qualified by the adopting owner. The old ordinary
copy behavior is unchanged.

The handle and its one-use state are in-process only. They are not a durable
request fence across a host/service crash, and a missing handle never proves an
original did not start. The adopting custodian must bind preparation and Start
to its existing durable identity and uncertainty recovery before native use.

The owner closes an abandoned handle. Once consumed, only the existing session
lifetime cleans it, after process Wait and the existing process-group kill.
Known Start failure cleans the preparation and permanently consumes its handle.
A replaced staging directory/file or unexpected sibling is retained with a
cleanup error rather than deleting a new occupant. Cleanup error contributes to
the session's failed completion, never a clean successful exit.

The existing session process-group boundary is unchanged: a descendant that
changes its own process group/session is outside that boundary. This component
is not proof of whole-native-job containment, independent-process equivalence,
caller authorization, current claim/FIT, limits, full closure, Wait/EOF/cleanup
return or enrolled provider admission. Those owning requirements remain before
the actual fixed Walking85 --check/--run and52-original plus195-stanceSVG motion
qualification. No Node/npm/tool version from an old host is transferred.

Darwin controls exercise a native child observing the final executable path,
normal session replay and cleanup, immutable policy copies, canonical npm
symlink resolution, wrong/missing pins, node/npm PATH shadows, changed Git,
invalid PATH, concurrent claims, same-byte inode replacement, known Start
failure, abandonment and JSON/zero-handle refusal. The existing ordinary pinning
controls remain in the full gate. Run the targeted and full checks on ENG-UK
under the current capacity rule; no Mat gate is authorised.

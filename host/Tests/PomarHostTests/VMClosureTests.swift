import Testing
@testable import PomarHostCore

// sow: pomar-SOW-87. These exercise the helper's actual cleanup decision,
// without a VM, signer, or manufactured manager closure receipt.
private enum CleanupFailure: Error { case expected }

@Test func cleanupAcknowledgesOnlySuccessfulOperations() async {
    let fields = await VMClosure.acknowledge(stop: {}, delete: {})
    #expect(fields["cleanup_schema"] == "pomar.vm-cleanup/v1")
    #expect(fields["cleanup_stop_acknowledged"] == "true")
    #expect(fields["cleanup_delete_acknowledged"] == "true")
    #expect(fields["cleanup_stop_error"] == nil)
    #expect(fields["cleanup_delete_error"] == nil)
}

@Test func failedStopStillAttemptsDeleteButCannotClaimClosure() async {
    let fields = await VMClosure.acknowledge(
        stop: { throw CleanupFailure.expected }, delete: {})
    #expect(fields["cleanup_stop_acknowledged"] == "false")
    #expect(fields["cleanup_stop_error"] == "stop_failed")
    #expect(fields["cleanup_delete_acknowledged"] == "true")
}

@Test func failedDeleteIsNotHiddenBySuccessfulStop() async {
    let fields = await VMClosure.acknowledge(
        stop: {}, delete: { throw CleanupFailure.expected })
    #expect(fields["cleanup_stop_acknowledged"] == "true")
    #expect(fields["cleanup_delete_acknowledged"] == "false")
    #expect(fields["cleanup_delete_error"] == "delete_failed")
}

@Test func bothCleanupFailuresRemainVisible() async {
    let fields = await VMClosure.acknowledge(
        stop: { throw CleanupFailure.expected },
        delete: { throw CleanupFailure.expected })
    #expect(fields["cleanup_stop_acknowledged"] == "false")
    #expect(fields["cleanup_delete_acknowledged"] == "false")
    #expect(fields["cleanup_stop_error"] == "stop_failed")
    #expect(fields["cleanup_delete_error"] == "delete_failed")
}

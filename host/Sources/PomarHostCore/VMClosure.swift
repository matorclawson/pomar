import Foundation

// sow: pomar-SOW-87. These are acknowledgments from the VM-owning helper,
// not proof inferred from a missing process or directory. The manager must
// bind them to its original helper identity before publishing a closure.
enum VMClosure {
    static func acknowledge(
        stop: () async throws -> Void,
        delete: () throws -> Void
    ) async -> [String: String] {
        var fields = [
            "cleanup_schema": "pomar.vm-cleanup/v1",
            "cleanup_helper_pid": String(ProcessInfo.processInfo.processIdentifier),
            "cleanup_stop_acknowledged": "false",
            "cleanup_delete_acknowledged": "false",
        ]
        do {
            try await stop()
            fields["cleanup_stop_acknowledged"] = "true"
        } catch {
            // Fixed reason codes: never copy private exception payloads into
            // the closure contract. Still attempt deletion after stop fails.
            fields["cleanup_stop_error"] = "stop_failed"
        }
        do {
            try delete()
            fields["cleanup_delete_acknowledged"] = "true"
        } catch {
            fields["cleanup_delete_error"] = "delete_failed"
        }
        return fields
    }
}

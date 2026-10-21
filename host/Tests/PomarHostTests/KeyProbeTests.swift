import Foundation
import Testing

@testable import PomarHostCore

// This unit exercises the real file-key primitive only. Secure Enclave and
// keychain availability are account/platform observations from the separate
// explicit B2 probe, not prerequisites for an unattended file-key unit test.
@Test func keyProbeFileKeyRoundTrips() throws {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("pomar-file-key-" + UUID().uuidString, isDirectory: true)
    try FileManager.default.createDirectory(
        at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: dir) }
    var result = KeyProbe.Result()
    KeyProbe.fileKey(dir, &result)
    #expect(result.ok)
    #expect(result.lines.contains("file_key_mode=600"))
    #expect(result.lines.contains("file_key_reload_verify=true"))
    #expect(result.lines.contains { $0.hasPrefix("file_public_key_sha256=") })
}

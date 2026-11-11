import CryptoKit
import Darwin
import Foundation
import Testing
@testable import PomarHostCore

private func artifactSHA(_ text: String) -> String {
    SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
}
private func artifactFixture(_ body: (Int32, String) throws -> Void) throws {
    let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("artifact-frame-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: root) }
    let fd = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw ArtifactSinkError.io }; defer { _ = Darwin.close(fd) }
    try body(fd, root.path)
}
private func artifactWire(_ payload: String, name: String = "tree.tar", size: Int? = nil, hash: String? = nil) -> Data {
    Data(("POMAR_ARTIFACT_V1 \(name) \(size ?? payload.utf8.count) \(hash ?? artifactSHA(payload))\n" + payload + "\nPOMAR_ARTIFACT_END\n").utf8)
}

@Test func artifactFrameAcceptsOnlyCompleteFragmentedFile() throws {
    try artifactFixture { fd, root in
        let budget = try ArtifactBudget(maximum: 8, seconds: 10)
        let frame = ArtifactFrame(directoryFD: fd, name: "tree.tar", perFile: 8, budget: budget)
        for byte in artifactWire("abc") { try frame.write(Data([byte])) }
        try frame.finish()
        #expect(try Data(contentsOf: URL(fileURLWithPath: root + "/tree.tar")) == Data("abc".utf8))
        let attrs = try FileManager.default.attributesOfItem(atPath: root + "/tree.tar")
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o400)
    }
}

@Test func artifactFrameRejectsWrongNameAndOversizeHeaderBeforeCreation() throws {
    for wire in [artifactWire("a", name: "other"), Data(repeating: 65, count: 513)] {
        try artifactFixture { fd, root in
            let frame = ArtifactFrame(directoryFD: fd, name: "tree.tar", perFile: 8, budget: try ArtifactBudget(maximum: 8, seconds: 10))
            #expect(throws: (any Error).self) { try frame.write(wire) }
            #expect(!FileManager.default.fileExists(atPath: root + "/tree.tar"))
            #expect(throws: (any Error).self) { try frame.finish() }
        }
    }
}

@Test func artifactFrameRejectsTruncationDigestAndTrailingBytes() throws {
    let good = artifactWire("abc")
    let cases = [Data(good.dropLast()), artifactWire("abc", hash: artifactSHA("bad")), good + Data("extra".utf8), artifactWire("abc", size: 2)]
    for wire in cases {
        try artifactFixture { fd, _ in
            let frame = ArtifactFrame(directoryFD: fd, name: "tree.tar", perFile: 8, budget: try ArtifactBudget(maximum: 8, seconds: 10))
            // A dependency may suppress write errors. Completion MUST still fail.
            try? frame.write(wire)
            #expect(throws: (any Error).self) { try frame.finish() }
        }
    }
}

@Test func artifactFrameRejectsPayloadOverClassLimitWithoutWriting() throws {
    try artifactFixture { fd, root in
        let frame = ArtifactFrame(directoryFD: fd, name: "tree.tar", perFile: 2, budget: try ArtifactBudget(maximum: 8, seconds: 10))
        #expect(throws: (any Error).self) { try frame.write(artifactWire("abc")) }
        #expect(!FileManager.default.fileExists(atPath: root + "/tree.tar"))
    }
}

@Test func artifactFramesShareAggregateBudgetAndRejectReuse() throws {
    try artifactFixture { fd, _ in
        let budget = try ArtifactBudget(maximum: 4, seconds: 10)
        let one = ArtifactFrame(directoryFD: fd, name: "one", perFile: 4, budget: budget)
        try one.write(artifactWire("abc", name: "one")); try one.finish()
        let two = ArtifactFrame(directoryFD: fd, name: "two", perFile: 4, budget: budget)
        try? two.write(artifactWire("ab", name: "two"))
        #expect(throws: (any Error).self) { try two.finish() }
        let reused = ArtifactFrame(directoryFD: fd, name: "one", perFile: 4, budget: budget)
        #expect(throws: (any Error).self) { try reused.write(artifactWire("a", name: "one")) }
    }
}

@Test func artifactOwnerLimitsAreExplicitAndNamesCannotAlias() {
    #expect(Helper.artifactLimits(perFile: nil, seconds: nil, aggregate: 0)?.perFile == 0)
    #expect(Helper.artifactLimits(perFile: "8", seconds: nil, aggregate: 8) == nil)
    #expect(Helper.artifactLimits(perFile: "9", seconds: "1", aggregate: 8) == nil)
    #expect(Helper.artifactLimits(perFile: "8", seconds: "601", aggregate: 8) == nil)
    #expect(Helper.artifactLimits(perFile: "8", seconds: "1", aggregate: 1 << 31) == nil)
    #expect(Helper.artifactLimits(perFile: "8", seconds: "1", aggregate: 8)?.seconds == 1)
    #expect(Helper.artifactNamesValid(["tree.tar", "stamp.json"]))
    for names in [["one", "ONE"], ["a..b"], ["READY.json"], ["../x"], []] {
        #expect(!Helper.artifactNamesValid(names))
    }
}

@Test func artifactFrameReadsSharedGoExporterFixture() throws {
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let wire = try Data(contentsOf: root.appendingPathComponent("testdata/artifact-stream-v1.txt"))
    try artifactFixture { fd, path in
        let frame = ArtifactFrame(directoryFD: fd, name: "tree.tar", perFile: 8, budget: try ArtifactBudget(maximum: 8, seconds: 10))
        try frame.write(wire); try frame.finish()
        #expect(try Data(contentsOf: URL(fileURLWithPath: path + "/tree.tar")) == Data("abc".utf8))
    }
}

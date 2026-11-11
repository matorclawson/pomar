import Containerization
import CryptoKit
import Darwin
import Foundation

// Bounded byte sink for the explicit artifact helper path. Integration must
// check finish() after complete framed I/O before accepting any output.
enum ArtifactSinkError: Error { case limit, identity, stream, digest, deadline, io }

final class ArtifactBudget: @unchecked Sendable {
    private let lock = NSLock()
    private let maximum: Int64
    private let deadline: Double
    private let now: @Sendable () -> Double
    private var used: Int64 = 0
    init(maximum: Int64, seconds: Double, now: @escaping @Sendable () -> Double = { ProcessInfo.processInfo.systemUptime }) throws {
        guard maximum > 0, maximum <= 1 << 30, seconds > 0, seconds <= 600 else { throw ArtifactSinkError.limit }
        self.maximum = maximum; self.now = now; self.deadline = now() + seconds
    }
    func reserve(_ count: Int64) throws {
        lock.lock(); defer { lock.unlock() }
        guard now() <= deadline else { throw ArtifactSinkError.deadline }
        guard count >= 0, count <= maximum - used else { throw ArtifactSinkError.limit }
        used += count
    }
}

// All errors are latched because the pinned dependency logs Writer.write
// errors instead of propagating them. Integrators MUST call finish() and
// reject its failure before signing a successful artifact result.
final class ArtifactSink: @unchecked Sendable {
    private let lock = NSLock()
    private let budget: ArtifactBudget
    private let expected: Int64
    private let expectedHash: String
    private var fd: Int32
    private var count: Int64 = 0
    private var hash = SHA256()
    private var failed: Error?
    private var complete: String?

    init(directoryFD: Int32, name: String, bytes: Int64, sha256: String, perFile: Int64, budget: ArtifactBudget) throws {
        let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
        guard !name.isEmpty, name.utf8.count <= 128, !name.contains(".."),
              name.unicodeScalars.allSatisfy({ allowed.contains($0) }),
              name.first!.isASCII, name.first!.isLetter || name.first!.isNumber,
              bytes >= 0, bytes <= perFile, perFile > 0, perFile <= 1 << 30,
              sha256.utf8.count == 64, sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw ArtifactSinkError.identity }
        try budget.reserve(0)
        let handle = name.withCString { Darwin.openat(directoryFD, $0, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600) }
        guard handle >= 0 else { throw ArtifactSinkError.io }
        self.fd = handle; self.expected = bytes; self.expectedHash = sha256; self.budget = budget
    }
    deinit { if fd >= 0 { _ = Darwin.close(fd) } }

    func write(_ data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        do {
            if let failed { throw failed }
            guard complete == nil, fd >= 0 else { throw ArtifactSinkError.stream }
            let n = Int64(data.count)
            // Check the entire incoming fragment before any host disk write.
            guard n <= expected - count else { throw ArtifactSinkError.limit }
            try budget.reserve(n)
            try data.withUnsafeBytes { raw in
                var offset = 0
                while offset < raw.count {
                    let written = Darwin.write(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                    if written < 0 && errno == EINTR { continue }
                    guard written > 0 else { throw ArtifactSinkError.io }
                    offset += written
                }
            }
            hash.update(data: data); count += n
        } catch { failed = error; throw error }
    }

    func finish() throws -> String {
        lock.lock(); defer { lock.unlock() }
        if let failed { throw failed }
        if let complete { return complete }
        do {
            try budget.reserve(0)
            guard count == expected else { throw ArtifactSinkError.stream }
            let digest = hash.finalize().map { String(format: "%02x", $0) }.joined()
            guard digest == expectedHash else { throw ArtifactSinkError.digest }
            guard fchmod(fd, 0o400) == 0, fsync(fd) == 0 else { throw ArtifactSinkError.io }
            let result = Darwin.close(fd); fd = -1
            guard result == 0 else { throw ArtifactSinkError.io }
            complete = digest
            return digest
        } catch { failed = error; throw error }
    }
}

// The pinned library may suppress errors from these methods, so the owner
// explicitly checks finish() after export. A zero process exit is not enough.
extension ArtifactSink: Writer {
    func close() throws { _ = try finish() }
}

extension ArtifactBudget {
    func secondsRemaining() throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        let left = deadline - now()
        guard left > 0 else { throw ArtifactSinkError.deadline }
        return Int64(ceil(left))
    }
}

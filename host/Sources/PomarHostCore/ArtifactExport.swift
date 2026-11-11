import Containerization
import Darwin
import Foundation

private final class ArtifactErrorFlag: Writer, @unchecked Sendable {
    private let lock = NSLock()
    private var seen = false
    func write(_ data: Data) throws { lock.lock(); defer { lock.unlock() }; seen = seen || !data.isEmpty }
    func close() throws {}
    var hasBytes: Bool { lock.lock(); defer { lock.unlock() }; return seen }
}

extension Helper {
    /// Both flags or neither. These are internal owner-class bounds, never
    /// selected from a guest header or used to expand the legacy default.
    public static func artifactLimits(perFile: String?, seconds: String?, aggregate: Int64) -> (perFile: Int64, seconds: Int64)? {
        if perFile == nil && seconds == nil { return (0, 0) }
        guard let perFile, let seconds, let bytes = Int64(perFile), let duration = Int64(seconds),
              aggregate > 0, aggregate <= 1 << 30, bytes > 0, bytes <= aggregate,
              duration > 0, duration <= 600 else { return nil }
        return (bytes, duration)
    }

    public static func artifactNamesValid(_ names: [String]) -> Bool {
        let reserved: Set<String> = ["original-result.json", "ready.json", "failed.json"]
        guard !names.isEmpty, names.count <= 16,
              Set(names.map { $0.lowercased() }).count == names.count,
              outputsFlags(names.joined(separator: ","), dir: "/unused", max: "1") != nil
        else { return false }
        return names.allSatisfy { !$0.contains("..") && !reserved.contains($0.lowercased()) }
    }

    // The existing static Go shim emits one bounded regular-file frame. No
    // guest interpreter, archive extraction or host credentials are involved.
    static func copyArtifactOutputs(_ container: LinuxContainer, names: [String], to dir: String,
                                    maximum: Int64, perFile: Int64, seconds: Int64) async throws -> Int {
        guard artifactNamesValid(names), artifactLimits(perFile: String(perFile), seconds: String(seconds), aggregate: maximum) != nil
        else { throw ArtifactSinkError.identity }
        guard Rootfs.freeBytes((dir as NSString).deletingLastPathComponent) >= maximum else { throw ArtifactSinkError.io }
        let budget = try ArtifactBudget(maximum: maximum, seconds: Double(seconds))
        guard mkdir(dir, 0o700) == 0 else { throw ArtifactSinkError.io }
        let fd = Darwin.open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ArtifactSinkError.io }; defer { _ = Darwin.close(fd) }
        for (index, name) in names.enumerated() {
            let frame = ArtifactFrame(directoryFD: fd, name: name, perFile: perFile, budget: budget)
            let stderr = ArtifactErrorFlag()
            let duration = try budget.secondsRemaining()
            let process = try await container.exec("pomar-artifact-\(index)") { config in
                config.arguments = [shimInGuest, "-artifact-export", name, "-artifact-max", String(perFile),
                                    "-artifact-timeout-s", String(duration)]
                config.stdout = frame; config.stderr = stderr
            }
            do {
                try await process.start()
                let status = try await process.wait(timeoutInSeconds: try budget.secondsRemaining())
                guard status.exitCode == 0, !stderr.hasBytes else { throw ArtifactSinkError.stream }
                try frame.finish()
                try await process.delete()
            } catch {
                try? await process.kill(.kill)
                try? await process.delete()
                // Caller retains the complete private set and closes the VM;
                // the manager must never expose a subset as accepted output.
                throw error
            }
        }
        guard fsync(fd) == 0 else { throw ArtifactSinkError.io }
        _ = try budget.secondsRemaining()
        return names.count
    }
}

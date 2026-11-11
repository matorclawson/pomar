import Containerization
import Foundation

// One owner-selected regular file per stream. The export protocol carries no
// guest path, archive type or host attributes: header, exact payload, footer.
// Neither a zero process exit nor the dependency's I/O timeout is acceptance.
final class ArtifactFrame: Writer, @unchecked Sendable {
    static let footer = Array("\nPOMAR_ARTIFACT_END\n".utf8)
    private let lock = NSLock()
    private let directoryFD: Int32
    private let name: String
    private let perFile: Int64
    private let budget: ArtifactBudget
    private var header: [UInt8] = []
    private var sink: ArtifactSink?
    private var remaining: Int64 = 0
    private var footerOffset = 0
    private var done = false
    private var failed: Error?

    init(directoryFD: Int32, name: String, perFile: Int64, budget: ArtifactBudget) {
        self.directoryFD = directoryFD; self.name = name
        self.perFile = perFile; self.budget = budget
    }

    func write(_ data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        do {
            if let failed { throw failed }
            try budget.reserve(0)
            let bytes = Array(data)
            var offset = 0
            while offset < bytes.count {
                guard !done else { throw ArtifactSinkError.stream }
                if sink == nil {
                    guard header.count < 512 else { throw ArtifactSinkError.identity }
                    let byte = bytes[offset]; offset += 1
                    if byte != 10 { header.append(byte); continue }
                    guard let line = String(bytes: header, encoding: .ascii) else { throw ArtifactSinkError.identity }
                    let fields = line.split(separator: " ", omittingEmptySubsequences: false)
                    guard fields.count == 4, fields[0] == "POMAR_ARTIFACT_V1", fields[1] == Substring(name),
                          let size = Int64(fields[2]), String(size) == fields[2], size >= 0,
                          size <= perFile else { throw ArtifactSinkError.identity }
                    sink = try ArtifactSink(directoryFD: directoryFD, name: name, bytes: size,
                                            sha256: String(fields[3]), perFile: perFile, budget: budget)
                    remaining = size
                    continue
                }
                if remaining > 0 {
                    let count = min(Int64(bytes.count - offset), remaining)
                    try sink!.write(Data(bytes[offset..<(offset + Int(count))]))
                    remaining -= count; offset += Int(count)
                    continue
                }
                guard footerOffset < Self.footer.count, bytes[offset] == Self.footer[footerOffset]
                else { throw ArtifactSinkError.stream }
                footerOffset += 1; offset += 1
                if footerOffset == Self.footer.count {
                    _ = try sink!.finish(); done = true
                }
            }
        } catch { failed = error; throw error }
    }

    // Always call after the bounded exporter has finished. Errors from write
    // may have been swallowed by the pinned Containerization stream relay.
    func finish() throws {
        lock.lock(); defer { lock.unlock() }
        if let failed { throw failed }
        try budget.reserve(0)
        guard done else { throw ArtifactSinkError.stream }
        _ = try sink!.finish()
    }
    func close() throws { try finish() }
}

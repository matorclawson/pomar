import CryptoKit
import Darwin
import Foundation
import Testing
@testable import PomarHostCore

// Real owned metadata/resource reads, with a single failure injected at the
// native boundary. No process is stopped, unlinked executable trusted or
// another account made accessible to manufacture a passing fence.
private func withFenceIdentityFixture(_ body: (AgentFenceProbe.Request, proc_bsdinfo, URL) throws -> Void) throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pomar-fence-identity-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: dir) }
    let disk = dir.appendingPathComponent("workspace.ext4")
    try Data("retained writer fixture".utf8).write(to: disk)
    chmod(disk.path, 0o600)
    let handle = try FileHandle(forReadingFrom: disk)
    defer { try? handle.close() }
    var identity = proc_bsdinfo()
    #expect(proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &identity, Int32(MemoryLayout<proc_bsdinfo>.size)) == MemoryLayout<proc_bsdinfo>.size)
    let request = AgentFenceProbe.Request(environment: "fixture", session: "session",
        incarnation: "actor", operation: "probe", rootfs: disk.path,
        helper: "/unavailable/retained/helper", pid: getpid(), uid: getuid(), birth: identity.pbi_start_tvsec)
    try body(request, identity, dir)
    #expect(try Data(contentsOf: disk) == Data("retained writer fixture".utf8))
}

private func missingOwnExecutable() -> AgentFenceProbe.ProcessAccess {
    var access = AgentFenceProbe.ProcessAccess()
    let native = access.executable
    access.executable = { pid in
        if pid == getpid() { errno = ENOENT; return nil }
        return native(pid)
    }
    return access
}

@Test func missingExecutableStillFindsBoundHelperAndWorkspaceHandle() throws {
    try withFenceIdentityFixture { request, _, _ in
        let evidence = try AgentFenceProbe.run(request, access: missingOwnExecutable())
        #expect(!evidence.confirmed)
        #expect(evidence.issues.contains { $0.contains("pid \(getpid()): executable path unavailable errno 2") })
        #expect(evidence.issues.contains { $0.contains("original helper binding still live at unavailable executable path") })
        #expect(evidence.issues.contains { $0.contains("pid \(getpid()) fd") && $0.contains("workspace inode remains open") })
        #expect(evidence.ownProcessesChecked > 0)
        #expect(evidence.vnodeDescriptorsChecked > 0)
    }
}

@Test func reusedPIDWithAnotherBirthCannotMatchOriginalHelper() throws {
    try withFenceIdentityFixture { request, _, _ in
        let anotherBirth = AgentFenceProbe.Request(environment: request.environment, session: request.session,
            incarnation: request.incarnation, operation: request.operation, rootfs: request.rootfs,
            helper: request.helper, pid: request.pid, uid: request.uid, birth: request.birth + 1)
        let evidence = try AgentFenceProbe.run(anotherBirth, access: missingOwnExecutable())
        #expect(!evidence.confirmed) // missing path is still unresolved
        #expect(!evidence.issues.contains { $0.contains("original helper binding still live") })
        #expect(evidence.issues.contains { $0.contains("workspace inode remains open") })
    }
}

@Test func inaccessibleKernelIdentityRemainsUnknown() throws {
    try withFenceIdentityFixture { request, _, _ in
        var access = missingOwnExecutable()
        let native = access.info
        access.info = { pid, flavor, arg, buffer, size in
            if pid == getpid() && flavor == PROC_PIDTBSDINFO { errno = EACCES; return 0 }
            return native(pid, flavor, arg, buffer, size)
        }
        let evidence = try AgentFenceProbe.run(request, access: access)
        #expect(!evidence.confirmed)
        #expect(evidence.issues.contains { $0.contains("owned process birth/identity unavailable") })
        #expect(!evidence.issues.contains { $0.contains("original helper binding still live") })
    }
}

@Test func unavailableResourceCoverageIsSeparateFromMissingExecutable() throws {
    try withFenceIdentityFixture { request, _, _ in
        for (flavor, expected) in [(PROC_PIDLISTFDS, "descriptor inventory unavailable"),
                                   (PROC_PIDLISTFILEPORTS, "fileport inventory unavailable"),
                                   (PROC_PIDREGIONPATHINFO, "mapped-region lookup unavailable")] {
            var access = missingOwnExecutable()
            let native = access.info
            access.info = { pid, query, arg, buffer, size in
                if pid == getpid() && query == flavor { errno = EACCES; return 0 }
                return native(pid, query, arg, buffer, size)
            }
            let evidence = try AgentFenceProbe.run(request, access: access)
            #expect(!evidence.confirmed)
            #expect(evidence.issues.contains { $0.contains("pid \(getpid()): executable path unavailable") })
            #expect(evidence.issues.contains { $0.contains("pid \(getpid()): " + expected) })
        }
    }
}

@Test func fullDescriptorBufferCannotBecomeCompleteEmptyCoverage() throws {
    try withFenceIdentityFixture { request, _, _ in
        var access = missingOwnExecutable()
        let native = access.info
        access.info = { pid, flavor, arg, buffer, size in
            if pid == getpid() && flavor == PROC_PIDLISTFDS && buffer != nil { return size }
            return native(pid, flavor, arg, buffer, size)
        }
        let evidence = try AgentFenceProbe.run(request, access: access)
        #expect(!evidence.confirmed)
        #expect(evidence.issues.contains { $0.contains("pid \(getpid()): descriptor inventory incomplete") })
    }
}

@Test func identityChangeDuringResourceScanRetainsUnknown() throws {
    try withFenceIdentityFixture { request, _, _ in
        var access = missingOwnExecutable()
        let native = access.info
        var reads = 0
        access.info = { pid, flavor, arg, buffer, size in
            let result = native(pid, flavor, arg, buffer, size)
            if pid == getpid() && flavor == PROC_PIDTBSDINFO && result == MemoryLayout<proc_bsdinfo>.size {
                reads += 1
                if reads % 2 == 0, let info = buffer?.assumingMemoryBound(to: proc_bsdinfo.self) {
                    info.pointee.pbi_start_tvusec += 1
                }
            }
            return result
        }
        let evidence = try AgentFenceProbe.run(request, access: access)
        #expect(!evidence.confirmed)
        #expect(evidence.issues.contains { $0.contains("process identity changed during resource observation") })
    }
}

@Test func missingExecutableCannotHideUnlinkedWorkspaceCustody() throws {
    try withFenceIdentityFixture { original, _, dir in
        // Keep the fixture's original FD open while removing only its own
        // pathname. Restore it afterwards for the fixture's preservation check.
        let disk = URL(fileURLWithPath: original.rootfs)
        let saved = try Data(contentsOf: disk)
        try FileManager.default.removeItem(at: disk)
        defer { try? saved.write(to: disk); chmod(disk.path, 0o600) }
        var request = original
        request.workspaceAbsent = true
        request.container = dir.path + "/containers/agent-fixture-actor"
        let evidence = try AgentFenceProbe.run(request, access: missingOwnExecutable())
        #expect(!evidence.confirmed)
        #expect(evidence.issues.contains { $0.contains("unlinked vnode ownership unresolved") })
        #expect(evidence.issues.contains { $0.contains("original helper binding still live") })
    }
}

@Test func foreignMissingPathNamesEveryDeniedResourceBoundary() throws {
    try withFenceIdentityFixture { request, _, _ in
        var access = missingOwnExecutable()
        let native = access.info
        access.info = { pid, flavor, arg, buffer, size in
            guard pid == getpid() else { return native(pid, flavor, arg, buffer, size) }
            if flavor == PROC_PIDT_SHORTBSDINFO {
                let result = native(pid, flavor, arg, buffer, size)
                buffer?.assumingMemoryBound(to: proc_bsdshortinfo.self).pointee.pbsi_uid = getuid() + 1000
                return result
            }
            if [PROC_PIDTBSDINFO, PROC_PIDLISTFDS, PROC_PIDLISTFILEPORTS, PROC_PIDREGIONPATHINFO].contains(flavor) {
                errno = EPERM; return 0
            }
            return native(pid, flavor, arg, buffer, size)
        }
        let evidence = try AgentFenceProbe.run(request, access: access)
        #expect(!evidence.confirmed)
        for text in ["foreign process birth/identity unavailable errno 1", "descriptor inventory target exclusion unproven, errno 1", "fileport inventory target exclusion unproven, errno 1", "mapped-region target exclusion unproven, errno 1"] {
            #expect(evidence.issues.contains { $0.contains("pid \(getpid())") && $0.contains(text) })
        }
    }
}

@Test func stableForeignResourceCoverageCanExcludeOnlyTheTargetInode() throws {
    try withFenceIdentityFixture { request, _, _ in
        var access = missingOwnExecutable()
        let native = access.info
        access.info = { pid, flavor, arg, buffer, size in
            guard pid == getpid() else { return native(pid, flavor, arg, buffer, size) }
            if flavor == PROC_PIDT_SHORTBSDINFO || flavor == PROC_PIDTBSDINFO {
                let result = native(pid, flavor, arg, buffer, size)
                if flavor == PROC_PIDT_SHORTBSDINFO { buffer?.assumingMemoryBound(to: proc_bsdshortinfo.self).pointee.pbsi_uid = getuid() + 1000 }
                else { buffer?.assumingMemoryBound(to: proc_bsdinfo.self).pointee.pbi_uid = getuid() + 1000 }
                return result
            }
            if flavor == PROC_PIDLISTFDS || flavor == PROC_PIDLISTFILEPORTS { errno = 0; return 0 }
            if flavor == PROC_PIDREGIONPATHINFO { errno = EINVAL; return 0 }
            return native(pid, flavor, arg, buffer, size)
        }
        let evidence = try AgentFenceProbe.run(request, access: access)
        // This deliberately synthetic empty target inventory checks the fallback
        // decision, never the actual account's permissions or global clearance.
        #expect(!evidence.issues.contains { $0.contains("pid \(getpid()): executable path unavailable") })
        #expect(!evidence.issues.contains { $0.contains("pid \(getpid())") && $0.contains("original helper binding") })
    }
}


// An owned, inert file exercises the production file validation independently
// of the foreign-owned SwiftPM host that loads this test image. Never executed.
private func ownedLaunchExecutable(in directory: URL) throws -> (URL, AgentLaunchCustody.ExecutableAccess) {
    let file = directory.appendingPathComponent("owned-executable")
    try Data("owned inert executable fixture".utf8).write(to: file)
    try #require(chmod(file.path, 0o700) == 0)
    var access = AgentLaunchCustody.ExecutableAccess()
    access.path = { file.path }
    return (file, access)
}

private func expectExecutableRefusal(_ body: () throws -> Void) {
    do { try body(); Issue.record("Unsafe executable observation was accepted") }
    catch AgentLaunchCustody.Failure.executable(_) { }
    catch { Issue.record("Wrong executable failure boundary: \(error)") }
}

@Test func launchCustodyIsPrivateExactAndNeverReplacesAnIncarnation() throws {
    try withFenceIdentityFixture { request, identity, directory in
        let (executableFile, access) = try ownedLaunchExecutable(in: directory)
        try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
            environment: request.environment, session: request.session, incarnation: request.incarnation,
            sourceSHA: String(repeating: "a", count: 40), executable: access)
        let receipt = directory.appendingPathComponent("launch-custody-actor.json")
        let bytes = try Data(contentsOf: receipt)
        let object = try #require(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        #expect(object["helperExecutable"] as? String == executableFile.path)
        #expect(object["helperFileSHA256"] as? String == "640213d502b9f6fd416891127273e2b21af3f9244512a08f1b24ddc842feb528")
        #expect((object["helperPID"] as? NSNumber)?.int32Value == getpid())
        #expect((object["observerUID"] as? NSNumber)?.uint32Value == getuid())
        #expect(object["stage"] as? String == "before-virtualization-create")
        #expect((object["helperBirthSeconds"] as? NSNumber)?.uint64Value == identity.pbi_start_tvsec)
        #expect((object["helperBirthMicroseconds"] as? NSNumber)?.uint64Value == identity.pbi_start_tvusec)
        var disk = stat(), record = stat()
        #expect(lstat(request.rootfs, &disk) == 0)
        #expect(lstat(receipt.path, &record) == 0)
        #expect(record.st_mode & 0o777 == 0o600)
        #expect((object["rootfsInode"] as? NSNumber)?.uint64Value == disk.st_ino)
        #expect(throws: AgentLaunchCustody.Failure.self) {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: "changed", session: request.session, incarnation: request.incarnation,
                sourceSHA: String(repeating: "b", count: 40), executable: access)
        }
        #expect(try Data(contentsOf: receipt) == bytes)
    }
}

private func expectCustodyRefusal(_ body: () throws -> Void) {
    do { try body(); Issue.record("Unsafe rootfs custody was accepted") }
    catch AgentLaunchCustody.Failure.custody { }
    catch { Issue.record("Wrong rootfs custody failure boundary: \(error)") }
}

@Test func launchCustodyRefusesPublicOrLinkedWorkspaceBeforeReceipt() throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        chmod(request.rootfs, 0o644)
        defer { chmod(request.rootfs, 0o600) }
        expectCustodyRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "public",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-public.json").path))
        chmod(request.rootfs, 0o600)
        let link = directory.appendingPathComponent("alias.ext4")
        #expect(Darwin.link(request.rootfs, link.path) == 0)
        defer { unlink(link.path) }
        expectCustodyRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "linked",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-linked.json").path))
    }
}

@Test func foreignFallbackCannotHideAnActualTargetDescriptor() throws {
    try withFenceIdentityFixture { request, _, _ in
        var access = missingOwnExecutable()
        let native = access.info
        access.info = { pid, flavor, arg, buffer, size in
            let result = native(pid, flavor, arg, buffer, size)
            if pid == getpid() {
                if flavor == PROC_PIDT_SHORTBSDINFO { buffer?.assumingMemoryBound(to: proc_bsdshortinfo.self).pointee.pbsi_uid = getuid() + 1000 }
                if flavor == PROC_PIDTBSDINFO { buffer?.assumingMemoryBound(to: proc_bsdinfo.self).pointee.pbi_uid = getuid() + 1000 }
            }
            return result
        }
        let evidence = try AgentFenceProbe.run(request, access: access)
        #expect(!evidence.confirmed)
        #expect(evidence.issues.contains { $0.contains("pid \(getpid()) fd") && $0.contains("workspace inode remains open") })
        #expect(evidence.issues.contains { $0.contains("pid \(getpid()): executable path unavailable") })
    }
}

@Test func vanishedOrNegativeResourceReadCannotClearMissingPathHold() throws {
    try withFenceIdentityFixture { request, _, _ in
        for failure in [ESRCH, Int32(0)] {
            var access = missingOwnExecutable()
            let native = access.info
            access.info = { pid, flavor, arg, buffer, size in
                let result = native(pid, flavor, arg, buffer, size)
                if pid == getpid() {
                    if flavor == PROC_PIDT_SHORTBSDINFO { buffer?.assumingMemoryBound(to: proc_bsdshortinfo.self).pointee.pbsi_uid = getuid() + 1000 }
                    if flavor == PROC_PIDTBSDINFO { buffer?.assumingMemoryBound(to: proc_bsdinfo.self).pointee.pbi_uid = getuid() + 1000 }
                    if flavor == PROC_PIDLISTFDS { errno = failure; return -1 }
                }
                return result
            }
            let evidence = try AgentFenceProbe.run(request, access: access)
            #expect(!evidence.confirmed)
            #expect(evidence.issues.contains { $0.contains("pid \(getpid()): executable path unavailable") })
            #expect(evidence.issues.contains { $0.contains("pid \(getpid()): descriptor inventory unavailable") })
        }
    }
}

@Test func launchReceiptFullFlushFailureIsRetainedAndBlocksReplay() throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        for failOn in [1, 2] {
            let incarnation = "flush-\(failOn)"
            var calls = 0
            #expect(throws: AgentLaunchCustody.Failure.self) {
                try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                    environment: request.environment, session: request.session, incarnation: incarnation,
                    sourceSHA: String(repeating: "a", count: 40), executable: access, fullSync: { fd in
                        calls += 1
                        if calls == failOn { errno = EIO; return -1 }
                        return fcntl(fd, F_FULLFSYNC)
                    })
            }
            try #require(calls == failOn)
            let receipt = directory.appendingPathComponent("launch-custody-" + incarnation + ".json")
            #expect(FileManager.default.fileExists(atPath: receipt.path))
            let retained = try Data(contentsOf: receipt)
            #expect(throws: AgentLaunchCustody.Failure.self) {
                try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                    environment: request.environment, session: request.session, incarnation: incarnation,
                    sourceSHA: String(repeating: "a", count: 40), executable: access)
            }
            #expect(try Data(contentsOf: receipt) == retained)
        }
    }
}

@Test func privilegedHolderDiagnosticRefusesOrdinaryOwnerWithoutElevation() throws {
    try withFenceIdentityFixture { target, _, _ in
        var disk = stat()
        #expect(lstat(target.rootfs, &disk) == 0)
        let request = AgentFenceDiagnostic.Request(target: target,
            expectedDevice: UInt32(bitPattern: disk.st_dev), expectedInode: disk.st_ino)
        #expect(getuid() != 0)
        #expect(throws: (any Error).self) { try AgentFenceDiagnostic.run(request) }
        #expect(throws: (any Error).self) { try AgentFenceDiagnostic.readRequest(target.rootfs) }
    }
}

// Record the actual test process executable rather than inferring it from the
// package image or an installed helper with an unobserved relationship to it.
@Test func nativeLaunchExecutableIdentityDiagnostic() throws {
    try withFenceIdentityFixture { request, _, directory in
        let path = try AgentLaunchCustody.observedExecutablePath()
        var file = stat()
        try #require(lstat(path, &file) == 0)
        let regular = file.st_mode & S_IFMT == S_IFREG
        let allowedOwner = file.st_uid == getuid() || file.st_uid == 0
        let hash = regular && file.st_size > 0 && file.st_size <= 256 * 1024 * 1024
            ? SHA256.hash(data: try Data(contentsOf: URL(fileURLWithPath: path)))
                .map { String(format: "%02x", $0) }.joined() : "UNREAD"
        print("NATIVE_EXECUTABLE_OBSERVATION path=\(path) uid=\(file.st_uid) caller=\(getuid()) mode=\(file.st_mode) nlink=\(file.st_nlink) bytes=\(file.st_size) sha256=\(hash) allowedOwner=\(allowedOwner)")
        try #require(regular && file.st_size > 0 && file.st_size <= 256 * 1024 * 1024)
        try #require(file.st_mode & 0o022 == 0 && file.st_nlink == 1)
        if allowedOwner {
            try AgentLaunchCustody.write(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "native-diagnostic",
                sourceSHA: String(repeating: "a", count: 40))
            let receipt = directory.appendingPathComponent("launch-custody-native-diagnostic.json")
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: receipt)) as? [String: Any])
            #expect(object["helperExecutable"] as? String == path)
            #expect(object["helperFileSHA256"] as? String == hash)
        } else {
            do {
                try AgentLaunchCustody.write(directory: directory.path, rootfs: request.rootfs,
                    environment: request.environment, session: request.session, incarnation: "native-diagnostic",
                    sourceSHA: String(repeating: "a", count: 40))
                Issue.record("Native foreign-owner executable was accepted")
            } catch AgentLaunchCustody.Failure.executable(let evidence) {
                // A nonexistent/alternate path and unrelated executable failure
                // must not impersonate dispatch to this actual native observer.
                #expect(evidence.path == path)
                #expect(evidence.predicate == .owner)
                #expect(evidence.fileOwner == file.st_uid)
                #expect(evidence.callerUID == getuid())
            } catch { Issue.record("Wrong native failure boundary: \(error)") }
        }
    }
}

@Test(arguments: ["directory", "symlink", "group-writable", "other-writable", "hardlink"])
func launchExecutableFilePolicyRefusesUnsafeFiles(_ kind: String) throws {
    try withFenceIdentityFixture { request, _, directory in
        let (file, original) = try ownedLaunchExecutable(in: directory)
        var access = original
        switch kind {
        case "directory": access.path = { directory.path }
        case "symlink":
            let alias = directory.appendingPathComponent("alias-executable")
            try #require(symlink(file.path, alias.path) == 0)
            access.path = { alias.path }
        case "group-writable": try #require(chmod(file.path, 0o720) == 0)
        case "other-writable": try #require(chmod(file.path, 0o702) == 0)
        case "hardlink": try #require(Darwin.link(file.path, directory.appendingPathComponent("hardlink").path) == 0)
        default: Issue.record("Unknown fixture")
        }
        expectExecutableRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "file-policy",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-file-policy.json").path))
    }
}

@Test func launchExecutableNoFollowRejectsSameInodeBehindNewSymlink() throws {
    try withFenceIdentityFixture { request, _, directory in
        let (file, original) = try ownedLaunchExecutable(in: directory)
        var access = original
        let moved = directory.appendingPathComponent("moved-original")
        var transitioned = false
        access.openDescriptor = { path, flags in
            guard rename(path, moved.path) == 0, symlink(moved.path, path) == 0 else { return -1 }
            transitioned = true
            return Darwin.open(path, flags)
        }
        expectExecutableRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "nofollow",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        try #require(transitioned)
        #expect(FileManager.default.fileExists(atPath: file.path))
    }
}

@Test func launchExecutableRefusesReplacementInodeBeforeOpen() throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, original) = try ownedLaunchExecutable(in: directory)
        var access = original
        var replaced = false
        access.openDescriptor = { path, flags in
            guard rename(path, directory.appendingPathComponent("old-inode").path) == 0 else { return -1 }
            do { try Data("owned inert executable fixture".utf8).write(to: URL(fileURLWithPath: path)) }
            catch { return -1 }
            guard chmod(path, 0o700) == 0 else { return -1 }
            replaced = true
            return Darwin.open(path, flags)
        }
        expectExecutableRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "inode",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        try #require(replaced)
    }
}

@Test(arguments: ["device", "short-read", "mtime"])
func launchExecutableRefusesChangedOrIncompleteObservation(_ kind: String) throws {
    try withFenceIdentityFixture { request, _, directory in
        let (file, original) = try ownedLaunchExecutable(in: directory)
        var access = original
        var calls = 0
        if kind == "short-read" || kind == "device" {
            access.metadata = { path, data in
                let result = Darwin.lstat(path, data)
                if result == 0 && kind == "short-read" { data.pointee.st_size += 1 }
                if result == 0 && kind == "device" { data.pointee.st_dev ^= 1 }
                return result
            }
        }
        access.descriptorMetadata = { fd, data in
            calls += 1
            if kind == "mtime" && calls == 2 {
                do { try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSince1970: 1234567890)], ofItemAtPath: file.path) }
                catch { Issue.record("Could not change owned fixture mtime: \(error)") }
            }
            let result = Darwin.fstat(fd, data)
            if result == 0 && kind == "short-read" { data.pointee.st_size += 1 }
            return result
        }
        expectExecutableRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "observation",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(calls > 0)
    }
}

@Test(arguments: [1, 2])
func launchReceiptSyncFailureRetainsBytesAndBlocksReplay(_ failOn: Int) throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        var calls = 0
        do {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "fsync",
                sourceSHA: String(repeating: "a", count: 40), executable: access,
                fileSync: { fd in
                    calls += 1
                    if calls == failOn { errno = EIO; return -1 }
                    return Darwin.fsync(fd)
                })
            Issue.record("Failed native sync was accepted")
        } catch AgentLaunchCustody.Failure.persistence { }
        catch { Issue.record("Wrong sync failure boundary: \(error)") }
        try #require(calls == failOn)
        let receipt = directory.appendingPathComponent("launch-custody-fsync.json")
        let retained = try Data(contentsOf: receipt)
        #expect(!retained.isEmpty)
        #expect(throws: AgentLaunchCustody.Failure.self) {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "fsync",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(try Data(contentsOf: receipt) == retained)
    }
}

@Test(arguments: ["directory", "empty", "oversize"])
func launchExecutableRejectsInvalidKindOrSizeBeforeOpen(_ kind: String) throws {
    try withFenceIdentityFixture { request, _, directory in
        let (file, original) = try ownedLaunchExecutable(in: directory)
        var access = original
        if kind == "directory" { access.path = { directory.path } }
        else {
            let handle = try FileHandle(forWritingTo: file)
            // Sparse oversize fixture: no large allocation, read or execution.
            try handle.truncate(atOffset: kind == "empty" ? 0 : 256 * 1024 * 1024 + 1)
            try handle.close()
        }
        var opened = false
        access.openDescriptor = { _, _ in
            opened = true
            Issue.record("Invalid executable kind or size reached open")
            return -1
        }
        expectExecutableRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "pre-open",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!opened)
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-pre-open.json").path))
    }
}

@Test(arguments: ["directory-mode", "path"])
func launchRootfsRefusesInvalidDirectoryOrPath(_ kind: String) throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        var rootfs = request.rootfs
        if kind == "directory-mode" {
            try #require(chmod(directory.path, 0o770) == 0)
        } else {
            let alternate = directory.appendingPathComponent("alternate.ext4")
            try Data("retained writer fixture".utf8).write(to: alternate)
            try #require(chmod(alternate.path, 0o600) == 0)
            rootfs = alternate.path
        }
        defer { chmod(directory.path, 0o700) }
        expectCustodyRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: rootfs,
                environment: request.environment, session: request.session, incarnation: "rootfs-boundary",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-rootfs-boundary.json").path))
    }
}

// Untested guard: native self proc_pidinfo failure or short result (no kernel identity override).
// Untested guard: native self PID mismatch (no process identity override).
// Untested guard: native self UID mismatch (no caller identity override).
// Untested guard: native self birth seconds equal zero (no kernel identity override).
// Untested guard: foreign rootfs owner (no chown or alternate actor).
// Untested guard: foreign parent owner (no chown or alternate actor).
// Untested guard: early rootfs descriptor/path device mismatch (no production-reachable swap seam).
// Untested guard: early rootfs descriptor/path inode mismatch (no production-reachable swap seam).
// The full-entry symlink refusal overlaps O_NOFOLLOW and early identity.
// O_NOFOLLOW has a separate direct test of the fixed native operation below;
// this full-entry check is never separate mutant proof for early identity.
@Test func launchRootfsRefusesSymlinkBeforeReceipt() throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        let retained = directory.appendingPathComponent("retained-original.ext4")
        try #require(rename(request.rootfs, retained.path) == 0)
        try #require(symlink(retained.path, request.rootfs) == 0)
        expectCustodyRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "rootfs-symlink",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-rootfs-symlink.json").path))
    }
}

@Test(arguments: ["inode", "mode"])
func launchRootfsPostFlushChangeRetainsReceiptAndBlocksReplay(_ kind: String) throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        var changed = false
        do {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "post-flush",
                sourceSHA: String(repeating: "a", count: 40), executable: access,
                fullSync: { fd in
                    let result = fcntl(fd, F_FULLFSYNC)
                    if result == 0 && !changed {
                        if kind == "inode" {
                            guard rename(request.rootfs, directory.appendingPathComponent("pre-flush.ext4").path) == 0 else { return -1 }
                            do { try Data("retained writer fixture".utf8).write(to: URL(fileURLWithPath: request.rootfs)) }
                            catch { return -1 }
                        }
                        guard chmod(request.rootfs, kind == "mode" ? 0o644 : 0o600) == 0 else { return -1 }
                        changed = true
                    }
                    return result
                })
            Issue.record("Changed rootfs custody was accepted")
        } catch AgentLaunchCustody.Failure.persistence { }
        catch { Issue.record("Wrong post-flush failure boundary: \(error)") }
        try #require(changed)
        try #require(chmod(request.rootfs, 0o600) == 0)
        let receipt = directory.appendingPathComponent("launch-custody-post-flush.json")
        let retained = try Data(contentsOf: receipt)
        #expect(!retained.isEmpty)
        #expect(throws: AgentLaunchCustody.Failure.self) {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "post-flush",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(try Data(contentsOf: receipt) == retained)
    }
}

@Test func launchRootfsRejectsSingleLinkFIFOWithPrivateFileMode() throws {
    try withFenceIdentityFixture { request, _, directory in
        let (_, access) = try ownedLaunchExecutable(in: directory)
        let saved = directory.appendingPathComponent("retained-file.ext4")
        try #require(rename(request.rootfs, saved.path) == 0)
        defer {
            unlink(request.rootfs)
            rename(saved.path, request.rootfs)
        }
        try #require(mkfifo(request.rootfs, 0o600) == 0)
        // Keep a reader/writer present: the production read-only FIFO open must
        // not block. No process is spawned and no fixture executable is run.
        let holder = Darwin.open(request.rootfs, O_RDWR | O_NONBLOCK | O_CLOEXEC)
        try #require(holder >= 0)
        defer { close(holder) }
        var file = stat()
        try #require(lstat(request.rootfs, &file) == 0)
        try #require(file.st_mode & S_IFMT == S_IFIFO)
        try #require(file.st_mode & 0o777 == 0o600)
        try #require(file.st_uid == getuid())
        try #require(file.st_nlink == 1)
        expectCustodyRefusal {
            try AgentLaunchCustody.writeObserved(directory: directory.path, rootfs: request.rootfs,
                environment: request.environment, session: request.session, incarnation: "rootfs-kind",
                sourceSHA: String(repeating: "a", count: 40), executable: access)
        }
        #expect(!FileManager.default.fileExists(atPath: directory.appendingPathComponent("launch-custody-rootfs-kind.json").path))
    }
}

@Test func launchRootfsNativeOpenRefusesSymlinkToValidOwnedFile() throws {
    try withFenceIdentityFixture { request, _, directory in
        var file = stat()
        try #require(lstat(request.rootfs, &file) == 0)
        try #require(file.st_mode & S_IFMT == S_IFREG)
        try #require(file.st_mode & 0o777 == 0o600)
        try #require(file.st_uid == getuid())
        try #require(file.st_nlink == 1)
        let alias = directory.appendingPathComponent("rootfs-native-alias")
        try #require(symlink(request.rootfs, alias.path) == 0)
        defer { unlink(alias.path) }
        // Exercise the exact fixed native operation used by the production
        // entry, before any subsequent path/descriptor identity comparison.
        let opened = AgentLaunchCustody.openRootfsDescriptor(alias.path)
        if opened >= 0 { close(opened) }
        #expect(opened < 0, "Native rootfs nofollow accepted a symlink to a valid owned file")
        let direct = AgentLaunchCustody.openRootfsDescriptor(request.rootfs)
        try #require(direct >= 0)
        defer { close(direct) }
        var observed = stat()
        try #require(fstat(direct, &observed) == 0)
        #expect(observed.st_dev == file.st_dev && observed.st_ino == file.st_ino)
    }
}

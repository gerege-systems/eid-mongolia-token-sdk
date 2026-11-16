import XCTest
@testable import EIDTokenReader

/// The private OpenSC config folder: created with one file, removed again, and stale ones swept — only the exact
/// `eid-token-test-<UUID>` folders holding nothing but `opensc.conf`.
final class OpenSCConfigTests: XCTestCase {
    private let fm = FileManager.default
    private var root: URL!
    private let day: TimeInterval = 24 * 60 * 60

    override func setUpWithError() throws {
        root = fm.temporaryDirectory.appendingPathComponent("eid-token-test-unit-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: root, withIntermediateDirectories: false)
    }

    override func tearDownWithError() throws {
        try? fm.removeItem(at: root)
    }

    private var later: Date { Date().addingTimeInterval(3 * day) }

    func testCreatedFolderHoldsOnlyTheConfigAndIsRemoved() throws {
        let dir = try OpenSCConfig.createConfigDirectory(in: root)
        XCTAssertEqual(try fm.contentsOfDirectory(atPath: dir.path), ["opensc.conf"])
        XCTAssertTrue(dir.lastPathComponent.hasPrefix("eid-token-test-"))

        XCTAssertTrue(OpenSCConfig.removeConfigDirectory(dir))
        XCTAssertFalse(fm.fileExists(atPath: dir.path))
        XCTAssertFalse(OpenSCConfig.removeConfigDirectory(dir))   // already gone: no crash, false
    }

    func testCleanupLeavesAFolderWithAnUnexpectedFile() throws {
        let dir = try OpenSCConfig.createConfigDirectory(in: root)
        try "x".write(to: dir.appendingPathComponent("notes.txt"), atomically: true, encoding: .utf8)
        XCTAssertFalse(OpenSCConfig.removeConfigDirectory(dir))
        XCTAssertTrue(fm.fileExists(atPath: dir.appendingPathComponent("opensc.conf").path))
        XCTAssertTrue(fm.fileExists(atPath: dir.appendingPathComponent("notes.txt").path))
    }

    func testSweepRemovesOldMatchingFolders() throws {
        let dir = try OpenSCConfig.createConfigDirectory(in: root)
        OpenSCConfig.sweepStale(in: root, olderThan: day, now: later)
        XCTAssertFalse(fm.fileExists(atPath: dir.path))
    }

    func testSweepLeavesRecentFolders() throws {
        let dir = try OpenSCConfig.createConfigDirectory(in: root)
        OpenSCConfig.sweepStale(in: root, olderThan: day, now: Date())
        XCTAssertTrue(fm.fileExists(atPath: dir.path))
    }

    func testSweepLeavesFoldersWithUnexpectedContent() throws {
        let extra = try OpenSCConfig.createConfigDirectory(in: root)
        try "x".write(to: extra.appendingPathComponent("other.txt"), atomically: true, encoding: .utf8)

        let renamed = try OpenSCConfig.createConfigDirectory(in: root)
        try fm.moveItem(at: renamed.appendingPathComponent("opensc.conf"), to: renamed.appendingPathComponent("other.conf"))

        let confIsFolder = try OpenSCConfig.createConfigDirectory(in: root)
        try fm.removeItem(at: confIsFolder.appendingPathComponent("opensc.conf"))
        try fm.createDirectory(at: confIsFolder.appendingPathComponent("opensc.conf"), withIntermediateDirectories: false)

        OpenSCConfig.sweepStale(in: root, olderThan: day, now: later)

        for dir in [extra, renamed, confIsFolder] {
            XCTAssertTrue(fm.fileExists(atPath: dir.path), dir.lastPathComponent)
        }
    }

    func testSweepLeavesFoldersWhoseNameDoesNotMatchExactly() throws {
        let names = ["eid-token-test-abc123",
                     "eid-token-test-\(UUID().uuidString.lowercased())",
                     "eid-token-test-\(UUID().uuidString)-x"]
        for name in names {
            let dir = root.appendingPathComponent(name, isDirectory: true)
            try fm.createDirectory(at: dir, withIntermediateDirectories: false)
            try "x".write(to: dir.appendingPathComponent("opensc.conf"), atomically: true, encoding: .utf8)
        }
        OpenSCConfig.sweepStale(in: root, olderThan: day, now: later)
        for name in names {
            XCTAssertTrue(fm.fileExists(atPath: root.appendingPathComponent(name).path), name)
        }
    }

    func testSweepNeverFollowsASymlink() throws {
        // The target's own name does not match, so only the link is a candidate; it must be skipped, not followed.
        let target = root.appendingPathComponent("real-target", isDirectory: true)
        try fm.createDirectory(at: target, withIntermediateDirectories: false)
        try "x".write(to: target.appendingPathComponent("opensc.conf"), atomically: true, encoding: .utf8)
        let link = root.appendingPathComponent("eid-token-test-\(UUID().uuidString)")
        try fm.createSymbolicLink(at: link, withDestinationURL: target)

        OpenSCConfig.sweepStale(in: root, olderThan: day, now: later)

        XCTAssertTrue(fm.fileExists(atPath: target.appendingPathComponent("opensc.conf").path))
        XCTAssertNotNil(try? fm.destinationOfSymbolicLink(atPath: link.path))
    }
}

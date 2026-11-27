import Foundation
import XCTest
@testable import SpruceCore
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// The scanner reads files malware may have planted. A named pipe nobody writes to blocks
/// a plain open for good, so none of these calls may wait on one. (A regression here shows
/// up as a hung test, which the CI timeout turns into a failure.)
final class ProtectionSpecialFileTests: XCTestCase {
    private var fixture: ProtectionFixture!

    override func setUp() {
        super.setUp()
        fixture = ProtectionFixture()
    }

    override func tearDown() {
        fixture.remove()
        super.tearDown()
    }

    private func pipe(_ logical: String) throws -> String {
        let real = fixture.path(logical)
        try FileManager.default.createDirectory(atPath: (real as NSString).deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        XCTAssertEqual(mkfifo(real, 0o644), 0, "mkfifo failed")
        return real
    }

    func testNamedPipeIsNeverOpenedForReading() throws {
        let fifo = try pipe("~/Library/LaunchAgents/com.example.pipe.plist")
        XCTAssertNil(ProtectionFileSniffer.openRegular(fifo))
        XCTAssertNil(ProtectionFileSniffer.readRegular(fifo))
        XCTAssertNil(ProtectionFileSniffer.readPrefix(of: fifo, limit: 256))
        XCTAssertNil(ProtectionFileSniffer.text(of: fifo))
        XCTAssertEqual(ProtectionFileSniffer.type(of: fifo), .other)

        let item = ProtectionLaunchItem.parse(path: fifo, domain: .user, kind: .launchAgent, home: fixture.home)
        XCTAssertFalse(item.isValidPlist)
        XCTAssertNil(item.label)
    }

    func testSymlinkToANamedPipeIsRefusedToo() throws {
        let fifo = try pipe("/private/tmp/x")
        let link = fixture.path("~/Library/LaunchAgents/com.example.link.plist")
        try FileManager.default.createDirectory(atPath: (link as NSString).deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: fifo)
        XCTAssertNil(ProtectionFileSniffer.readRegular(link))
        XCTAssertFalse(ProtectionLaunchItem.parse(path: link, domain: .user, kind: .launchAgent, home: fixture.home).isValidPlist)
    }

    func testBundleWithAPipeForItsInfoPlistReadsAsEmpty() throws {
        _ = try pipe("/Applications/Trap.app/Contents/Info.plist")
        let info = ProtectionBundleInfo.read(bundlePath: fixture.path("/Applications/Trap.app"))
        XCTAssertNil(info.bundleID)
    }

    func testRegularFilesAndLinksToThemStillRead() throws {
        let plist = try PropertyListSerialization.data(
            fromPropertyList: ["Label": "com.example.agent", "ProgramArguments": ["/bin/sh", "-c", "true"]],
            format: .xml, options: 0)
        let real = fixture.file("~/Library/LaunchAgents/com.example.agent.plist", plist)
        XCTAssertEqual(ProtectionFileSniffer.readRegular(real), plist)
        XCTAssertEqual(ProtectionFileSniffer.readRegular(real, limit: 5), plist.prefix(5))
        XCTAssertEqual(ProtectionLaunchItem.parse(path: real, domain: .user, kind: .launchAgent, home: fixture.home).label,
                       "com.example.agent")

        let link = fixture.path("~/Library/LaunchAgents/link.plist")
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: real)
        XCTAssertEqual(ProtectionFileSniffer.readRegular(link), plist)

        // Bigger than one read buffer, and an empty file.
        let big = Data((0..<200_000).map { UInt8(truncatingIfNeeded: $0) })
        XCTAssertEqual(ProtectionFileSniffer.readRegular(fixture.file("~/big.bin", big)), big)
        XCTAssertEqual(ProtectionFileSniffer.readRegular(fixture.file("~/empty", Data())), Data())

        XCTAssertNil(ProtectionFileSniffer.readRegular(fixture.home), "a folder is not a regular file")
        XCTAssertNil(ProtectionFileSniffer.readRegular(fixture.path("~/missing")))
    }
}

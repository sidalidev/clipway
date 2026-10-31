import XCTest
@testable import ClipwayCore

/// Settings, Permissions: each state leads to the prompt or to the exact pane, both ways.
final class AccessTests: XCTestCase {
    func testPermissions() {
        XCTAssertEqual(Access.action(.notAsked, kind: .permission), .ask)
        XCTAssertEqual(Access.action(.off, kind: .permission), .openToTurnOn)
        XCTAssertEqual(Access.action(.on, kind: .permission), .openToTurnOff)
        XCTAssertEqual(Access.action(.needsApproval, kind: .permission), .openToTurnOn)
    }

    func testSettings() {
        XCTAssertEqual(Access.action(.off, kind: .setting), .turnOnHere)
        XCTAssertEqual(Access.action(.notAsked, kind: .setting), .turnOnHere)
        XCTAssertEqual(Access.action(.on, kind: .setting), .turnOffHere)
        XCTAssertEqual(Access.action(.needsApproval, kind: .setting), .openToTurnOn)
    }

    func testEveryOnStateCanBeTurnedOff() {
        for kind in [Access.Kind.permission, .setting] {
            let a = Access.action(.on, kind: kind)
            XCTAssertTrue(a == .openToTurnOff || a == .turnOffHere)
            XCTAssertTrue(Access.label(a).hasPrefix("Turn off"))
        }
    }

    func testLabels() {
        XCTAssertEqual(Access.label(.openToTurnOff), "Turn off in System Settings…")
        XCTAssertEqual(Access.label(.openToTurnOn), "Turn on in System Settings…")
        XCTAssertEqual(Access.label(Access.State.on), "On")
        XCTAssertEqual(Access.label(Access.State.off), "Off")
    }
}

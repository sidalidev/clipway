import XCTest
@testable import ClipwayCore

/// The master switch: paused stops everything, on brings everything back, erased always wins.
final class PowerTests: XCTestCase {
    func testConnectsOnlyWhenPairedOnAndNotErased() {
        XCTAssertTrue(Power.mayConnect(paired: true, erased: false, paused: false))
        XCTAssertFalse(Power.mayConnect(paired: true, erased: false, paused: true))
        XCTAssertFalse(Power.mayConnect(paired: false, erased: false, paused: false))
        XCTAssertFalse(Power.mayConnect(paired: true, erased: true, paused: false))
    }

    func testNoAutomaticSendingWhilePaused() {
        XCTAssertTrue(Power.mayAutoSend(paired: true, erased: false, paused: false, sendAutomatically: true))
        XCTAssertFalse(Power.mayAutoSend(paired: true, erased: false, paused: true, sendAutomatically: true))
        XCTAssertFalse(Power.mayAutoSend(paired: true, erased: false, paused: false, sendAutomatically: false))
    }

    func testManualSendingIsRefusedWhilePaused() {
        XCTAssertFalse(Power.maySend(paired: true, erased: false, paused: true))
        XCTAssertTrue(Power.maySend(paired: true, erased: false, paused: false))
    }

    func testLabelAndSentence() {
        XCTAssertEqual(Power.label(paused: false), "On")
        XCTAssertEqual(Power.label(paused: true), "Paused")
        XCTAssertTrue(Power.detail(paused: true, peer: "Pixel").contains("24 hours"))
        XCTAssertFalse(Power.detail(paused: false, peer: "Pixel").contains("24 hours"))
    }
}

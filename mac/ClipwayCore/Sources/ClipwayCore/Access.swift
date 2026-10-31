import Foundation

/// What each row of Settings, Permissions shows and what a click on it does. Turning something
/// off is as direct as turning it on: when it is on, the row opens the exact pane of System
/// Settings where it can be turned off.
public enum Access {
    /// A permission macOS keeps (Bluetooth, notifications), or a choice the app can apply itself
    /// (open at login), which macOS may still ask to approve.
    public enum Kind: Sendable { case permission, setting }

    public enum State: Sendable, Equatable { case on, off, notAsked, needsApproval }

    public enum Action: Sendable, Equatable {
        /// macOS's own prompt.
        case ask
        case turnOnHere, turnOffHere
        /// macOS no longer prompts: the pane of System Settings where it can be turned on.
        case openToTurnOn
        /// The pane of System Settings where it can be turned off.
        case openToTurnOff
    }

    public static func action(_ state: State, kind: Kind) -> Action {
        switch (kind, state) {
        case (_, .needsApproval): .openToTurnOn
        case (.permission, .notAsked): .ask
        case (.permission, .off): .openToTurnOn
        case (.permission, .on): .openToTurnOff
        case (.setting, .on): .turnOffHere
        case (.setting, .off), (.setting, .notAsked): .turnOnHere
        }
    }

    public static func label(_ action: Action) -> String {
        switch action {
        case .ask: "Allow…"
        case .turnOnHere: "Turn on"
        case .turnOffHere: "Turn off"
        case .openToTurnOn: "Turn on in System Settings…"
        case .openToTurnOff: "Turn off in System Settings…"
        }
    }

    public static func label(_ state: State) -> String {
        switch state {
        case .on: "On"
        case .off: "Off"
        case .notAsked: "Not asked"
        case .needsApproval: "Waiting for approval"
        }
    }
}

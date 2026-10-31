/// The master switch, at the top of the menu and in the History window: Clipway on, or paused.
/// Paused means no relay connection, no automatic sending, nothing received, until it is turned
/// back on, also after a restart. What the phone sends meanwhile waits on the relay (24 h at most).
public enum Power {
    /// The connection may run: paired, not erased elsewhere, not paused.
    public static func mayConnect(paired: Bool, erased: Bool, paused: Bool) -> Bool {
        paired && !erased && !paused
    }

    /// The clipboard watch may send what is copied.
    public static func mayAutoSend(paired: Bool, erased: Bool, paused: Bool, sendAutomatically: Bool) -> Bool {
        mayConnect(paired: paired, erased: erased, paused: paused) && sendAutomatically
    }

    /// Sending a file by hand: refused while paused, so nothing waits silently on this Mac.
    public static func maySend(paired: Bool, erased: Bool, paused: Bool) -> Bool {
        mayConnect(paired: paired, erased: erased, paused: paused)
    }

    /// "On" or "Paused", as the switch and VoiceOver say it.
    public static func label(paused: Bool) -> String { paused ? "Paused" : "On" }

    /// The one sentence under the switch.
    public static func detail(paused: Bool, peer: String) -> String {
        paused
            ? "Nothing is sent or received. What \(peer) sends waits on the relay for 24 hours at most."
            : "Sends what you copy and receives from \(peer)."
    }
}

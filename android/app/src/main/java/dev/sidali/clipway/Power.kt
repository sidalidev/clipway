package dev.sidali.clipway

/**
 * The switch on the Home screen: Clipway on, or paused. Paused means no background work at all:
 * the service is stopped, no relay connection, no alarm, no notification, and it stays paused
 * after a restart until the user turns it back on. No Android types, so it is unit tested (PowerTest).
 */
object Power {
    enum class Tile { Ready, Paused, Unavailable }

    /** The connection may run: paired, not erased elsewhere, not paused. */
    fun mayRun(paired: Boolean, erased: Boolean, paused: Boolean): Boolean = paired && !erased && !paused

    /** Sending from the phone: refused while paused, so nothing waits silently on the phone. */
    fun maySend(paired: Boolean, erased: Boolean, paused: Boolean): Boolean = mayRun(paired, erased, paused)

    /** What the Send to Mac tile shows. */
    fun tile(paired: Boolean, erased: Boolean, paused: Boolean): Tile = when {
        !paired || erased -> Tile.Unavailable
        paused -> Tile.Paused
        else -> Tile.Ready
    }

    /** The link the screens show once the service is gone. Erased stays erased. */
    fun linkWhenStopped(current: Status.Link, paused: Boolean): Status.Link = when {
        current == Status.Link.Erased -> Status.Link.Erased
        paused -> Status.Link.Paused
        else -> Status.Link.Off
    }
}

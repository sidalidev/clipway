package dev.sidali.clipway

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Home switch: paused stops everything, on brings everything back, erased always wins. */
class PowerTest {

    @Test fun runsOnlyWhenPairedOnAndNotErased() {
        assertTrue(Power.mayRun(paired = true, erased = false, paused = false))
        assertFalse(Power.mayRun(paired = true, erased = false, paused = true))
        assertFalse(Power.mayRun(paired = false, erased = false, paused = false))
        assertFalse(Power.mayRun(paired = true, erased = true, paused = false))
    }

    @Test fun sendingIsRefusedWhilePaused() {
        assertFalse(Power.maySend(paired = true, erased = false, paused = true))
        assertTrue(Power.maySend(paired = true, erased = false, paused = false))
    }

    @Test fun tileFollowsTheSwitch() {
        assertEquals(Power.Tile.Ready, Power.tile(paired = true, erased = false, paused = false))
        assertEquals(Power.Tile.Paused, Power.tile(paired = true, erased = false, paused = true))
        assertEquals(Power.Tile.Unavailable, Power.tile(paired = false, erased = false, paused = true))
        assertEquals(Power.Tile.Unavailable, Power.tile(paired = true, erased = true, paused = false))
    }

    @Test fun linkWhenStopped() {
        assertEquals(Status.Link.Paused, Power.linkWhenStopped(Status.Link.Online, paused = true))
        assertEquals(Status.Link.Off, Power.linkWhenStopped(Status.Link.Online, paused = false))
        assertEquals(Status.Link.Erased, Power.linkWhenStopped(Status.Link.Erased, paused = true))
        assertEquals(Status.Link.Off, Power.linkWhenStopped(Status.Link.Paused, paused = false))
    }
}

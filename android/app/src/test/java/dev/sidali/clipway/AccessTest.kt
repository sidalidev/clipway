package dev.sidali.clipway

import dev.sidali.clipway.Access.Action
import dev.sidali.clipway.Access.State
import org.junit.Assert.assertEquals
import org.junit.Test

/** The Permissions screen: each state leads to the dialog or to the exact Settings page, both ways. */
class AccessTest {

    @Test fun state() {
        assertEquals(State.On, Access.state(on = true, asked = false))
        assertEquals(State.On, Access.state(on = true, asked = true))
        assertEquals(State.Off, Access.state(on = false, asked = true))
        assertEquals(State.NotAsked, Access.state(on = false, asked = false))
    }

    @Test fun runtimeNeverAskedShowsTheDialog() =
        assertEquals(Action.Ask, Access.runtime(granted = false, asked = false, rationale = false))

    @Test fun runtimeRefusedOnceShowsTheDialogAgain() =
        assertEquals(Action.Ask, Access.runtime(granted = false, asked = true, rationale = true))

    @Test fun runtimeRefusedTwiceOpensSettingsToTurnOn() =
        assertEquals(Action.OpenToTurnOn, Access.runtime(granted = false, asked = true, rationale = false))

    @Test fun runtimeGrantedOpensSettingsToTurnOff() {
        assertEquals(Action.OpenToTurnOff, Access.runtime(granted = true, asked = false, rationale = false))
        assertEquals(Action.OpenToTurnOff, Access.runtime(granted = true, asked = true, rationale = true))
    }

    @Test fun notifications() {
        // On: the app's notification page, to turn them off.
        assertEquals(Action.OpenToTurnOff, Access.notifications(enabled = true, permissionGranted = true, asked = true, rationale = false))
        // Permission missing: like any runtime permission.
        assertEquals(Action.Ask, Access.notifications(enabled = false, permissionGranted = false, asked = false, rationale = false))
        assertEquals(Action.Ask, Access.notifications(enabled = false, permissionGranted = false, asked = true, rationale = true))
        assertEquals(Action.OpenToTurnOn, Access.notifications(enabled = false, permissionGranted = false, asked = true, rationale = false))
        // Permission granted but the app's switch is off in Settings: only Settings turns it back on.
        assertEquals(Action.OpenToTurnOn, Access.notifications(enabled = false, permissionGranted = true, asked = false, rationale = false))
    }

    @Test fun battery() {
        assertEquals(Action.Ask, Access.battery(exempt = false))
        assertEquals(Action.OpenToTurnOff, Access.battery(exempt = true))
    }
}

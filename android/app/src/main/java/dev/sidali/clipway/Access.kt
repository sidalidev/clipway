package dev.sidali.clipway

/**
 * What each row of the Permissions screen shows, and what a tap on it does. No Android types, so
 * it is unit tested (AccessTest). Turning a permission off is as direct as turning it on: when it
 * is on, the row opens the exact Settings page where it can be turned off.
 */
object Access {
    enum class State { On, Off, NotAsked }

    enum class Action {
        /** Android's own dialog. */
        Ask,
        /** Android no longer shows its dialog: the Settings page where it can be turned on. */
        OpenToTurnOn,
        /** The Settings page where it can be turned off. */
        OpenToTurnOff,
    }

    fun state(on: Boolean, asked: Boolean): State = when {
        on -> State.On
        asked -> State.Off
        else -> State.NotAsked
    }

    /**
     * A runtime permission (camera, nearby devices). Android shows its dialog again after one
     * refusal ([rationale] is then true), and stops after the second: only Settings can turn it on.
     */
    fun runtime(granted: Boolean, asked: Boolean, rationale: Boolean): Action = when {
        granted -> Action.OpenToTurnOff
        !asked || rationale -> Action.Ask
        else -> Action.OpenToTurnOn
    }

    /**
     * Notifications: the permission (Android 13 and later) and the app's own switch in Settings,
     * which can be off while the permission is granted.
     */
    fun notifications(enabled: Boolean, permissionGranted: Boolean, asked: Boolean, rationale: Boolean): Action = when {
        enabled -> Action.OpenToTurnOff
        !permissionGranted -> runtime(false, asked, rationale)
        else -> Action.OpenToTurnOn
    }

    /** Background use: Android's dialog can be shown each time; turning it off is in the battery optimization list. */
    fun battery(exempt: Boolean): Action = if (exempt) Action.OpenToTurnOff else Action.Ask
}

package app.localotp.ui

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.onClick
import androidx.compose.ui.semantics.password
import androidx.compose.ui.semantics.semantics

/**
 * Marks account names and codes as sensitive for accessibility (Android 14+):
 * only services declared as assistive tools receive them. Compose does not
 * inherit the window-level flag, so each such node is marked here.
 */
fun Modifier.sensitive(): Modifier = semantics { isSensitiveData = true }

/**
 * A text field state that is NOT saved into the instance-state Bundle (which
 * the system keeps outside the app). Used for passwords and secrets.
 */
@Composable
fun rememberUnsavedTextFieldState(initial: String = ""): TextFieldState = remember { TextFieldState(initial) }

/**
 * For password and secret fields: accessibility services learn only the
 * field's label and that it is a password field, never the typed text
 * (Compose would otherwise expose it, unlike a classic password EditText).
 * A tap or TalkBack double-tap still focuses the field for typing.
 */
@androidx.compose.runtime.Composable
fun Modifier.secretField(label: String): Modifier {
    val focus = remember { androidx.compose.ui.focus.FocusRequester() }
    return this
        .then(Modifier.focusRequester(focus))
        .clearAndSetSemantics {
            contentDescription = label
            password()
            isSensitiveData = true
            onClick {
                focus.requestFocus()
                true
            }
        }
}

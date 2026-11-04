package app.localotp.ui

import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.isSensitiveData
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

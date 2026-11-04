package app.localotp.ui

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import app.localotp.otp.ParsedAccount
import app.localotp.vault.Authenticator
import app.localotp.vault.VaultController
import app.localotp.vault.VaultState
import kotlinx.coroutines.delay

/** Parsed accounts waiting to be added. Secrets are cleared when discarded. */
class Draft(val accounts: List<ParsedAccount>) {
    fun wipe() = accounts.forEach { it.secret.fill(0) }
}

private sealed interface Page {
    data object List : Page
    data class Add(val draft: Draft?) : Page
    data object Scan : Page
    data class Import(val draft: Draft) : Page
}

@Composable
fun LocalOtpRoot(vault: VaultController, auth: Authenticator) {
    when (val state = vault.state.collectAsState().value) {
        VaultState.NoVault -> SetupScreen(vault, auth)
        is VaultState.Locked -> UnlockScreen(vault, auth, state.reason)
        is VaultState.Unlocked -> UnlockedPages(vault, state)
    }
}

@Composable
private fun UnlockedPages(vault: VaultController, state: VaultState.Unlocked) {
    // One clock for all codes, aligned to the start of each second.
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(Unit) {
        while (true) {
            val ms = System.currentTimeMillis()
            now = ms / 1000
            vault.checkIdle()
            delay(1000 - ms % 1000)
        }
    }
    var page by remember { mutableStateOf<Page>(Page.List) }
    fun discard(p: Page) {
        when (p) {
            is Page.Add -> p.draft?.wipe()
            is Page.Import -> p.draft.wipe()
            else -> {}
        }
    }
    fun go(next: Page) {
        val old = page
        page = next
        // Keep a draft that moves on to the next page; wipe the rest.
        val kept = (next as? Page.Add)?.draft ?: (next as? Page.Import)?.draft
        val oldDraft = (old as? Page.Add)?.draft ?: (old as? Page.Import)?.draft
        if (oldDraft != null && oldDraft !== kept) discard(old)
    }
    // Leaving composition (the vault locked) wipes any pending draft.
    DisposableEffect(Unit) { onDispose { discard(page) } }

    if (page != Page.List) BackHandler { go(Page.List) }
    val names = state.accounts.map { it.name }
    when (val p = page) {
        Page.List -> AccountsScreen(vault, state, now, onAdd = { go(Page.Add(null)) })
        is Page.Add -> AddScreen(
            vault = vault,
            draft = p.draft,
            existingNames = names,
            now = now,
            onScan = { go(Page.Scan) },
            onImport = { go(Page.Import(it)) },
            onDone = { go(Page.List) },
        )
        Page.Scan -> ScanScreen(
            onResult = { accounts ->
                val draft = Draft(accounts)
                go(if (accounts.size == 1) Page.Add(draft) else Page.Import(draft))
            },
            onCancel = { go(Page.Add(null)) },
        )
        is Page.Import -> ImportScreen(vault, p.draft, names, now, onDone = { go(Page.List) })
    }
}

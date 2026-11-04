package app.localotp.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.localotp.otp.Totp
import app.localotp.vault.AccountInfo
import app.localotp.vault.Authenticator
import app.localotp.vault.VaultController
import app.localotp.vault.VaultState
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AccountsScreen(vault: VaultController, auth: Authenticator, state: VaultState.Unlocked, now: Long, onAdd: () -> Unit) {
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val search = rememberUnsavedTextFieldState()
    var deleting by remember { mutableStateOf<AccountInfo?>(null) }
    var menu by remember { mutableStateOf(false) }
    var quickDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Local OTP", fontWeight = FontWeight.Bold)
                        Text(
                            "${state.level.label}로 보호됨",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                },
                actions = {
                    IconButton(onClick = { vault.lock(VaultController.LOCKED_MANUAL) }) {
                        Icon(Icons.Filled.Lock, contentDescription = "잠그기")
                    }
                    IconButton(onClick = { menu = true }) {
                        Icon(Icons.Filled.MoreVert, contentDescription = "설정")
                    }
                    DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                        DropdownMenuItem(
                            text = { Text(if (state.quickEnabled) "생체인증 잠금 해제 끄기" else "생체인증 잠금 해제 켜기") },
                            onClick = {
                                menu = false
                                quickDialog = true
                            },
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onAdd,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("계정 추가") },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (state.accounts.isEmpty()) {
                Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
                    Text(
                        "등록된 계정이 없습니다.\n‘계정 추가’로 QR 코드를 스캔하거나\n원본 시크릿키를 입력하세요.",
                        textAlign = TextAlign.Center,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                return@Column
            }
            if (state.accounts.size > 4) {
                OutlinedTextField(
                    state = search,
                    placeholder = { Text("계정 검색") },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    lineLimits = TextFieldLineLimits.SingleLine,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
            val query = search.text.toString().trim().lowercase()
            val shown = state.accounts.filter { query.isEmpty() || it.name.lowercase().contains(query) }
            if (shown.isEmpty()) {
                Text(
                    "검색 결과가 없습니다.",
                    modifier = Modifier.fillMaxWidth().padding(32.dp),
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            LazyColumn(
                contentPadding = PaddingValues(start = 16.dp, top = 8.dp, end = 16.dp, bottom = 104.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                items(shown, key = { it.index }) { account ->
                    AccountCard(
                        account = account,
                        code = vault.code(account.index, now),
                        remaining = Totp.remaining(now, account.period),
                        onCopy = {
                            if (vault.copy(account.index, System.currentTimeMillis() / 1000)) {
                                scope.launch {
                                    snackbar.currentSnackbarData?.dismiss()
                                    snackbar.showSnackbar("코드를 복사했습니다 · 30초 후 지워집니다")
                                }
                            }
                        },
                        onLongPress = { deleting = account },
                    )
                }
            }
        }
    }

    if (quickDialog) {
        QuickUnlockDialog(vault, auth, state.quickEnabled, onClose = { quickDialog = false }, onChanged = { message ->
            quickDialog = false
            scope.launch { snackbar.showSnackbar(message) }
        })
    }

    deleting?.let { account ->
        DeleteDialog(vault, account, onClose = { deleting = null }, onDeleted = {
            deleting = null
            scope.launch { snackbar.showSnackbar("계정을 삭제했습니다.") }
        })
    }
}

@Composable
private fun QuickUnlockDialog(
    vault: VaultController,
    auth: Authenticator,
    enabled: Boolean,
    onClose: () -> Unit,
    onChanged: (String) -> Unit,
) {
    val scope = rememberCoroutineScope()
    val pass = rememberUnsavedTextFieldState()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (busy) return
        if (enabled) {
            busy = true
            scope.launch {
                runVaultAction({ error = it }) { vault.disableQuick() }
                busy = false
                onChanged("생체인증 잠금 해제를 껐습니다.")
            }
            return
        }
        val p = pass.chars()
        if (p.isEmpty()) {
            error = "비밀번호를 입력하세요."
            return
        }
        busy = true
        scope.launch {
            var ok = false
            runVaultAction({ error = it }) {
                vault.enableQuick(p, auth)
                ok = true
            }
            p.fill('\u0000')
            busy = false
            if (ok) onChanged("생체인증 잠금 해제를 켰습니다.")
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text(if (enabled) "생체인증 잠금 해제 끄기" else "생체인증 잠금 해제 켜기") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (enabled) {
                    Text("다음부터는 비밀번호와 화면 잠금 인증으로 엽니다.")
                } else {
                    Text(
                        "비밀번호 없이 강한 생체인증만으로 보관함을 엽니다. 대부분 지문이며, 일부 기기에서는 보안 등급이 높은 얼굴 인식도 포함됩니다. 화면 잠금 PIN·패턴으로는 열 수 없습니다.\n" +
                            "• 생체 정보를 새로 등록하면 자동으로 꺼집니다.\n" +
                            "• 비밀번호를 잊지 않도록 14일마다 한 번은 비밀번호가 필요합니다(알림용이며 보안 한계는 아님).\n" +
                            "• 잠든 사이나 강요로 생체인증을 당할 수 있는 상황이 걱정되면 켜지 마세요.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedSecureTextField(
                        state = pass,
                        modifier = Modifier.secretField("보관함 비밀번호"),
                    label = { Text("보관함 비밀번호") },
                        enabled = !busy,
                        onKeyboardAction = { submit() },
                    )
                }
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = { submit() }, enabled = !busy) { Text(if (enabled) "끄기" else "켜기") }
        },
        dismissButton = {
            TextButton(onClick = onClose, enabled = !busy) { Text("취소") }
        },
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun AccountCard(
    account: AccountInfo,
    code: String?,
    remaining: Int,
    onCopy: () -> Unit,
    onLongPress: () -> Unit,
) {
    val haptics = LocalHapticFeedback.current
    val urgent = remaining <= 5
    val codeColor = if (urgent) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    ElevatedCard(
        Modifier
            .fillMaxWidth()
            .sensitive()
            .combinedClickable(
                onClickLabel = "코드 복사",
                onLongClickLabel = "삭제",
                onClick = onCopy,
                onLongClick = {
                    haptics.performHapticFeedback(HapticFeedbackType.LongPress)
                    onLongPress()
                },
            ),
    ) {
        Row(Modifier.padding(horizontal = 18.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    account.name,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    "${account.algorithm.label} · ${account.digits}자리 · ${account.period}초",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    code?.let { Totp.group(it) } ?: "------",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = if (account.digits == 8) 24.sp else 28.sp,
                    color = codeColor,
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    LinearProgressIndicator(
                        progress = { remaining / account.period.toFloat() },
                        modifier = Modifier.width(64.dp),
                        color = codeColor,
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "${remaining}초",
                        style = MaterialTheme.typography.labelMedium,
                        color = if (urgent) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun DeleteDialog(
    vault: VaultController,
    account: AccountInfo,
    onClose: () -> Unit,
    onDeleted: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val pass = rememberUnsavedTextFieldState()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (busy) return
        val p = pass.chars()
        if (p.isEmpty()) {
            error = "비밀번호를 입력하세요."
            return
        }
        busy = true
        scope.launch {
            var ok = false
            runVaultAction({ error = it }) {
                vault.delete(account.index, account.name, p)
                ok = true
            }
            p.fill('\u0000')
            busy = false
            if (ok) onDeleted()
        }
    }

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        title = { Text("계정 삭제") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    "‘${account.name}’ 계정을 영구 삭제합니다. 원본 시크릿키가 없으면 다시 등록할 수 없습니다.",
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.sensitive(),
                )
                OutlinedSecureTextField(
                    state = pass,
                    modifier = Modifier.secretField("보관함 비밀번호"),
                    label = { Text("보관함 비밀번호") },
                    enabled = !busy,
                    onKeyboardAction = { submit() },
                )
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
        },
        confirmButton = {
            TextButton(onClick = { submit() }, enabled = !busy) {
                Text("삭제", color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(onClick = onClose, enabled = !busy) { Text("취소") }
        },
    )
}

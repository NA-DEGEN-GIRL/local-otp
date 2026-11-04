package app.localotp.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldLineLimits
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.localotp.otp.Algorithm
import app.localotp.otp.Base32
import app.localotp.otp.Links
import app.localotp.otp.OtpException
import app.localotp.otp.ParsedAccount
import app.localotp.otp.SUPPORTED_DIGITS
import app.localotp.otp.SUPPORTED_PERIODS
import app.localotp.otp.Totp
import app.localotp.vault.VaultController
import kotlinx.coroutines.launch

private fun previewCode(secret: ByteArray, now: Long, algorithm: Algorithm, digits: Int, period: Int) =
    Totp.group(Totp.code(secret, now, period, digits, algorithm))

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddScreen(
    vault: VaultController,
    draft: Draft?,
    existingNames: List<String>,
    now: Long,
    onScan: () -> Unit,
    onImport: (Draft) -> Unit,
    onDone: () -> Unit,
) {
    val scope = rememberCoroutineScope()
    val first = draft?.accounts?.firstOrNull()
    val name = rememberTextFieldState(first?.name ?: "")
    val secretField = rememberTextFieldState()
    var algorithm by remember { mutableStateOf(first?.algorithm ?: Algorithm.SHA1) }
    var digits by remember { mutableStateOf(first?.digits ?: 6) }
    var period by remember { mutableStateOf(first?.period ?: 30) }
    // A secret from a QR code or pasted link; never shown, cleared on exit.
    var pasted by remember { mutableStateOf<ParsedAccount?>(null) }
    val linkSecret = pasted?.secret ?: first?.secret
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { pasted?.secret?.fill(0) } }

    // A pasted otpauth link fills the form; an export link opens the import list.
    LaunchedEffect(secretField) {
        snapshotFlow { secretField.text.toString() }.collect { text ->
            if (!Links.isLink(text)) return@collect
            try {
                val accounts = Links.parse(text)
                secretField.clearText()
                if (accounts.size > 1) {
                    onImport(Draft(accounts))
                } else {
                    val a = accounts[0]
                    pasted?.secret?.fill(0)
                    pasted = a
                    if (name.text.isBlank()) name.setTextAndPlaceCursorAtEnd(a.name)
                    algorithm = a.algorithm
                    digits = a.digits
                    period = a.period
                    error = null
                }
            } catch (e: OtpException) {
                error = e.message
            }
        }
    }

    val text = secretField.text
    val (code, secretError) = try {
        when {
            linkSecret != null -> previewCode(linkSecret, now, algorithm, digits, period) to null
            text.isBlank() || Links.isLink(text) -> null to null
            else -> {
                val bytes = Base32.decode(text)
                try {
                    previewCode(bytes, now, algorithm, digits, period) to null
                } finally {
                    bytes.fill(0)
                }
            }
        }
    } catch (e: OtpException) {
        null to e.message
    }
    val duplicate = existingNames.any { it.equals(name.text.toString().trim(), ignoreCase = true) }

    fun submit() {
        if (busy) return
        val n = name.text.toString().trim()
        if (n.isEmpty()) {
            error = "계정 이름을 입력하세요."
            return
        }
        val secret = try {
            linkSecret?.copyOf() ?: Base32.decode(secretField.text)
        } catch (e: OtpException) {
            error = e.message
            return
        }
        val account = ParsedAccount(n, secret, algorithm, digits, period)
        busy = true
        scope.launch {
            var ok = false
            runVaultAction({ error = it }) {
                vault.add(listOf(account))
                ok = true
            }
            account.secret.fill(0)
            busy = false
            if (ok) {
                secretField.clearText()
                onDone()
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("계정 추가") },
                navigationIcon = {
                    IconButton(onClick = onDone) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "뒤로") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            OutlinedButton(onClick = onScan, modifier = Modifier.fillMaxWidth().height(52.dp), enabled = !busy) {
                Text("QR 코드 스캔")
            }
            Text(
                "Google Authenticator 내보내기 QR(여러 계정)도 읽을 수 있습니다. 카메라 영상은 기기 안에서만 처리됩니다.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                state = name,
                label = { Text("계정 이름") },
                lineLimits = TextFieldLineLimits.SingleLine,
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                supportingText = if (duplicate) {
                    { Text("같은 이름의 계정이 이미 있습니다.") }
                } else {
                    null
                },
            )
            if (linkSecret != null) {
                Card(Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Text("QR·링크에서 읽은 비밀키 사용 중 (표시하지 않음)", Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                        if (pasted != null) {
                            TextButton(onClick = {
                                pasted?.secret?.fill(0)
                                pasted = null
                            }) { Text("지우기") }
                        }
                    }
                }
            } else {
                OutlinedSecureTextField(
                    state = secretField,
                    label = { Text("비밀키 (Base32 또는 otpauth:// 링크)") },
                    modifier = Modifier.fillMaxWidth(),
                    enabled = !busy,
                )
            }
            Choice("알고리즘", Algorithm.entries, algorithm, { it.label }) { algorithm = it }
            Choice("자릿수", SUPPORTED_DIGITS, digits, { "${it}자리" }) { digits = it }
            Choice("주기", SUPPORTED_PERIODS, period, { "${it}초" }) { period = it }
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    when {
                        secretError != null -> Text(secretError, color = MaterialTheme.colorScheme.error)
                        code == null -> Text(
                            "비밀키를 입력하면 현재 코드가 여기에 표시됩니다.",
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        else -> {
                            Text(
                                "현재 코드 · ${Totp.remaining(now, period)}초 남음",
                                style = MaterialTheme.typography.labelLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                            Text(
                                code,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.Bold,
                                fontSize = 34.sp,
                                color = MaterialTheme.colorScheme.primary,
                            )
                            Text(
                                "기존 인증 앱의 코드와 같은지 확인한 후 추가하세요.",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                }
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(onClick = { submit() }, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("추가")
            }
            Text(
                "저장한 비밀키는 이 앱에서 다시 보거나 내보낼 수 없습니다. 원본은 별도의 안전한 곳에 보관하세요.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun <T> Choice(label: String, options: List<T>, selected: T, text: (T) -> String, onSelect: (T) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge)
        SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
            options.forEachIndexed { i, option ->
                SegmentedButton(
                    selected = option == selected,
                    onClick = { onSelect(option) },
                    shape = SegmentedButtonDefaults.itemShape(index = i, count = options.size),
                ) { Text(text(option)) }
            }
        }
    }
}

/** Several accounts from one export QR: review the preview codes, then add. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportScreen(vault: VaultController, draft: Draft, existingNames: List<String>, now: Long, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    val selected = remember {
        mutableStateListOf<Boolean>().apply {
            draft.accounts.forEach { a -> add(existingNames.none { it.equals(a.name, ignoreCase = true) }) }
        }
    }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val count = selected.count { it }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("계정 ${draft.accounts.size}개 가져오기") },
                navigationIcon = {
                    IconButton(onClick = onDone) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "뒤로") }
                },
            )
        },
        bottomBar = {
            Column(Modifier.padding(16.dp)) {
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                Button(
                    onClick = {
                        busy = true
                        scope.launch {
                            var ok = false
                            runVaultAction({ error = it }) {
                                vault.add(draft.accounts.filterIndexed { i, _ -> selected[i] })
                                ok = true
                            }
                            busy = false
                            if (ok) onDone()
                        }
                    },
                    enabled = count > 0 && !busy,
                    modifier = Modifier.fillMaxWidth().height(52.dp),
                ) { Text("선택한 ${count}개 추가") }
            }
        },
    ) { padding ->
        LazyColumn(
            Modifier.padding(padding),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            item {
                Text(
                    "각 계정의 코드가 기존 인증 앱과 같은지 확인하세요. 이미 있는 이름은 기본으로 선택 해제됩니다.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            itemsIndexed(draft.accounts) { i, a ->
                Card(Modifier.fillMaxWidth()) {
                    Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Checkbox(checked = selected[i], onCheckedChange = { selected[i] = it }, enabled = !busy)
                        Column(Modifier.weight(1f)) {
                            Text(a.name, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(
                                "${a.algorithm.label} · ${a.digits}자리 · ${a.period}초",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Text(
                            previewCode(a.secret, now, a.algorithm, a.digits, a.period),
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 20.sp,
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }
        }
    }
}

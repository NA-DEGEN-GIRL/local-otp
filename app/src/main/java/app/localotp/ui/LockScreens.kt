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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.input.TextFieldState
import androidx.compose.foundation.text.input.clearText
import androidx.compose.foundation.text.input.rememberTextFieldState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedSecureTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.localotp.otp.OtpException
import app.localotp.vault.AuthCancelled
import app.localotp.vault.Authenticator
import app.localotp.vault.VaultController
import kotlinx.coroutines.launch

/** Copy a text field into a CharArray that the caller clears. */
internal fun TextFieldState.chars(): CharArray = text.let { t -> CharArray(t.length) { t[it] } }

internal suspend fun runVaultAction(setError: (String?) -> Unit, action: suspend () -> Unit) {
    setError(null)
    try {
        action()
    } catch (e: AuthCancelled) {
        // The user closed the prompt.
    } catch (e: OtpException) {
        setError(e.message)
    }
}

@Composable
fun SetupScreen(vault: VaultController, auth: Authenticator) {
    val scope = rememberCoroutineScope()
    val pass = rememberTextFieldState()
    val confirm = rememberTextFieldState()
    var understood by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (busy) return
        val p = pass.chars()
        val c = confirm.chars()
        when {
            p.size < VaultController.MIN_PASSWORD -> error = "비밀번호는 ${VaultController.MIN_PASSWORD}자 이상이어야 합니다."
            !p.contentEquals(c) -> error = "비밀번호 확인이 일치하지 않습니다."
            !understood -> error = "복구할 수 없다는 안내를 확인해 주세요."
            else -> {
                busy = true
                scope.launch {
                    runVaultAction({ error = it }) { vault.create(p, auth) }
                    p.fill('\u0000')
                    busy = false
                }
                c.fill('\u0000')
                return
            }
        }
        p.fill('\u0000')
        c.fill('\u0000')
    }

    Scaffold { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text("Local OTP", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text("새 보관함 만들기", style = MaterialTheme.typography.titleMedium)
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer)) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(
                        "이 보관함은 복원할 수 없도록 만들어집니다.",
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                    listOf(
                        "비밀키는 이 휴대폰의 보안 칩 키와 비밀번호로 암호화되며, 다시 보거나 내보낼 수 없습니다.",
                        "비밀번호 분실, 앱 삭제·데이터 초기화, 기기 초기화·교체, 화면 잠금 해제 시 복구할 수 없습니다.",
                        "각 서비스의 원본 시크릿키(또는 복구 코드)는 반드시 별도의 안전한 곳에 보관하세요.",
                    ).forEach {
                        Text("• $it", color = MaterialTheme.colorScheme.onErrorContainer, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            OutlinedSecureTextField(
                state = pass,
                label = { Text("새 비밀번호 (${VaultController.MIN_PASSWORD}자 이상)") },
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
            )
            OutlinedSecureTextField(
                state = confirm,
                label = { Text("비밀번호 확인") },
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                onKeyboardAction = { submit() },
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = understood, onCheckedChange = { understood = it }, enabled = !busy)
                Text(
                    "복구할 수 없으며 원본 시크릿키를 따로 보관해야 한다는 점을 이해했습니다.",
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(onClick = { submit() }, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("보관함 만들기")
            }
            Text(
                "만들 때와 열 때마다 지문·얼굴 또는 화면 잠금 인증을 요청합니다.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
fun UnlockScreen(vault: VaultController, auth: Authenticator, reason: String) {
    val scope = rememberCoroutineScope()
    val pass = rememberTextFieldState()
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        if (busy) return
        val p = pass.chars()
        if (p.isEmpty()) {
            error = "비밀번호를 입력하세요."
            return
        }
        pass.clearText()
        busy = true
        scope.launch {
            runVaultAction({ error = it }) { vault.unlock(p, auth) }
            p.fill('\u0000')
            busy = false
        }
    }

    Scaffold { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Spacer(Modifier.height(48.dp))
            Icon(Icons.Filled.Lock, contentDescription = null, modifier = Modifier.size(56.dp), tint = MaterialTheme.colorScheme.primary)
            Text("Local OTP", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text(reason, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
            OutlinedSecureTextField(
                state = pass,
                label = { Text("비밀번호") },
                modifier = Modifier.fillMaxWidth(),
                enabled = !busy,
                onKeyboardAction = { submit() },
            )
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(onClick = { submit() }, enabled = !busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
                if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp) else Text("잠금 해제")
            }
            Text(
                "비밀번호와 지문·얼굴 또는 화면 잠금이 모두 필요합니다.\n5분 동안 사용하지 않거나, 화면이 꺼지거나, 앱을 벗어나면 잠깁니다.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

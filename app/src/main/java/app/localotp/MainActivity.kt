package app.localotp

import android.app.Application
import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.Bundle
import android.os.CancellationSignal
import android.os.PowerManager
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.localotp.otp.OtpException
import app.localotp.ui.LocalOtpRoot
import app.localotp.ui.LocalOtpTheme
import app.localotp.vault.AuthCancelled
import app.localotp.vault.VaultController
import javax.crypto.Cipher
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

class LocalOtpApp : Application() {
    lateinit var vault: VaultController
        private set

    override fun onCreate() {
        super.onCreate()
        vault = VaultController(this)
        // Lock the moment the screen turns off.
        registerReceiver(
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    vault.lock(VaultController.LOCKED_SCREEN)
                }
            },
            IntentFilter(Intent.ACTION_SCREEN_OFF),
        )
    }
}

class MainActivity : ComponentActivity() {
    private val vault get() = (application as LocalOtpApp).vault

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, screen recording, casting or recents thumbnail.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        // Hide other apps' overlay windows over ours (tapjacking, fake prompts).
        window.setHideOverlayWindows(true)
        // Android 14+: services that are not declared assistive tools are
        // denied this window's content; sensitive Compose nodes are also
        // marked individually (see ui/Sensitive.kt).
        if (Build.VERSION.SDK_INT >= 34) {
            window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        }
        // Never offer to save the vault password or a TOTP secret to an
        // autofill service (often a cloud password manager).
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        enableEdgeToEdge()
        setContent {
            LocalOtpTheme {
                LocalOtpRoot(vault, ::authenticate)
            }
        }
    }

    override fun onStart() {
        super.onStart()
        vault.onForeground()
    }

    override fun onStop() {
        super.onStop()
        getSystemService(AutofillManager::class.java)?.cancel()
        // Screen off or keyguard shown: lock now, without relying on a timer
        // or a broadcast that a frozen process would receive late. Otherwise
        // (app switch, a prompt) the 30-second grace period applies.
        val power = getSystemService(PowerManager::class.java)
        val keyguard = getSystemService(KeyguardManager::class.java)
        if (!power.isInteractive || keyguard.isKeyguardLocked) {
            vault.lock(VaultController.LOCKED_SCREEN)
        } else {
            vault.onBackground()
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        vault.touch()
    }

    /**
     * Authorize one Keystore operation. Biometric-only prompts (quick unlock)
     * offer no screen-lock fallback; the user can fall back to the password.
     */
    private suspend fun authenticate(cipher: Cipher, title: String, biometricOnly: Boolean): Cipher =
        suspendCancellableCoroutine { cont ->
            val builder = BiometricPrompt.Builder(this)
                .setTitle(title)
                .setConfirmationRequired(false)
            if (biometricOnly) {
                builder.setSubtitle("등록된 생체 정보로 확인하세요")
                    .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                    .setNegativeButton("비밀번호 사용", mainExecutor) { _, _ ->
                        if (cont.isActive) cont.resumeWithException(AuthCancelled())
                    }
            } else {
                builder.setSubtitle("지문·얼굴 또는 화면 잠금으로 확인하세요")
                    .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            }
            val prompt = builder.build()
            val cancel = CancellationSignal()
            cont.invokeOnCancellation { cancel.cancel() }
            prompt.authenticate(
                BiometricPrompt.CryptoObject(cipher),
                cancel,
                mainExecutor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authorized = result.cryptoObject?.cipher
                        if (!cont.isActive) return
                        if (authorized == null) {
                            cont.resumeWithException(OtpException("인증 결과에 보안 키 작업이 없습니다."))
                        } else {
                            cont.resume(authorized)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!cont.isActive) return
                        // 13 = negative button ("비밀번호 사용"); timeout is also not an error.
                        val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                            errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED ||
                            errorCode == BiometricPrompt.BIOMETRIC_ERROR_TIMEOUT ||
                            errorCode == 13
                        cont.resumeWithException(
                            if (cancelled) AuthCancelled() else OtpException("인증 실패: $errString")
                        )
                    }
                },
            )
        }
}

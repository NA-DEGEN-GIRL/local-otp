package app.localotp.vault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.hardware.biometrics.BiometricManager
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import app.localotp.otp.Algorithm
import app.localotp.otp.OtpException
import app.localotp.otp.ParsedAccount
import app.localotp.otp.Totp
import java.io.File
import java.io.FileOutputStream
import java.security.GeneralSecurityException
import java.security.ProviderException
import javax.crypto.Cipher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Authorizes one Keystore operation through BiometricPrompt and returns the
 * cipher. `biometricOnly` allows strong biometrics only (no screen-lock PIN).
 */
typealias Authenticator = suspend (cipher: Cipher, title: String, biometricOnly: Boolean) -> Cipher

/** The user dismissed the prompt, or a lock interrupted the action; not an error. */
class AuthCancelled : Exception()

data class AccountInfo(
    val index: Int,
    val name: String,
    val algorithm: Algorithm,
    val digits: Int,
    val period: Int,
)

sealed interface VaultState {
    data object NoVault : VaultState

    /** `quick`: biometric unlock can be offered now; `quickNote` explains why not. */
    data class Locked(val reason: String, val quick: Boolean, val quickNote: String?) : VaultState

    data class Unlocked(
        val accounts: List<AccountInfo>,
        val level: HardwareKey.Level,
        val quickEnabled: Boolean,
    ) : VaultState
}

/**
 * Owns the open vault. All public methods run on the main thread; crypto runs
 * on background dispatchers. Every action re-checks [generation], which
 * increments on every lock, after each suspension: nothing is unlocked or saved
 * after a lock. Commit sections run non-cancellable so that the file on disk
 * and the in-memory state never disagree.
 */
class VaultController(context: Context) {
    private val app = context.applicationContext
    private val dir = app.noBackupFilesDir
    private val file = File(dir, "vault.bin")
    private val quickFile = File(dir, "quick.bin")
    private val prefs = app.getSharedPreferences("settings", Context.MODE_PRIVATE)
    private val clipboard = app.getSystemService(ClipboardManager::class.java)
    private val biometrics = app.getSystemService(BiometricManager::class.java)
    private val main = Handler(Looper.getMainLooper())
    private val mutex = Mutex()

    private class Session(
        val header: VaultHeader,
        val passwordKey: ByteArray,
        val key: ByteArray,
        var blob: ByteArray,
        val accounts: MutableList<Account>,
        val level: HardwareKey.Level,
    ) {
        fun wipe() {
            passwordKey.fill(0)
            key.fill(0)
            accounts.forEach { it.wipe() }
            accounts.clear()
        }
    }

    private var session: Session? = null
    private var generation = 0L
    private var foreground = true
    private var stoppedAt = 0L
    private var lastActivity = SystemClock.elapsedRealtime()
    private var clipboardPending = false
    private var copiedAt = 0L

    private val _state = MutableStateFlow<VaultState>(lockedState(LOCKED))
    val state: StateFlow<VaultState> = _state

    private fun lockedState(reason: String): VaultState {
        if (!file.exists()) return VaultState.NoVault
        val note = quickBlockedReason()
        return VaultState.Locked(reason, quick = quickFile.exists() && note == null, quickNote = if (quickFile.exists()) note else null)
    }

    // ---- Locking ---------------------------------------------------------------

    fun touch() {
        lastActivity = SystemClock.elapsedRealtime()
    }

    /** Called every second by the UI while unlocked. */
    fun checkIdle() {
        if (session != null && SystemClock.elapsedRealtime() - lastActivity >= IDLE_MS) lock(LOCKED_IDLE)
    }

    private val backgroundLock = Runnable { lock(LOCKED_BACKGROUND) }

    fun onBackground() {
        foreground = false
        stoppedAt = SystemClock.elapsedRealtime()
        main.removeCallbacks(backgroundLock)
        if (session != null) main.postDelayed(backgroundLock, BACKGROUND_MS)
    }

    /**
     * Called before the app is drawn again. The Handler timer pauses in deep
     * sleep and in a frozen process, so the elapsed real time decides: away
     * for 30 seconds or more locks before anything is shown. Returning does
     * not count as activity (another app could start us to extend the timer).
     */
    fun onForeground() {
        foreground = true
        main.removeCallbacks(backgroundLock)
        val now = SystemClock.elapsedRealtime()
        if (session != null && stoppedAt > 0 && now - stoppedAt >= BACKGROUND_MS) lock(LOCKED_BACKGROUND)
        if (clipboardPending && now - copiedAt >= CLIPBOARD_MS) clearClipboardIfOurs()
    }

    /** Wipe all key material and secrets immediately. */
    fun lock(reason: String) {
        android.util.Log.i(TAG, "lock: $reason (open=${session != null})")
        generation++
        main.removeCallbacks(backgroundLock)
        session?.wipe()
        session = null
        clearClipboardIfOurs()
        _state.value = lockedState(reason)
    }

    /** Abort silently if a lock happened while the action was suspended. */
    private fun checkNotLocked(gen: Long) {
        if (gen != generation) {
            android.util.Log.i(TAG, "action cancelled: locked meanwhile")
            throw AuthCancelled()
        }
    }

    /** Open the session, unless a lock happened meanwhile (then wipe the keys). */
    private fun startSession(gen: Long, s: Session) {
        if (gen != generation) {
            android.util.Log.i(TAG, "unlock discarded: locked meanwhile")
            s.wipe()
            throw AuthCancelled()
        }
        session = s
        touch()
        // Opened while the app was already in the background (e.g. behind the
        // device-credential screen): the background timer still applies.
        if (!foreground) main.postDelayed(backgroundLock, BACKGROUND_MS)
        publish()
    }

    // ---- Create / unlock -------------------------------------------------------

    suspend fun create(password: CharArray, auth: Authenticator) = mutex.withLock {
        if (file.exists() || session != null) throw OtpException("이미 보관함이 있습니다.")
        if (password.size < MIN_PASSWORD) throw OtpException("비밀번호는 ${MIN_PASSWORD}자 이상이어야 합니다.")
        val gen = generation
        removeQuick() // A leftover from an earlier vault can never apply to a new one.
        val keyId = VaultFile.randomBytes(16)
        val key = withContext(Dispatchers.IO) { HardwareKey.createVaultKey(keyId) }
        var written = false
        val s = VaultFile.randomBytes(32)
        var pk: ByteArray? = null
        var k: ByteArray? = null
        try {
            val level = HardwareKey.level(key) ?: throw OtpException("하드웨어 보안 키가 아닙니다.")
            val salt = VaultFile.randomBytes(32)
            val draft = VaultHeader(VaultFile.ITERATIONS, salt, keyId, ByteArray(12), ByteArray(48))
            val cipher = auth(HardwareKey.encryptCipher(key), "보관함 만들기", false)
            checkNotLocked(gen)
            val wrapped = keystoreOp { cipher.updateAAD(draft.wrapAad()); cipher.doFinal(s) }
            val iv = cipher.iv
            if (wrapped.size != 48 || iv == null || iv.size != 12) throw OtpException("보안 키 출력 형식이 올바르지 않습니다.")
            val header = VaultHeader(VaultFile.ITERATIONS, salt, keyId, iv, wrapped)
            pk = withContext(Dispatchers.Default) { VaultFile.derivePassword(password, salt, header.iterations) }
            k = VaultFile.combine(pk, s)
            val blob = withContext(Dispatchers.Default) { VaultFile.seal(header, k, EntryCodec.serialize(emptyList())) }
            checkNotLocked(gen)
            // From here the file exists: never cancel, never delete its key.
            withContext(NonCancellable + Dispatchers.IO) {
                writeVerified(file, blob, replace = false)
                written = true
            }
            markPasswordUsed()
            val session = Session(header, pk, k, blob, mutableListOf(), level)
            pk = null
            k = null
            if (gen == generation) startSession(gen, session) else session.wipe()
        } finally {
            s.fill(0)
            pk?.fill(0)
            k?.fill(0)
            // Never leave a key behind for a vault that was not written.
            if (!written && !file.exists()) runCatching { HardwareKey.delete(HardwareKey.vaultAlias(keyId)) }
        }
        if (_state.value is VaultState.NoVault) _state.value = lockedState(LOCKED)
    }

    suspend fun unlock(password: CharArray, auth: Authenticator) = mutex.withLock {
        if (session != null) return@withLock
        val gen = generation
        val blob = withContext(Dispatchers.IO) { readVault() }
        val header = VaultFile.readHeader(blob)
        val key = keystoreCall { HardwareKey.get(HardwareKey.vaultAlias(header.keyId)) } ?: throw OtpException(
            "이 보관함의 보안 키가 이 기기에 없습니다. 보관함은 영구히 열 수 없습니다."
        )
        val level = keystoreCall { HardwareKey.level(key) } ?: throw OtpException("하드웨어 보안 키가 아닙니다.")
        val cipher = try {
            auth(keystoreCall { HardwareKey.decryptCipher(key, header.wrapIv) }, "잠금 해제", false)
        } catch (e: KeyInvalidated) {
            throw OtpException("기기의 화면 잠금이 해제되었거나 보안 키가 무효화되어 이 보관함은 영구히 열 수 없습니다.")
        }
        checkNotLocked(gen)
        val s = keystoreOp { cipher.updateAAD(header.wrapAad()); cipher.doFinal(header.wrapped) }
        val pk = try {
            withContext(Dispatchers.Default) { VaultFile.derivePassword(password, header.salt, header.iterations) }
        } catch (e: Throwable) {
            s.fill(0)
            throw e
        }
        val k = VaultFile.combine(pk, s)
        s.fill(0)
        open(gen, blob, header, pk, k, level)
        markPasswordUsed()
    }

    /** Biometric-only unlock with the session keys sealed by the quick key. */
    suspend fun quickUnlock(auth: Authenticator) = mutex.withLock {
        if (session != null) return@withLock
        val gen = generation
        quickBlockedReason()?.let { throw OtpException(it) }
        val blob = withContext(Dispatchers.IO) { readVault() }
        val header = VaultFile.readHeader(blob)
        val vaultKey = keystoreCall { HardwareKey.get(HardwareKey.vaultAlias(header.keyId)) }
            ?: throw OtpException("이 보관함의 보안 키가 이 기기에 없습니다.")
        val level = keystoreCall { HardwareKey.level(vaultKey) } ?: throw OtpException("하드웨어 보안 키가 아닙니다.")
        val quick = withContext(Dispatchers.IO) { readQuick() } ?: throw OtpException("생체인증 잠금 해제가 꺼져 있습니다.")
        val quickKey = keystoreCall { HardwareKey.get(HardwareKey.quickAlias(quick.keyId)) }
        if (quickKey == null) {
            removeQuick()
            publishLocked()
            throw OtpException("생체인증 잠금 해제 키가 없어 꺼졌습니다. 비밀번호로 여세요.")
        }
        val cipher = try {
            auth(keystoreCall { HardwareKey.decryptCipher(quickKey, quick.iv) }, "생체인증으로 열기", true)
        } catch (e: KeyInvalidated) {
            removeQuick()
            publishLocked()
            throw OtpException("생체 정보가 바뀌어 생체인증 잠금 해제가 꺼졌습니다. 비밀번호로 여세요.")
        }
        checkNotLocked(gen)
        val plain = keystoreOp { cipher.updateAAD(QuickBlob.aad(quick.keyId, header)); cipher.doFinal(quick.ciphertext) }
        if (plain.size != QuickBlob.PLAINTEXT) {
            plain.fill(0)
            throw OtpException("생체인증 잠금 해제 정보가 손상되었습니다.")
        }
        val pk = plain.copyOfRange(0, 32)
        val k = plain.copyOfRange(32, 64)
        plain.fill(0)
        open(gen, blob, header, pk, k, level)
    }

    private suspend fun open(gen: Long, blob: ByteArray, header: VaultHeader, pk: ByteArray, k: ByteArray, level: HardwareKey.Level) {
        val accounts = try {
            withContext(Dispatchers.Default) {
                val plain = VaultFile.open(blob, k)
                try {
                    EntryCodec.deserialize(plain)
                } finally {
                    plain.fill(0)
                }
            }
        } catch (e: Exception) {
            pk.fill(0)
            k.fill(0)
            throw e
        }
        startSession(gen, Session(header, pk, k, blob, accounts.toMutableList(), level))
    }

    // ---- Biometric quick unlock ------------------------------------------------

    /** Strong (class 3) biometrics are enrolled and usable. */
    fun biometricsReady(): Boolean =
        biometrics.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    /** Turn on biometric unlock; re-confirms the password first. */
    suspend fun enableQuick(password: CharArray, auth: Authenticator) = mutex.withLock {
        val s = session ?: throw OtpException("보관함이 잠겨 있습니다.")
        val gen = generation
        if (!biometricsReady()) throw OtpException("지문 등 강한 생체인증을 먼저 등록하세요. (설정 → 보안 → 생체 인식)")
        checkPassword(s, gen, password)
        removeQuick()
        val keyId = VaultFile.randomBytes(16)
        val key = withContext(Dispatchers.IO) { HardwareKey.createQuickKey(keyId) }
        var written = false
        try {
            val cipher = auth(HardwareKey.encryptCipher(key), "생체인증 잠금 해제 켜기", true)
            if (gen != generation || session !== s) throw AuthCancelled()
            val plain = s.passwordKey + s.key
            val ct = try {
                keystoreOp { cipher.updateAAD(QuickBlob.aad(keyId, s.header)); cipher.doFinal(plain) }
            } finally {
                plain.fill(0)
            }
            val iv = cipher.iv
            if (iv == null || iv.size != 12 || ct.size != QuickBlob.SIZE - 36) {
                throw OtpException("보안 키 출력 형식이 올바르지 않습니다.")
            }
            withContext(NonCancellable + Dispatchers.IO) {
                writeVerified(quickFile, QuickBlob(keyId, iv, ct).encode(), replace = false)
                written = true
            }
            markPasswordUsed()
            publish()
        } finally {
            if (!written) {
                runCatching { HardwareKey.delete(HardwareKey.quickAlias(keyId)) }
                quickFile.delete()
            }
        }
    }

    suspend fun disableQuick() = mutex.withLock {
        removeQuick()
        if (session != null) publish() else publishLocked()
    }

    /** Why biometric unlock can't be used now, or null if it can. */
    private fun quickBlockedReason(): String? {
        if (!quickFile.exists()) return "생체인증 잠금 해제가 꺼져 있습니다."
        if (!biometricsReady()) return "생체인증을 사용할 수 없습니다. 비밀번호로 여세요."
        val last = prefs.getLong(PREF_PASSWORD_AT, 0L)
        val now = System.currentTimeMillis()
        // A reminder, not a security boundary: the clock and prefs are not
        // hardware-protected. Clock moved back also asks for the password.
        if (last <= 0L || now < last || now - last > PASSWORD_EVERY_MS) {
            return "비밀번호를 잊지 않도록 14일마다 한 번은 비밀번호로 열어야 합니다."
        }
        return null
    }

    private fun markPasswordUsed() {
        prefs.edit().putLong(PREF_PASSWORD_AT, System.currentTimeMillis()).apply()
    }

    private fun readQuick(): QuickBlob? = if (quickFile.exists()) QuickBlob.decode(quickFile.readBytes()) else null

    /** Delete every quick key and the quick file; never touches the vault or its key. */
    private fun removeQuick() {
        runCatching { HardwareKey.deleteAllQuick() }
        quickFile.delete()
    }

    // ---- Changes ---------------------------------------------------------------

    /** Add accounts; the caller still owns and clears the parsed secrets. */
    suspend fun add(items: List<ParsedAccount>) = mutex.withLock {
        val s = session ?: throw OtpException("보관함이 잠겨 있습니다.")
        val gen = generation
        val added = items.map { Account(it.name.trim(), it.secret.copyOf(), it.algorithm, it.digits, it.period) }
        var kept = false
        try {
            if (added.any { it.name.isEmpty() }) throw OtpException("계정 이름을 입력하세요.")
            kept = save(s, gen, s.accounts + added) { s.accounts.addAll(added) }
        } finally {
            if (!kept) added.forEach { it.wipe() }
        }
    }

    /** Delete one account after re-confirming the vault password. */
    suspend fun delete(index: Int, name: String, password: CharArray) = mutex.withLock {
        val s = session ?: throw OtpException("보관함이 잠겨 있습니다.")
        val gen = generation
        if (s.accounts.getOrNull(index)?.name != name) throw OtpException("선택한 계정이 바뀌었습니다. 다시 시도하세요.")
        checkPassword(s, gen, password)
        save(s, gen, s.accounts.filterIndexed { i, _ -> i != index }) { s.accounts.removeAt(index).wipe() }
    }

    private suspend fun checkPassword(s: Session, gen: Long, password: CharArray) {
        val typed = withContext(Dispatchers.Default) {
            VaultFile.derivePassword(password, s.header.salt, s.header.iterations)
        }
        val ok = VaultFile.sameKey(typed, s.passwordKey)
        typed.fill(0)
        if (gen != generation || session !== s) throw AuthCancelled()
        if (!ok) throw OtpException("비밀번호가 올바르지 않습니다.")
    }

    /**
     * Seal and write `next`; then apply `commit` to the session. Returns false
     * when the vault was locked meanwhile (the file may hold the change, but
     * the wiped session is left alone).
     */
    private suspend fun save(s: Session, gen: Long, next: List<Account>, commit: () -> Unit): Boolean {
        val blob = withContext(Dispatchers.Default) {
            val plain = EntryCodec.serialize(next)
            try {
                VaultFile.seal(s.header, s.key, plain)
            } finally {
                plain.fill(0)
            }
        }
        if (gen != generation || session !== s) throw OtpException("보관함이 잠겨 변경하지 않았습니다.")
        return withContext(NonCancellable) {
            withContext(Dispatchers.IO) {
                if (!readVault().contentEquals(s.blob)) {
                    throw OtpException("보관함 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.")
                }
                writeVerified(file, blob, replace = true)
            }
            if (gen != generation || session !== s) return@withContext false
            s.blob = blob
            commit()
            publish()
            true
        }
    }

    // ---- Codes and clipboard ---------------------------------------------------

    fun code(index: Int, now: Long): String? {
        val a = session?.accounts?.getOrNull(index) ?: return null
        return Totp.code(a.secret, now, a.period, a.digits, a.algorithm)
    }

    /** Copy the current code, marked sensitive, and clear it after 30 seconds. */
    fun copy(index: Int, now: Long): Boolean {
        val code = code(index, now) ?: return false
        val clip = ClipData.newPlainText(CLIP_LABEL, code)
        // Hides the value from the clipboard preview and keyboard suggestions.
        clip.description.extras = PersistableBundle().apply {
            putBoolean("android.content.extra.IS_SENSITIVE", true)
        }
        clipboard.setPrimaryClip(clip)
        clipboardPending = true
        copiedAt = SystemClock.elapsedRealtime()
        main.removeCallbacks(clearClip)
        main.postDelayed(clearClip, CLIPBOARD_MS)
        // Backup for a frozen or killed process: an alarm that wakes a
        // non-exported receiver, even if this process is gone.
        ClipboardClearReceiver.schedule(app, CLIPBOARD_MS)
        return true
    }

    /** A pasted otpauth link (with its secret) should not stay on the clipboard. */
    fun clearClipboardIfHolds(text: String) {
        val current = runCatching { clipboard.primaryClip?.getItemAt(0)?.text?.toString()?.trim() }.getOrNull()
        if (current != null && current == text.trim()) runCatching { clipboard.clearPrimaryClip() }
    }

    private val clearClip = Runnable { clearClipboardIfOurs() }

    private fun clearClipboardIfOurs() {
        main.removeCallbacks(clearClip)
        if (!clipboardPending) return
        clipboardPending = false
        ClipboardClearReceiver.cancel(app)
        clearClipboardLabelled(clipboard)
    }

    // ---- Helpers ---------------------------------------------------------------

    private fun publish() {
        val s = session ?: return
        _state.value = VaultState.Unlocked(
            s.accounts.mapIndexed { i, a -> AccountInfo(i, a.name, a.algorithm, a.digits, a.period) },
            s.level,
            quickFile.exists(),
        )
    }

    private fun publishLocked() {
        val reason = (_state.value as? VaultState.Locked)?.reason ?: LOCKED
        _state.value = lockedState(reason)
    }

    /** Keystore failures (GeneralSecurityException or ProviderException) as user errors. */
    private inline fun <T> keystoreCall(op: () -> T): T = try {
        op()
    } catch (e: OtpException) {
        throw e
    } catch (e: GeneralSecurityException) {
        throw OtpException("보안 키 작업에 실패했습니다. (${e.javaClass.simpleName})")
    } catch (e: ProviderException) {
        throw OtpException("보안 키 작업에 실패했습니다. (${e.javaClass.simpleName})")
    }

    private inline fun keystoreOp(op: () -> ByteArray): ByteArray = keystoreCall(op)

    private fun readVault(): ByteArray {
        if (!file.exists()) throw OtpException("보관함 파일이 없습니다.")
        if (file.length() > VaultFile.MAX_FILE) throw OtpException("보관함 파일이 너무 큽니다.")
        return file.readBytes()
    }

    /**
     * Write to a temporary file, fsync, rename over the target (atomic on the
     * same file system), then read the target back and compare. Any failure
     * throws, so a change is never reported as saved when it is not on disk.
     */
    private fun writeVerified(target: File, blob: ByteArray, replace: Boolean) {
        if (!replace && target.exists()) throw OtpException("기존 파일이 있어 새로 만들 수 없습니다.")
        val tmp = File(dir, target.name + ".tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(blob)
                out.fd.sync()
            }
            if (!tmp.renameTo(target)) throw OtpException("저장하지 못했습니다: 파일을 교체할 수 없습니다.")
            if (!target.readBytes().contentEquals(blob)) throw OtpException("저장 확인에 실패했습니다.")
        } catch (e: java.io.IOException) {
            throw OtpException("저장하지 못했습니다: ${e.message}")
        } finally {
            tmp.delete()
        }
    }

    companion object {
        private const val TAG = "LocalOtp"
        const val MIN_PASSWORD = 12
        const val LOCKED = "보관함이 잠겨 있습니다."
        const val LOCKED_MANUAL = "잠갔습니다."
        const val LOCKED_IDLE = "5분 동안 사용하지 않아 잠겼습니다."
        const val LOCKED_BACKGROUND = "앱을 벗어나 잠겼습니다."
        const val LOCKED_SCREEN = "화면이 꺼져 잠겼습니다."
        const val CLIP_LABEL = "Local OTP"

        /**
         * Clear the clipboard if it holds our code. In the background Android
         * hides the clipboard from apps (null); then clear anyway.
         */
        fun clearClipboardLabelled(clipboard: ClipboardManager) {
            val label = runCatching { clipboard.primaryClipDescription?.label }.getOrNull()
            if (label == null || label == CLIP_LABEL) runCatching { clipboard.clearPrimaryClip() }
        }
        private const val PREF_PASSWORD_AT = "passwordUnlockedAt"
        private const val IDLE_MS = 5 * 60 * 1000L
        private const val BACKGROUND_MS = 30 * 1000L
        private const val CLIPBOARD_MS = 30 * 1000L
        private const val PASSWORD_EVERY_MS = 14 * 24 * 60 * 60 * 1000L
    }
}

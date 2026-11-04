package app.localotp.vault

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.util.AtomicFile
import app.localotp.otp.Algorithm
import app.localotp.otp.OtpException
import app.localotp.otp.ParsedAccount
import app.localotp.otp.Totp
import java.io.File
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Authorizes one Keystore operation through BiometricPrompt and returns the cipher. */
typealias Authenticator = suspend (cipher: Cipher, title: String) -> Cipher

/** The user dismissed the biometric/screen-lock prompt; not an error. */
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
    data class Locked(val reason: String) : VaultState
    data class Unlocked(val accounts: List<AccountInfo>, val level: HardwareKey.Level) : VaultState
}

/**
 * Owns the open vault. All public methods run on the main thread; crypto runs
 * on background dispatchers with the result re-checked against [generation],
 * which increments on every lock, so nothing is saved after a lock.
 */
class VaultController(context: Context) {
    private val app = context.applicationContext
    private val file = File(app.noBackupFilesDir, "vault.bin")
    private val atomic = AtomicFile(file)
    private val clipboard = app.getSystemService(ClipboardManager::class.java)
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
    private var lastActivity = SystemClock.elapsedRealtime()
    private var clipboardPending = false

    private val _state = MutableStateFlow<VaultState>(lockedState(LOCKED))
    val state: StateFlow<VaultState> = _state

    private fun lockedState(reason: String) =
        if (vaultExists()) VaultState.Locked(reason) else VaultState.NoVault

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
        main.removeCallbacks(backgroundLock)
        if (session != null) main.postDelayed(backgroundLock, BACKGROUND_MS)
    }

    fun onForeground() {
        main.removeCallbacks(backgroundLock)
        touch()
    }

    /** Wipe all key material and secrets immediately. */
    fun lock(reason: String) {
        generation++
        main.removeCallbacks(backgroundLock)
        session?.wipe()
        session = null
        clearClipboardIfOurs()
        _state.value = lockedState(reason)
    }

    // ---- Create / unlock -------------------------------------------------------

    suspend fun create(password: CharArray, auth: Authenticator) = mutex.withLock {
        if (vaultExists() || session != null) throw OtpException("이미 보관함이 있습니다.")
        if (password.size < MIN_PASSWORD) throw OtpException("비밀번호는 ${MIN_PASSWORD}자 이상이어야 합니다.")
        val keyId = VaultFile.randomBytes(16)
        val key = withContext(Dispatchers.IO) { HardwareKey.create(keyId) }
        var written = false
        val s = VaultFile.randomBytes(32)
        var passwordKey: ByteArray? = null
        var combined: ByteArray? = null
        try {
            val level = HardwareKey.level(key) ?: throw OtpException("하드웨어 보안 키가 아닙니다.")
            val salt = VaultFile.randomBytes(32)
            val draft = VaultHeader(VaultFile.ITERATIONS, salt, keyId, ByteArray(12), ByteArray(48))
            val cipher = auth(HardwareKey.encryptCipher(key), "보관함 만들기")
            val wrapped = keystoreOp { cipher.updateAAD(draft.wrapAad()); cipher.doFinal(s) }
            val iv = cipher.iv
            if (wrapped.size != 48 || iv == null || iv.size != 12) throw OtpException("보안 키 출력 형식이 올바르지 않습니다.")
            val header = VaultHeader(VaultFile.ITERATIONS, salt, keyId, iv, wrapped)
            val pk = withContext(Dispatchers.Default) { VaultFile.derivePassword(password, salt, header.iterations) }
            passwordKey = pk
            val k = VaultFile.combine(pk, s)
            combined = k
            val blob = withContext(Dispatchers.Default) {
                VaultFile.seal(header, k, EntryCodec.serialize(emptyList()))
            }
            withContext(Dispatchers.IO) { writeNew(blob) }
            written = true
            session = Session(header, pk, k, blob, mutableListOf(), level)
            passwordKey = null
            combined = null
            touch()
            publish()
        } finally {
            s.fill(0)
            passwordKey?.fill(0)
            combined?.fill(0)
            // Never leave a key behind for a vault that was not written.
            if (!written) runCatching { HardwareKey.delete(keyId) }
        }
    }

    suspend fun unlock(password: CharArray, auth: Authenticator) = mutex.withLock {
        if (session != null) return@withLock
        val blob = withContext(Dispatchers.IO) { readVault() }
        val header = VaultFile.readHeader(blob)
        val key = HardwareKey.get(header.keyId) ?: throw OtpException(
            "이 보관함의 보안 키가 이 기기에 없습니다. 보관함은 영구히 열 수 없습니다."
        )
        val level = HardwareKey.level(key) ?: throw OtpException("하드웨어 보안 키가 아닙니다.")
        val cipher = auth(HardwareKey.decryptCipher(key, header.wrapIv), "잠금 해제")
        val s = keystoreOp { cipher.updateAAD(header.wrapAad()); cipher.doFinal(header.wrapped) }
        val pk = withContext(Dispatchers.Default) { VaultFile.derivePassword(password, header.salt, header.iterations) }
        val k = VaultFile.combine(pk, s)
        s.fill(0)
        try {
            val accounts = withContext(Dispatchers.Default) {
                val plain = VaultFile.open(blob, k)
                try {
                    EntryCodec.deserialize(plain)
                } finally {
                    plain.fill(0)
                }
            }
            session = Session(header, pk, k, blob, accounts.toMutableList(), level)
            touch()
            publish()
        } catch (e: Exception) {
            pk.fill(0)
            k.fill(0)
            throw e
        }
    }

    // ---- Changes ---------------------------------------------------------------

    /** Add accounts; the caller still owns and clears the parsed secrets. */
    suspend fun add(items: List<ParsedAccount>) = mutex.withLock {
        val s = session ?: throw OtpException("보관함이 잠겨 있습니다.")
        val gen = generation
        val added = items.map { Account(it.name.trim(), it.secret.copyOf(), it.algorithm, it.digits, it.period) }
        try {
            if (added.any { it.name.isEmpty() }) throw OtpException("계정 이름을 입력하세요.")
            save(s, gen, s.accounts + added)
            s.accounts.addAll(added)
            publish()
        } catch (e: Exception) {
            added.forEach { it.wipe() }
            throw e
        }
    }

    /** Delete one account after re-confirming the vault password. */
    suspend fun delete(index: Int, name: String, password: CharArray) = mutex.withLock {
        val s = session ?: throw OtpException("보관함이 잠겨 있습니다.")
        val gen = generation
        if (s.accounts.getOrNull(index)?.name != name) throw OtpException("선택한 계정이 바뀌었습니다. 다시 시도하세요.")
        val typed = withContext(Dispatchers.Default) {
            VaultFile.derivePassword(password, s.header.salt, s.header.iterations)
        }
        val ok = VaultFile.sameKey(typed, s.passwordKey)
        typed.fill(0)
        if (gen != generation) throw OtpException("보관함이 잠겼습니다.")
        if (!ok) throw OtpException("비밀번호가 올바르지 않습니다.")
        save(s, gen, s.accounts.filterIndexed { i, _ -> i != index })
        s.accounts.removeAt(index).wipe()
        publish()
    }

    private suspend fun save(s: Session, gen: Long, next: List<Account>) {
        val blob = withContext(Dispatchers.Default) {
            val plain = EntryCodec.serialize(next)
            try {
                VaultFile.seal(s.header, s.key, plain)
            } finally {
                plain.fill(0)
            }
        }
        if (gen != generation || session !== s) throw OtpException("보관함이 잠겨 변경하지 않았습니다.")
        withContext(Dispatchers.IO) { writeReplace(s.blob, blob) }
        s.blob = blob
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
        main.removeCallbacks(clearClip)
        main.postDelayed(clearClip, CLIPBOARD_MS)
        return true
    }

    private val clearClip = Runnable { clearClipboardIfOurs() }

    private fun clearClipboardIfOurs() {
        main.removeCallbacks(clearClip)
        if (!clipboardPending) return
        clipboardPending = false
        // In the background Android hides the clipboard from apps (null);
        // then clear anyway, since our code may still be there.
        val label = runCatching { clipboard.primaryClipDescription?.label }.getOrNull()
        if (label == null || label == CLIP_LABEL) runCatching { clipboard.clearPrimaryClip() }
    }

    // ---- Helpers ---------------------------------------------------------------

    private fun publish() {
        val s = session ?: return
        _state.value = VaultState.Unlocked(
            s.accounts.mapIndexed { i, a -> AccountInfo(i, a.name, a.algorithm, a.digits, a.period) },
            s.level,
        )
    }

    private inline fun keystoreOp(op: () -> ByteArray): ByteArray = try {
        op()
    } catch (e: GeneralSecurityException) {
        throw OtpException("보안 키 작업에 실패했습니다. (${e.javaClass.simpleName})")
    }

    /** AtomicFile may leave the previous version as "<name>.bak" after a crash. */
    private fun vaultExists() = file.exists() || File(file.path + ".bak").exists()

    private fun readVault(): ByteArray {
        if (!vaultExists()) throw OtpException("보관함 파일이 없습니다.")
        if (file.length() > VaultFile.MAX_FILE) throw OtpException("보관함 파일이 너무 큽니다.")
        return atomic.readFully()
    }

    private fun writeNew(blob: ByteArray) {
        if (vaultExists()) throw OtpException("기존 보관함이 있어 새로 만들 수 없습니다.")
        write(blob)
    }

    private fun writeReplace(expected: ByteArray, blob: ByteArray) {
        if (!readVault().contentEquals(expected)) {
            throw OtpException("보관함 파일이 다른 곳에서 변경되었습니다. 잠근 뒤 다시 여세요.")
        }
        write(blob)
    }

    private fun write(blob: ByteArray) {
        val out = atomic.startWrite()
        try {
            out.write(blob)
            atomic.finishWrite(out) // fsync, then atomic rename
        } catch (e: Exception) {
            atomic.failWrite(out)
            throw OtpException("보관함을 저장하지 못했습니다: ${e.message}")
        }
    }

    companion object {
        const val MIN_PASSWORD = 12
        const val LOCKED = "보관함이 잠겨 있습니다."
        const val LOCKED_IDLE = "5분 동안 사용하지 않아 잠겼습니다."
        const val LOCKED_BACKGROUND = "앱을 벗어나 잠겼습니다."
        const val LOCKED_SCREEN = "화면이 꺼져 잠겼습니다."
        private const val CLIP_LABEL = "Local OTP"
        private const val IDLE_MS = 5 * 60 * 1000L
        private const val BACKGROUND_MS = 30 * 1000L
        private const val CLIPBOARD_MS = 30 * 1000L
    }
}

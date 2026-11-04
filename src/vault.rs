//! Windows-only TPM-bound vault. No plaintext is written by this module.
//!
//! `open` never creates a key. A caller must NOT call `create` to initialize
//! an existing vault after a failed open: a missing TPM key is permanent loss.
//! This provides no isolation from malware running as this user or administrator.

use std::{ffi::c_void, ptr};

type Handle = *mut c_void;
type NtStatus = i32;
type SecurityStatus = i32;
const MAGIC: &[u8; 8] = b"OTPVT001";
#[cfg(not(test))]
const KEY_NAME: &str = "OtpMigration.WindowsOtp.VaultKey.v1";
#[cfg(test)]
fn test_key_name() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        let mut id = [0u8; 16];
        random(&mut id).expect("test key name RNG");
        let suffix = id.iter().map(|x| format!("{x:02x}")).collect::<String>();
        format!("OtpMigration.WindowsOtp.SyntheticTestKey.{suffix}")
    })
}
const HEADER: usize = 92;
const TAG_LEN: usize = 16;
const MAX_CIPHER: usize = 16 * 1024 * 1024;
const ITERATIONS: u64 = 600_000;
const NTE_BAD_KEYSET: u32 = 0x80090016;
const NTE_NOT_FOUND: u32 = 0x80090011;
const NTE_EXISTS: u32 = 0x8009000f;

#[repr(C)]
struct OaepInfo {
    hash: *const u16,
    label: *mut u8,
    label_len: u32,
}
#[repr(C)]
struct AuthInfo {
    size: u32,
    version: u32,
    nonce: *mut u8,
    nonce_len: u32,
    aad: *mut u8,
    aad_len: u32,
    tag: *mut u8,
    tag_len: u32,
    mac_context: *mut u8,
    mac_context_len: u32,
    aad_total: u32,
    data_total: u64,
    flags: u32,
}

#[link(name = "ncrypt")]
unsafe extern "system" {
    fn NCryptOpenStorageProvider(out: *mut Handle, name: *const u16, flags: u32) -> SecurityStatus;
    fn NCryptOpenKey(
        provider: Handle,
        out: *mut Handle,
        name: *const u16,
        legacy: u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptCreatePersistedKey(
        provider: Handle,
        out: *mut Handle,
        alg: *const u16,
        name: *const u16,
        legacy: u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptSetProperty(
        obj: Handle,
        name: *const u16,
        data: *const u8,
        len: u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptGetProperty(
        obj: Handle,
        name: *const u16,
        data: *mut u8,
        len: u32,
        result: *mut u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptFinalizeKey(key: Handle, flags: u32) -> SecurityStatus;
    fn NCryptEncrypt(
        key: Handle,
        input: *const u8,
        len: u32,
        padding: *mut c_void,
        out: *mut u8,
        out_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptDecrypt(
        key: Handle,
        input: *const u8,
        len: u32,
        padding: *mut c_void,
        out: *mut u8,
        out_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptExportKey(
        key: Handle,
        export_key: Handle,
        blob_type: *const u16,
        params: *mut c_void,
        output: *mut u8,
        output_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> SecurityStatus;
    fn NCryptFreeObject(obj: Handle) -> SecurityStatus;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptOpenAlgorithmProvider(
        out: *mut Handle,
        alg: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> NtStatus;
    fn BCryptCloseAlgorithmProvider(alg: Handle, flags: u32) -> NtStatus;
    fn BCryptSetProperty(
        obj: Handle,
        name: *const u16,
        data: *const u8,
        len: u32,
        flags: u32,
    ) -> NtStatus;
    fn BCryptGenRandom(alg: Handle, out: *mut u8, len: u32, flags: u32) -> NtStatus;
    fn BCryptDeriveKeyPBKDF2(
        alg: Handle,
        password: *const u8,
        password_len: u32,
        salt: *const u8,
        salt_len: u32,
        iterations: u64,
        out: *mut u8,
        out_len: u32,
        flags: u32,
    ) -> NtStatus;
    fn BCryptGenerateSymmetricKey(
        alg: Handle,
        out: *mut Handle,
        object: *mut u8,
        object_len: u32,
        secret: *const u8,
        secret_len: u32,
        flags: u32,
    ) -> NtStatus;
    fn BCryptDestroyKey(key: Handle) -> NtStatus;
    fn BCryptEncrypt(
        key: Handle,
        input: *const u8,
        len: u32,
        padding: *mut c_void,
        iv: *mut u8,
        iv_len: u32,
        out: *mut u8,
        out_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> NtStatus;
    fn BCryptDecrypt(
        key: Handle,
        input: *const u8,
        len: u32,
        padding: *mut c_void,
        iv: *mut u8,
        iv_len: u32,
        out: *mut u8,
        out_len: u32,
        result: *mut u32,
        flags: u32,
    ) -> NtStatus;
    fn BCryptHash(
        alg: Handle,
        secret: *const u8,
        secret_len: u32,
        input: *const u8,
        len: u32,
        out: *mut u8,
        out_len: u32,
    ) -> NtStatus;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn nt(s: i32, operation: &str) -> Result<(), String> {
    if s < 0 {
        Err(format!("{operation}: 0x{:08x}", s as u32))
    } else {
        Ok(())
    }
}
fn sec(s: i32, operation: &str) -> Result<(), String> {
    if s != 0 {
        Err(format!("{operation}: 0x{:08x}", s as u32))
    } else {
        Ok(())
    }
}
struct N(Handle);
impl Drop for N {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
struct Alg(Handle);
impl Drop for Alg {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptCloseAlgorithmProvider(self.0, 0);
            }
        }
    }
}
struct Sym(Handle);
impl Drop for Sym {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                BCryptDestroyKey(self.0);
            }
        }
    }
}
struct Secret<const N: usize>([u8; N]);
fn wipe(bytes: &mut [u8]) {
    for b in bytes {
        unsafe { ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}
impl<const N: usize> Drop for Secret<{ N }> {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn alg(name: &str, flags: u32) -> Result<Alg, String> {
    let mut h = ptr::null_mut();
    nt(
        unsafe { BCryptOpenAlgorithmProvider(&mut h, wide(name).as_ptr(), ptr::null(), flags) },
        "BCryptOpenAlgorithmProvider",
    )?;
    Ok(Alg(h))
}
fn random(out: &mut [u8]) -> Result<(), String> {
    nt(
        unsafe { BCryptGenRandom(ptr::null_mut(), out.as_mut_ptr(), out.len() as u32, 2) },
        "BCryptGenRandom",
    )
}
fn check_key(key: N) -> Result<N, String> {
    let mut policy = 0u32;
    let mut got = 0;
    sec(
        unsafe {
            NCryptGetProperty(
                key.0,
                wide("Export Policy").as_ptr(),
                (&mut policy as *mut u32).cast(),
                4,
                &mut got,
                0,
            )
        },
        "TPM export policy",
    )?;
    if got != 4 || policy != 0 {
        return Err("TPM key is exportable".into());
    }
    let mut bits = 0u32;
    got = 0;
    sec(
        unsafe {
            NCryptGetProperty(
                key.0,
                wide("Length").as_ptr(),
                (&mut bits as *mut u32).cast(),
                4,
                &mut got,
                0,
            )
        },
        "TPM key length",
    )?;
    if got != 4 || bits != 2048 {
        return Err("Unexpected TPM key length".into());
    }
    let mut usage = 0u32;
    got = 0;
    sec(
        unsafe {
            NCryptGetProperty(
                key.0,
                wide("Key Usage").as_ptr(),
                (&mut usage as *mut u32).cast(),
                4,
                &mut got,
                0,
            )
        },
        "TPM key usage",
    )?;
    if got != 4 || usage & 1 == 0 {
        return Err("TPM key cannot decrypt".into());
    }
    let mut name = [0u16; 32];
    got = 0;
    sec(
        unsafe {
            NCryptGetProperty(
                key.0,
                wide("Algorithm Name").as_ptr(),
                name.as_mut_ptr().cast(),
                (name.len() * 2) as u32,
                &mut got,
                0,
            )
        },
        "TPM key algorithm",
    )?;
    if got == 0 || got as usize > name.len() * 2 || got % 2 != 0 {
        return Err("Invalid TPM algorithm name".into());
    }
    let name_len = got as usize / 2;
    let end = name[..name_len]
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(name_len);
    if name[..end] != ['R' as u16, 'S' as u16, 'A' as u16] {
        return Err("TPM key is not RSA".into());
    }
    Ok(key)
}
fn tpm_key(create: bool) -> Result<N, String> {
    let mut p = ptr::null_mut();
    sec(
        unsafe {
            NCryptOpenStorageProvider(
                &mut p,
                wide("Microsoft Platform Crypto Provider").as_ptr(),
                0,
            )
        },
        "TPM provider",
    )?;
    let p = N(p);
    let mut implementation = 0u32;
    let mut got = 0;
    sec(
        unsafe {
            NCryptGetProperty(
                p.0,
                wide("Impl Type").as_ptr(),
                (&mut implementation as *mut u32).cast(),
                4,
                &mut got,
                0,
            )
        },
        "TPM provider type",
    )?;
    if got != 4 || implementation & 1 == 0 {
        return Err("TPM 하드웨어 암호화 공급자를 사용할 수 없습니다.".into());
    }
    let mut h = ptr::null_mut();
    #[cfg(not(test))]
    let name = wide(KEY_NAME);
    #[cfg(test)]
    let name = wide(test_key_name());
    let status = unsafe { NCryptOpenKey(p.0, &mut h, name.as_ptr(), 0, 0) };
    if status == 0 {
        return check_key(N(h));
    }
    if !create || !matches!(status as u32, NTE_BAD_KEYSET | NTE_NOT_FOUND) {
        return Err(format!(
            "이 Windows 사용자의 TPM 보관함 키를 열 수 없습니다 (0x{:08x}).",
            status as u32
        ));
    }
    let status =
        unsafe { NCryptCreatePersistedKey(p.0, &mut h, wide("RSA").as_ptr(), name.as_ptr(), 0, 0) };
    if status as u32 == NTE_EXISTS {
        sec(
            unsafe { NCryptOpenKey(p.0, &mut h, name.as_ptr(), 0, 0) },
            "TPM open key",
        )?;
        return check_key(N(h));
    }
    sec(status, "TPM create key")?;
    let key = N(h);
    for (name, value) in [
        ("Length", 2048u32),
        ("Export Policy", 0u32),
        ("Key Usage", 1u32),
    ] {
        sec(
            unsafe {
                NCryptSetProperty(
                    key.0,
                    wide(name).as_ptr(),
                    (&value as *const u32).cast(),
                    4,
                    0,
                )
            },
            "TPM key property",
        )?;
    }
    sec(unsafe { NCryptFinalizeKey(key.0, 0) }, "TPM finalize")?;
    check_key(key)
}
fn key_id(key: &N) -> Result<[u8; 32], String> {
    let mut len = 0;
    let typ = wide("RSAPUBLICBLOB");
    sec(
        unsafe {
            NCryptExportKey(
                key.0,
                ptr::null_mut(),
                typ.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                &mut len,
                0,
            )
        },
        "TPM public key length",
    )?;
    if len == 0 || len > 16384 {
        return Err("Invalid TPM public key length".into());
    }
    let mut data = vec![0u8; len as usize];
    sec(
        unsafe {
            NCryptExportKey(
                key.0,
                ptr::null_mut(),
                typ.as_ptr(),
                ptr::null_mut(),
                data.as_mut_ptr(),
                len,
                &mut len,
                0,
            )
        },
        "TPM public key",
    )?;
    data.truncate(len as usize);
    let alg = alg("SHA256", 0)?;
    let mut out = [0u8; 32];
    nt(
        unsafe {
            BCryptHash(
                alg.0,
                ptr::null(),
                0,
                data.as_ptr(),
                data.len() as u32,
                out.as_mut_ptr(),
                32,
            )
        },
        "SHA256",
    )?;
    Ok(out)
}
fn rsa(key: &N, input: &[u8], encrypt: bool) -> Result<Vec<u8>, String> {
    let hash = wide("SHA256");
    let mut padding = OaepInfo {
        hash: hash.as_ptr(),
        label: ptr::null_mut(),
        label_len: 0,
    };
    let p = (&mut padding as *mut OaepInfo).cast();
    let mut len = 0;
    let f = if encrypt {
        NCryptEncrypt
    } else {
        NCryptDecrypt
    };
    sec(
        unsafe {
            f(
                key.0,
                input.as_ptr(),
                input.len() as u32,
                p,
                ptr::null_mut(),
                0,
                &mut len,
                4,
            )
        },
        "TPM OAEP size",
    )?;
    if len == 0 || len > 16384 {
        return Err("Invalid TPM ciphertext length".into());
    }
    let mut out = vec![0u8; len as usize];
    let status = unsafe {
        f(
            key.0,
            input.as_ptr(),
            input.len() as u32,
            p,
            out.as_mut_ptr(),
            len,
            &mut len,
            4,
        )
    };
    if status != 0 {
        wipe(&mut out);
        return Err(format!("TPM OAEP operation: 0x{:08x}", status as u32));
    }
    out.truncate(len as usize);
    Ok(out)
}
fn password_key(password: &str, salt: &[u8]) -> Result<Secret<32>, String> {
    if password.is_empty() || password.len() > 4096 {
        return Err("비밀번호는 1~4096바이트여야 합니다.".into());
    }
    let a = alg("SHA256", 8)?;
    let mut key = Secret([0; 32]);
    nt(
        unsafe {
            BCryptDeriveKeyPBKDF2(
                a.0,
                password.as_ptr(),
                password.len() as u32,
                salt.as_ptr(),
                salt.len() as u32,
                ITERATIONS,
                key.0.as_mut_ptr(),
                32,
                0,
            )
        },
        "PBKDF2",
    )?;
    Ok(key)
}
fn aes(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    tag: &mut [u8; 16],
    encrypt: bool,
) -> Result<Vec<u8>, String> {
    let a = alg("AES", 0)?;
    let mode = wide("ChainingModeGCM");
    nt(
        unsafe {
            BCryptSetProperty(
                a.0,
                wide("ChainingMode").as_ptr(),
                mode.as_ptr().cast(),
                (mode.len() * 2) as u32,
                0,
            )
        },
        "AES GCM mode",
    )?;
    let mut h = ptr::null_mut();
    nt(
        unsafe { BCryptGenerateSymmetricKey(a.0, &mut h, ptr::null_mut(), 0, key.as_ptr(), 32, 0) },
        "AES key",
    )?;
    let h = Sym(h);
    let mut info = AuthInfo {
        size: std::mem::size_of::<AuthInfo>() as u32,
        version: 1,
        nonce: nonce.as_ptr() as *mut u8,
        nonce_len: nonce.len() as u32,
        aad: aad.as_ptr() as *mut u8,
        aad_len: aad.len() as u32,
        tag: tag.as_mut_ptr(),
        tag_len: 16,
        mac_context: ptr::null_mut(),
        mac_context_len: 0,
        aad_total: 0,
        data_total: 0,
        flags: 0,
    };
    let mut out = vec![0u8; input.len().max(1)];
    let mut len = 0;
    let f = if encrypt {
        BCryptEncrypt
    } else {
        BCryptDecrypt
    };
    let status = unsafe {
        f(
            h.0,
            input.as_ptr(),
            input.len() as u32,
            (&mut info as *mut AuthInfo).cast(),
            ptr::null_mut(),
            0,
            out.as_mut_ptr(),
            out.len() as u32,
            &mut len,
            0,
        )
    };
    if status < 0 {
        wipe(&mut out);
        return Err("Authentication failed or AES-GCM unavailable".into());
    }
    if len as usize != input.len() {
        wipe(&mut out);
        return Err("Unexpected AES output length".into());
    }
    out.truncate(len as usize);
    Ok(out)
}

/// The password-derived half of the vault key. It is kept only while the vault
/// is open, so that adding an account does not require retyping the password,
/// and it is wiped on drop. It never leaves this process and cannot decrypt a
/// vault without the non-exportable TPM key.
pub struct VaultKey {
    password: Secret<32>,
    salt: [u8; 32],
}
impl VaultKey {
    fn derive(password: &str, salt: [u8; 32]) -> Result<Self, String> {
        Ok(VaultKey {
            password: password_key(password, &salt)?,
            salt,
        })
    }
    /// Re-derive from a typed password and compare in constant time. Used to
    /// confirm destructive changes such as deleting an account.
    pub fn matches_password(&self, password: &str) -> Result<bool, String> {
        let other = password_key(password, &self.salt)?;
        let mut diff = 0u8;
        for (a, b) in other.0.iter().zip(self.password.0.iter()) {
            diff |= a ^ b;
        }
        Ok(std::hint::black_box(diff) == 0)
    }
}

fn check_password(password: &str) -> Result<(), String> {
    if password.is_empty() || password.len() > 4096 {
        return Err("비밀번호는 1~4096바이트여야 합니다.".into());
    }
    Ok(())
}

fn check_plaintext(plaintext: &[u8]) -> Result<(), String> {
    if plaintext.len() > MAX_CIPHER {
        return Err("보관함이 너무 큽니다.".into());
    }
    Ok(())
}

fn check_owner(tpm: &N, blob: &[u8]) -> Result<(), String> {
    if key_id(tpm)? != blob[52..84] {
        return Err(
            "이 보관함은 다른 TPM 키(다른 PC 또는 Windows 사용자)로 만들어졌습니다.".into(),
        );
    }
    Ok(())
}

/// Create a new vault with a fresh salt and a new TPM key if none exists.
pub fn create(password: &str, plaintext: &[u8]) -> Result<(Vec<u8>, VaultKey), String> {
    check_password(password)?;
    check_plaintext(plaintext)?;
    let tpm = tpm_key(true)?;
    let mut salt = [0u8; 32];
    random(&mut salt)?;
    let key = VaultKey::derive(password, salt)?;
    let blob = seal(&tpm, &key, plaintext)?;
    Ok((blob, key))
}

/// Open an existing vault. Never creates a TPM key.
pub fn open(password: &str, blob: &[u8]) -> Result<(Vec<u8>, VaultKey), String> {
    validate_blob(blob)?;
    check_password(password)?;
    let tpm = tpm_key(false)?;
    check_owner(&tpm, blob)?;
    let key = VaultKey::derive(password, blob[8..40].try_into().unwrap())?;
    let plaintext = unseal(&tpm, &key, blob)?;
    Ok((plaintext, key))
}

/// Re-encrypt an existing vault only with the TPM key and password that opened
/// it. The existing blob is decrypted first so that a corrupted, replaced or
/// differently protected vault is never silently overwritten. Each write uses
/// a fresh random TPM-wrapped secret and nonce; the salt is kept.
pub fn reencrypt(key: &VaultKey, plaintext: &[u8], existing: &[u8]) -> Result<Vec<u8>, String> {
    check_plaintext(plaintext)?;
    validate_blob(existing)?;
    if existing[8..40] != key.salt {
        return Err("보관함이 다른 비밀번호로 다시 저장되었습니다. 잠근 뒤 다시 여세요.".into());
    }
    let tpm = tpm_key(false)?;
    check_owner(&tpm, existing)?;
    let mut verified = unseal(&tpm, key, existing)?;
    wipe(&mut verified);
    seal(&tpm, key, plaintext)
}

fn seal(tpm: &N, key: &VaultKey, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let id = key_id(tpm)?;
    let mut nonce = [0u8; 12];
    random(&mut nonce)?;
    let mut secret = Secret([0u8; 32]);
    random(&mut secret.0)?;
    let wrapped = rsa(tpm, &secret.0, true)?;
    let mut derived = Secret(key.password.0);
    for i in 0..32 {
        derived.0[i] ^= secret.0[i];
    }
    let mut out = Vec::with_capacity(HEADER + wrapped.len() + plaintext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&key.salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&id);
    out.extend_from_slice(&(wrapped.len() as u32).to_le_bytes());
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes());
    out.extend_from_slice(&wrapped);
    let mut tag = [0u8; 16];
    let ciphertext = aes(&derived.0, &nonce, &out, plaintext, &mut tag, true)?;
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&tag);
    Ok(out)
}

/// Fail closed if the TPM key, password, or authenticated data does not match.
fn unseal(tpm: &N, key: &VaultKey, blob: &[u8]) -> Result<Vec<u8>, String> {
    let (wrapped_len, end) = validate_blob(blob)?;
    let mut raw = rsa(tpm, &blob[HEADER..HEADER + wrapped_len], false)?;
    if raw.len() != 32 {
        wipe(&mut raw);
        return Err("보관함의 TPM 보호 키가 올바르지 않습니다.".into());
    }
    let mut derived = Secret(key.password.0);
    for (d, r) in derived.0.iter_mut().zip(raw.iter()) {
        *d ^= r;
    }
    wipe(&mut raw);
    let data_start = HEADER + wrapped_len;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&blob[end - 16..]);
    aes(
        &derived.0,
        &blob[40..52],
        &blob[..data_start],
        &blob[data_start..end - 16],
        &mut tag,
        false,
    )
    .map_err(|_| "비밀번호가 올바르지 않거나 보관함 파일이 손상되었습니다.".into())
}

fn validate_blob(blob: &[u8]) -> Result<(usize, usize), String> {
    if blob.len() < HEADER + TAG_LEN || &blob[..8] != MAGIC {
        return Err("보관함 파일 형식이 올바르지 않습니다.".into());
    }
    let wrapped_len = u32::from_le_bytes(blob[84..88].try_into().unwrap()) as usize;
    let data_len = u32::from_le_bytes(blob[88..92].try_into().unwrap()) as usize;
    // The only supported format uses RSA-2048, so OAEP ciphertext is 256 bytes.
    if wrapped_len != 256 || data_len > MAX_CIPHER {
        return Err("보관함 파일 길이가 올바르지 않습니다.".into());
    }
    let end = HEADER
        .checked_add(wrapped_len)
        .and_then(|n| n.checked_add(data_len))
        .and_then(|n| n.checked_add(TAG_LEN))
        .ok_or("보관함 파일 길이가 올바르지 않습니다.")?;
    if blob.len() != end {
        return Err("보관함 파일 길이가 올바르지 않습니다.".into());
    }
    Ok((wrapped_len, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Opt-in only: this test creates (or reuses) a persistent key named
    // OtpMigration.WindowsOtp.SyntheticTestKey.<random> under the current Windows
    // account and does not delete it. Ordinary cargo test must never create,
    // alter, or delete TPM keys. Never remove an existing key unless its
    // ownership has been established.
    #[test]
    #[ignore = "creates a randomly named persistent synthetic TPM test key"]
    fn synthetic_roundtrip_and_tamper() {
        let message = b"synthetic vault test, no real secrets";
        let (blob, key) = create("synthetic-password", message).expect("TPM encrypt");
        let (plain, opened) = open("synthetic-password", &blob).unwrap();
        assert_eq!(plain, message);
        assert!(opened.matches_password("synthetic-password").unwrap());
        assert!(!opened.matches_password("wrong-password").unwrap());
        assert!(open("wrong-password", &blob).is_err());
        let updated = reencrypt(&key, b"updated", &blob).unwrap();
        assert_eq!(updated[8..40], blob[8..40]);
        assert_ne!(updated[40..52], blob[40..52]);
        assert_eq!(open("synthetic-password", &updated).unwrap().0, b"updated");
        let (_, wrong) = create("wrong-password", b"other").unwrap();
        assert!(reencrypt(&wrong, b"updated", &blob).is_err());
        let mut corrupted = blob.clone();
        let end = corrupted.len();
        corrupted[end - 17] ^= 1;
        assert!(open("synthetic-password", &corrupted).is_err());
        assert!(reencrypt(&key, b"updated", &corrupted).is_err());
        let mut corrupted = blob.clone();
        corrupted[8] ^= 1;
        assert!(open("synthetic-password", &corrupted).is_err());
        assert!(reencrypt(&key, b"updated", &corrupted).is_err());
        let mut wrong_key = blob.clone();
        wrong_key[52] ^= 1;
        assert!(reencrypt(&key, b"updated", &wrong_key).is_err());
    }

    #[test]
    fn reject_malformed_header_without_accessing_tpm() {
        assert!(open("test-password", b"not a vault").is_err());
        let mut header = vec![0u8; HEADER + TAG_LEN];
        header[..8].copy_from_slice(MAGIC);
        assert!(open("test-password", &header).is_err());
        header[84..88].copy_from_slice(&256u32.to_le_bytes());
        assert!(open("test-password", &header).is_err());
        let key = VaultKey {
            password: Secret([0; 32]),
            salt: [0; 32],
        };
        assert!(reencrypt(&key, b"data", &header).is_err());
    }

    #[test]
    fn password_comparison_without_accessing_tpm() {
        let key = VaultKey::derive("synthetic password", [7; 32]).unwrap();
        assert!(key.matches_password("synthetic password").unwrap());
        assert!(!key.matches_password("synthetic passwore").unwrap());
        assert!(key.matches_password("").is_err());
    }

    #[test]
    fn aes_256_gcm_known_answer_and_tamper() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let expected = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let mut tag = [0u8; 16];
        let ciphertext = aes(&key, &nonce, &[], &plaintext, &mut tag, true).unwrap();
        assert_eq!(ciphertext, expected);
        assert_eq!(
            tag,
            [
                0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
                0xb9, 0x19
            ]
        );
        assert_eq!(
            aes(&key, &nonce, &[], &ciphertext, &mut tag, false).unwrap(),
            plaintext
        );
        tag[0] ^= 1;
        assert!(aes(&key, &nonce, &[], &ciphertext, &mut tag, false).is_err());
    }
}

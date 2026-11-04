//! TOTP and strict Base32 decoding. Cryptographic operations use Windows CNG.

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{compiler_fence, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

const MAX_SECRET_BYTES: usize = 4096;

/// Accepts RFC 4648 Base32 in upper/lower case, optionally without padding.
/// Spaces and hyphens are accepted for manually entered, grouped keys.
pub fn decode_base32(input: &str) -> Result<Vec<u8>, String> {
    // A limit prevents accidentally pasting extremely large inputs into a secret field.
    if input.len() > 8192 {
        return Err("비밀키가 너무 깁니다.".into());
    }
    let mut values = SensitiveVec(Vec::with_capacity(input.len()));
    let mut padding = 0usize;
    let mut seen_padding = false;
    for c in input.bytes() {
        if c.is_ascii_whitespace() || c == b'-' {
            continue;
        }
        if c == b'=' {
            seen_padding = true;
            padding += 1;
            continue;
        }
        if seen_padding {
            return Err("Base32 패딩(=)은 끝에만 올 수 있습니다.".into());
        }
        let value = match c.to_ascii_uppercase() {
            b'A'..=b'Z' => c.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            b'0' | b'1' | b'8' | b'9' => {
                return Err(
                    "숫자 0, 1, 8, 9는 Base32에 없습니다. O, I, B 등을 잘못 읽었는지 확인하세요."
                        .into(),
                )
            }
            _ => return Err("Base32에 사용할 수 없는 문자가 있습니다. (A–Z, 2–7만 가능)".into()),
        };
        values.0.push(value);
        if values.0.len() > (MAX_SECRET_BYTES * 8).div_ceil(5) {
            return Err("비밀키가 너무 깁니다.".into());
        }
    }
    if values.0.is_empty() {
        return Err("비밀키가 비어 있습니다.".into());
    }
    let remainder = values.0.len() % 8;
    let expected_padding = match remainder {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => {
            return Err(
                "비밀키 길이가 올바르지 않습니다. 빠지거나 더 들어간 글자를 확인하세요.".into(),
            )
        }
    };
    if padding != 0 && padding != expected_padding {
        return Err("Base32 패딩(=) 개수가 올바르지 않습니다.".into());
    }
    let mut out = Vec::with_capacity(values.0.len() * 5 / 8);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for value in values.0.iter().copied() {
        accumulator = (accumulator << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    // Unused trailing bits are ignored, as other authenticator apps do. Secrets
    // generated as random Base32 characters (for example 26 or 52 characters)
    // often have nonzero trailing bits and must still produce the same codes.
    Ok(out)
}

/// Parameters from an `otpauth://totp/...` link. The secret is cleared on drop.
pub struct OtpAuth {
    pub name: String,
    pub secret: Vec<u8>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}
impl Drop for OtpAuth {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

fn percent_decode(input: &str, plus_is_space: bool) -> Result<SensitiveVec, String> {
    let bytes = input.as_bytes();
    let mut out = SensitiveVec(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let value = bytes
                    .get(i + 1..i + 3)
                    .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                    .and_then(|h| std::str::from_utf8(h).ok())
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                    .ok_or("otpauth 링크의 % 인코딩이 올바르지 않습니다.")?;
                out.0.push(value);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.0.push(b' ');
                i += 1;
            }
            b => {
                out.0.push(b);
                i += 1;
            }
        }
    }
    Ok(out)
}

fn percent_decode_text(input: &str, plus_is_space: bool) -> Result<String, String> {
    let raw = percent_decode(input, plus_is_space)?;
    std::str::from_utf8(&raw.0)
        .map(str::to_string)
        .map_err(|_| "otpauth 링크의 문자 인코딩이 올바르지 않습니다.".into())
}

/// Parse a Key URI (`otpauth://totp/Issuer:account?secret=...`). Only TOTP is
/// accepted. Missing parameters take the standard defaults (SHA-1, 6, 30).
pub fn parse_otpauth(uri: &str) -> Result<OtpAuth, String> {
    const SCHEME: &str = "otpauth://";
    let uri = uri.trim();
    if uri.len() > 16384 {
        return Err("otpauth 링크가 너무 깁니다.".into());
    }
    if !uri
        .get(..SCHEME.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(SCHEME))
    {
        return Err("otpauth:// 링크가 아닙니다.".into());
    }
    let (kind, rest) = uri[SCHEME.len()..]
        .split_once('/')
        .ok_or("otpauth 링크 형식이 올바르지 않습니다.")?;
    if kind.eq_ignore_ascii_case("hotp") {
        return Err("HOTP(카운터 방식) 링크는 지원하지 않습니다.".into());
    }
    if !kind.eq_ignore_ascii_case("totp") {
        return Err("TOTP 링크가 아닙니다.".into());
    }
    let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
    let label = percent_decode_text(label, false)?;
    let mut secret: Option<SensitiveVec> = None;
    let mut issuer = String::new();
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u64;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key.to_ascii_lowercase().as_str() {
            "secret" => {
                let raw = percent_decode(value, true)?;
                let text = std::str::from_utf8(&raw.0)
                    .map_err(|_| "Base32에 사용할 수 없는 문자가 있습니다.".to_string())?;
                secret = Some(SensitiveVec(decode_base32(text)?));
            }
            "issuer" => issuer = percent_decode_text(value, true)?,
            "algorithm" => {
                algorithm = match value.to_ascii_uppercase().replace('-', "").as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return Err(format!("지원하지 않는 알고리즘입니다: {value}")),
                }
            }
            "digits" => {
                digits = value
                    .parse()
                    .map_err(|_| format!("자릿수 값이 올바르지 않습니다: {value}"))?
            }
            "period" => {
                period = value
                    .parse()
                    .map_err(|_| format!("주기 값이 올바르지 않습니다: {value}"))?
            }
            // A non-standard encoder (e.g. Steam Guard) would never match our
            // numeric codes; refuse instead of silently producing wrong codes.
            "encoder" => return Err(format!("지원하지 않는 코드 형식입니다: {value}")),
            _ => {}
        }
    }
    let mut secret = secret.ok_or("링크에 secret 값이 없습니다.")?;
    let label = label.trim();
    let issuer = issuer.trim();
    let name = if label.is_empty() {
        issuer.to_string()
    } else if let Some((prefix, account)) = label.split_once(':') {
        format!("{}:{}", prefix.trim(), account.trim())
    } else if !issuer.is_empty() && label != issuer {
        format!("{issuer}:{label}")
    } else {
        label.to_string()
    };
    Ok(OtpAuth {
        name,
        secret: std::mem::take(&mut secret.0),
        algorithm,
        digits,
        period,
    })
}

/// RFC 6238. The caller owns the secret and is responsible for clearing it.
pub fn totp(
    secret: &[u8],
    time: u64,
    period: u64,
    digits: u32,
    algorithm: Algorithm,
) -> Result<String, String> {
    if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
        return Err("Secret length is invalid".into());
    }
    if period == 0 || !(6..=8).contains(&digits) {
        return Err("TOTP period or digit count is invalid".into());
    }
    let counter = (time / period).to_be_bytes();
    // Keep the digest in a zeroizing owner even if a later operation fails.
    let digest = hmac(secret, &counter, algorithm)?;
    let offset = usize::from(
        digest
            .0
            .last()
            .ok_or("Windows CNG returned an empty digest")?
            & 0x0f,
    );
    let bytes = digest
        .0
        .get(offset..offset + 4)
        .ok_or("Windows CNG returned an invalid digest")?;
    let binary = (u32::from(bytes[0] & 0x7f) << 24)
        | (u32::from(bytes[1]) << 16)
        | (u32::from(bytes[2]) << 8)
        | u32::from(bytes[3]);
    let code = binary % 10u32.pow(digits);
    Ok(format!("{code:0width$}", width = digits as usize))
}

fn wipe(data: &mut [u8]) {
    for byte in data {
        // Volatile writes are retained by the optimizer.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

type Handle = *mut c_void;
#[link(name = "bcrypt")]
extern "system" {
    fn BCryptOpenAlgorithmProvider(
        algorithm: *mut Handle,
        id: *const u16,
        implementation: *const u16,
        flags: u32,
    ) -> i32;
    fn BCryptCloseAlgorithmProvider(algorithm: Handle, flags: u32) -> i32;
    fn BCryptGetProperty(
        object: Handle,
        property: *const u16,
        output: *mut u8,
        output_len: u32,
        result_len: *mut u32,
        flags: u32,
    ) -> i32;
    fn BCryptCreateHash(
        algorithm: Handle,
        hash: *mut Handle,
        object: *mut u8,
        object_len: u32,
        secret: *const u8,
        secret_len: u32,
        flags: u32,
    ) -> i32;
    fn BCryptHashData(hash: Handle, input: *const u8, input_len: u32, flags: u32) -> i32;
    fn BCryptFinishHash(hash: Handle, output: *mut u8, output_len: u32, flags: u32) -> i32;
    fn BCryptDestroyHash(hash: Handle) -> i32;
}

struct AlgorithmHandle(Handle);
impl Drop for AlgorithmHandle {
    fn drop(&mut self) {
        unsafe {
            BCryptCloseAlgorithmProvider(self.0, 0);
        }
    }
}
struct HashHandle(Handle);
impl Drop for HashHandle {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyHash(self.0);
        }
    }
}
struct SensitiveVec(Vec<u8>);
impl Drop for SensitiveVec {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

fn status(value: i32) -> Result<(), String> {
    if value >= 0 {
        Ok(())
    } else {
        Err(format!("Windows CNG error: 0x{:08X}", value as u32))
    }
}

fn hmac(secret: &[u8], message: &[u8], algorithm: Algorithm) -> Result<SensitiveVec, String> {
    const HMAC_FLAG: u32 = 8;
    let secret_len = u32::try_from(secret.len()).map_err(|_| "Secret is too long")?;
    let message_len = u32::try_from(message.len()).map_err(|_| "Message is too long")?;
    let (id, size): (&[u16], usize) = match algorithm {
        Algorithm::Sha1 => (&[83, 72, 65, 49, 0], 20),
        Algorithm::Sha256 => (&[83, 72, 65, 50, 53, 54, 0], 32),
        Algorithm::Sha512 => (&[83, 72, 65, 53, 49, 50, 0], 64),
    };
    let mut handle = null_mut();
    status(unsafe { BCryptOpenAlgorithmProvider(&mut handle, id.as_ptr(), null(), HMAC_FLAG) })?;
    if handle.is_null() {
        return Err("Windows CNG returned a null algorithm handle".into());
    }
    let provider = AlgorithmHandle(handle);
    let property: Vec<u16> = "ObjectLength\0".encode_utf16().collect();
    let mut object_len = 0u32;
    let mut result_len = 0u32;
    status(unsafe {
        BCryptGetProperty(
            provider.0,
            property.as_ptr(),
            (&mut object_len as *mut u32).cast(),
            4,
            &mut result_len,
            0,
        )
    })?;
    if result_len != 4 || object_len == 0 || object_len > 1_048_576 {
        return Err("Windows CNG returned an invalid object size".into());
    }
    let mut object = SensitiveVec(vec![0; object_len as usize]);
    let mut hash = null_mut();
    status(unsafe {
        BCryptCreateHash(
            provider.0,
            &mut hash,
            object.0.as_mut_ptr(),
            object_len,
            secret.as_ptr(),
            secret_len,
            0,
        )
    })?;
    if hash.is_null() {
        return Err("Windows CNG returned a null hash handle".into());
    }
    let hash = HashHandle(hash);
    status(unsafe { BCryptHashData(hash.0, message.as_ptr(), message_len, 0) })?;
    let mut digest = SensitiveVec(vec![0; size]);
    status(unsafe { BCryptFinishHash(hash.0, digest.0.as_mut_ptr(), size as u32, 0) })?;
    // CNG must release its object before its backing memory is erased.
    drop(hash);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_and_bad_encodings() {
        for (encoded, expected) in [
            ("MY======", "f"),
            ("MZXQ====", "fo"),
            ("MZXW6===", "foo"),
            ("MZXW6YQ=", "foob"),
            ("mzxw6ytb", "fooba"),
            ("MZXW-6YTB OI======", "foobar"),
        ] {
            assert_eq!(decode_base32(encoded).unwrap(), expected.as_bytes());
        }
        for encoded in [
            "",
            "A",
            "MZX",
            "MZXW6Y",
            "MY=",
            "MY=======",
            "M=Y",
            "MZXW6!",
            "MZXW6===A",
            "MZXW6===-A",
            "MZXW6===é",
            "========",
        ] {
            assert!(decode_base32(encoded).is_err(), "accepted {encoded}");
        }
        assert_eq!(decode_base32("my").unwrap(), b"f");
        // Nonzero unused trailing bits are ignored like other authenticators.
        assert_eq!(decode_base32("MZ").unwrap(), b"f");
        assert_eq!(decode_base32("MZ======").unwrap(), b"f");
        assert_eq!(
            decode_base32(&"A".repeat(6554)).unwrap().len(),
            MAX_SECRET_BYTES
        );
        assert!(decode_base32(&"A".repeat(6555)).is_err());
        assert!(decode_base32(&"A".repeat(8193)).is_err());
    }

    #[test]
    fn rfc_6238_vectors() {
        let cases = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        for (time, sha1, sha256, sha512) in cases {
            assert_eq!(
                totp(b"12345678901234567890", time, 30, 8, Algorithm::Sha1).unwrap(),
                sha1
            );
            assert_eq!(
                totp(
                    b"12345678901234567890123456789012",
                    time,
                    30,
                    8,
                    Algorithm::Sha256
                )
                .unwrap(),
                sha256
            );
            assert_eq!(
                totp(
                    b"1234567890123456789012345678901234567890123456789012345678901234",
                    time,
                    30,
                    8,
                    Algorithm::Sha512
                )
                .unwrap(),
                sha512
            );
            assert_eq!(
                totp(b"12345678901234567890", time, 30, 6, Algorithm::Sha1).unwrap(),
                &sha1[2..]
            );
            assert_eq!(
                totp(b"12345678901234567890", time, 30, 7, Algorithm::Sha1).unwrap(),
                &sha1[1..]
            );
        }
    }

    #[test]
    fn counter_and_parameter_boundaries() {
        let key = b"12345678901234567890";
        // HOTP RFC 4226 counter 0 and counter 1, plus a large counter.
        assert_eq!(totp(key, 0, 30, 6, Algorithm::Sha1).unwrap(), "755224");
        assert_eq!(
            totp(key, u64::MAX, 1, 6, Algorithm::Sha1).unwrap(),
            "094451"
        );
        assert_eq!(
            totp(key, u64::MAX, u64::MAX, 6, Algorithm::Sha1).unwrap(),
            "287082"
        );
        assert!(totp(&vec![0x42; 4096], 0, 30, 6, Algorithm::Sha1).is_ok());
        assert!(totp(&vec![0x42; 4097], 0, 30, 6, Algorithm::Sha1).is_err());
    }

    #[test]
    fn otpauth_links() {
        let p = parse_otpauth(
            "otpauth://totp/Example:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(p.name, "Example:alice@google.com");
        assert_eq!(p.secret, b"Hello!\xde\xad\xbe\xef");
        assert_eq!((p.algorithm, p.digits, p.period), (Algorithm::Sha1, 6, 30));
        let p = parse_otpauth(
            "OTPAUTH://TOTP/alice?issuer=My+Org&secret=jbswy3dpehpk3pxp&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(p.name, "My Org:alice");
        assert_eq!(
            (p.algorithm, p.digits, p.period),
            (Algorithm::Sha256, 8, 60)
        );
        let p = parse_otpauth("otpauth://totp/?secret=MZXW6&issuer=Solo").unwrap();
        assert_eq!(p.name, "Solo");
        assert_eq!(p.secret, b"foo");
        for bad in [
            "https://example.com/?secret=MZXW6",
            "otpauth://hotp/x?secret=MZXW6&counter=1",
            "otpauth://totp/x?issuer=a",
            "otpauth://totp/x%zz?secret=MZXW6",
            "otpauth://totp/x?secret=MZXW6&algorithm=MD5",
            "otpauth://totp/x?secret=MZXW6&digits=six",
            "otpauth://totp/x?secret=MZ0W6",
            "otpauth://totp/x?secret=MZ%+9XW6",
            "otpauth://totp/x?secret=MZXW6&encoder=steam",
        ] {
            assert!(parse_otpauth(bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn invalid_parameters() {
        assert!(totp(b"", 0, 30, 6, Algorithm::Sha1).is_err());
        assert!(totp(b"key", 0, 0, 6, Algorithm::Sha1).is_err());
        assert!(totp(b"key", 0, 30, 9, Algorithm::Sha1).is_err());
        assert!(totp(b"key", 0, 30, 5, Algorithm::Sha1).is_err());
    }
}

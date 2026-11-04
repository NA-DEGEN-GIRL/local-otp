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
        return Err("Base32 key is too long".into());
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
            return Err("Base32 padding must be at the end".into());
        }
        let value = match c.to_ascii_uppercase() {
            b'A'..=b'Z' => c.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err("Invalid Base32 character".into()),
        };
        values.0.push(value);
        if values.0.len() > (MAX_SECRET_BYTES * 8).div_ceil(5) {
            return Err("Base32 key is too long".into());
        }
    }
    if values.0.is_empty() {
        return Err("Base32 key is empty".into());
    }
    let remainder = values.0.len() % 8;
    let expected_padding = match remainder {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => return Err("Invalid Base32 length".into()),
    };
    if padding != 0 && padding != expected_padding {
        return Err("Invalid Base32 padding".into());
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
    // Nonzero unused bits encode an ambiguous, noncanonical value.
    let invalid = accumulator != 0;
    if invalid {
        wipe(&mut out);
        return Err("Invalid Base32 trailing bits".into());
    }
    Ok(out)
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
            "MZ",
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
    fn invalid_parameters() {
        assert!(totp(b"", 0, 30, 6, Algorithm::Sha1).is_err());
        assert!(totp(b"key", 0, 0, 6, Algorithm::Sha1).is_err());
        assert!(totp(b"key", 0, 30, 9, Algorithm::Sha1).is_err());
        assert!(totp(b"key", 0, 30, 5, Algorithm::Sha1).is_err());
    }
}

//! Current-user DPAPI protection for the local storage key.

use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

use messenger_core::StorageKey;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use zeroize::Zeroizing;

use crate::{Error, Result};

const PURPOSE: &[u8] = b"private-messenger.storage-key.dpapi.v1";
const KEY_LEN: usize = 32;
const MAX_BLOB_LEN: usize = 64 * 1024;

pub(crate) fn protect(key: &StorageKey) -> Result<Vec<u8>> {
    protect_bytes_with_entropy(key.as_bytes(), PURPOSE)
}

pub(crate) fn unprotect(blob: &[u8]) -> Result<StorageKey> {
    if blob.is_empty() || blob.len() > MAX_BLOB_LEN {
        return Err(Error::ProtectionFailed);
    }

    // CRYPT_INTEGER_BLOB uses a mutable data pointer, even for DPAPI input.
    // Own copies so the native API never receives a mutable pointer into a
    // caller's shared slice, and wipe those copies on every exit path.
    let mut input_bytes = Zeroizing::new(blob.to_vec());
    let input = input_blob(&mut input_bytes)?;
    let mut entropy_bytes = Zeroizing::new(PURPOSE.to_vec());
    let entropy = input_blob(&mut entropy_bytes)?;
    let mut output = LocalBlob::new();

    // SAFETY: Both input blobs point to live, owned buffers with their exact
    // lengths. Optional UI, description, and reserved arguments are null.
    // On success DPAPI writes a LocalAlloc-owned result into an initialized
    // descriptor. The guard then owns it and frees (and wipes) it on every
    // subsequent exit path; failed output descriptors are never inspected.
    let succeeded = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.raw,
        )
    };
    if succeeded == 0 {
        return Err(Error::ProtectionFailed);
    }
    output.owned = true;
    if output.raw.cbData as usize != KEY_LEN {
        return Err(Error::InvalidKey);
    }
    if output.raw.pbData.is_null() {
        return Err(Error::ProtectionFailed);
    }

    let mut key_bytes = Zeroizing::new([0; KEY_LEN]);
    // SAFETY: A successful DPAPI call returns an initialized allocation with
    // cbData bytes. We checked both its pointer and the exact 32-byte length.
    // The slice is only borrowed while the owning guard is alive.
    let plaintext = unsafe { std::slice::from_raw_parts(output.raw.pbData, KEY_LEN) };
    key_bytes.copy_from_slice(plaintext);
    Ok(StorageKey::from_bytes(*key_bytes))
}

fn protect_bytes_with_entropy(bytes: &[u8], purpose: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_BLOB_LEN || purpose.len() > MAX_BLOB_LEN {
        return Err(Error::ProtectionFailed);
    }
    let mut input_bytes = Zeroizing::new(bytes.to_vec());
    let input = input_blob(&mut input_bytes)?;
    let mut entropy_bytes = Zeroizing::new(purpose.to_vec());
    let entropy = input_blob(&mut entropy_bytes)?;
    let mut output = LocalBlob::new();

    // SAFETY: Both input blobs describe live, owned buffers. The output starts
    // null and its allocation is owned by the guard only after DPAPI reports
    // success. Null UI and description arguments and UI_FORBIDDEN prohibit
    // interaction. With no machine-scope flag, DPAPI protects for the current
    // Windows user.
    let succeeded = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.raw,
        )
    };
    if succeeded == 0 {
        return Err(Error::ProtectionFailed);
    }
    output.owned = true;
    let output_len = output.raw.cbData as usize;
    if output.raw.pbData.is_null() || output_len == 0 || output_len > MAX_BLOB_LEN {
        return Err(Error::ProtectionFailed);
    }

    // SAFETY: Successful DPAPI output is initialized for cbData bytes. The
    // checked length is bounded well below isize::MAX on all Windows targets,
    // and the LocalBlob guard remains alive through the copy.
    let ciphertext = unsafe { std::slice::from_raw_parts(output.raw.pbData, output_len) };
    Ok(ciphertext.to_vec())
}

fn input_blob(bytes: &mut [u8]) -> Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(|_| Error::ProtectionFailed)?,
        pbData: bytes.as_mut_ptr(),
    })
}

/// Owns only memory supplied by DPAPI; intentionally has no Debug impl.
struct LocalBlob {
    raw: CRYPT_INTEGER_BLOB,
    owned: bool,
}

impl LocalBlob {
    fn new() -> Self {
        Self {
            raw: CRYPT_INTEGER_BLOB {
                cbData: 0,
                pbData: ptr::null_mut(),
            },
            owned: false,
        }
    }
}

impl Drop for LocalBlob {
    fn drop(&mut self) {
        // A failed DPAPI call provides no allocation/length guarantee. Do not
        // even inspect its output descriptor unless the call succeeded.
        if !self.owned {
            return;
        }
        if self.raw.pbData.is_null() {
            return;
        }

        // SAFETY: DPAPI succeeded before the guard acquired ownership. Its
        // non-null output owns a LocalAlloc buffer of cbData initialized bytes.
        // Use volatile byte writes to wipe native plaintext even when its
        // length fails validation, without first constructing a Rust slice.
        // wrapping_add keeps pointer arithmetic defined before each valid
        // in-allocation byte is written. Ciphertext is wiped as well.
        for offset in 0..self.raw.cbData as usize {
            unsafe {
                ptr::write_volatile(self.raw.pbData.wrapping_add(offset), 0);
            }
        }
        compiler_fence(Ordering::SeqCst);

        // SAFETY: This pointer was allocated by DPAPI with LocalAlloc, has not
        // been freed, and is released exactly once by this owning guard.
        unsafe {
            LocalFree(self.raw.pbData.cast());
        }
        self.raw.pbData = ptr::null_mut();
        self.raw.cbData = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_user_round_trip() {
        let key = StorageKey::generate();
        let blob = protect(&key).expect("current-user protection succeeds");
        let recovered = unprotect(&blob).expect("current-user unprotection succeeds");
        assert!(recovered.as_bytes() == key.as_bytes());
    }

    #[test]
    fn altered_blob_is_rejected() {
        let key = StorageKey::generate();
        let mut blob = protect(&key).expect("current-user protection succeeds");
        let last = blob.len() - 1;
        blob[last] ^= 1;
        assert!(matches!(unprotect(&blob), Err(Error::ProtectionFailed)));
    }

    #[test]
    fn different_purpose_is_rejected() {
        let key = StorageKey::generate();
        let blob = protect_bytes_with_entropy(key.as_bytes(), b"other-purpose")
            .expect("current-user protection succeeds");
        assert!(matches!(unprotect(&blob), Err(Error::ProtectionFailed)));
    }

    #[test]
    fn unexpected_plaintext_length_is_rejected() {
        let plaintext = Zeroizing::new([7; KEY_LEN - 1]);
        let blob = protect_bytes_with_entropy(plaintext.as_ref(), PURPOSE)
            .expect("current-user protection succeeds");
        assert!(matches!(unprotect(&blob), Err(Error::InvalidKey)));
    }

    #[test]
    fn oversized_or_empty_input_is_rejected() {
        assert!(matches!(unprotect(&[]), Err(Error::ProtectionFailed)));
        let oversized = vec![0; MAX_BLOB_LEN + 1];
        assert!(matches!(
            unprotect(&oversized),
            Err(Error::ProtectionFailed)
        ));
    }
}

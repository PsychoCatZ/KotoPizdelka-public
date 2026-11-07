//! OS protection of the random client database key: Windows DPAPI or Android
//! Keystore. No plaintext fallback. Linux protection is not implemented.
//! Callers must serialize key initialization with database initialization.

use messenger_core::StorageKey;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "android", test))]
mod android;
#[cfg(windows)]
mod backup_dialog;
#[cfg(any(windows, target_os = "android", test))]
mod key_file;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use backup_dialog::choose as choose_backup_file;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("system key storage is not implemented on this platform")]
    UnsupportedPlatform,
    #[error("the operating system could not protect or unlock the storage key")]
    ProtectionFailed,
    #[error("invalid or corrupted protected key file")]
    InvalidKey,
    #[error("local protected-key file operation failed")]
    LocalIo,
    #[error("the existing database has no protected storage key")]
    MissingKey,
    #[error("a protected key file already exists")]
    AlreadyExists,
}
pub type Result<T> = std::result::Result<T, Error>;

/// Initializes the Android backend from the native runtime's JNI context.
/// This exposes no commands to the renderer and does not access profile data.
/// Key protection and unlocking subsequently run on the profile worker thread.
#[cfg(target_os = "android")]
pub fn initialize_android(vm: jni::JavaVM) -> Result<()> {
    android::initialize(vm)
}

pub fn ensure_supported() -> Result<()> {
    #[cfg(windows)]
    {
        Ok(())
    }
    #[cfg(target_os = "android")]
    {
        android::ensure_initialized()
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        Err(Error::UnsupportedPlatform)
    }
}

/// Path of an opaque OS-protected sidecar; it never contains a plaintext key.
pub fn key_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    #[cfg(not(target_os = "android"))]
    path.push(".key.dpapi");
    #[cfg(target_os = "android")]
    path.push(".key.android-keystore");
    PathBuf::from(path)
}

/// Publish a provided recovery key under this device's OS protection. Never overwrites.
pub fn protect_new(database: &Path, key: &StorageKey) -> Result<()> {
    ensure_supported()?;
    #[cfg(any(windows, target_os = "android"))]
    {
        key_file::protect_new(database, key, &SystemProtector)
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        let _ = (database, key);
        Err(Error::UnsupportedPlatform)
    }
}

/// Returns the existing key, or creates one only if the database does not exist.
/// Hold the application's database worker lock before calling this, and keep it
/// held until database initialization completes. Never reset on an error.
pub fn load_or_create(database: &Path) -> Result<StorageKey> {
    ensure_supported()?;
    #[cfg(any(windows, target_os = "android"))]
    {
        key_file::load_or_create(database, &SystemProtector)
    }
    #[cfg(not(any(windows, target_os = "android")))]
    {
        let _ = database;
        Err(Error::UnsupportedPlatform)
    }
}

#[cfg(windows)]
struct SystemProtector;
#[cfg(windows)]
impl key_file::Protector for SystemProtector {
    fn protect(&self, key: &StorageKey) -> Result<Vec<u8>> {
        windows::protect(key)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<StorageKey> {
        windows::unprotect(blob)
    }
}

#[cfg(target_os = "android")]
struct SystemProtector;
#[cfg(target_os = "android")]
impl key_file::Protector for SystemProtector {
    fn protect(&self, key: &StorageKey) -> Result<Vec<u8>> {
        android::protect(key)
    }
    fn unprotect(&self, blob: &[u8]) -> Result<StorageKey> {
        android::unprotect(blob)
    }
}

#[cfg(all(test, not(any(windows, target_os = "android"))))]
mod unsupported_tests {
    use super::*;

    #[test]
    fn unsupported_platform_does_not_create_files_or_plaintext_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite");
        assert!(matches!(
            load_or_create(&path),
            Err(Error::UnsupportedPlatform)
        ));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

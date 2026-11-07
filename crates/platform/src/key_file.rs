use crate::{key_path, Error, Result};
use messenger_core::StorageKey;
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;

#[cfg(not(target_os = "android"))]
const MAGIC: &[u8] = b"KotoPizdelka.storage-key.dpapi.v1\0";
#[cfg(target_os = "android")]
const MAGIC: &[u8] = b"KotoPizdelka.storage-key.android-keystore.v1\0";
const MAX_PROTECTED: usize = 64 * 1024;

pub(crate) trait Protector {
    fn protect(&self, key: &StorageKey) -> Result<Vec<u8>>;
    fn unprotect(&self, blob: &[u8]) -> Result<StorageKey>;
}

fn regular_file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(Error::LocalIo),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(Error::LocalIo),
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = parent_directory(path);
        fs::File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| Error::LocalIo)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn read_key(path: &Path, protector: &impl Protector) -> Result<StorageKey> {
    if !regular_file_exists(path)? {
        return Err(Error::MissingKey);
    }
    // Write access permits FlushFileBuffers on Windows; the file is immutable
    // in this implementation, but retrying initialization completes its flush.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| Error::LocalIo)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_PROTECTED + MAGIC.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::LocalIo)?;
    let blob = bytes.strip_prefix(MAGIC).ok_or(Error::InvalidKey)?;
    if blob.is_empty() || blob.len() > MAX_PROTECTED {
        return Err(Error::InvalidKey);
    }
    let key = protector.unprotect(blob)?;
    file.sync_all().map_err(|_| Error::LocalIo)?;
    sync_parent(path)?;
    Ok(key)
}

#[cfg(windows)]
fn publish(file: &NamedTempFile, path: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS},
        Storage::FileSystem::{
            MoveFileExW, SetFileAttributesW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_WRITE_THROUGH,
        },
    };
    fn wide(path: &Path) -> Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(Error::LocalIo);
        }
        value.push(0);
        Ok(value)
    }
    let source = wide(file.path())?;
    let destination = wide(path)?;
    // SAFETY: both paths are NUL-terminated UTF-16 owned until the calls finish.
    // Clearing the temporary attribute matches tempfile's Windows persistence.
    if unsafe { SetFileAttributesW(source.as_ptr(), FILE_ATTRIBUTE_NORMAL) } == 0 {
        return Err(Error::LocalIo);
    }
    // No REPLACE_EXISTING: publishing never overwrites a protected key.
    // WRITE_THROUGH is requested, but hardware/power-loss behavior is untested.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        // SAFETY: GetLastError has no pointers and follows the failed API call.
        return Err(match unsafe { GetLastError() } {
            ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS => Error::AlreadyExists,
            _ => Error::LocalIo,
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn publish(file: NamedTempFile, path: &Path) -> Result<()> {
    file.persist_noclobber(path).map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            Error::AlreadyExists
        } else {
            Error::LocalIo
        }
    })?;
    Ok(())
}

fn write_new(path: &Path, protected: &[u8]) -> Result<()> {
    if protected.is_empty() || protected.len() > MAX_PROTECTED {
        return Err(Error::InvalidKey);
    }
    let parent = parent_directory(path);
    let mut file = NamedTempFile::new_in(parent).map_err(|_| Error::LocalIo)?;
    file.write_all(MAGIC)
        .and_then(|_| file.write_all(protected))
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| Error::LocalIo)?;
    #[cfg(windows)]
    publish(&file, path)?;
    #[cfg(not(windows))]
    publish(file, path)?;
    sync_parent(path)?;
    Ok(())
}

pub(crate) fn protect_new(
    database: &Path,
    key: &StorageKey,
    protector: &impl Protector,
) -> Result<()> {
    let protected = protector.protect(key)?;
    write_new(&key_path(database), &protected)
}

pub(crate) fn load_or_create(database: &Path, protector: &impl Protector) -> Result<StorageKey> {
    let database_exists = regular_file_exists(database)?;
    let path = key_path(database);
    if regular_file_exists(&path)? {
        return read_key(&path, protector);
    }
    if database_exists {
        return Err(Error::MissingKey);
    }
    let key = StorageKey::generate();
    let protected = protector.protect(&key)?;
    match write_new(&path, &protected) {
        Ok(()) => Ok(key),
        // Another creator's complete publication wins. Never return our
        // unpublished key, and never overwrite or remove the winning file.
        Err(Error::AlreadyExists) => read_key(&path, protector),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
#[path = "key_file_tests.rs"]
mod tests;

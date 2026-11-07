#![cfg(test)]

use super::*;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::{
    fs::File,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    },
    thread,
};
use zeroize::Zeroizing;

// This authenticated lab provider is private to tests. Production has no
// alternate provider or plaintext fallback when OS protection is unavailable.
struct LabProtector {
    master: [u8; 32],
    protect_calls: AtomicUsize,
    unprotect_calls: AtomicUsize,
    fail_protect: bool,
    creators: Option<Arc<Barrier>>,
}

impl LabProtector {
    fn new() -> Self {
        Self {
            master: [0x6b; 32],
            protect_calls: AtomicUsize::new(0),
            unprotect_calls: AtomicUsize::new(0),
            fail_protect: false,
            creators: None,
        }
    }

    fn assert_calls(&self, protect: usize, unprotect: usize) {
        assert_eq!(self.protect_calls.load(Ordering::SeqCst), protect);
        assert_eq!(self.unprotect_calls.load(Ordering::SeqCst), unprotect);
    }
}

impl Protector for LabProtector {
    fn protect(&self, key: &StorageKey) -> Result<Vec<u8>> {
        self.protect_calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_protect {
            return Err(Error::ProtectionFailed);
        }
        if let Some(creators) = &self.creators {
            creators.wait();
        }
        let cipher = ChaCha20Poly1305::new((&self.master).into());
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = cipher
            .encrypt(Nonce::from_slice(&nonce), key.as_bytes().as_slice())
            .map_err(|_| Error::ProtectionFailed)?;
        let mut protected = nonce.to_vec();
        protected.extend_from_slice(&encrypted);
        Ok(protected)
    }

    fn unprotect(&self, blob: &[u8]) -> Result<StorageKey> {
        self.unprotect_calls.fetch_add(1, Ordering::SeqCst);
        let (nonce, encrypted) = blob.split_at_checked(12).ok_or(Error::InvalidKey)?;
        let cipher = ChaCha20Poly1305::new((&self.master).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(nonce), encrypted)
                .map_err(|_| Error::ProtectionFailed)?,
        );
        if plaintext.len() != 32 {
            return Err(Error::InvalidKey);
        }
        let mut bytes = Zeroizing::new([0; 32]);
        bytes.copy_from_slice(&plaintext);
        Ok(StorageKey::from_bytes(*bytes))
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("profile.sqlite");
    (directory, database)
}

fn database_bytes() -> &'static [u8] {
    b"existing database fixture: must never be changed by key initialization"
}

#[test]
fn new_protected_file_reloads_the_same_key_without_reprotecting() {
    let (directory, database) = fixture();
    let protector = LabProtector::new();

    let created = load_or_create(&database, &protector).unwrap();
    let path = key_path(&database);
    let protected = fs::read(&path).unwrap();
    assert!(protected.starts_with(MAGIC));
    assert_eq!(protected.len(), MAGIC.len() + 12 + 32 + 16);
    assert!(!protected
        .windows(created.as_bytes().len())
        .any(|window| window == created.as_bytes()));
    assert!(!database.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);

    let loaded = load_or_create(&database, &protector).unwrap();
    assert!(created.as_bytes() == loaded.as_bytes());
    fs::write(&database, database_bytes()).unwrap();
    let loaded_with_database = load_or_create(&database, &protector).unwrap();
    assert!(created.as_bytes() == loaded_with_database.as_bytes());
    assert_eq!(fs::read(&path).unwrap(), protected);
    assert_eq!(fs::read(&database).unwrap(), database_bytes());
    protector.assert_calls(1, 2);
}

#[test]
fn existing_database_without_a_key_fails_closed_and_preserves_database() {
    let (directory, database) = fixture();
    fs::write(&database, database_bytes()).unwrap();
    let protector = LabProtector::new();

    assert!(matches!(
        load_or_create(&database, &protector),
        Err(Error::MissingKey)
    ));

    assert_eq!(fs::read(&database).unwrap(), database_bytes());
    assert!(!key_path(&database).exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    protector.assert_calls(0, 0);
}

#[test]
fn malformed_protected_files_are_never_overwritten() {
    let maker = LabProtector::new();
    let blob = maker.protect(&StorageKey::generate()).unwrap();
    let mut valid = MAGIC.to_vec();
    valid.extend_from_slice(&blob);
    let mut corrupt = valid.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut truncated = valid.clone();
    truncated.pop();
    let mut bad_header = valid.clone();
    bad_header[0] ^= 1;
    let mut oversized = MAGIC.to_vec();
    oversized.extend(vec![0; MAX_PROTECTED + 1]);

    for (bytes, expected_error, unprotect_calls) in [
        (corrupt, Error::ProtectionFailed, 1),
        (truncated, Error::ProtectionFailed, 1),
        (bad_header, Error::InvalidKey, 0),
        (MAGIC.to_vec(), Error::InvalidKey, 0),
        (oversized, Error::InvalidKey, 0),
    ] {
        let (directory, database) = fixture();
        let path = key_path(&database);
        fs::write(&database, database_bytes()).unwrap();
        fs::write(&path, &bytes).unwrap();
        let protector = LabProtector::new();

        assert!(load_or_create(&database, &protector).err() == Some(expected_error));

        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(fs::read(&database).unwrap(), database_bytes());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
        protector.assert_calls(0, unprotect_calls);
    }
}

#[test]
fn failed_protection_creates_no_files() {
    let (directory, database) = fixture();
    let mut protector = LabProtector::new();
    protector.fail_protect = true;

    assert!(matches!(
        load_or_create(&database, &protector),
        Err(Error::ProtectionFailed)
    ));

    assert!(!database.exists());
    assert!(!key_path(&database).exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    protector.assert_calls(1, 0);
}

#[test]
fn orphaned_valid_key_is_reused_after_database_creation_fails() {
    let (directory, database) = fixture();
    let protector = LabProtector::new();
    let original = load_or_create(&database, &protector).unwrap();
    let path = key_path(&database);
    let protected = fs::read(&path).unwrap();

    // Model an initializer failing to create the database because another local
    // operation temporarily occupied its path. The key remains published.
    fs::create_dir(&database).unwrap();
    assert!(File::create(&database).is_err());
    assert_eq!(fs::read(&path).unwrap(), protected);
    fs::remove_dir(&database).unwrap();

    let retried = load_or_create(&database, &protector).unwrap();
    assert!(original.as_bytes() == retried.as_bytes());
    assert_eq!(fs::read(&path).unwrap(), protected);
    assert!(!database.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    protector.assert_calls(1, 1);
}

#[test]
fn concurrent_first_creators_all_return_the_one_persisted_key() {
    const CREATORS: usize = 8;
    let (directory, database) = fixture();
    let mut protector = LabProtector::new();
    protector.creators = Some(Arc::new(Barrier::new(CREATORS)));
    let protector = Arc::new(protector);
    let mut workers = Vec::new();
    for _ in 0..CREATORS {
        let database = database.clone();
        let protector = Arc::clone(&protector);
        workers.push(thread::spawn(move || {
            load_or_create(&database, protector.as_ref()).unwrap()
        }));
    }
    let keys: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();

    let path = key_path(&database);
    let protected = fs::read(&path).unwrap();
    let persisted = read_key(&path, protector.as_ref()).unwrap();
    assert!(keys
        .iter()
        .all(|key| key.as_bytes() == persisted.as_bytes()));
    assert_eq!(fs::read(&path).unwrap(), protected);
    assert!(!database.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    protector.assert_calls(CREATORS, CREATORS);
}

#[test]
fn write_new_never_overwrites_an_existing_target() {
    let (directory, database) = fixture();
    let path = key_path(&database);
    let protector = LabProtector::new();
    let blob = protector.protect(&StorageKey::generate()).unwrap();
    write_new(&path, &blob).unwrap();
    let protected = fs::read(&path).unwrap();

    assert!(matches!(
        write_new(&path, b"different protected blob"),
        Err(Error::AlreadyExists)
    ));

    assert_eq!(fs::read(&path).unwrap(), protected);
    assert!(!database.exists());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    protector.assert_calls(1, 0);
}

#[test]
fn a_different_protector_master_cannot_unlock_or_replace_the_key() {
    let (directory, database) = fixture();
    let owner = LabProtector::new();
    let _key = load_or_create(&database, &owner).unwrap();
    let path = key_path(&database);
    let protected = fs::read(&path).unwrap();
    fs::write(&database, database_bytes()).unwrap();
    let mut other = LabProtector::new();
    other.master = [0x29; 32];

    assert!(matches!(
        load_or_create(&database, &other),
        Err(Error::ProtectionFailed)
    ));

    assert_eq!(fs::read(&path).unwrap(), protected);
    assert_eq!(fs::read(&database).unwrap(), database_bytes());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 2);
    owner.assert_calls(1, 0);
    other.assert_calls(0, 1);
}

#[test]
fn losing_os_protection_never_recreates_a_key_even_without_a_database() {
    // Android alias loss is an unlocking failure, not permission to generate a
    // replacement. Exercise both an existing database and an orphan sidecar.
    for database_exists in [false, true] {
        let (_directory, database) = fixture();
        let owner = LabProtector::new();
        let original = load_or_create(&database, &owner).unwrap();
        let path = key_path(&database);
        let protected = fs::read(&path).unwrap();
        if database_exists {
            fs::write(&database, database_bytes()).unwrap();
        }
        let mut unavailable = LabProtector::new();
        unavailable.master = [0x29; 32];
        assert!(matches!(
            load_or_create(&database, &unavailable),
            Err(Error::ProtectionFailed)
        ));
        unavailable.assert_calls(0, 1);
        assert_eq!(fs::read(&path).unwrap(), protected);
        if database_exists {
            assert_eq!(fs::read(&database).unwrap(), database_bytes());
        } else {
            assert!(!database.exists());
        }
        let recovered = load_or_create(&database, &owner).unwrap();
        assert_eq!(recovered.as_bytes(), original.as_bytes());
        owner.assert_calls(1, 1);
    }
}

#[test]
fn a_directory_at_the_key_path_is_rejected_and_preserved() {
    let (_directory, database) = fixture();
    fs::write(&database, database_bytes()).unwrap();
    let path = key_path(&database);
    fs::create_dir(&path).unwrap();
    let marker = path.join("preserve-me");
    fs::write(&marker, b"directory contents").unwrap();
    let protector = LabProtector::new();

    assert!(matches!(
        load_or_create(&database, &protector),
        Err(Error::LocalIo)
    ));

    assert!(fs::symlink_metadata(&path).unwrap().is_dir());
    assert_eq!(fs::read(&marker).unwrap(), b"directory contents");
    assert_eq!(fs::read(&database).unwrap(), database_bytes());
    protector.assert_calls(0, 0);
}

#[test]
fn database_nonfiles_and_metadata_errors_fail_before_protection() {
    let (directory, database) = fixture();
    fs::create_dir(&database).unwrap();
    let marker = database.join("preserve-me");
    fs::write(&marker, b"directory contents").unwrap();
    let protector = LabProtector::new();

    assert!(matches!(
        load_or_create(&database, &protector),
        Err(Error::LocalIo)
    ));

    assert!(fs::symlink_metadata(&database).unwrap().is_dir());
    assert_eq!(fs::read(&marker).unwrap(), b"directory contents");
    assert!(!key_path(&database).exists());
    protector.assert_calls(0, 0);

    #[cfg(unix)]
    {
        let blocker = directory.path().join("parent-is-a-file");
        fs::write(&blocker, b"preserve blocking file").unwrap();
        let inaccessible = blocker.join("profile.sqlite");
        assert_eq!(
            fs::symlink_metadata(&inaccessible).unwrap_err().kind(),
            std::io::ErrorKind::NotADirectory
        );

        assert!(matches!(
            load_or_create(&inaccessible, &protector),
            Err(Error::LocalIo)
        ));

        assert_eq!(fs::read(&blocker).unwrap(), b"preserve blocking file");
        assert!(fs::symlink_metadata(key_path(&inaccessible)).is_err());
        protector.assert_calls(0, 0);
    }
    #[cfg(not(unix))]
    let _ = directory;
}

#[cfg(unix)]
#[test]
fn database_and_key_symlinks_are_rejected_without_changing_their_targets() {
    use std::os::unix::fs::symlink;

    let (directory, database) = fixture();
    let target_database = directory.path().join("database-target");
    fs::write(&target_database, database_bytes()).unwrap();
    symlink(&target_database, &database).unwrap();
    let protector = LabProtector::new();

    assert!(matches!(
        load_or_create(&database, &protector),
        Err(Error::LocalIo)
    ));

    assert!(fs::symlink_metadata(&database)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target_database).unwrap(), database_bytes());
    assert!(!key_path(&database).exists());
    protector.assert_calls(0, 0);

    fs::remove_file(&database).unwrap();
    fs::write(&database, database_bytes()).unwrap();
    let target_key = directory.path().join("key-target");
    fs::write(&target_key, b"preserve key target").unwrap();
    let path = key_path(&database);
    symlink(&target_key, &path).unwrap();

    assert!(matches!(
        load_or_create(&database, &protector),
        Err(Error::LocalIo)
    ));

    assert!(fs::symlink_metadata(&path)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target_key).unwrap(), b"preserve key target");
    assert_eq!(fs::read(&database).unwrap(), database_bytes());
    protector.assert_calls(0, 0);
}

#[test]
fn an_empty_key_file_never_regenerates_even_without_a_database() {
    for database_exists in [false, true] {
        let (directory, database) = fixture();
        if database_exists {
            fs::write(&database, database_bytes()).unwrap();
        }
        let path = key_path(&database);
        fs::write(&path, []).unwrap();
        let protector = LabProtector::new();

        assert!(matches!(
            load_or_create(&database, &protector),
            Err(Error::InvalidKey)
        ));

        assert!(fs::read(&path).unwrap().is_empty());
        if database_exists {
            assert_eq!(fs::read(&database).unwrap(), database_bytes());
        } else {
            assert!(!database.exists());
        }
        assert_eq!(
            fs::read_dir(directory.path()).unwrap().count(),
            1 + usize::from(database_exists)
        );
        protector.assert_calls(0, 0);
    }
}

#[test]
fn recovery_key_publication_is_protected_and_never_overwrites_existing_key() {
    let d = tempfile::tempdir().unwrap();
    let database = d.path().join("restored.sqlite");
    let provider = LabProtector::new();
    let key = StorageKey::generate();
    protect_new(&database, &key, &provider).unwrap();
    let reopened = load_or_create(&database, &provider).unwrap();
    assert!(reopened.as_bytes() == key.as_bytes());
    assert!(matches!(
        protect_new(&database, &StorageKey::generate(), &provider),
        Err(Error::AlreadyExists)
    ));
    let reopened = load_or_create(&database, &provider).unwrap();
    assert!(reopened.as_bytes() == key.as_bytes());
}

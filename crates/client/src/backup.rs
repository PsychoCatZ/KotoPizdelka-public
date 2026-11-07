//! Native recovery publication. A staged protected key + database can resume after interruption.
use super::*;
use messenger_store::backup;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use zeroize::Zeroizing;

fn failure() -> Error {
    Error::LocalIo
}
fn pending(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".restore-pending");
    PathBuf::from(name)
}
fn regular(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && !m.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(failure()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(failure()),
    }
}
fn hash(path: &Path) -> Result<String> {
    if !regular(path)? {
        return Err(failure());
    }
    let mut file = File::open(path).map_err(|_| failure())?;
    let mut h = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf).map_err(|_| failure())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}
fn flush_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path.parent().ok_or_else(failure)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| failure())?;
    Ok(())
}
/// Native UI uses this only to decide whether to offer restoration. Lock rechecks at commit.
pub fn can_restore(path: &Path) -> bool {
    !path.exists() && !messenger_platform::key_path(path).exists() && !pending(path).exists()
}
fn publish(source: &Path, destination: &Path, expected: &str) -> Result<()> {
    if regular(destination)? {
        if hash(destination)? != expected {
            return Err(failure());
        }
    } else {
        let parent = destination.parent().ok_or_else(failure)?;
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| failure())?;
        std::io::copy(&mut File::open(source).map_err(|_| failure())?, &mut file)
            .map_err(|_| failure())?;
        file.as_file().sync_all().map_err(|_| failure())?;
        file.persist_noclobber(destination).map_err(|_| failure())?;
        flush_parent(destination)?;
    }
    Ok(())
}
/// Caller holds the existing worker lock. An unrelated existing file is never replaced.
pub(crate) fn finish_pending(path: &Path) -> Result<()> {
    let stage = pending(path);
    match std::fs::symlink_metadata(&stage) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => (),
        _ => return Err(failure()),
    }
    let meta_path = stage.join("manifest.json");
    if !regular(&meta_path)? || std::fs::metadata(&meta_path).map_err(|_| failure())?.len() > 4096 {
        return Err(failure());
    }
    let manifest: Manifest =
        serde_json::from_slice(&std::fs::read(meta_path).map_err(|_| failure())?)
            .map_err(|_| failure())?;
    if manifest.version != 1 || !valid_hex(&manifest.database, 64) || !valid_hex(&manifest.key, 64)
    {
        return Err(failure());
    }
    let database = stage.join("profile.sqlite");
    let key = messenger_platform::key_path(&database);
    if hash(&database)? != manifest.database || hash(&key)? != manifest.key {
        return Err(failure());
    }
    publish(&database, path, &manifest.database)?;
    publish(&key, &messenger_platform::key_path(path), &manifest.key)?;
    std::fs::remove_dir_all(stage).map_err(|_| failure())?;
    flush_parent(path)
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u8,
    database: String,
    key: String,
}

fn decrypt_file(archive: &Path, password: &str) -> Result<(StorageKey, Zeroizing<Vec<u8>>)> {
    if !regular(archive)?
        || std::fs::metadata(archive).map_err(|_| failure())?.len() > backup::MAX_ARCHIVE as u64
    {
        return Err(failure());
    }
    let mut bytes = Vec::new();
    File::open(archive)
        .map_err(|_| failure())?
        .take((backup::MAX_ARCHIVE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| failure())?;
    backup::decrypt(&bytes, password).map_err(|_| failure())
}
pub fn verify_profile(archive: &Path, password: String) -> Result<()> {
    let password = Zeroizing::new(password);
    let (key, bytes) = decrypt_file(archive, &password)?;
    let mut file = tempfile::NamedTempFile::new().map_err(|_| failure())?;
    backup::write_database(file.as_file_mut(), &bytes).map_err(|_| failure())?;
    let mut store = ClientStore::open(file.path(), key)?;
    store.prepare_recovery().map_err(|_| failure())
}

impl ClientWorker {
    /// An explicit native file export; no plaintext key or profile path reaches the WebView.
    pub fn export_profile(&mut self, target: &Path, password: String) -> Result<()> {
        let password = Zeroizing::new(password);
        let bytes = self.store.export_backup(&password).map_err(|_| failure())?;
        let parent = target.parent().ok_or_else(failure)?;
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|_| failure())?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| failure())?;
        file.persist_noclobber(target).map_err(|_| failure())?;
        flush_parent(target)
    }
    pub fn restore_profile(
        path: &Path,
        archive: &Path,
        password: String,
        allow_loopback_http: bool,
    ) -> Result<Self> {
        messenger_platform::ensure_supported()?;
        restore_inner(
            path,
            archive,
            password,
            allow_loopback_http,
            |p, k| messenger_platform::protect_new(p, k).map_err(Error::from),
            |p| messenger_platform::load_or_create(p).map_err(Error::from),
        )
    }
}
fn restore_inner(
    path: &Path,
    archive: &Path,
    password: String,
    allow_loopback_http: bool,
    protect: impl Fn(&Path, &StorageKey) -> Result<()>,
    unlock: impl Fn(&Path) -> Result<StorageKey>,
) -> Result<ClientWorker> {
    let password = Zeroizing::new(password);
    let path = canonical_database(path)?;
    let guard = acquire_worker_lock(&path)?;
    if !can_restore(&path) || !regular(archive)? {
        return Err(failure());
    }
    let (key, database) = decrypt_file(archive, &password)?;
    let parent = path.parent().ok_or_else(failure)?;
    let stage = tempfile::tempdir_in(parent).map_err(|_| failure())?;
    let stage_database = stage.path().join("profile.sqlite");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage_database)
        .map_err(|_| failure())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| failure())?;
    }
    backup::write_database(&mut file, &database).map_err(|_| failure())?;
    drop(file);
    drop(database);
    let key_copy = StorageKey::from_bytes(*key.as_bytes());
    let mut store = ClientStore::open(&stage_database, key_copy)?;
    store.prepare_recovery().map_err(|_| failure())?;
    drop(store);
    protect(&stage_database, &key)?;
    let manifest = Manifest {
        version: 1,
        database: hash(&stage_database)?,
        key: hash(&messenger_platform::key_path(&stage_database))?,
    };
    let mut marker = File::create(stage.path().join("manifest.json")).map_err(|_| failure())?;
    marker
        .write_all(&serde_json::to_vec(&manifest).map_err(|_| failure())?)
        .and_then(|_| marker.sync_all())
        .map_err(|_| failure())?;
    drop(marker);
    flush_parent(&stage.path().join("manifest.json"))?;
    std::fs::rename(stage.path(), pending(&path)).map_err(|_| failure())?;
    flush_parent(&path)?;
    finish_pending(&path)?;
    let key = unlock(&path)?;
    Ok(ClientWorker {
        incoming_contacts: Vec::new(),
        store: ClientStore::open(&path, key)?,
        transport: Transport::new(allow_loopback_http)?,
        _guard: guard,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use messenger_core::Contact;
    use rand::{rngs::OsRng, RngCore};
    const PASSWORD: &str = "a long profile recovery phrase";
    fn protect(path: &Path, key: &StorageKey) -> Result<()> {
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&[5; 32]).unwrap();
        let mut blob = nonce.to_vec();
        blob.extend(
            cipher
                .encrypt(XNonce::from_slice(&nonce), key.as_bytes().as_ref())
                .unwrap(),
        );
        std::fs::write(messenger_platform::key_path(path), blob).unwrap();
        Ok(())
    }
    fn unlock(path: &Path) -> Result<StorageKey> {
        let blob = std::fs::read(messenger_platform::key_path(path)).unwrap();
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(&[5; 32])
                .unwrap()
                .decrypt(XNonce::from_slice(&blob[..24]), &blob[24..])
                .unwrap(),
        );
        let mut key = [0; 32];
        key.copy_from_slice(&plain);
        Ok(StorageKey::from_bytes(key))
    }
    fn fixture(path: &Path) -> (ClientWorker, String) {
        let mut a = Contact::new();
        let mut b = Contact::new();
        let ak = a.public_bundle();
        let bk = b.public_bundle();
        a.bind_peer(bk.clone(), &bk.fingerprint().unwrap()).unwrap();
        b.bind_peer(ak.clone(), &ak.fingerprint().unwrap()).unwrap();
        a.start_session().unwrap();
        let mut worker = ClientWorker::open(path, StorageKey::generate(), true).unwrap();
        let id = worker.store.insert_contact(a).unwrap();
        worker
            .store
            .enqueue(&id, "private history before backup")
            .unwrap();
        worker.store.set_nickname("Кот из копии").unwrap();
        worker.store.set_contact_alias(&id, "Сестра").unwrap();
        let identity = messenger_core::accounts::AccountIdentity::default();
        worker
            .store
            .save_account(&messenger_store::AccountState {
                login: "backupcat".into(),
                relay_url: "https://relay.example.test".into(),
                identity,
                session: "a".repeat(64),
                registered: true,
                authenticated: true,
                cursor: 7,
            })
            .unwrap();
        (worker, id)
    }
    #[tokio::test]
    async fn portable_restore_preserves_history_identity_and_permanently_quarantines_old_ratchets()
    {
        let d = tempfile::tempdir().unwrap();
        let (mut original, id) = fixture(&d.path().join("old"));
        let identity = original
            .store
            .account()
            .unwrap()
            .unwrap()
            .identity
            .public_key();
        let archive = d.path().join("backup");
        original.export_profile(&archive, PASSWORD.into()).unwrap();
        let bytes = std::fs::read(&archive).unwrap();
        assert!(!bytes
            .windows(b"private history".len())
            .any(|w| w == b"private history"));
        assert!(!bytes
            .windows(PASSWORD.len())
            .any(|w| w == PASSWORD.as_bytes()));
        verify_profile(&archive, PASSWORD.into()).unwrap();
        original.store.enqueue(&id, "after snapshot").unwrap();
        let target = d.path().join("restored");
        let mut recovered =
            restore_inner(&target, &archive, PASSWORD.into(), true, protect, unlock).unwrap();
        assert_eq!(
            recovered.store.profile_name().unwrap().nickname,
            "Кот из копии"
        );
        assert_eq!(recovered.store.contact_names(&id).unwrap().alias, "Сестра");
        assert_eq!(recovered.store.history(&id, 0).unwrap().len(), 1);
        assert_eq!(
            recovered.store.history(&id, 0).unwrap()[0].text,
            "private history before backup"
        );
        let account = recovered.store.account().unwrap().unwrap();
        assert!(account.identity.public_key() == identity);
        assert!(!account.authenticated);
        assert!(account.session != "a".repeat(64));
        assert!(recovered.store.is_archived(&id).unwrap());
        assert!(matches!(
            recovered.store.enqueue(&id, "must never encrypt"),
            Err(messenger_store::Error::Archived)
        ));
        assert!(matches!(
            recovered.sync(&id).await,
            Err(Error::Store(messenger_store::Error::Archived))
        ));
        assert!(recovered.store.route(&id).is_err());
        assert_eq!(original.store.history(&id, 0).unwrap().len(), 2);
        drop(recovered);
        let mut again = ClientWorker::open(&target, unlock(&target).unwrap(), true).unwrap();
        assert!(again.store.is_archived(&id).unwrap());
        assert!(again.store.enqueue(&id, "still forbidden").is_err());
        again.store.delete_contact(&id).unwrap();
        assert!(again.store.contact_ids().unwrap().is_empty());
    }
    #[test]
    fn wrong_password_tampering_and_platform_failure_leave_no_profile_to_replace() {
        let d = tempfile::tempdir().unwrap();
        let (mut source, _) = fixture(&d.path().join("old"));
        let archive = d.path().join("backup");
        source.export_profile(&archive, PASSWORD.into()).unwrap();
        let target = d.path().join("new");
        assert!(restore_inner(
            &target,
            &archive,
            "wrong password with sufficient length".into(),
            true,
            protect,
            unlock
        )
        .is_err());
        assert!(can_restore(&target));
        assert!(restore_inner(
            &target,
            &archive,
            PASSWORD.into(),
            true,
            |_, _| Err(failure()),
            unlock
        )
        .is_err());
        assert!(can_restore(&target));
        let mut bytes = std::fs::read(&archive).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&archive, bytes).unwrap();
        assert!(restore_inner(&target, &archive, PASSWORD.into(), true, protect, unlock).is_err());
        assert!(can_restore(&target));
    }
    #[test]
    fn existing_profiles_and_backup_files_are_never_overwritten() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("old");
        let (mut source, id) = fixture(&path);
        let archive = d.path().join("backup");
        source.export_profile(&archive, PASSWORD.into()).unwrap();
        let before = std::fs::read(&archive).unwrap();
        assert!(source.export_profile(&archive, PASSWORD.into()).is_err());
        assert!(std::fs::read(&archive).unwrap() == before);
        assert!(restore_inner(&path, &archive, PASSWORD.into(), true, protect, unlock).is_err());
        assert_eq!(source.store.history(&id, 0).unwrap().len(), 1);
    }
    fn staged(path: &Path) -> (PathBuf, Vec<u8>, Vec<u8>) {
        let stage = pending(path);
        std::fs::create_dir(&stage).unwrap();
        let database = stage.join("profile.sqlite");
        std::fs::write(&database, b"staged encrypted database fixture").unwrap();
        let key = StorageKey::generate();
        protect(&database, &key).unwrap();
        let key_path = messenger_platform::key_path(&database);
        let manifest = Manifest {
            version: 1,
            database: hash(&database).unwrap(),
            key: hash(&key_path).unwrap(),
        };
        std::fs::write(
            stage.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        (
            stage,
            std::fs::read(database).unwrap(),
            std::fs::read(key_path).unwrap(),
        )
    }
    #[test]
    fn interrupted_pair_publication_can_finish_but_never_replace_unrelated_data() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("profile");
        let (stage, database, key) = staged(&target);
        std::fs::write(&target, &database).unwrap(); // crash after first publication, before key
        finish_pending(&target).unwrap();
        assert!(std::fs::read(messenger_platform::key_path(&target)).unwrap() == key);
        assert!(!stage.exists());
        let other = d.path().join("other");
        let (stage, _, _) = staged(&other);
        std::fs::write(&other, b"existing unrelated profile").unwrap();
        assert!(finish_pending(&other).is_err());
        assert!(stage.exists());
        assert_eq!(
            std::fs::read(&other).unwrap(),
            b"existing unrelated profile"
        );
        assert!(!messenger_platform::key_path(&other).exists());
    }
    #[test]
    fn untrusted_header_and_short_password_fail_without_kdf_work() {
        assert!(backup::decrypt(b"not a profile archive", PASSWORD).is_err());
        let d = tempfile::tempdir().unwrap();
        let (source, _) = fixture(&d.path().join("old"));
        assert!(source.store.export_backup("short").is_err());
    }
}

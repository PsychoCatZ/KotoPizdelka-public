//! Profile initialization must never replace a lost, corrupted or mismatched key.

#[cfg(not(any(windows, target_os = "android")))]
#[test]
fn unsupported_system_profile_does_not_create_a_lock_or_profile() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("missing-parent")
        .join("profile.sqlite");
    assert!(matches!(
        messenger_client::ClientWorker::open_system(&path, false),
        Err(messenger_client::Error::Platform(
            messenger_platform::Error::UnsupportedPlatform
        ))
    ));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[cfg(windows)]
mod windows_tests {
    use messenger_client::{ClientWorker, Error};
    use messenger_core::Contact;
    use messenger_platform::key_path;
    use std::{fs, path::Path};

    const TEXT: &str = "Windows profile survives a process restart.";

    fn seed(path: &Path) -> String {
        let mut worker = ClientWorker::open_system(path, false).unwrap();
        let id = worker.store().insert_contact(Contact::new()).unwrap();
        let peer = Contact::new().public_bundle();
        worker
            .store()
            .bind_peer(&id, peer.clone(), &peer.fingerprint().unwrap())
            .unwrap();
        worker.store().start_session(&id).unwrap();
        worker.store().enqueue(&id, TEXT).unwrap();
        id
    }

    #[test]
    fn current_user_profile_reopens_with_exact_history_and_outbox() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite");
        let id = seed(&path);
        let mut worker = ClientWorker::open_system(&path, false).unwrap();
        let pending = worker.store().pending_outbox(&id).unwrap();
        assert_eq!(pending.len(), 1);
        let history = worker.store().history(&id, 0).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].text, TEXT);
        // This call runs while we own the worker guard, as the platform API
        // requires. Neither the raw key nor plaintext should appear on disk.
        let key = messenger_platform::load_or_create(&path).unwrap();
        for entry in fs::read_dir(directory.path()).unwrap() {
            let entry = entry.unwrap();
            if entry
                .file_name()
                .to_string_lossy()
                .ends_with(".worker.lock")
            {
                continue;
            }
            let bytes = fs::read(entry.path()).unwrap();
            assert!(!bytes.windows(32).any(|slice| slice == key.as_bytes()));
            assert!(!bytes
                .windows(TEXT.len())
                .any(|slice| slice == TEXT.as_bytes()));
        }
        drop(worker);
        let mut worker = ClientWorker::open_system(&path, false).unwrap();
        let recovered = worker.store().pending_outbox(&id).unwrap();
        assert_eq!(recovered[0].id, pending[0].id);
        assert_eq!(recovered[0].payload, pending[0].payload);
    }

    #[test]
    fn missing_key_never_generates_a_replacement_for_existing_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite");
        let id = seed(&path);
        let key = key_path(&path);
        let backup = directory.path().join("backup.dpapi");
        fs::rename(&key, &backup).unwrap();
        let original_database = fs::read(&path).unwrap();
        assert!(matches!(
            ClientWorker::open_system(&path, false),
            Err(Error::Platform(messenger_platform::Error::MissingKey))
        ));
        assert!(!key.try_exists().unwrap());
        assert!(fs::read(&path).unwrap() == original_database);
        fs::rename(&backup, &key).unwrap();
        let mut recovered = ClientWorker::open_system(&path, false).unwrap();
        assert_eq!(recovered.store().history(&id, 0).unwrap()[0].text, TEXT);
    }

    #[test]
    fn corrupt_key_is_preserved_and_never_reset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite");
        seed(&path);
        let key = key_path(&path);
        let original = fs::read(&key).unwrap();
        let original_database = fs::read(&path).unwrap();
        let mut corrupt = original.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        fs::write(&key, &corrupt).unwrap();
        assert!(matches!(
            ClientWorker::open_system(&path, false),
            Err(Error::Platform(messenger_platform::Error::ProtectionFailed))
        ));
        assert!(fs::read(&key).unwrap() == corrupt);
        assert!(fs::read(&path).unwrap() == original_database);
        fs::write(&key, original).unwrap();
        assert!(ClientWorker::open_system(&path, false).is_ok());
    }

    #[test]
    fn key_from_another_profile_cannot_reinitialize_the_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("profile.sqlite");
        let other = directory.path().join("other.sqlite");
        seed(&path);
        seed(&other);
        let key = key_path(&path);
        let original = fs::read(&key).unwrap();
        let replacement = fs::read(key_path(&other)).unwrap();
        let database = fs::read(&path).unwrap();
        fs::write(&key, &replacement).unwrap();
        assert!(matches!(
            ClientWorker::open_system(&path, false),
            Err(Error::Store(messenger_store::Error::InvalidStore))
        ));
        assert!(fs::read(&key).unwrap() == replacement);
        assert!(fs::read(&path).unwrap() == database);
        fs::write(&key, original).unwrap();
        assert!(ClientWorker::open_system(&path, false).is_ok());
    }
}

use base64::{engine::general_purpose::STANDARD, Engine};
use messenger_core::{Contact, Envelope, StorageKey};
use messenger_store::{AcceptStatus, ClientStore, Error};
use rusqlite::Connection;
fn copy(k: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*k.as_bytes())
}
fn pair() -> (Contact, Contact) {
    let mut a = Contact::new();
    let mut b = Contact::new();
    let ak = a.public_bundle();
    let bk = b.public_bundle();
    a.bind_peer(bk.clone(), &bk.fingerprint().unwrap()).unwrap();
    b.bind_peer(ak.clone(), &ak.fingerprint().unwrap()).unwrap();
    a.start_session().unwrap();
    (a, b)
}
#[test]
fn profiles_are_sealed_durable_hidden_and_reordered_or_replayed_updates_do_not_revert_names() {
    let d = tempfile::tempdir().unwrap();
    let key = StorageKey::generate();
    let (a, b) = pair();
    let mut sender = ClientStore::open(d.path().join("a"), StorageKey::generate()).unwrap();
    let path = d.path().join("b");
    let mut receiver = ClientStore::open(&path, copy(&key)).unwrap();
    let a = sender.insert_contact(a).unwrap();
    let b = receiver.insert_contact(b).unwrap();
    sender.set_nickname("Кот Учёный 🐱").unwrap();
    sender.enqueue_profile(&a).unwrap();
    let first = sender.pending_outbox(&a).unwrap()[0].clone();
    sender.enqueue_profile(&a).unwrap();
    assert_eq!(sender.pending_outbox(&a).unwrap().len(), 1);
    sender.set_nickname("Новый Кот").unwrap();
    sender.enqueue_profile(&a).unwrap();
    let second = sender.pending_outbox(&a).unwrap()[1].clone();
    receiver.set_contact_alias(&b, "Мой друг").unwrap();
    assert_eq!(
        receiver.accept_profile(&b, &second).unwrap(),
        AcceptStatus::New
    );
    receiver.accept_profile(&b, &first).unwrap();
    assert_eq!(receiver.contact_names(&b).unwrap().nickname, "Новый Кот");
    assert_eq!(receiver.contact_names(&b).unwrap().alias, "Мой друг");
    assert_eq!(
        receiver.accept_profile(&b, &second).unwrap(),
        AcceptStatus::Duplicate
    );
    assert_eq!(receiver.unread_count(&b).unwrap(), 0);
    assert!(receiver.history(&b, 0).unwrap().is_empty());
    assert!(sender.history(&a, 0).unwrap().is_empty());
    let text = sender.enqueue(&a, "ordinary message").unwrap();
    receiver.accept(&b, &text).unwrap();
    assert_eq!(receiver.unread_count(&b).unwrap(), 1);
    assert_eq!(receiver.history(&b, 0).unwrap()[0].text, "ordinary message");
    drop(receiver);
    let sql = Connection::open(&path).unwrap();
    let blob: Vec<u8> = sql
        .query_row("SELECT record FROM contact_names", [], |r| r.get(0))
        .unwrap();
    assert!(!blob
        .windows("Новый Кот".len())
        .any(|w| w == "Новый Кот".as_bytes()));
    let mut receiver = ClientStore::open(&path, copy(&key)).unwrap();
    assert_eq!(receiver.contact_names(&b).unwrap().alias, "Мой друг");
    sender.set_nickname("").unwrap();
    sender.enqueue_profile(&a).unwrap();
    let latest = sender.pending_outbox(&a).unwrap().pop().unwrap();
    receiver.accept_profile(&b, &latest).unwrap();
    assert_eq!(receiver.contact_names(&b).unwrap().nickname, "");
    assert_eq!(receiver.contact_names(&b).unwrap().alias, "Мой друг");
    receiver.delete_contact(&b).unwrap();
    assert!(matches!(receiver.contact_names(&b), Err(Error::NotFound)));
    assert_eq!(
        sql.query_row("SELECT count(*) FROM contact_names", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn v4_migration_preserves_unread_checks_key_and_rolls_back_on_failure() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("db");
    let key = StorageKey::generate();
    let (mut a, b) = pair();
    let mut store = ClientStore::open(&p, copy(&key)).unwrap();
    let id = store.insert_contact(b).unwrap();
    store
        .accept(&id, &a.encrypt("unread retained").unwrap())
        .unwrap();
    drop(store);
    let sql = Connection::open(&p).unwrap();
    sql.execute_batch("DROP TABLE contact_names; DROP TABLE profile_name; ALTER TABLE messages DROP COLUMN kind; UPDATE store_meta SET version=4;").unwrap();
    assert!(ClientStore::open(&p, StorageKey::generate()).is_err());
    sql.execute_batch("CREATE TRIGGER fail BEFORE UPDATE OF version ON store_meta BEGIN SELECT RAISE(ABORT,'test'); END;").unwrap();
    assert!(ClientStore::open(&p, copy(&key)).is_err());
    assert_eq!(
        sql.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='profile_name'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    sql.execute_batch("DROP TRIGGER fail").unwrap();
    let store = ClientStore::open(&p, copy(&key)).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 1);
    assert_eq!(store.history(&id, 0).unwrap()[0].text, "unread retained");
    assert!(store.profile_name().unwrap().nickname.is_empty());
}
#[test]
fn invalid_profile_frames_and_failed_commits_never_consume_ratchet_or_modify_labels() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("db");
    let (mut a, b) = pair();
    let mut store = ClientStore::open(&p, StorageKey::generate()).unwrap();
    let id = store.insert_contact(b).unwrap();
    for name in ["x\nname", "\u{202e}fake", &"a".repeat(49)] {
        assert!(store.set_nickname(name).is_err());
        assert!(store.set_contact_alias(&id, name).is_err());
    }
    let inner = a.encrypt_profile("Барсик", 1).unwrap();
    let mut raw = b"koto-profile:v1:".to_vec();
    raw.extend(STANDARD.decode(&inner.payload).unwrap());
    let envelope = Envelope {
        id: inner.id.clone(),
        payload: STANDARD.encode(raw),
    };
    let renamed = Envelope {
        id: "a".repeat(32),
        payload: envelope.payload.clone(),
    };
    assert!(store.accept_profile(&id, &renamed).is_err());
    let sql = Connection::open(&p).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER fail BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT,'test'); END;",
    )
    .unwrap();
    assert!(store.accept_profile(&id, &envelope).is_err());
    assert!(store.contact_names(&id).unwrap().nickname.is_empty());
    sql.execute_batch("DROP TRIGGER fail;").unwrap();
    store.accept_profile(&id, &envelope).unwrap();
    assert_eq!(store.contact_names(&id).unwrap().nickname, "Барсик");
    let chat = a.encrypt("this is not a profile").unwrap();
    let mut raw = b"koto-profile:v1:".to_vec();
    raw.extend(STANDARD.decode(&chat.payload).unwrap());
    let fake = Envelope {
        id: chat.id.clone(),
        payload: STANDARD.encode(raw),
    };
    assert!(store.accept_profile(&id, &fake).is_err());
    store.accept(&id, &chat).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 1);
}
#[test]
fn old_text_decoder_can_skip_profile_controls_and_still_receive_chat() {
    let (mut a, mut b) = pair();
    let control = a.encrypt_profile("New nickname", 1).unwrap();
    // 0.2.4 uses exactly this unchanged text decoder, with no profile handler.
    assert!(b.decrypt(&control).is_err());
    assert_eq!(
        b.decrypt(&a.encrypt("text still works").unwrap()).unwrap(),
        "text still works"
    );
}

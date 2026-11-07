use messenger_core::{Contact, StorageKey};
use messenger_store::{AcceptStatus, ClientStore, Direction, Error};
use rusqlite::Connection;
fn copy(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}
fn pair() -> (Contact, Contact) {
    let mut sender = Contact::new();
    let mut receiver = Contact::new();
    let a = sender.public_bundle();
    let b = receiver.public_bundle();
    sender
        .bind_peer(b.clone(), &b.fingerprint().unwrap())
        .unwrap();
    receiver
        .bind_peer(a.clone(), &a.fingerprint().unwrap())
        .unwrap();
    sender.start_session().unwrap();
    (sender, receiver)
}
#[test]
fn count_survives_reopen_and_reading_history_or_ack_retries_does_not_change_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut sender, receiver) = pair();
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    let id = store.insert_contact(receiver).unwrap();
    let first = sender.encrypt("new incoming").unwrap();
    store.accept(&id, &first).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 1);
    let history = store.history(&id, 0).unwrap();
    assert!(history[0].unread);
    assert_eq!(store.unread_count(&id).unwrap(), 1);
    store.enqueue(&id, "outgoing never unread").unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 1);
    assert!(store
        .history(&id, 0)
        .unwrap()
        .iter()
        .filter(|e| e.direction == Direction::Outgoing)
        .all(|e| !e.unread));
    drop(store);
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 1);
    assert_eq!(store.accept(&id, &first).unwrap(), AcceptStatus::Duplicate);
    assert_eq!(store.unread_count(&id).unwrap(), 1);
    store.mark_read(&id, &[history[0].sequence]).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 0);
    // A lost ACK causes redelivery, but must not restore the read flag.
    assert_eq!(store.accept(&id, &first).unwrap(), AcceptStatus::Duplicate);
    assert_eq!(store.unread_count(&id).unwrap(), 0);
    assert_eq!(store.pending_acks(&id).unwrap().len(), 1);
    drop(store);
    let store = ClientStore::open(&path, copy(&key)).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 0);
}
#[test]
fn exact_rows_do_not_clear_unseen_new_arrivals_or_other_conversations_and_failures_roll_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let (mut sender, receiver) = pair();
    let id = store.insert_contact(receiver).unwrap();
    let (mut other_sender, other_receiver) = pair();
    let other = store.insert_contact(other_receiver).unwrap();
    for text in ["visible", "offscreen", "new concurrent arrival"] {
        store.accept(&id, &sender.encrypt(text).unwrap()).unwrap();
    }
    store
        .accept(
            &other,
            &other_sender.encrypt("different conversation").unwrap(),
        )
        .unwrap();
    let history = store.history(&id, 0).unwrap();
    let other_seq = store.history(&other, 0).unwrap()[0].sequence;
    assert!(matches!(
        store.mark_read(&id, &[history[0].sequence, other_seq]),
        Err(Error::NotFound)
    ));
    assert_eq!(store.unread_count(&id).unwrap(), 3);
    store.mark_read(&id, &[history[0].sequence]).unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 2);
    assert_eq!(store.unread_count(&other).unwrap(), 1);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_read BEFORE UPDATE OF unread ON messages WHEN OLD.seq > 1 BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(matches!(
        store.mark_read(&id, &[history[1].sequence, history[2].sequence]),
        Err(Error::Database)
    ));
    assert_eq!(store.unread_count(&id).unwrap(), 2);
    sql.execute_batch("DROP TRIGGER fail_read;").unwrap();
    assert!(matches!(store.mark_read(&id, &[]), Err(Error::InvalidId)));
    assert!(matches!(store.mark_read(&id, &[0]), Err(Error::InvalidId)));
    assert!(matches!(
        store.mark_read(&id, &[history[0].sequence; 101]),
        Err(Error::InvalidId)
    ));
    store
        .mark_read(&id, &[history[1].sequence, history[2].sequence])
        .unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 0);
    store.delete_contact(&id).unwrap();
    assert_eq!(store.unread_count(&other).unwrap(), 1);
    assert!(matches!(store.unread_count(&id), Err(Error::NotFound)));
}
#[test]
fn v3_upgrade_is_key_checked_atomic_and_treats_old_history_as_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut sender, receiver) = pair();
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    let id = store.insert_contact(receiver).unwrap();
    store
        .accept(&id, &sender.encrypt("old history").unwrap())
        .unwrap();
    drop(store);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("DROP TABLE profile_name; DROP TABLE contact_names; ALTER TABLE messages DROP COLUMN kind; DROP INDEX unread_messages; ALTER TABLE messages DROP COLUMN unread; UPDATE store_meta SET version=3;").unwrap();
    assert!(matches!(
        ClientStore::open(&path, StorageKey::generate()),
        Err(Error::InvalidStore)
    ));
    let version = || {
        sql.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(version(), 3);
    sql.execute_batch("CREATE TRIGGER fail_upgrade BEFORE UPDATE OF version ON store_meta BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(matches!(
        ClientStore::open(&path, copy(&key)),
        Err(Error::Database)
    ));
    assert_eq!(version(), 3);
    let columns = sql
        .prepare("PRAGMA table_info(messages)")
        .unwrap()
        .query_map([], |r| r.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(!columns.iter().any(|c| c == "unread"));
    sql.execute_batch("DROP TRIGGER fail_upgrade;").unwrap();
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    assert_eq!(version(), 8);
    assert_eq!(store.unread_count(&id).unwrap(), 0);
    assert_eq!(store.history(&id, 0).unwrap()[0].text, "old history");
    store
        .accept(&id, &sender.encrypt("received after upgrade").unwrap())
        .unwrap();
    assert_eq!(store.unread_count(&id).unwrap(), 1);
}

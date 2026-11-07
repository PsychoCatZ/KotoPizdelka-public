use messenger_core::{Contact, StorageKey};
use messenger_store::{ClientStore, ContactRoute, Error, QueueEndpoint, SetupData};
use rusqlite::Connection;

fn key_copy(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}
fn route() -> ContactRoute {
    ContactRoute {
        send: QueueEndpoint {
            relay_url: "https://relay.example".into(),
            queue_id: "a".repeat(32),
            token: "b".repeat(64),
        },
        receive: QueueEndpoint {
            relay_url: "https://relay.example".into(),
            queue_id: "c".repeat(32),
            token: "d".repeat(64),
        },
    }
}
fn sender() -> Contact {
    let mut contact = Contact::new();
    let peer = Contact::new().public_bundle();
    contact
        .bind_peer(peer.clone(), &peer.fingerprint().unwrap())
        .unwrap();
    contact.start_session().unwrap();
    contact
}

#[test]
fn deletion_removes_history_outbox_keys_and_routes_but_preserves_other_contacts_and_replay_guard() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, key_copy(&key)).unwrap();
    let setup = SetupData {
        replay_tag: Some("e".repeat(64)),
        ready: true,
        payload: b"sensitive setup ticket".to_vec(),
    };
    let route = route();
    let id = store
        .insert_setup_contact(sender(), &route, &setup)
        .unwrap();
    let other = store.insert_contact(sender()).unwrap();
    store.enqueue(&id, "delete only this message").unwrap();
    store.enqueue(&other, "keep this message").unwrap();
    store.delete_contact(&id).unwrap();
    assert_eq!(store.contact_ids().unwrap(), vec![other.clone()]);
    assert!(store.history(&id, 0).unwrap().is_empty());
    assert!(store.pending_outbox(&id).unwrap().is_empty());
    assert!(matches!(store.route(&id), Err(Error::NotFound)));
    assert_eq!(
        store.history(&other, 0).unwrap()[0].text,
        "keep this message"
    );
    assert!(matches!(store.delete_contact(&id), Err(Error::NotFound)));
    drop(store);
    let mut store = ClientStore::open(&path, key_copy(&key)).unwrap();
    assert!(store
        .has_setup_replay(setup.replay_tag.as_deref().unwrap())
        .unwrap());
    assert!(matches!(
        store.insert_setup_contact(sender(), &route, &setup),
        Err(Error::SetupReplay)
    ));
    let sql = Connection::open(&path).unwrap();
    let count: i64 = sql
        .query_row("SELECT count(*) FROM retired_contacts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
    let blob: Vec<u8> = sql
        .query_row("SELECT record FROM retired_contacts", [], |row| row.get(0))
        .unwrap();
    assert!(!blob
        .windows(64)
        .any(|part| part == setup.replay_tag.as_deref().unwrap().as_bytes()));
    // Decrypt the marker to prove that retained data contains no route bearer,
    // profile keys, invitation payload or message history.
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    let db_id: String = sql
        .query_row("SELECT db_id FROM store_meta", [], |row| row.get(0))
        .unwrap();
    let aad = format!("private-messenger.client-store.v1|{db_id}|retired|{id}|");
    let plain = XChaCha20Poly1305::new_from_slice(key.as_bytes())
        .unwrap()
        .decrypt(
            XNonce::from_slice(&blob[1..25]),
            Payload {
                msg: &blob[25..],
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(record.as_object().unwrap().len(), 2);
    assert!(!plain
        .windows(64)
        .any(|part| part == route.receive.token.as_bytes() || part == route.send.token.as_bytes()));
    assert_eq!(store.retired_queues().unwrap().len(), 2);
}

#[test]
fn failed_delete_is_atomic_and_retryable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let setup = SetupData {
        replay_tag: Some("e".repeat(64)),
        ready: true,
        payload: vec![],
    };
    let id = store
        .insert_setup_contact(sender(), &route(), &setup)
        .unwrap();
    store.enqueue(&id, "survive aborted deletion").unwrap();
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_delete BEFORE DELETE ON contacts BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(matches!(store.delete_contact(&id), Err(Error::Database)));
    assert_eq!(store.contact_ids().unwrap(), vec![id.clone()]);
    assert_eq!(store.pending_outbox(&id).unwrap().len(), 1);
    assert!(store.route(&id).is_ok());
    let count: i64 = sql
        .query_row("SELECT count(*) FROM retired_contacts", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    sql.execute_batch("DROP TRIGGER fail_delete;").unwrap();
    store.delete_contact(&id).unwrap();
    assert!(store.contact_ids().unwrap().is_empty());
}

#[test]
fn existing_v2_profile_migrates_only_after_key_check() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, key_copy(&key)).unwrap();
    let id = store.insert_contact(sender()).unwrap();
    store.enqueue(&id, "preserve v2 history").unwrap();
    drop(store);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("DROP TABLE profile_name; DROP TABLE contact_names; ALTER TABLE messages DROP COLUMN kind; DROP INDEX unread_messages; ALTER TABLE messages DROP COLUMN unread; DROP TABLE retired_contacts; UPDATE store_meta SET version=2;")
        .unwrap();
    assert!(matches!(
        ClientStore::open(&path, StorageKey::generate()),
        Err(Error::InvalidStore)
    ));
    let version: i64 = sql
        .query_row("SELECT version FROM store_meta", [], |r| r.get(0))
        .unwrap();
    assert_eq!(version, 2);
    let mut store = ClientStore::open(&path, key_copy(&key)).unwrap();
    assert_eq!(
        store.history(&id, 0).unwrap()[0].text,
        "preserve v2 history"
    );
    store.delete_contact(&id).unwrap();
}

//! Encrypted queue capabilities and authenticated v1 -> v2 migration.
use std::path::Path;

use messenger_core::{Contact, StorageKey};
use messenger_store::{ClientStore, ContactRoute, Error, QueueEndpoint};
use rusqlite::{params, Connection};

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn example_route() -> ContactRoute {
    ContactRoute {
        send: QueueEndpoint {
            relay_url: "https://send.example.test".into(),
            queue_id: "a".repeat(32),
            token: "b".repeat(64),
        },
        receive: QueueEndpoint {
            relay_url: "https://receive.example.test".into(),
            queue_id: "c".repeat(32),
            token: "d".repeat(64),
        },
    }
}

fn fixture(path: &Path, key: &StorageKey) -> (ClientStore, String) {
    let mut store = ClientStore::open(path, copy_key(key)).unwrap();
    let id = store.insert_contact(Contact::new()).unwrap();
    (store, id)
}

fn assert_same_route(actual: &ContactRoute, expected: &ContactRoute) {
    // Boolean assertions avoid printing bearer capabilities on a failure.
    assert!(actual.send.relay_url == expected.send.relay_url);
    assert!(actual.send.queue_id == expected.send.queue_id);
    assert!(actual.send.token == expected.send.token);
    assert!(actual.receive.relay_url == expected.receive.relay_url);
    assert!(actual.receive.queue_id == expected.receive.queue_id);
    assert!(actual.receive.token == expected.receive.token);
}

fn table_exists(sql: &Connection, name: &str) -> bool {
    sql.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
        [name],
        |row| row.get(0),
    )
    .unwrap()
}

fn version(sql: &Connection) -> i64 {
    sql.query_row(
        "SELECT version FROM store_meta WHERE singleton=1",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn state(sql: &Connection, contact: &str) -> Vec<u8> {
    sql.query_row("SELECT state FROM contacts WHERE id=?", [contact], |row| {
        row.get(0)
    })
    .unwrap()
}

fn route_blob(sql: &Connection, contact: &str) -> Vec<u8> {
    sql.query_row(
        "SELECT record FROM routes WHERE contact=?",
        [contact],
        |row| row.get(0),
    )
    .unwrap()
}

fn make_legacy(sql: &Connection) {
    // The encryption domain and sentinel are unchanged between schema versions;
    // removing the new empty table reconstructs an authentic v1 fixture.
    sql.execute_batch(
        "BEGIN IMMEDIATE;
         DROP TABLE profile_name; DROP TABLE contact_names; ALTER TABLE messages DROP COLUMN kind; DROP INDEX unread_messages;
         ALTER TABLE messages DROP COLUMN unread;
         DROP TABLE routes;
         DROP TABLE retired_contacts;
         UPDATE store_meta SET version=1 WHERE singleton=1;
         COMMIT;",
    )
    .unwrap();
}

fn assert_capabilities_absent(dir: &Path, route: &ContactRoute) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for value in [
            &route.send.relay_url,
            &route.send.queue_id,
            &route.send.token,
            &route.receive.relay_url,
            &route.receive.queue_id,
            &route.receive.token,
        ] {
            assert!(!bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes()));
        }
    }
}

#[test]
fn encrypted_route_survives_reopen_without_plaintext_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    let route = example_route();
    assert!(matches!(store.route(&id), Err(Error::NotFound)));
    store.set_route(&id, &route).unwrap();
    assert_same_route(&store.route(&id).unwrap(), &route);
    // Includes the live WAL, not just the checkpointed main database.
    assert_capabilities_absent(dir.path(), &route);
    drop(store);
    let store = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_same_route(&store.route(&id).unwrap(), &route);
    assert_capabilities_absent(dir.path(), &route);
    let sql = Connection::open(&path).unwrap();
    assert_eq!(version(&sql), 8);
}

#[test]
fn valid_legacy_store_migrates_without_changing_ratchet_or_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let mut sender = Contact::new();
    let mut receiver = Contact::new();
    let sender_bundle = sender.public_bundle();
    let receiver_bundle = receiver.public_bundle();
    sender
        .bind_peer(
            receiver_bundle.clone(),
            &receiver_bundle.fingerprint().unwrap(),
        )
        .unwrap();
    receiver
        .bind_peer(sender_bundle.clone(), &sender_bundle.fingerprint().unwrap())
        .unwrap();
    sender.start_session().unwrap();
    let id = store.insert_contact(sender).unwrap();
    let envelope = store
        .enqueue(&id, "outbox survives schema migration")
        .unwrap();
    drop(store);
    let sql = Connection::open(&path).unwrap();
    let before_state = state(&sql, &id);
    make_legacy(&sql);
    assert_eq!(version(&sql), 1);
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_eq!(version(&sql), 8);
    assert!(table_exists(&sql, "routes"));
    assert_eq!(state(&sql, &id), before_state);
    let pending = store.pending_outbox(&id).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].id == envelope.id && pending[0].payload == envelope.payload);
    assert_eq!(
        receiver.decrypt(&pending[0]).unwrap(),
        "outbox survives schema migration"
    );
    assert!(matches!(store.route(&id), Err(Error::NotFound)));
    store.set_route(&id, &example_route()).unwrap();
}

#[test]
fn wrong_key_does_not_migrate_a_legacy_store_or_change_journal_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (store, id) = fixture(&path, &key);
    drop(store);
    let sql = Connection::open(&path).unwrap();
    make_legacy(&sql);
    sql.execute_batch("PRAGMA journal_mode=DELETE;").unwrap();
    let before_state = state(&sql, &id);
    let before_file = std::fs::read(&path).unwrap();
    assert!(matches!(
        ClientStore::open(&path, StorageKey::generate()),
        Err(Error::InvalidStore)
    ));
    assert_eq!(version(&sql), 1);
    assert!(!table_exists(&sql, "routes"));
    assert_eq!(state(&sql, &id), before_state);
    assert_eq!(std::fs::read(&path).unwrap(), before_file);
    let mode: String = sql
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
}

#[test]
fn missing_routes_in_v2_is_rejected_without_repair() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (store, _) = fixture(&path, &key);
    drop(store);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("DROP TABLE routes;").unwrap();
    assert!(matches!(
        ClientStore::open(&path, copy_key(&key)),
        Err(Error::InvalidStore)
    ));
    assert_eq!(version(&sql), 8);
    assert!(!table_exists(&sql, "routes"));
}

#[test]
fn tampered_route_ciphertext_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    store.set_route(&id, &example_route()).unwrap();
    let sql = Connection::open(&path).unwrap();
    let mut blob = route_blob(&sql, &id);
    let last = blob.len() - 1;
    blob[last] ^= 1;
    sql.execute(
        "UPDATE routes SET record=? WHERE contact=?",
        params![blob, id],
    )
    .unwrap();
    assert!(matches!(store.route(&id), Err(Error::InvalidRecord)));
}

#[test]
fn swapping_routes_between_contacts_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, first) = fixture(&path, &key);
    let second = store.insert_contact(Contact::new()).unwrap();
    store.set_route(&first, &example_route()).unwrap();
    store.set_route(&second, &example_route()).unwrap();
    let sql = Connection::open(&path).unwrap();
    let first_blob = route_blob(&sql, &first);
    let second_blob = route_blob(&sql, &second);
    sql.execute(
        "UPDATE routes SET record=? WHERE contact=?",
        params![second_blob, first],
    )
    .unwrap();
    sql.execute(
        "UPDATE routes SET record=? WHERE contact=?",
        params![first_blob, second],
    )
    .unwrap();
    assert!(matches!(store.route(&first), Err(Error::InvalidRecord)));
    assert!(matches!(store.route(&second), Err(Error::InvalidRecord)));
}

#[test]
fn a_second_route_set_cannot_overwrite_capabilities_even_from_another_handle() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    let mut second = ClientStore::open(&path, copy_key(&key)).unwrap();
    let original = example_route();
    store.set_route(&id, &original).unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = route_blob(&sql, &id);
    let mut replacement = original.clone();
    replacement.send.token = "e".repeat(64);
    assert!(matches!(
        second.set_route(&id, &replacement),
        Err(Error::RouteAlreadySet)
    ));
    assert!(matches!(
        store.set_route(&id, &original),
        Err(Error::RouteAlreadySet)
    ));
    assert_eq!(route_blob(&sql, &id), before);
    assert_same_route(&second.route(&id).unwrap(), &original);
}

#[test]
fn unknown_contact_cannot_receive_a_route() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    let unknown = if id == "f".repeat(32) {
        "e".repeat(32)
    } else {
        "f".repeat(32)
    };
    assert!(matches!(
        store.set_route(&unknown, &example_route()),
        Err(Error::NotFound)
    ));
    assert!(matches!(store.route(&unknown), Err(Error::NotFound)));
    assert!(matches!(
        store.set_route("invalid", &example_route()),
        Err(Error::InvalidId)
    ));
    assert!(matches!(store.route("invalid"), Err(Error::InvalidId)));
}

#[test]
fn malformed_queue_ids_tokens_and_url_bounds_are_rejected_without_inserting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    let route = example_route();
    let mut bad = Vec::new();
    let mut item = route.clone();
    item.send.queue_id = "a".repeat(31);
    bad.push(item);
    let mut item = route.clone();
    item.receive.queue_id = "g".repeat(32);
    bad.push(item);
    let mut item = route.clone();
    item.send.token = "b".repeat(63);
    bad.push(item);
    let mut item = route.clone();
    item.receive.token = "D".repeat(64);
    bad.push(item);
    let mut item = route.clone();
    item.send.relay_url.clear();
    bad.push(item);
    let mut item = route.clone();
    item.receive.relay_url = "x".repeat(2049);
    bad.push(item);
    for invalid in bad {
        assert!(matches!(
            store.set_route(&id, &invalid),
            Err(Error::InvalidRoute)
        ));
        assert!(matches!(store.route(&id), Err(Error::NotFound)));
    }
    let mut boundary = route;
    boundary.send.relay_url = format!("https://example.test/{}", "x".repeat(2027));
    assert_eq!(boundary.send.relay_url.len(), 2048);
    store.set_route(&id, &boundary).unwrap();
}

#[test]
fn route_and_endpoint_deserialization_reject_unknown_fields() {
    let route = example_route();
    let mut json = serde_json::to_value(&route).unwrap();
    json["extra"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<ContactRoute>(json).is_err());
    let mut json = serde_json::to_value(&route).unwrap();
    json["send"]["extra"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<ContactRoute>(json).is_err());
}

#[test]
fn aborted_route_insert_rolls_back_and_allows_a_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    let sql = Connection::open(&path).unwrap();
    let before_state = state(&sql, &id);
    sql.execute_batch(
        "CREATE TRIGGER fail_route AFTER INSERT ON routes
         BEGIN SELECT RAISE(ABORT, 'injected route failure'); END;",
    )
    .unwrap();
    assert!(matches!(
        store.set_route(&id, &example_route()),
        Err(Error::Database)
    ));
    assert!(matches!(store.route(&id), Err(Error::NotFound)));
    assert_eq!(state(&sql, &id), before_state);
    sql.execute_batch("DROP TRIGGER fail_route;").unwrap();
    store.set_route(&id, &example_route()).unwrap();
    assert_same_route(&store.route(&id).unwrap(), &example_route());
}

#[test]
fn aborted_migration_rolls_back_table_and_version_then_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (store, id) = fixture(&path, &key);
    drop(store);
    let sql = Connection::open(&path).unwrap();
    make_legacy(&sql);
    let before_state = state(&sql, &id);
    sql.execute_batch(
        "CREATE TRIGGER fail_migration AFTER UPDATE OF version ON store_meta
         BEGIN SELECT RAISE(ABORT, 'injected migration failure'); END;",
    )
    .unwrap();
    assert!(matches!(
        ClientStore::open(&path, copy_key(&key)),
        Err(Error::Database)
    ));
    assert_eq!(version(&sql), 1);
    assert!(!table_exists(&sql, "routes"));
    assert_eq!(state(&sql, &id), before_state);
    sql.execute_batch("DROP TRIGGER fail_migration;").unwrap();
    let store = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_eq!(version(&sql), 8);
    assert!(table_exists(&sql, "routes"));
    assert!(matches!(store.route(&id), Err(Error::NotFound)));
}

#[test]
fn route_insert_is_included_in_global_byte_budget_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut store, id) = fixture(&path, &key);
    let sql = Connection::open(&path).unwrap();
    let state_bytes: i64 = sql
        .query_row("SELECT sum(length(state)) FROM contacts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let remaining = 64 * 1024 * 1024 - state_bytes;
    // Synthetic SQL fixture fills the logical budget without allocating a
    // 64 MiB Rust value; it is never decoded as a real message.
    sql.execute(
        "INSERT INTO messages(contact,direction,id,record,pending) VALUES(?,'out',?,zeroblob(?),0)",
        params![id, "e".repeat(32), remaining],
    )
    .unwrap();
    let before_state = state(&sql, &id);
    assert!(matches!(
        store.set_route(&id, &example_route()),
        Err(Error::QuotaExceeded)
    ));
    assert!(matches!(store.route(&id), Err(Error::NotFound)));
    assert_eq!(state(&sql, &id), before_state);
}

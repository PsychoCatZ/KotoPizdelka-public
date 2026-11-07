//! Transactional, encrypted invitation state and permanent replay markers.
use std::path::Path;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use messenger_core::{Contact, PublicBundle, StorageKey};
use messenger_store::{
    ClientStore, ContactRoute, Error, QueueEndpoint, SetupCompletion, SetupData,
};
use rusqlite::{params, Connection};

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn route() -> ContactRoute {
    ContactRoute {
        send: QueueEndpoint {
            relay_url: "https://invitation-send.example.test".into(),
            queue_id: "a".repeat(32),
            token: "b".repeat(64),
        },
        receive: QueueEndpoint {
            relay_url: "https://invitation-receive.example.test".into(),
            queue_id: "c".repeat(32),
            token: "d".repeat(64),
        },
    }
}

fn setup(tag: char) -> SetupData {
    SetupData {
        replay_tag: Some(tag.to_string().repeat(64)),
        payload: b"private invitation that survives restarts and retries".to_vec(),
        ready: false,
    }
}

fn completion(expected: &SetupData, peer: &PublicBundle) -> SetupCompletion {
    let mut replacement = expected.clone();
    replacement.ready = true;
    replacement.payload = b"retained authenticated reply".to_vec();
    let mut completed_route = route();
    completed_route.send.queue_id = "e".repeat(32);
    completed_route.send.token = "f".repeat(64);
    SetupCompletion {
        expected: expected.clone(),
        replacement,
        peer: peer.clone(),
        trusted_fingerprint: peer.fingerprint().unwrap(),
        initiate: true,
        route: completed_route,
    }
}

fn record(sql: &Connection, table: &str, column: &str, contact: &str) -> Vec<u8> {
    let selector = if table == "contacts" { "id" } else { "contact" };
    sql.query_row(
        &format!("SELECT {column} FROM {table} WHERE {selector}=?"),
        [contact],
        |row| row.get(0),
    )
    .unwrap()
}

fn route_plain(sql: &Connection, key: &StorageKey, contact: &str) -> serde_json::Value {
    let blob = record(sql, "routes", "record", contact);
    let db_id: String = sql
        .query_row("SELECT db_id FROM store_meta", [], |r| r.get(0))
        .unwrap();
    let aad = format!("private-messenger.client-store.v1|{db_id}|route|{contact}|");
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap();
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&blob[1..25]),
            Payload {
                msg: &blob[25..],
                aad: aad.as_bytes(),
            },
        )
        .unwrap();
    serde_json::from_slice(&plain).unwrap()
}

fn counts(sql: &Connection) -> (i64, i64) {
    sql.query_row(
        "SELECT (SELECT count(*) FROM contacts),(SELECT count(*) FROM routes)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

fn assert_route(actual: &ContactRoute, expected: &ContactRoute) {
    assert!(serde_json::to_vec(actual).unwrap() == serde_json::to_vec(expected).unwrap());
}

fn assert_private(dir: &Path, route: &ContactRoute, setup: &SetupData) {
    let serialized_payload = serde_json::to_vec(&setup.payload).unwrap();
    let mut values: Vec<&[u8]> = vec![
        route.send.relay_url.as_bytes(),
        route.send.queue_id.as_bytes(),
        route.send.token.as_bytes(),
        route.receive.relay_url.as_bytes(),
        route.receive.queue_id.as_bytes(),
        route.receive.token.as_bytes(),
        &serialized_payload,
    ];
    if let Some(tag) = &setup.replay_tag {
        values.push(tag.as_bytes());
    }
    for entry in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for value in &values {
            assert!(!bytes.windows(value.len()).any(|window| window == *value));
        }
    }
}

#[test]
fn legacy_route_json_remains_unchanged_and_is_ready_without_setup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let id = store.insert_contact(Contact::new()).unwrap();
    let route = route();
    store.set_route(&id, &route).unwrap();
    let sql = Connection::open(&path).unwrap();
    let plain = route_plain(&sql, &key, &id);
    assert!(plain == serde_json::to_value(&route).unwrap());
    assert_eq!(
        sql.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        8
    );
    drop(store);
    let store = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_route(&store.route(&id).unwrap(), &route);
    assert!(store.setup_records().unwrap().is_empty());
}

#[test]
fn pending_setup_is_encrypted_reopens_and_hides_unready_route() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let route = route();
    let setup = setup('1');
    let id = store
        .insert_setup_contact(Contact::new(), &route, &setup)
        .unwrap();
    assert!(matches!(store.route(&id), Err(Error::SetupPending)));
    assert_private(dir.path(), &route, &setup);
    drop(store);
    let store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let setups = store.setup_records().unwrap();
    assert!(setups.len() == 1 && setups[0].0 == id && setups[0].1 == setup);
    assert!(matches!(store.route(&id), Err(Error::SetupPending)));
    assert_private(dir.path(), &route, &setup);
}

#[test]
fn ready_import_keeps_replay_marker_and_available_route() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let mut setup = setup('2');
    setup.ready = true;
    let route = route();
    let id = store
        .insert_setup_contact(Contact::new(), &route, &setup)
        .unwrap();
    assert_route(&store.route(&id).unwrap(), &route);
    drop(store);
    let mut first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let mut second = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert!(matches!(
        first.insert_setup_contact(Contact::new(), &route, &setup),
        Err(Error::SetupReplay)
    ));
    assert!(matches!(
        second.insert_setup_contact(Contact::new(), &route, &setup),
        Err(Error::SetupReplay)
    ));
    assert!(first.setup_records().unwrap()[0].1 == setup);
    assert_eq!(first.contact_ids().unwrap().len(), 1);
}

#[test]
fn simultaneous_imports_have_only_one_winning_replay_marker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let second = ClientStore::open(&path, copy_key(&key)).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [first, second]
        .into_iter()
        .map(|mut store| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.insert_setup_contact(Contact::new(), &route(), &setup('3'))
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::SetupReplay)))
            .count(),
        1
    );
}

#[test]
fn failed_route_insert_rolls_back_contact_and_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_route BEFORE INSERT ON routes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    let setup = setup('4');
    assert!(matches!(
        store.insert_setup_contact(Contact::new(), &route(), &setup),
        Err(Error::Database)
    ));
    assert_eq!(counts(&sql), (0, 0));
    sql.execute_batch("DROP TRIGGER fail_route;").unwrap();
    store
        .insert_setup_contact(Contact::new(), &route(), &setup)
        .unwrap();
    assert_eq!(counts(&sql), (1, 1));
}

#[test]
fn contact_and_byte_quotas_roll_back_setup_insert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let sql = Connection::open(&path).unwrap();
    let id = store.insert_contact(Contact::new()).unwrap();
    sql.execute("INSERT INTO messages(contact,direction,id,record,pending) VALUES(?,'out',?,zeroblob(67108864),0)", params![id, "1".repeat(32)]).unwrap();
    assert!(matches!(
        store.insert_setup_contact(Contact::new(), &route(), &setup('5')),
        Err(Error::QuotaExceeded)
    ));
    assert_eq!(counts(&sql), (1, 0));
    sql.execute("DELETE FROM messages", []).unwrap();
    for _ in 1..128 {
        store.insert_contact(Contact::new()).unwrap();
    }
    assert!(matches!(
        store.insert_setup_contact(Contact::new(), &route(), &setup('5')),
        Err(Error::QuotaExceeded)
    ));
    assert_eq!(counts(&sql), (128, 0));
}

#[test]
fn completing_sql_failure_rolls_back_peer_route_and_setup_then_retry_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let expected = setup('6');
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let state = record(&sql, "contacts", "state", &id);
    let route_blob = record(&sql, "routes", "record", &id);
    let mut peer = Contact::new();
    let peer_bundle = peer.public_bundle();
    let local = store.public_bundle(&id).unwrap();
    peer.bind_peer(local.clone(), &local.fingerprint().unwrap())
        .unwrap();
    sql.execute_batch("CREATE TRIGGER fail_route BEFORE UPDATE ON routes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(matches!(
        store.complete_setup_contact(&id, completion(&expected, &peer_bundle)),
        Err(Error::Database)
    ));
    assert!(record(&sql, "contacts", "state", &id) == state);
    assert!(record(&sql, "routes", "record", &id) == route_blob);
    assert!(store.setup_records().unwrap()[0].1 == expected);
    assert!(matches!(store.route(&id), Err(Error::SetupPending)));
    sql.execute_batch("DROP TRIGGER fail_route;").unwrap();
    store
        .complete_setup_contact(&id, completion(&expected, &peer_bundle))
        .unwrap();
    assert_route(
        &store.route(&id).unwrap(),
        &completion(&expected, &peer_bundle).route,
    );
    let replacement = completion(&expected, &peer_bundle).replacement;
    assert!(store.setup_records().unwrap()[0].1 == replacement);
    let envelope = store
        .enqueue(&id, "atomic setup established a session")
        .unwrap();
    assert_eq!(
        peer.decrypt(&envelope).unwrap(),
        "atomic setup established a session"
    );
    assert!(matches!(
        store.complete_setup_contact(&id, completion(&expected, &peer_bundle)),
        Err(Error::SetupConflict)
    ));
    assert!(matches!(
        store.complete_setup_contact(&id, completion(&replacement, &peer_bundle)),
        Err(Error::SetupConflict)
    ));
    assert!(matches!(
        store.insert_setup_contact(Contact::new(), &route(), &expected),
        Err(Error::SetupReplay)
    ));
}

#[test]
fn stale_setup_changed_receive_tag_or_readiness_cannot_complete() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let expected = setup('7');
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let peer = Contact::new().public_bundle();
    let sql = Connection::open(&path).unwrap();
    let state = record(&sql, "contacts", "state", &id);
    let blob = record(&sql, "routes", "record", &id);
    let mut wrong_expected = completion(&expected, &peer);
    wrong_expected.expected.payload.push(0);
    let mut wrong_receive = completion(&expected, &peer);
    wrong_receive.route.receive.token = "e".repeat(64);
    let mut wrong_tag = completion(&expected, &peer);
    wrong_tag.replacement.replay_tag = Some("8".repeat(64));
    let mut still_pending = completion(&expected, &peer);
    still_pending.replacement.ready = false;
    for candidate in [wrong_expected, wrong_receive, wrong_tag, still_pending] {
        assert!(matches!(
            store.complete_setup_contact(&id, candidate),
            Err(Error::SetupConflict)
        ));
        assert!(record(&sql, "contacts", "state", &id) == state);
        assert!(record(&sql, "routes", "record", &id) == blob);
    }
    let mut wrong_fingerprint = completion(&expected, &peer);
    wrong_fingerprint.trusted_fingerprint = "9".repeat(64);
    assert!(matches!(
        store.complete_setup_contact(&id, wrong_fingerprint),
        Err(Error::Crypto(messenger_core::Error::FingerprintMismatch))
    ));
    assert!(record(&sql, "contacts", "state", &id) == state);
    assert!(record(&sql, "routes", "record", &id) == blob);
}

#[test]
fn sealed_setup_cannot_be_swapped_between_contacts_or_databases() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("first.sqlite");
    let key = StorageKey::generate();
    let mut first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let left = first
        .insert_setup_contact(Contact::new(), &route(), &setup('a'))
        .unwrap();
    let right = first
        .insert_setup_contact(Contact::new(), &route(), &setup('b'))
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let left_blob = record(&sql, "routes", "record", &left);
    sql.execute(
        "UPDATE routes SET record=? WHERE contact=?",
        params![left_blob, right],
    )
    .unwrap();
    assert!(matches!(first.route(&right), Err(Error::InvalidRecord)));
    assert!(matches!(first.setup_records(), Err(Error::InvalidRecord)));
    let other_path = dir.path().join("second.sqlite");
    let mut second = ClientStore::open(&other_path, copy_key(&key)).unwrap();
    let other_id = second
        .insert_setup_contact(Contact::new(), &route(), &setup('c'))
        .unwrap();
    let other_sql = Connection::open(&other_path).unwrap();
    // Keep the original contact ID as well to isolate the database AAD binding.
    other_sql.execute("PRAGMA foreign_keys=OFF", []).unwrap();
    other_sql
        .execute(
            "UPDATE contacts SET id=? WHERE id=?",
            params![left, other_id],
        )
        .unwrap();
    other_sql
        .execute(
            "UPDATE routes SET contact=?,record=? WHERE contact=?",
            params![left, left_blob, other_id],
        )
        .unwrap();
    assert!(matches!(second.route(&left), Err(Error::InvalidRecord)));
    assert!(matches!(second.setup_records(), Err(Error::InvalidRecord)));
}

#[test]
fn setup_bounds_fail_without_writes_and_maximum_payload_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let mut oversized = setup('d');
    oversized.payload = vec![0; 8193];
    let mut uppercase = setup('d');
    uppercase.replay_tag = Some("D".repeat(64));
    let mut short = setup('d');
    short.replay_tag = Some("d".repeat(63));
    for invalid in [oversized, uppercase, short] {
        assert!(matches!(
            store.insert_setup_contact(Contact::new(), &route(), &invalid),
            Err(Error::InvalidSetup)
        ));
    }
    assert!(store.contact_ids().unwrap().is_empty());
    let mut maximum = setup('d');
    maximum.payload = vec![255; 8192];
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &maximum)
        .unwrap();
    let records = store.setup_records().unwrap();
    assert!(records.len() == 1 && records[0].0 == id && records[0].1 == maximum);
}

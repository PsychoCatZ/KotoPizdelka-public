//! Compare-and-set progress for durable setup jobs, without changing a session.
use std::path::Path;

use messenger_core::{Contact, StorageKey};
use messenger_store::{ClientStore, ContactRoute, Error, QueueEndpoint, SetupData};
use rusqlite::{params, Connection};

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn route() -> ContactRoute {
    ContactRoute {
        send: QueueEndpoint {
            relay_url: "https://setup-job-send.example.test".into(),
            queue_id: "a".repeat(32),
            token: "b".repeat(64),
        },
        receive: QueueEndpoint {
            relay_url: "https://setup-job-receive.example.test".into(),
            queue_id: "c".repeat(32),
            token: "d".repeat(64),
        },
    }
}

fn setup(ready: bool) -> SetupData {
    SetupData {
        replay_tag: Some("e".repeat(64)),
        payload: b"private setup job before queue provisioning".to_vec(),
        ready,
    }
}

fn replacement(expected: &SetupData) -> SetupData {
    let mut replacement = expected.clone();
    replacement.payload = b"private setup job with provisioned queue capability".to_vec();
    replacement
}

fn blob(sql: &Connection, table: &str, id: &str) -> Vec<u8> {
    let (column, selector) = if table == "contacts" {
        ("state", "id")
    } else {
        ("record", "contact")
    };
    sql.query_row(
        &format!("SELECT {column} FROM {table} WHERE {selector}=?"),
        [id],
        |row| row.get(0),
    )
    .unwrap()
}

fn assert_setup(store: &ClientStore, id: &str, expected: &SetupData) {
    let records = store.setup_records().unwrap();
    assert!(records.len() == 1 && records[0].0 == id && records[0].1 == *expected);
}

fn assert_private(dir: &Path, route: &ContactRoute, setup: &SetupData) {
    let serialized_payload = serde_json::to_vec(&setup.payload).unwrap();
    let mut secrets: Vec<&[u8]> = vec![
        route.send.relay_url.as_bytes(),
        route.send.queue_id.as_bytes(),
        route.send.token.as_bytes(),
        route.receive.relay_url.as_bytes(),
        route.receive.queue_id.as_bytes(),
        route.receive.token.as_bytes(),
        &setup.payload,
        &serialized_payload,
    ];
    if let Some(tag) = &setup.replay_tag {
        secrets.push(tag.as_bytes());
    }
    for entry in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in &secrets {
            assert!(!bytes.windows(secret.len()).any(|window| window == *secret));
        }
    }
}

#[test]
fn updates_use_fresh_state_across_two_handles_and_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let expected = setup(false);
    let id = first
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let mut second = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_setup(&second, &id, &expected);
    let updated = replacement(&expected);
    first.update_setup_data(&id, &expected, &updated).unwrap();
    assert!(matches!(
        second.update_setup_data(&id, &expected, &updated),
        Err(Error::SetupConflict)
    ));
    assert_setup(&second, &id, &updated);
    let mut next = updated.clone();
    next.payload.extend_from_slice(b" and response saved");
    second.update_setup_data(&id, &updated, &next).unwrap();
    assert_setup(&first, &id, &next);
    assert!(matches!(first.route(&id), Err(Error::SetupPending)));
    drop(first);
    drop(second);
    let reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_setup(&reopened, &id, &next);
}

#[test]
fn simultaneous_compare_and_set_has_one_winning_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let expected = setup(false);
    let id = first
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let second = ClientStore::open(&path, copy_key(&key)).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [first, second]
        .into_iter()
        .enumerate()
        .map(|(index, mut store)| {
            let barrier = barrier.clone();
            let id = id.clone();
            let expected = expected.clone();
            let mut updated = replacement(&expected);
            updated.payload.push(index as u8);
            std::thread::spawn(move || {
                barrier.wait();
                let result = store.update_setup_data(&id, &expected, &updated);
                (result, updated)
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        results.iter().filter(|(result, _)| result.is_ok()).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(result, _)| matches!(result, Err(Error::SetupConflict)))
            .count(),
        1
    );
    let winner = &results.iter().find(|(result, _)| result.is_ok()).unwrap().1;
    let reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_setup(&reopened, &id, winner);
}

#[test]
fn readiness_replay_marker_and_stale_payload_cannot_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let expected = setup(false);
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let state = blob(&sql, "contacts", &id);
    let original = blob(&sql, "routes", &id);
    let mut wrong_tag = replacement(&expected);
    wrong_tag.replay_tag = Some("f".repeat(64));
    let mut missing_tag = replacement(&expected);
    missing_tag.replay_tag = None;
    let mut wrong_ready = replacement(&expected);
    wrong_ready.ready = true;
    for changed in [wrong_tag, missing_tag, wrong_ready] {
        assert!(matches!(
            store.update_setup_data(&id, &expected, &changed),
            Err(Error::SetupConflict)
        ));
    }
    let mut stale = expected.clone();
    stale.payload.push(0);
    assert!(matches!(
        store.update_setup_data(&id, &stale, &replacement(&expected)),
        Err(Error::SetupConflict)
    ));
    assert!(blob(&sql, "contacts", &id) == state);
    assert!(blob(&sql, "routes", &id) == original);
    assert_setup(&store, &id, &expected);
}

#[test]
fn sql_failure_rolls_back_setup_then_the_same_update_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let expected = setup(false);
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let original = blob(&sql, "routes", &id);
    let state = blob(&sql, "contacts", &id);
    sql.execute_batch("CREATE TRIGGER fail_setup AFTER UPDATE ON routes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    let updated = replacement(&expected);
    assert!(matches!(
        store.update_setup_data(&id, &expected, &updated),
        Err(Error::Database)
    ));
    assert!(blob(&sql, "routes", &id) == original);
    assert!(blob(&sql, "contacts", &id) == state);
    assert_setup(&store, &id, &expected);
    sql.execute_batch("DROP TRIGGER fail_setup;").unwrap();
    store.update_setup_data(&id, &expected, &updated).unwrap();
    assert_setup(&store, &id, &updated);
    assert!(blob(&sql, "contacts", &id) == state);
}

#[test]
fn quota_failure_after_update_rolls_back_payload_and_allows_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let expected = setup(false);
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let original = blob(&sql, "routes", &id);
    sql.execute("INSERT INTO messages(contact,direction,id,record,pending) VALUES(?,'out',?,zeroblob(67108864),0)", params![id, "1".repeat(32)]).unwrap();
    let updated = replacement(&expected);
    assert!(matches!(
        store.update_setup_data(&id, &expected, &updated),
        Err(Error::QuotaExceeded)
    ));
    assert!(blob(&sql, "routes", &id) == original);
    assert_setup(&store, &id, &expected);
    sql.execute("DELETE FROM messages", []).unwrap();
    store.update_setup_data(&id, &expected, &updated).unwrap();
    assert_setup(&store, &id, &updated);
}

#[test]
fn ready_update_preserves_endpoints_exact_outbox_and_ratchet() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let mut local = Contact::new();
    let mut peer = Contact::new();
    let local_bundle = local.public_bundle();
    let peer_bundle = peer.public_bundle();
    local
        .bind_peer(peer_bundle.clone(), &peer_bundle.fingerprint().unwrap())
        .unwrap();
    peer.bind_peer(local_bundle.clone(), &local_bundle.fingerprint().unwrap())
        .unwrap();
    local.start_session().unwrap();
    let expected = setup(true);
    let route = route();
    let id = store
        .insert_setup_contact(local, &route, &expected)
        .unwrap();
    let first = store.enqueue(&id, "before setup payload update").unwrap();
    assert_eq!(peer.decrypt(&first).unwrap(), "before setup payload update");
    let sql = Connection::open(&path).unwrap();
    let state = blob(&sql, "contacts", &id);
    let updated = replacement(&expected);
    store.update_setup_data(&id, &expected, &updated).unwrap();
    assert!(blob(&sql, "contacts", &id) == state);
    assert!(
        serde_json::to_vec(&store.route(&id).unwrap()).unwrap()
            == serde_json::to_vec(&route).unwrap()
    );
    let pending = store.pending_outbox(&id).unwrap();
    assert!(pending.len() == 1 && pending[0].id == first.id && pending[0].payload == first.payload);
    assert_private(dir.path(), &route, &expected);
    assert_private(dir.path(), &route, &updated);
    drop(store);
    let mut reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_setup(&reopened, &id, &updated);
    let next = reopened.enqueue(&id, "after setup payload update").unwrap();
    assert_eq!(peer.decrypt(&next).unwrap(), "after setup payload update");
}

#[test]
fn invalid_payload_bounds_do_not_write_and_maximum_payload_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let expected = setup(false);
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let original = blob(&sql, "routes", &id);
    let mut oversized = replacement(&expected);
    oversized.payload = vec![0; 8193];
    assert!(matches!(
        store.update_setup_data(&id, &expected, &oversized),
        Err(Error::InvalidSetup)
    ));
    assert!(matches!(
        store.update_setup_data(&id, &oversized, &replacement(&expected)),
        Err(Error::InvalidSetup)
    ));
    let mut invalid_tag = replacement(&expected);
    invalid_tag.replay_tag = Some("E".repeat(64));
    assert!(matches!(
        store.update_setup_data(&id, &expected, &invalid_tag),
        Err(Error::InvalidSetup)
    ));
    assert!(blob(&sql, "routes", &id) == original);
    let mut maximum = replacement(&expected);
    maximum.payload = vec![255; 8192];
    store.update_setup_data(&id, &expected, &maximum).unwrap();
    assert_setup(&store, &id, &maximum);
}

#[test]
fn missing_setup_missing_contact_and_corrupted_contact_fail_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let expected = setup(false);
    let updated = replacement(&expected);
    assert!(matches!(
        store.update_setup_data("invalid", &expected, &updated),
        Err(Error::InvalidId)
    ));
    assert!(matches!(
        store.update_setup_data(&"1".repeat(32), &expected, &updated),
        Err(Error::NotFound)
    ));
    let legacy = store.insert_contact(Contact::new()).unwrap();
    store.set_route(&legacy, &route()).unwrap();
    assert!(matches!(
        store.update_setup_data(&legacy, &expected, &updated),
        Err(Error::SetupConflict)
    ));
    let id = store
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let original = blob(&sql, "routes", &id);
    sql.execute("UPDATE contacts SET state=x'00' WHERE id=?", [&id])
        .unwrap();
    assert!(matches!(
        store.update_setup_data(&id, &expected, &updated),
        Err(Error::InvalidRecord)
    ));
    assert!(blob(&sql, "routes", &id) == original);
}

#[test]
fn contact_listing_detects_rows_over_the_contact_quota() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store.insert_contact(Contact::new()).unwrap();
    let sql = Connection::open(&path).unwrap();
    let state = blob(&sql, "contacts", &id);
    for index in 0..128 {
        sql.execute(
            "INSERT INTO contacts(id,state) VALUES(?,?)",
            params![format!("{index:032x}"), state],
        )
        .unwrap();
    }
    assert!(matches!(store.contact_ids(), Err(Error::InvalidRecord)));
}

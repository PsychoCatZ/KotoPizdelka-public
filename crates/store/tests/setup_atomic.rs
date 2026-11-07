//! Setup controls advance crypto and durable setup together, without chat rows.
use std::{cell::Cell, path::Path};

use messenger_core::{Contact, Envelope, StorageKey};
use messenger_store::{ClientStore, ContactRoute, Error, QueueEndpoint, SetupData};
use rusqlite::{params, Connection};

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn route() -> ContactRoute {
    ContactRoute {
        send: QueueEndpoint {
            relay_url: "https://atomic-setup-send.example.test".into(),
            queue_id: "a".repeat(32),
            token: "b".repeat(64),
        },
        receive: QueueEndpoint {
            relay_url: "https://atomic-setup-receive.example.test".into(),
            queue_id: "c".repeat(32),
            token: "d".repeat(64),
        },
    }
}

fn setup(ready: bool) -> SetupData {
    SetupData {
        replay_tag: Some("e".repeat(64)),
        payload: b"private setup before the authenticated control".to_vec(),
        ready,
    }
}

fn pair() -> (Contact, Contact, String, String) {
    let mut local = Contact::new();
    let mut peer = Contact::new();
    let local_bundle = local.public_bundle();
    let peer_bundle = peer.public_bundle();
    let offer = local_bundle.fingerprint().unwrap();
    let reply = peer_bundle.fingerprint().unwrap();
    local.bind_peer_from_invitation(peer_bundle).unwrap();
    peer.bind_peer_from_invitation(local_bundle).unwrap();
    (local, peer, offer, reply)
}

fn snapshot_rows(sql: &Connection, id: &str) -> (Vec<u8>, Vec<u8>) {
    sql.query_row(
        "SELECT state,record FROM contacts JOIN routes ON id=contact WHERE id=?",
        [id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .unwrap()
}

fn assert_setup(store: &ClientStore, id: &str, expected: &SetupData) {
    let records = store.setup_records().unwrap();
    assert!(records.len() == 1 && records[0].0 == id && records[0].1 == *expected);
}

fn assert_no_chat_rows(store: &ClientStore, id: &str, sql: &Connection) {
    assert!(store.history(id, 0).unwrap().is_empty());
    assert!(store.pending_outbox(id).unwrap().is_empty());
    assert!(store.pending_acks(id).unwrap().is_empty());
    assert_eq!(
        sql.query_row("SELECT count(*) FROM messages", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

fn changed_send(route: &mut ContactRoute) {
    route.send.relay_url = "https://atomic-setup-provisioned.example.test".into();
    route.send.queue_id = "f".repeat(32);
    route.send.token = "1".repeat(64);
}

fn save_control(
    store: &mut ClientStore,
    id: &str,
    expected: &SetupData,
    offer: &str,
    reply: &str,
) -> messenger_store::Result<Envelope> {
    store.update_setup_contact_atomic(id, expected, |contact, setup, route| {
        let control = contact.encrypt_setup_control(offer, reply)?;
        setup.payload = serde_json::to_vec(&control).unwrap();
        setup.ready = true;
        changed_send(route);
        Ok(control)
    })
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
fn saved_control_and_both_ratchet_directions_survive_reopen_without_chat_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut local, mut peer, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    let control = save_control(&mut store, &id, &expected, &offer, &reply).unwrap();
    let after = snapshot_rows(&sql, &id);
    assert_ne!(after.0, before.0);
    assert_ne!(after.1, before.1);
    let mut sent = expected.clone();
    sent.payload = serde_json::to_vec(&control).unwrap();
    sent.ready = true;
    assert_setup(&store, &id, &sent);
    let mut provisioned = route();
    changed_send(&mut provisioned);
    assert!(
        serde_json::to_vec(&store.route(&id).unwrap()).unwrap()
            == serde_json::to_vec(&provisioned).unwrap()
    );
    assert_no_chat_rows(&store, &id, &sql);
    assert_private(dir.path(), &provisioned, &sent);
    drop(store);

    let mut reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    assert_setup(&reopened, &id, &sent);
    let persisted: Envelope = serde_json::from_slice(&sent.payload).unwrap();
    assert!(persisted.id == control.id && persisted.payload == control.payload);
    peer.decrypt_setup_control(&persisted, &offer, &reply)
        .unwrap();
    let response = peer.encrypt_setup_control(&offer, &reply).unwrap();
    reopened
        .update_setup_contact_atomic(&id, &sent, |contact, setup, _| {
            contact.decrypt_setup_control(&response, &offer, &reply)?;
            setup.payload = b"authenticated setup response saved atomically".to_vec();
            Ok(())
        })
        .unwrap();
    assert_no_chat_rows(&reopened, &id, &sql);
    drop(reopened);

    let mut reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    let next = reopened
        .enqueue(&id, "chat after both setup controls and two restarts")
        .unwrap();
    assert_eq!(
        peer.decrypt(&next).unwrap(),
        "chat after both setup controls and two restarts"
    );
}

#[test]
fn outgoing_sql_failure_rolls_back_both_records_and_same_expected_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let (mut local, mut peer, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    sql.execute_batch("CREATE TRIGGER fail_atomic AFTER UPDATE ON routes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(matches!(
        save_control(&mut store, &id, &expected, &offer, &reply),
        Err(Error::Database)
    ));
    assert_eq!(snapshot_rows(&sql, &id), before);
    assert_setup(&store, &id, &expected);
    assert_no_chat_rows(&store, &id, &sql);
    sql.execute_batch("DROP TRIGGER fail_atomic;").unwrap();
    let control = save_control(&mut store, &id, &expected, &offer, &reply).unwrap();
    peer.decrypt_setup_control(&control, &offer, &reply)
        .unwrap();
    let chat = store
        .enqueue(&id, "retry preserved outgoing ratchet")
        .unwrap();
    assert_eq!(
        peer.decrypt(&chat).unwrap(),
        "retry preserved outgoing ratchet"
    );
}

#[test]
fn new_peer_binding_and_first_session_are_atomic_with_the_saved_control() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let local = Contact::new();
    let local_bundle = local.public_bundle();
    let mut peer = Contact::new();
    let peer_bundle = peer.public_bundle();
    let offer = local_bundle.fingerprint().unwrap();
    let reply = peer_bundle.fingerprint().unwrap();
    peer.bind_peer_from_invitation(local_bundle).unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    let apply = |contact: &mut Contact, setup: &mut SetupData, route: &mut ContactRoute| {
        contact.bind_peer_from_invitation(peer_bundle.clone())?;
        contact.start_session()?;
        let control = contact.encrypt_setup_control(&offer, &reply)?;
        setup.payload = serde_json::to_vec(&control).unwrap();
        setup.ready = true;
        changed_send(route);
        Ok(control)
    };
    sql.execute_batch("CREATE TRIGGER fail_atomic AFTER UPDATE ON routes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert!(matches!(
        store.update_setup_contact_atomic(&id, &expected, apply),
        Err(Error::Database)
    ));
    assert_eq!(snapshot_rows(&sql, &id), before);
    assert_setup(&store, &id, &expected);
    sql.execute_batch("DROP TRIGGER fail_atomic;").unwrap();
    let control = store
        .update_setup_contact_atomic(&id, &expected, apply)
        .unwrap();
    assert_no_chat_rows(&store, &id, &sql);
    peer.decrypt_setup_control(&control, &offer, &reply)
        .unwrap();
    drop(store);
    let mut reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    let message = reopened
        .enqueue(&id, "bound session survives atomic setup and reopen")
        .unwrap();
    assert_eq!(
        peer.decrypt(&message).unwrap(),
        "bound session survives atomic setup and reopen"
    );
}

#[test]
fn inbound_sql_failure_preserves_one_time_key_and_same_control_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let (local, mut peer, offer, reply) = pair();
    peer.start_session().unwrap();
    let control = peer.encrypt_setup_control(&offer, &reply).unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    sql.execute_batch("CREATE TRIGGER fail_atomic AFTER UPDATE ON routes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    let apply = |contact: &mut Contact, setup: &mut SetupData, route: &mut ContactRoute| {
        contact.decrypt_setup_control(&control, &offer, &reply)?;
        setup.payload = b"inbound control was authenticated".to_vec();
        setup.ready = true;
        changed_send(route);
        Ok(())
    };
    assert!(matches!(
        store.update_setup_contact_atomic(&id, &expected, apply),
        Err(Error::Database)
    ));
    assert_eq!(snapshot_rows(&sql, &id), before);
    assert_setup(&store, &id, &expected);
    assert_no_chat_rows(&store, &id, &sql);
    sql.execute_batch("DROP TRIGGER fail_atomic;").unwrap();
    store
        .update_setup_contact_atomic(&id, &expected, apply)
        .unwrap();
    assert_no_chat_rows(&store, &id, &sql);
    let chat = store
        .enqueue(&id, "retry preserved inbound session")
        .unwrap();
    assert_eq!(
        peer.decrypt(&chat).unwrap(),
        "retry preserved inbound session"
    );
}

#[test]
fn quota_failure_rolls_back_crypto_and_setup_then_same_update_retries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let (mut local, mut peer, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    sql.execute("INSERT INTO messages(contact,direction,id,record,pending) VALUES(?,'out',?,zeroblob(67108864),0)", params![id, "2".repeat(32)]).unwrap();
    assert!(matches!(
        save_control(&mut store, &id, &expected, &offer, &reply),
        Err(Error::QuotaExceeded)
    ));
    assert_eq!(snapshot_rows(&sql, &id), before);
    assert_setup(&store, &id, &expected);
    sql.execute("DELETE FROM messages", []).unwrap();
    assert_no_chat_rows(&store, &id, &sql);
    let control = save_control(&mut store, &id, &expected, &offer, &reply).unwrap();
    peer.decrypt_setup_control(&control, &offer, &reply)
        .unwrap();
    assert_no_chat_rows(&store, &id, &sql);
}

#[test]
fn closure_error_after_crypto_mutation_writes_neither_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let (mut local, mut peer, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    let result: messenger_store::Result<()> =
        store.update_setup_contact_atomic(&id, &expected, |contact, setup, route| {
            contact.encrypt_setup_control(&offer, &reply)?;
            setup.payload = b"must not be saved".to_vec();
            setup.ready = true;
            changed_send(route);
            Err(Error::InvalidRecord)
        });
    assert!(matches!(result, Err(Error::InvalidRecord)));
    assert_eq!(snapshot_rows(&sql, &id), before);
    assert_setup(&store, &id, &expected);
    assert_no_chat_rows(&store, &id, &sql);
    let control = save_control(&mut store, &id, &expected, &offer, &reply).unwrap();
    peer.decrypt_setup_control(&control, &offer, &reply)
        .unwrap();
}

#[test]
fn replay_marker_receive_capability_and_ready_downgrade_are_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let (mut local, _, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(true);
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    for change in 0..6 {
        let result = store.update_setup_contact_atomic(&id, &expected, |contact, setup, route| {
            contact.encrypt_setup_control(&offer, &reply)?;
            setup.payload = b"valid payload with forbidden state change".to_vec();
            changed_send(route);
            match change {
                0 => setup.replay_tag = Some("f".repeat(64)),
                1 => setup.replay_tag = None,
                2 => setup.ready = false,
                3 => route.receive.relay_url = "https://changed.example.test".into(),
                4 => route.receive.queue_id = "f".repeat(32),
                5 => route.receive.token = "f".repeat(64),
                _ => unreachable!(),
            }
            Ok(())
        });
        assert!(matches!(result, Err(Error::SetupConflict)));
        assert_eq!(snapshot_rows(&sql, &id), before);
        assert_setup(&store, &id, &expected);
    }
    assert_no_chat_rows(&store, &id, &sql);
}

#[test]
fn stale_expected_from_other_handle_never_invokes_update() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let expected = setup(false);
    let mut first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let id = first
        .insert_setup_contact(Contact::new(), &route(), &expected)
        .unwrap();
    let mut second = ClientStore::open(&path, copy_key(&key)).unwrap();
    first
        .update_setup_contact_atomic(&id, &expected, |_, setup, _| {
            setup.payload = b"new durable setup state".to_vec();
            Ok(())
        })
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    let invoked = Cell::new(false);
    let result = second.update_setup_contact_atomic(&id, &expected, |_, _, _| {
        invoked.set(true);
        Ok(())
    });
    assert!(matches!(result, Err(Error::SetupConflict)));
    assert!(!invoked.get());
    assert_eq!(snapshot_rows(&sql, &id), before);
    let mut updated = expected.clone();
    updated.payload = b"new durable setup state".to_vec();
    assert_setup(&second, &id, &updated);
}

#[test]
fn invalid_setup_or_send_route_rolls_back_crypto_and_max_payload_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let (mut local, _, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(false);
    let mut store = ClientStore::open(&path, StorageKey::generate()).unwrap();
    let id = store
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let sql = Connection::open(&path).unwrap();
    let before = snapshot_rows(&sql, &id);
    for change in 0..5 {
        let result = store.update_setup_contact_atomic(&id, &expected, |contact, setup, route| {
            contact.encrypt_setup_control(&offer, &reply)?;
            match change {
                0 => setup.payload = vec![0; 8193],
                1 => setup.replay_tag = Some("E".repeat(64)),
                2 => route.send.relay_url.clear(),
                3 => route.send.queue_id = "f".repeat(31),
                4 => route.send.token = "F".repeat(64),
                _ => unreachable!(),
            }
            Ok(())
        });
        if change == 0 {
            assert!(matches!(result, Err(Error::InvalidSetup)));
        } else if change == 1 {
            assert!(matches!(result, Err(Error::SetupConflict)));
        } else {
            assert!(matches!(result, Err(Error::InvalidRoute)));
        }
        assert_eq!(snapshot_rows(&sql, &id), before);
        assert_setup(&store, &id, &expected);
    }
    let mut invalid_expected = expected.clone();
    invalid_expected.payload = vec![0; 8193];
    let invoked = Cell::new(false);
    assert!(matches!(
        store.update_setup_contact_atomic(&id, &invalid_expected, |_, _, _| {
            invoked.set(true);
            Ok(())
        }),
        Err(Error::InvalidSetup)
    ));
    assert!(!invoked.get());
    assert_eq!(snapshot_rows(&sql, &id), before);
    store
        .update_setup_contact_atomic(&id, &expected, |_, setup, _| {
            setup.payload = vec![255; 8192];
            Ok(())
        })
        .unwrap();
    let mut maximum = expected.clone();
    maximum.payload = vec![255; 8192];
    assert_setup(&store, &id, &maximum);
    assert_no_chat_rows(&store, &id, &sql);
}

#[test]
fn simultaneous_crypto_transitions_have_one_winner_and_one_uninvoked_closure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let (mut local, mut peer, offer, reply) = pair();
    local.start_session().unwrap();
    let expected = setup(false);
    let mut first = ClientStore::open(&path, copy_key(&key)).unwrap();
    let id = first
        .insert_setup_contact(local, &route(), &expected)
        .unwrap();
    let second = ClientStore::open(&path, copy_key(&key)).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = [first, second]
        .into_iter()
        .map(|mut store| {
            let barrier = barrier.clone();
            let id = id.clone();
            let expected = expected.clone();
            let offer = offer.clone();
            let reply = reply.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let invoked = Cell::new(false);
                let result =
                    store.update_setup_contact_atomic(&id, &expected, |contact, setup, route| {
                        invoked.set(true);
                        let control = contact.encrypt_setup_control(&offer, &reply)?;
                        setup.payload = serde_json::to_vec(&control).unwrap();
                        setup.ready = true;
                        changed_send(route);
                        Ok(control)
                    });
                (result, invoked.get())
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|(result, invoked)| result.is_ok() && *invoked)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(result, invoked)| matches!(result, Err(Error::SetupConflict)) && !*invoked)
            .count(),
        1
    );
    let control = results
        .iter()
        .find(|(result, _)| result.is_ok())
        .unwrap()
        .0
        .as_ref()
        .unwrap();
    peer.decrypt_setup_control(control, &offer, &reply).unwrap();
    let reopened = ClientStore::open(&path, copy_key(&key)).unwrap();
    let records = reopened.setup_records().unwrap();
    let saved: Envelope = serde_json::from_slice(&records[0].1.payload).unwrap();
    assert!(saved.id == control.id && saved.payload == control.payload);
    let sql = Connection::open(&path).unwrap();
    assert_no_chat_rows(&reopened, &id, &sql);
}

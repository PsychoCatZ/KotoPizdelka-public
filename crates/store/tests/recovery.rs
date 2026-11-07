//! Durable ratchet/inbox/outbox behavior, including actual SQLite rollbacks.
//! Storage keys stay in memory: the test fixture never writes them to disk.
use std::path::Path;

use messenger_core::{Contact, Envelope, StorageKey};
use messenger_store::{AcceptStatus, ClientStore, Direction, Error};
use rusqlite::{params, Connection};

struct Peers {
    alice: ClientStore,
    bob: ClientStore,
    alice_id: String,
    bob_id: String,
    alice_key: StorageKey,
    bob_key: StorageKey,
}

fn contacts() -> (Contact, Contact) {
    let mut alice = Contact::new();
    let mut bob = Contact::new();
    let alice_bundle = alice.public_bundle();
    let bob_bundle = bob.public_bundle();
    alice
        .bind_peer(bob_bundle.clone(), &bob_bundle.fingerprint().unwrap())
        .unwrap();
    bob.bind_peer(alice_bundle.clone(), &alice_bundle.fingerprint().unwrap())
        .unwrap();
    alice.start_session().unwrap();
    (alice, bob)
}

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn peers(dir: &Path) -> Peers {
    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();
    let mut alice = ClientStore::open(dir.join("alice.sqlite"), copy_key(&alice_key)).unwrap();
    let mut bob = ClientStore::open(dir.join("bob.sqlite"), copy_key(&bob_key)).unwrap();
    let (alice_contact, bob_contact) = contacts();
    let alice_id = alice.insert_contact(alice_contact).unwrap();
    let bob_id = bob.insert_contact(bob_contact).unwrap();
    Peers {
        alice,
        bob,
        alice_id,
        bob_id,
        alice_key,
        bob_key,
    }
}

fn reopen(store: ClientStore, path: &Path, key: &StorageKey) -> ClientStore {
    drop(store);
    ClientStore::open(path, copy_key(key)).unwrap()
}

fn assert_envelope(actual: &Envelope, expected: &Envelope) {
    assert_eq!(actual.id, expected.id);
    assert_eq!(actual.payload, expected.payload);
}

fn contact_state(sql: &Connection, contact: &str) -> Vec<u8> {
    sql.query_row(
        "SELECT state FROM contacts WHERE id = ?1",
        [contact],
        |row| row.get(0),
    )
    .unwrap()
}

fn record(sql: &Connection, id: &str) -> Vec<u8> {
    sql.query_row("SELECT record FROM messages WHERE id = ?1", [id], |row| {
        row.get(0)
    })
    .unwrap()
}

fn message_count(sql: &Connection) -> i64 {
    sql.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .unwrap()
}

fn assert_plaintext_absent(dir: &Path, plaintext: &str) {
    for file in std::fs::read_dir(dir).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        assert!(!bytes
            .windows(plaintext.len())
            .any(|window| window == plaintext.as_bytes()));
    }
}

#[test]
fn exact_outbox_and_history_survive_reopen_without_reencrypting() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let first_text = "PRIVATE MESSAGE: exact persisted ciphertext survives a client restart";
    let first = peers.alice.enqueue(&peers.alice_id, first_text).unwrap();
    let second = peers
        .alice
        .enqueue(&peers.alice_id, "second message in the FIFO")
        .unwrap();
    peers.alice = reopen(
        peers.alice,
        &dir.path().join("alice.sqlite"),
        &peers.alice_key,
    );

    let pending = peers.alice.pending_outbox(&peers.alice_id).unwrap();
    assert_eq!(pending.len(), 2);
    assert_envelope(&pending[0], &first);
    assert_envelope(&pending[1], &second);
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &pending[0]).unwrap(),
        AcceptStatus::New
    ));
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &pending[1]).unwrap(),
        AcceptStatus::New
    ));
    peers.alice.mark_sent(&peers.alice_id, &first.id).unwrap();
    peers.alice = reopen(
        peers.alice,
        &dir.path().join("alice.sqlite"),
        &peers.alice_key,
    );
    let pending = peers.alice.pending_outbox(&peers.alice_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_envelope(&pending[0], &second);
    let history = peers.alice.history(&peers.alice_id, 0).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].id, first.id);
    assert_eq!(history[0].text, first_text);
    assert!(matches!(history[0].direction, Direction::Outgoing));
    assert!(history[0].sequence < history[1].sequence);
    let tail = peers
        .alice
        .history(&peers.alice_id, history[0].sequence)
        .unwrap();
    assert_eq!(tail.len(), 1);
    assert_eq!(tail[0].id, second.id);
    drop(peers);
    assert_plaintext_absent(dir.path(), first_text);
}

#[test]
fn accepted_inbox_and_ack_survive_reopen_and_exact_redelivery() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let envelope = peers
        .alice
        .enqueue(
            &peers.alice_id,
            "Received before an abrupt application exit",
        )
        .unwrap();
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &envelope).unwrap(),
        AcceptStatus::New
    ));
    peers.bob = reopen(peers.bob, &dir.path().join("bob.sqlite"), &peers.bob_key);
    assert_eq!(
        peers.bob.pending_acks(&peers.bob_id).unwrap(),
        vec![envelope.id.clone()]
    );
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &envelope).unwrap(),
        AcceptStatus::Duplicate
    ));
    let history = peers.bob.history(&peers.bob_id, 0).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].text,
        "Received before an abrupt application exit"
    );
    assert!(matches!(history[0].direction, Direction::Incoming));
    peers.bob.mark_acked(&peers.bob_id, &envelope.id).unwrap();
    peers.bob = reopen(peers.bob, &dir.path().join("bob.sqlite"), &peers.bob_key);
    assert!(peers.bob.pending_acks(&peers.bob_id).unwrap().is_empty());
    let reply = peers
        .bob
        .enqueue(&peers.bob_id, "Reply after recovery")
        .unwrap();
    assert!(matches!(
        peers.alice.accept(&peers.alice_id, &reply).unwrap(),
        AcceptStatus::New
    ));
    let alice_history = peers.alice.history(&peers.alice_id, 0).unwrap();
    assert_eq!(alice_history.len(), 2);
    assert_eq!(alice_history[1].text, "Reply after recovery");
}

#[test]
fn changed_payload_cannot_reuse_an_already_accepted_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let envelope = peers.alice.enqueue(&peers.alice_id, "original").unwrap();
    peers.bob.accept(&peers.bob_id, &envelope).unwrap();
    let mut changed = envelope.clone();
    changed.payload.push('A');
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &changed),
        Err(Error::Conflict)
    ));
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &envelope).unwrap(),
        AcceptStatus::Duplicate
    ));
    let next = peers
        .alice
        .enqueue(&peers.alice_id, "next authentic message")
        .unwrap();
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &next).unwrap(),
        AcceptStatus::New
    ));
    assert_eq!(peers.bob.history(&peers.bob_id, 0).unwrap().len(), 2);
}

#[test]
fn failed_outbox_insert_rolls_back_persisted_ratchet_and_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let sql = Connection::open(dir.path().join("alice.sqlite")).unwrap();
    let before = contact_state(&sql, &peers.alice_id);
    sql.execute_batch(
        "CREATE TRIGGER fail_message AFTER INSERT ON messages
         BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END;",
    )
    .unwrap();
    assert!(peers
        .alice
        .enqueue(&peers.alice_id, "must not be committed")
        .is_err());
    assert_eq!(contact_state(&sql, &peers.alice_id), before);
    assert_eq!(message_count(&sql), 0);
    assert!(peers
        .alice
        .pending_outbox(&peers.alice_id)
        .unwrap()
        .is_empty());
    sql.execute_batch("DROP TRIGGER fail_message").unwrap();
    peers.alice = reopen(
        peers.alice,
        &dir.path().join("alice.sqlite"),
        &peers.alice_key,
    );
    let envelope = peers
        .alice
        .enqueue(&peers.alice_id, "committed retry")
        .unwrap();
    peers.bob.accept(&peers.bob_id, &envelope).unwrap();
    assert_eq!(message_count(&sql), 1);
    assert_eq!(
        peers.bob.history(&peers.bob_id, 0).unwrap()[0].text,
        "committed retry"
    );
}

#[test]
fn failed_inbox_state_update_rolls_back_and_same_envelope_can_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let envelope = peers
        .alice
        .enqueue(&peers.alice_id, "retry after transaction failure")
        .unwrap();
    let sql = Connection::open(dir.path().join("bob.sqlite")).unwrap();
    let before = contact_state(&sql, &peers.bob_id);
    sql.execute_batch(
        "CREATE TRIGGER fail_contact AFTER UPDATE ON contacts
         BEGIN SELECT RAISE(ABORT, 'injected ratchet persistence failure'); END;",
    )
    .unwrap();
    assert!(peers.bob.accept(&peers.bob_id, &envelope).is_err());
    assert_eq!(contact_state(&sql, &peers.bob_id), before);
    assert_eq!(message_count(&sql), 0);
    assert!(peers.bob.pending_acks(&peers.bob_id).unwrap().is_empty());
    sql.execute_batch("DROP TRIGGER fail_contact").unwrap();
    peers.bob = reopen(peers.bob, &dir.path().join("bob.sqlite"), &peers.bob_key);
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &envelope).unwrap(),
        AcceptStatus::New
    ));
    assert_eq!(message_count(&sql), 1);
    assert_eq!(
        peers.bob.pending_acks(&peers.bob_id).unwrap(),
        vec![envelope.id]
    );
}

#[test]
fn two_handles_interleave_using_fresh_persisted_ratchet_state() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let mut second_handle =
        ClientStore::open(dir.path().join("alice.sqlite"), copy_key(&peers.alice_key)).unwrap();
    let first = peers
        .alice
        .enqueue(&peers.alice_id, "handle one, first")
        .unwrap();
    let second = second_handle
        .enqueue(&peers.alice_id, "handle two")
        .unwrap();
    let third = peers
        .alice
        .enqueue(&peers.alice_id, "handle one, third")
        .unwrap();
    for envelope in [&first, &second, &third] {
        peers.bob.accept(&peers.bob_id, envelope).unwrap();
    }
    let history = peers.bob.history(&peers.bob_id, 0).unwrap();
    let texts: Vec<_> = history.iter().map(|entry| entry.text.as_str()).collect();
    assert_eq!(
        texts,
        vec!["handle one, first", "handle two", "handle one, third"]
    );
    let pending = second_handle.pending_outbox(&peers.alice_id).unwrap();
    assert_eq!(pending.len(), 3);
    for (actual, expected) in pending.iter().zip([&first, &second, &third]) {
        assert_envelope(actual, expected);
    }
}

#[test]
fn incorrect_storage_key_cannot_open_or_overwrite_existing_database() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let envelope = peers
        .alice
        .enqueue(&peers.alice_id, "survives incorrect-key attempt")
        .unwrap();
    let path = dir.path().join("alice.sqlite");
    assert!(ClientStore::open(&path, StorageKey::generate()).is_err());
    peers.alice = reopen(peers.alice, &path, &peers.alice_key);
    let pending = peers.alice.pending_outbox(&peers.alice_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_envelope(&pending[0], &envelope);
}

#[test]
fn modified_record_ciphertext_is_rejected_instead_of_returning_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let envelope = peers
        .alice
        .enqueue(&peers.alice_id, "authenticated at-rest record")
        .unwrap();
    let sql = Connection::open(dir.path().join("alice.sqlite")).unwrap();
    let mut ciphertext = record(&sql, &envelope.id);
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    sql.execute(
        "UPDATE messages SET record = ?1 WHERE id = ?2",
        params![ciphertext, envelope.id],
    )
    .unwrap();
    assert!(peers.alice.history(&peers.alice_id, 0).is_err());
    assert!(peers.alice.pending_outbox(&peers.alice_id).is_err());
}

#[test]
fn swapping_encrypted_records_between_message_ids_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let first = peers.alice.enqueue(&peers.alice_id, "first row").unwrap();
    let second = peers.alice.enqueue(&peers.alice_id, "second row").unwrap();
    let sql = Connection::open(dir.path().join("alice.sqlite")).unwrap();
    let first_record = record(&sql, &first.id);
    let second_record = record(&sql, &second.id);
    sql.execute(
        "UPDATE messages SET record = ?1 WHERE id = ?2",
        params![second_record, first.id],
    )
    .unwrap();
    sql.execute(
        "UPDATE messages SET record = ?1 WHERE id = ?2",
        params![first_record, second.id],
    )
    .unwrap();
    assert!(peers.alice.pending_outbox(&peers.alice_id).is_err());
    assert!(peers.alice.history(&peers.alice_id, 0).is_err());
}

#[test]
fn swapping_contact_snapshots_between_contact_ids_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let (second_alice_contact, _) = contacts();
    let second_id = peers.alice.insert_contact(second_alice_contact).unwrap();
    let sql = Connection::open(dir.path().join("alice.sqlite")).unwrap();
    let first_state = contact_state(&sql, &peers.alice_id);
    let second_state = contact_state(&sql, &second_id);
    sql.execute(
        "UPDATE contacts SET state = ?1 WHERE id = ?2",
        params![second_state, peers.alice_id],
    )
    .unwrap();
    sql.execute(
        "UPDATE contacts SET state = ?1 WHERE id = ?2",
        params![first_state, second_id],
    )
    .unwrap();
    assert!(peers
        .alice
        .enqueue(&peers.alice_id, "must reject wrong contact state")
        .is_err());
    assert!(peers
        .alice
        .enqueue(&second_id, "must reject wrong contact state")
        .is_err());
    assert_eq!(message_count(&sql), 0);
}

#[test]
fn concurrent_first_open_with_different_keys_has_exactly_one_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.sqlite");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let barrier = std::sync::Arc::clone(&barrier);
            let path = path.clone();
            std::thread::spawn(move || {
                let key = StorageKey::generate();
                barrier.wait();
                let result = ClientStore::open(path, copy_key(&key)).map(drop);
                (result, key)
            })
        })
        .collect();
    let outcomes: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    let mut successes = 0;
    let mut rejected_keys = 0;
    for (result, key) in &outcomes {
        match result {
            Ok(()) => {
                successes += 1;
                assert!(ClientStore::open(&path, copy_key(key)).is_ok());
            }
            Err(Error::InvalidStore) => {
                rejected_keys += 1;
                assert!(matches!(
                    ClientStore::open(&path, copy_key(key)),
                    Err(Error::InvalidStore)
                ));
            }
            Err(error) => panic!("unexpected concurrent initialization error: {error:?}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(rejected_keys, 1);
    let sql = Connection::open(&path).unwrap();
    let checks: i64 = sql
        .query_row("SELECT COUNT(*) FROM store_meta", [], |row| row.get(0))
        .unwrap();
    assert_eq!(checks, 1);
}

#[test]
fn redelivery_after_recorded_ack_requeues_ack_without_consuming_ratchet_again() {
    let dir = tempfile::tempdir().unwrap();
    let mut peers = peers(dir.path());
    let envelope = peers
        .alice
        .enqueue(&peers.alice_id, "acknowledged message redelivered by relay")
        .unwrap();
    peers.bob.accept(&peers.bob_id, &envelope).unwrap();
    peers.bob.mark_acked(&peers.bob_id, &envelope.id).unwrap();
    peers.bob = reopen(peers.bob, &dir.path().join("bob.sqlite"), &peers.bob_key);
    assert!(peers.bob.pending_acks(&peers.bob_id).unwrap().is_empty());
    let sql = Connection::open(dir.path().join("bob.sqlite")).unwrap();
    let before = contact_state(&sql, &peers.bob_id);
    assert!(matches!(
        peers.bob.accept(&peers.bob_id, &envelope).unwrap(),
        AcceptStatus::Duplicate
    ));
    assert_eq!(contact_state(&sql, &peers.bob_id), before);
    assert_eq!(
        peers.bob.pending_acks(&peers.bob_id).unwrap(),
        vec![envelope.id.clone()]
    );
    let history = peers.bob.history(&peers.bob_id, 0).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].id, envelope.id);
    assert_eq!(message_count(&sql), 1);
}

#[test]
fn missing_key_sentinel_in_nonempty_store_is_rejected_without_reinitializing() {
    for remove_table in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("damaged.sqlite");
        let key = StorageKey::generate();
        let mut store = ClientStore::open(&path, copy_key(&key)).unwrap();
        let (contact, _) = contacts();
        let contact_id = store.insert_contact(contact).unwrap();
        let envelope = store
            .enqueue(&contact_id, "keep existing encrypted records")
            .unwrap();
        drop(store);
        let sql = Connection::open(&path).unwrap();
        let state_before = contact_state(&sql, &contact_id);
        let record_before = record(&sql, &envelope.id);
        sql.execute_batch(if remove_table {
            "DROP TABLE store_meta"
        } else {
            "DELETE FROM store_meta"
        })
        .unwrap();
        assert!(matches!(
            ClientStore::open(&path, copy_key(&key)),
            Err(Error::InvalidStore)
        ));
        assert_eq!(contact_state(&sql, &contact_id), state_before);
        assert_eq!(record(&sql, &envelope.id), record_before);
        assert_eq!(message_count(&sql), 1);
        let meta_tables: i64 = sql
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='store_meta'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(meta_tables, i64::from(!remove_table));
        if !remove_table {
            let checks: i64 = sql
                .query_row("SELECT COUNT(*) FROM store_meta", [], |row| row.get(0))
                .unwrap();
            assert_eq!(checks, 0);
        }
    }
}

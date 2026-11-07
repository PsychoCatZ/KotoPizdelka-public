use base64::{engine::general_purpose::STANDARD, Engine};
use messenger_core::{Contact, Envelope, StorageKey};
use messenger_store::{AcceptStatus, ClientStore, DeliveryStatus, DELIVERY_PREFIX};
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
fn delivery_replies_are_atomic_durable_hidden_and_idempotent_without_marking_read() {
    let d = tempfile::tempdir().unwrap();
    let ak = StorageKey::generate();
    let bk = StorageKey::generate();
    let (ac, bc) = pair();
    let ap = d.path().join("a");
    let bp = d.path().join("b");
    let mut a = ClientStore::open(&ap, copy(&ak)).unwrap();
    let mut b = ClientStore::open(&bp, copy(&bk)).unwrap();
    let ai = a.insert_contact(ac).unwrap();
    let bi = b.insert_contact(bc).unwrap();
    let first = a.enqueue(&ai, "durably delivered").unwrap();
    let second = a.enqueue(&ai, "still queued").unwrap();
    assert_eq!(
        a.history(&ai, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Queued)
    );
    a.mark_sent(&ai, &first.id).unwrap();
    assert_eq!(
        a.history(&ai, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Server)
    );
    // Simulate a failed transaction after inbox insertion; ratchet and reply roll back.
    let sql = Connection::open(&bp).unwrap();
    sql.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON messages WHEN new.kind='delivery' BEGIN SELECT RAISE(ABORT,'fail'); END;").unwrap();
    assert!(b.accept_with_delivery(&bi, &first).is_err());
    assert!(b.history(&bi, 0).unwrap().is_empty());
    assert!(b.pending_outbox(&bi).unwrap().is_empty());
    sql.execute_batch("DROP TRIGGER fail_receipt").unwrap();
    assert_eq!(
        b.accept_with_delivery(&bi, &first).unwrap(),
        AcceptStatus::New
    );
    let receipt = b.pending_outbox(&bi).unwrap().remove(0);
    assert!(STANDARD
        .decode(&receipt.payload)
        .unwrap()
        .starts_with(DELIVERY_PREFIX));
    assert_eq!(
        b.accept_with_delivery(&bi, &first).unwrap(),
        AcceptStatus::Duplicate
    );
    assert_eq!(b.pending_outbox(&bi).unwrap().len(), 1);
    assert_eq!(b.unread_count(&bi).unwrap(), 1);
    assert_eq!(b.history(&bi, 0).unwrap().len(), 1);
    drop(a);
    drop(b);
    let mut a = ClientStore::open(&ap, copy(&ak)).unwrap();
    let mut b = ClientStore::open(&bp, copy(&bk)).unwrap();
    assert_eq!(b.pending_outbox(&bi).unwrap()[0].payload, receipt.payload);
    // Lost sender POST response still permits a valid receipt to prove delivery.
    assert_eq!(a.accept_delivery(&ai, &receipt).unwrap(), AcceptStatus::New);
    assert_eq!(
        a.accept_delivery(&ai, &receipt).unwrap(),
        AcceptStatus::Duplicate
    );
    assert_eq!(
        a.history(&ai, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Delivered)
    );
    assert_eq!(
        a.history(&ai, 0).unwrap()[1].delivery,
        Some(DeliveryStatus::Queued)
    );
    assert_eq!(a.pending_outbox(&ai).unwrap()[0].id, second.id);
    assert_eq!(a.unread_count(&ai).unwrap(), 0);
    assert_eq!(a.history(&ai, 0).unwrap().len(), 2);
    a.mark_sent(&ai, &first.id).unwrap();
    a.mark_acked(&ai, &receipt.id).unwrap();
    assert_eq!(
        a.history(&ai, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Delivered)
    );
    drop(a);
    let a = ClientStore::open(&ap, copy(&ak)).unwrap();
    assert_eq!(
        a.history(&ai, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Delivered)
    );
    b.delete_contact(&bi).unwrap();
    assert_eq!(
        sql.query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn purpose_relabel_and_unknown_message_cannot_consume_ratchet_or_forge_delivery() {
    let d = tempfile::tempdir().unwrap();
    let (mut a, mut b) = pair();
    let message = a.encrypt("normal text").unwrap();
    b.decrypt(&message).unwrap();
    let receipt = b.encrypt_delivery(&message.id).unwrap();
    assert!(a.decrypt(&receipt).is_err());
    assert_eq!(a.decrypt_delivery(&receipt).unwrap(), message.id);
    let mut store = ClientStore::open(d.path().join("a"), StorageKey::generate()).unwrap();
    let (ac, mut bc) = pair();
    let id = store.insert_contact(ac).unwrap();
    let message = store.enqueue(&id, "hello").unwrap();
    bc.decrypt(&message).unwrap();
    let fake = bc.encrypt_delivery(&"f".repeat(32)).unwrap();
    let wrap = |e: Envelope| {
        let mut raw = DELIVERY_PREFIX.to_vec();
        raw.extend(STANDARD.decode(e.payload).unwrap());
        Envelope {
            id: e.id,
            payload: STANDARD.encode(raw),
        }
    };
    assert!(store.accept_delivery(&id, &wrap(fake)).is_err());
    let text = bc.encrypt("a chat relabelled as a receipt").unwrap();
    assert!(store.accept_delivery(&id, &wrap(text.clone())).is_err());
    store.accept(&id, &text).unwrap();
    let genuine = wrap(bc.encrypt_delivery(&message.id).unwrap());
    store.accept_delivery(&id, &genuine).unwrap();
    assert_eq!(
        store.history(&id, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Delivered)
    );
    assert_eq!(store.history(&id, 0).unwrap().len(), 2);
}
#[test]
fn v5_upgrade_preserves_records_unread_and_deleted_sequence_high_water() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let key = StorageKey::generate();
    let (a, mut b) = pair();
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    let id = store.insert_contact(a).unwrap();
    let text = store.enqueue(&id, "old outgoing").unwrap();
    b.decrypt(&text).unwrap();
    store.mark_sent(&id, &text.id).unwrap();
    store
        .accept(&id, &b.encrypt("old incoming").unwrap())
        .unwrap();
    drop(store);
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch("UPDATE store_meta SET version=5; UPDATE sqlite_sequence SET seq=300 WHERE name='messages';").unwrap();
    let before: Vec<Vec<u8>> = sql
        .prepare("SELECT record FROM messages ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert!(ClientStore::open(&path, StorageKey::generate()).is_err());
    assert_eq!(
        sql.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    let h = store.history(&id, 0).unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[0].delivery, Some(DeliveryStatus::Server));
    assert!(h[1].unread);
    assert_eq!(h[1].delivery, None);
    let after: Vec<Vec<u8>> = sql
        .prepare("SELECT record FROM messages ORDER BY seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(before, after);
    store.enqueue(&id, "new message").unwrap();
    assert_eq!(store.history(&id, 0).unwrap()[2].sequence, 301);
}

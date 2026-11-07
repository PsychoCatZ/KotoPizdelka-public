use messenger_core::{Contact, StorageKey};
use messenger_store::{AcceptStatus, ClientStore};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Demo databases are temporary. Keys stay in memory; a real client must
    // retain them in an OS-backed key store across process restarts.
    let dir = tempfile::tempdir()?;
    let a_path = dir.path().join("alice.sqlite");
    let b_path = dir.path().join("bob.sqlite");
    let a_key = StorageKey::generate();
    let b_key = StorageKey::generate();
    let mut alice = ClientStore::open(&a_path, StorageKey::from_bytes(*a_key.as_bytes()))?;
    let mut bob = ClientStore::open(&b_path, StorageKey::from_bytes(*b_key.as_bytes()))?;
    let a_id = alice.insert_contact(Contact::new())?;
    let b_id = bob.insert_contact(Contact::new())?;
    let a_bundle = alice.public_bundle(&a_id)?;
    let b_bundle = bob.public_bundle(&b_id)?;
    // Trusted local objects only; real invitations require independent verification.
    alice.bind_peer(&a_id, b_bundle.clone(), &b_bundle.fingerprint()?)?;
    bob.bind_peer(&b_id, a_bundle.clone(), &a_bundle.fingerprint()?)?;
    alice.start_session(&a_id)?;

    let envelope = alice.enqueue(&a_id, "Сообщение сохранено до отправки.")?;
    drop(alice);
    let mut alice = ClientStore::open(&a_path, StorageKey::from_bytes(*a_key.as_bytes()))?;
    let pending = alice.pending_outbox(&a_id)?;
    println!(
        "После открытия базы исходящий конверт совпадает: {}",
        pending[0].id == envelope.id && pending[0].payload == envelope.payload
    );
    assert_eq!(bob.accept(&b_id, &pending[0])?, AcceptStatus::New);
    // Simulate exit after inbox commit but before a relay acknowledgement.
    drop(bob);
    let mut bob = ClientStore::open(&b_path, StorageKey::from_bytes(*b_key.as_bytes()))?;
    println!(
        "Повтор принят без повторной расшифровки: {}",
        bob.accept(&b_id, &pending[0])? == AcceptStatus::Duplicate
    );
    println!("Сохранённая история: {}", bob.history(&b_id, 0)?[0].text);
    println!(
        "Ожидающих подтверждений: {}",
        bob.pending_acks(&b_id)?.len()
    );
    // The demo substitutes successful relay responses; there is no network here.
    alice.mark_sent(&a_id, &envelope.id)?;
    bob.mark_acked(&b_id, &envelope.id)?;
    let reply = bob.enqueue(&b_id, "Ответ после восстановления клиента.")?;
    alice.accept(&a_id, &reply)?;
    println!("Ответ в истории: {}", alice.history(&a_id, 0)?[1].text);
    Ok(())
}

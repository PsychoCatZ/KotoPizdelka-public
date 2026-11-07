use messenger_core::{Contact, StorageKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut alice = Contact::new();
    let mut bob = Contact::new();
    let alice_bundle = alice.public_bundle();
    let bob_bundle = bob.public_bundle();
    // Objects are local to this demo. Real peers must compare fingerprints
    // through an independently trusted channel, not trust relay output.
    alice.bind_peer(bob_bundle.clone(), &bob_bundle.fingerprint()?)?;
    bob.bind_peer(alice_bundle.clone(), &alice_bundle.fingerprint()?)?;
    alice.start_session()?;

    let message = alice.encrypt("Привет из desktop-клиента!")?;
    println!(
        "Зашифрованный конверт готов: {} байт base64",
        message.payload.len()
    );
    println!("Получатель расшифровал: {}", bob.decrypt(&message)?);
    let reply = bob.encrypt("Привет! Сообщение получил.")?;
    println!("Отправитель расшифровал ответ: {}", alice.decrypt(&reply)?);

    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();
    let alice_snapshot = alice.snapshot(&alice_key)?;
    let bob_snapshot = bob.snapshot(&bob_key)?;
    drop(alice);
    drop(bob);
    let mut alice = Contact::restore(&alice_snapshot, &alice_key)?;
    let mut bob = Contact::restore(&bob_snapshot, &bob_key)?;
    let next = alice.encrypt("Диалог продолжается после восстановления состояния.")?;
    println!("После восстановления: {}", bob.decrypt(&next)?);
    println!("Повтор конверта отклонён: {}", bob.decrypt(&next).is_err());
    Ok(())
}

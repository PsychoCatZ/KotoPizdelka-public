use base64::{engine::general_purpose::STANDARD, Engine};
use messenger_core::{Contact, Envelope, Error, StorageKey};
use vodozemac::{olm::OlmMessage, Curve25519PublicKey};

fn pair() -> (Contact, Contact) {
    let mut alice = Contact::new();
    let mut bob = Contact::new();
    let a = alice.public_bundle();
    let b = bob.public_bundle();
    alice
        .bind_peer(b.clone(), &b.fingerprint().unwrap())
        .unwrap();
    bob.bind_peer(a.clone(), &a.fingerprint().unwrap()).unwrap();
    alice.start_session().unwrap();
    (alice, bob)
}

fn established_pair() -> (Contact, Contact) {
    let (mut alice, mut bob) = pair();
    let first = alice.encrypt("first").unwrap();
    assert_eq!(bob.decrypt(&first).unwrap(), "first");
    let reply = bob.encrypt("reply").unwrap();
    assert_eq!(alice.decrypt(&reply).unwrap(), "reply");
    (alice, bob)
}

#[test]
fn requires_verified_peer_and_isolates_contact_identity() {
    let mut alice = Contact::new();
    let bob = Contact::new();
    assert_ne!(
        alice.public_bundle().identity_key,
        bob.public_bundle().identity_key
    );
    assert_eq!(alice.start_session(), Err(Error::PeerNotVerified));
    let b = bob.public_bundle();
    assert_eq!(
        alice.bind_peer(b.clone(), &"0".repeat(64)),
        Err(Error::FingerprintMismatch)
    );
    alice
        .bind_peer(b.clone(), &b.fingerprint().unwrap())
        .unwrap();
    assert_eq!(
        alice.bind_peer(b.clone(), &b.fingerprint().unwrap()),
        Err(Error::PeerAlreadyBound)
    );
    let mut unsupported = b;
    unsupported.protocol = "another-protocol".into();
    assert_eq!(unsupported.fingerprint(), Err(Error::InvalidBundle));
}

#[test]
fn inbound_requires_pinned_sender_and_does_not_consume_otk_on_rejection() {
    let (mut alice, mut bob) = pair();
    let mut stranger = Contact::new();
    let b = bob.public_bundle();
    stranger
        .bind_peer(b.clone(), &b.fingerprint().unwrap())
        .unwrap();
    stranger.start_session().unwrap();
    let forged = stranger.encrypt("not the verified contact").unwrap();
    assert_eq!(bob.decrypt(&forged), Err(Error::InvalidMessage));
    let correct = alice.encrypt("verified contact").unwrap();
    assert_eq!(bob.decrypt(&correct).unwrap(), "verified contact");
}

#[test]
fn substituted_id_does_not_consume_bootstrap_or_established_state() {
    let (mut alice, mut bob) = pair();
    let correct = alice.encrypt("bootstrap").unwrap();
    let mut forged = correct.clone();
    forged.id = "f".repeat(32);
    assert_eq!(bob.decrypt(&forged), Err(Error::InvalidMessage));
    assert_eq!(bob.decrypt(&correct).unwrap(), "bootstrap");
    let reply = bob.encrypt("reply").unwrap();
    alice.decrypt(&reply).unwrap();
    let next = alice.encrypt("established").unwrap();
    let mut forged = next.clone();
    forged.id = "e".repeat(32);
    assert_eq!(bob.decrypt(&forged), Err(Error::InvalidMessage));
    assert_eq!(bob.decrypt(&next).unwrap(), "established");
}

#[test]
fn bad_mac_is_rejected_without_consuming_valid_message() {
    let (mut alice, mut bob) = established_pair();
    let valid = alice.encrypt("authenticated text").unwrap();
    let wire = STANDARD.decode(&valid.payload).unwrap();
    let decoded: OlmMessage = serde_json::from_slice(&wire).unwrap();
    let (kind, mut bytes) = decoded.to_parts();
    *bytes.last_mut().unwrap() ^= 1;
    let corrupted = OlmMessage::from_parts(kind, &bytes).unwrap();
    let bad = Envelope {
        id: valid.id.clone(),
        payload: STANDARD.encode(serde_json::to_vec(&corrupted).unwrap()),
    };
    assert_eq!(bob.decrypt(&bad), Err(Error::InvalidMessage));
    assert_eq!(bob.decrypt(&valid).unwrap(), "authenticated text");
}

#[test]
fn altered_prekey_wrapper_is_rejected_on_existing_session() {
    let (mut alice, mut bob) = pair();
    let first = alice.encrypt("first").unwrap();
    bob.decrypt(&first).unwrap();
    // Alice has not yet received Bob's reply, so her next message is still PreKey.
    let next = alice.encrypt("second").unwrap();
    let decoded: OlmMessage =
        serde_json::from_slice(&STANDARD.decode(&next.payload).unwrap()).unwrap();
    let (kind, mut bytes) = decoded.to_parts();
    assert_eq!(kind, 0);
    let identity = Curve25519PublicKey::from_base64(&alice.public_bundle().identity_key)
        .unwrap()
        .to_bytes();
    let position = bytes.windows(32).position(|w| w == identity).unwrap();
    bytes[position] ^= 1;
    let changed = OlmMessage::from_parts(kind, &bytes).unwrap();
    let forged = Envelope {
        id: next.id.clone(),
        payload: STANDARD.encode(serde_json::to_vec(&changed).unwrap()),
    };
    assert_eq!(bob.decrypt(&forged), Err(Error::InvalidMessage));
    assert_eq!(bob.decrypt(&next).unwrap(), "second");
}

#[test]
fn small_out_of_order_delivery_and_replay_after_restore() {
    let (mut alice, mut bob) = established_pair();
    let one = alice.encrypt("one").unwrap();
    let two = alice.encrypt("two").unwrap();
    let three = alice.encrypt("three").unwrap();
    assert_eq!(bob.decrypt(&three).unwrap(), "three");
    assert_eq!(bob.decrypt(&one).unwrap(), "one");
    assert_eq!(bob.decrypt(&two).unwrap(), "two");
    let key = StorageKey::generate();
    let snapshot = bob.snapshot(&key).unwrap();
    drop(bob);
    let mut bob = Contact::restore(&snapshot, &key).unwrap();
    assert_eq!(bob.decrypt(&one), Err(Error::InvalidMessage));
    let reply = bob.encrypt("reply after restore").unwrap();
    assert_eq!(alice.decrypt(&reply).unwrap(), "reply after restore");
}

#[test]
fn both_sides_resume_after_encrypted_snapshot() {
    let (mut alice, bob) = established_pair();
    let pending = alice.encrypt("pending during restart").unwrap();
    let a_key = StorageKey::generate();
    let b_key = StorageKey::generate();
    let a = alice.snapshot(&a_key).unwrap();
    let b = bob.snapshot(&b_key).unwrap();
    drop(alice);
    drop(bob);
    let mut alice = Contact::restore(&a, &a_key).unwrap();
    let mut bob = Contact::restore(&b, &b_key).unwrap();
    assert_eq!(bob.decrypt(&pending).unwrap(), "pending during restart");
    let reply = bob.encrypt("works in both directions").unwrap();
    assert_eq!(alice.decrypt(&reply).unwrap(), "works in both directions");
}

#[test]
fn storage_key_snapshot_tampering_and_format_are_checked() {
    let (alice, _) = established_pair();
    let key = StorageKey::generate();
    let snapshot = alice.snapshot(&key).unwrap();
    assert!(matches!(
        Contact::restore(&snapshot, &StorageKey::generate()),
        Err(Error::InvalidSnapshot)
    ));
    for position in [0, 1, snapshot.len() - 1] {
        let mut bad = snapshot.clone();
        bad[position] ^= 1;
        assert!(matches!(
            Contact::restore(&bad, &key),
            Err(Error::InvalidSnapshot)
        ));
    }
    assert!(matches!(
        Contact::restore(&snapshot[..30], &key),
        Err(Error::InvalidSnapshot)
    ));
    assert!(matches!(
        Contact::restore(&vec![0; 1024 * 1024 + 1], &key),
        Err(Error::InvalidSnapshot)
    ));
}

#[test]
fn bounds_and_encoding_expansion_do_not_advance_session() {
    let (mut alice, mut bob) = established_pair();
    assert!(matches!(
        alice.encrypt(&"x".repeat(24 * 1024 + 1)),
        Err(Error::TooLarge)
    ));
    // Control characters expand during JSON encoding, exceeding wire quota.
    assert!(matches!(
        alice.encrypt(&"\0".repeat(24 * 1024)),
        Err(Error::TooLarge)
    ));
    let oversized = Envelope {
        id: "a".repeat(32),
        payload: "A".repeat(100 * 1024),
    };
    assert_eq!(bob.decrypt(&oversized), Err(Error::TooLarge));
    let invalid = Envelope {
        id: "a".repeat(32),
        payload: "invalid!".into(),
    };
    assert_eq!(bob.decrypt(&invalid), Err(Error::InvalidMessage));
    let valid = alice.encrypt("session still works").unwrap();
    assert_eq!(bob.decrypt(&valid).unwrap(), "session still works");
}

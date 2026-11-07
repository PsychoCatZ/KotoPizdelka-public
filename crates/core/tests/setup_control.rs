use messenger_core::{Contact, Envelope, Error, PublicBundle, StorageKey};

const OFFER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const REPLY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn pair() -> (Contact, Contact) {
    let mut offer = Contact::new();
    let mut reply = Contact::new();
    offer
        .bind_peer_from_invitation(reply.public_bundle())
        .unwrap();
    reply
        .bind_peer_from_invitation(offer.public_bundle())
        .unwrap();
    offer.start_session().unwrap();
    (offer, reply)
}

fn assert_control_rejected_then_accepted(offer: &mut Contact, reply: &mut Contact) {
    let control = offer.encrypt_setup_control(OFFER, REPLY).unwrap();
    assert_eq!(reply.decrypt(&control), Err(Error::InvalidMessage));
    assert_eq!(
        reply.decrypt_setup_control(&control, &"c".repeat(64), REPLY),
        Err(Error::InvalidMessage)
    );
    assert_eq!(
        reply.decrypt_setup_control(&control, OFFER, &"c".repeat(64)),
        Err(Error::InvalidMessage)
    );
    assert_eq!(
        reply.decrypt_setup_control(&control, REPLY, OFFER),
        Err(Error::InvalidMessage)
    );
    let substituted = Envelope {
        id: if control.id == "0".repeat(32) {
            "1".repeat(32)
        } else {
            "0".repeat(32)
        },
        payload: control.payload.clone(),
    };
    assert_eq!(
        reply.decrypt_setup_control(&substituted, OFFER, REPLY),
        Err(Error::InvalidMessage)
    );
    reply.decrypt_setup_control(&control, OFFER, REPLY).unwrap();
    assert_eq!(
        reply.decrypt_setup_control(&control, OFFER, REPLY),
        Err(Error::InvalidMessage)
    );
}

#[test]
fn invitation_binding_validates_keys_self_and_rebinding_without_identity_claim() {
    let mut contact = Contact::new();
    assert_eq!(
        contact.bind_peer_from_invitation(contact.public_bundle()),
        Err(Error::InvalidBundle)
    );
    let mut invalid = Contact::new().public_bundle();
    invalid.protocol = "unrecognized protocol".into();
    assert_eq!(
        contact.bind_peer_from_invitation(invalid),
        Err(Error::InvalidBundle)
    );
    let invalid: PublicBundle = serde_json::from_value(serde_json::json!({
        "protocol": contact.public_bundle().protocol,
        "identity_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "one_time_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }))
    .unwrap();
    assert_eq!(
        contact.bind_peer_from_invitation(invalid),
        Err(Error::InvalidBundle)
    );
    let peer = Contact::new().public_bundle();
    contact.bind_peer_from_invitation(peer.clone()).unwrap();
    assert_eq!(
        contact.bind_peer_from_invitation(peer.clone()),
        Err(Error::PeerAlreadyBound)
    );
    assert_eq!(
        contact.bind_peer(peer.clone(), &peer.fingerprint().unwrap()),
        Err(Error::PeerAlreadyBound)
    );
    contact.start_session().unwrap();
}

#[test]
fn control_purpose_and_both_bindings_are_checked_before_any_state_commit() {
    let (mut offer, mut reply) = pair();
    // This first control bootstraps the inbound session. All rejections must
    // leave the one-time key and account intact for the exact valid envelope.
    assert_control_rejected_then_accepted(&mut offer, &mut reply);
    let response = reply.encrypt("ordinary legacy reply").unwrap();
    assert_eq!(
        offer.decrypt_setup_control(&response, OFFER, REPLY),
        Err(Error::InvalidMessage)
    );
    assert_eq!(offer.decrypt(&response).unwrap(), "ordinary legacy reply");
    // Repeat against an established session, proving ratchet rollback too.
    assert_control_rejected_then_accepted(&mut offer, &mut reply);
    let text = offer.encrypt("ordinary legacy text after setup").unwrap();
    assert_eq!(
        reply.decrypt(&text).unwrap(),
        "ordinary legacy text after setup"
    );
}

#[test]
fn setup_fingerprint_encoding_is_strict_and_does_not_consume_valid_control() {
    let (mut offer, mut reply) = pair();
    for invalid in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        assert!(matches!(
            offer.encrypt_setup_control(&invalid, REPLY),
            Err(Error::InvalidMessage)
        ));
        assert!(matches!(
            offer.encrypt_setup_control(OFFER, &invalid),
            Err(Error::InvalidMessage)
        ));
    }
    let control = offer.encrypt_setup_control(OFFER, REPLY).unwrap();
    for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
        assert_eq!(
            reply.decrypt_setup_control(&control, &invalid, REPLY),
            Err(Error::InvalidMessage)
        );
        assert_eq!(
            reply.decrypt_setup_control(&control, OFFER, &invalid),
            Err(Error::InvalidMessage)
        );
    }
    reply.decrypt_setup_control(&control, OFFER, REPLY).unwrap();
}

#[test]
fn typed_control_is_not_recognized_by_magic_user_text_and_survives_snapshot() {
    let (mut offer, mut reply) = pair();
    let pretend_control = serde_json::json!({
        "protocol": "private-messenger.setup-control.v1",
        "id": "0".repeat(32),
        "offer_fingerprint": OFFER,
        "reply_fingerprint": REPLY
    })
    .to_string();
    let text = offer.encrypt(&pretend_control).unwrap();
    assert_eq!(
        reply.decrypt_setup_control(&text, OFFER, REPLY),
        Err(Error::InvalidMessage)
    );
    assert_eq!(reply.decrypt(&text).unwrap(), pretend_control);
    let control = reply.encrypt_setup_control(OFFER, REPLY).unwrap();
    let offer_key = StorageKey::generate();
    let reply_key = StorageKey::generate();
    let mut restored_offer =
        Contact::restore(&offer.snapshot(&offer_key).unwrap(), &offer_key).unwrap();
    let mut restored_reply =
        Contact::restore(&reply.snapshot(&reply_key).unwrap(), &reply_key).unwrap();
    restored_offer
        .decrypt_setup_control(&control, OFFER, REPLY)
        .unwrap();
    let next = restored_offer
        .encrypt("text after control and restore")
        .unwrap();
    assert_eq!(
        restored_reply.decrypt(&next).unwrap(),
        "text after control and restore"
    );
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use messenger_client::invitations::{Invitation, InvitationError, InvitationKind};
use messenger_core::Contact;
use messenger_store::QueueEndpoint;
use serde_json::{json, Value};

const PREFIX: &str = "koto-invite:v1:";

fn endpoint() -> QueueEndpoint {
    QueueEndpoint {
        relay_url: "https://relay.example/".into(),
        queue_id: "12".repeat(16),
        token: "34".repeat(32),
    }
}

fn offer() -> Invitation {
    Invitation::offer("56".repeat(16), Contact::new().public_bundle(), endpoint()).unwrap()
}

fn artifact(invitation: &Invitation) -> Value {
    let encoded = invitation.encode().unwrap();
    serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded.strip_prefix(PREFIX).unwrap())
            .unwrap(),
    )
    .unwrap()
}

fn from_json(value: &Value) -> Result<Invitation, InvitationError> {
    from_raw_json(&serde_json::to_string(value).unwrap())
}

fn from_raw_json(json: &str) -> Result<Invitation, InvitationError> {
    Invitation::decode(&format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

fn assert_invalid(value: &Value) {
    assert!(matches!(from_json(value), Err(InvitationError::Invalid)));
}

#[test]
fn round_trip_preserves_fingerprint_and_independent_verification() {
    let original = offer();
    let fingerprint = original.fingerprint().unwrap();
    let decoded = Invitation::decode(&original.encode().unwrap()).unwrap();
    assert_eq!(decoded.kind(), InvitationKind::Offer);
    assert_eq!(decoded.nonce(), original.nonce());
    assert_eq!(decoded.offer_fingerprint(), None);
    assert_eq!(decoded.bundle(), original.bundle());
    assert_eq!(decoded.write_endpoint().token, endpoint().token);
    assert_eq!(decoded.fingerprint().unwrap(), fingerprint);
    assert!(decoded.verify(&fingerprint).is_ok());
    assert!(matches!(
        original.clone().verify(&"00".repeat(32)),
        Err(InvitationError::FingerprintMismatch)
    ));
    assert!(matches!(
        original.verify(&"AF".repeat(32)),
        Err(InvitationError::Invalid)
    ));
}

#[test]
fn changing_any_valid_offer_field_breaks_original_authentication() {
    let original = offer();
    let expected = original.fingerprint().unwrap();
    let value = artifact(&original);
    let other_bundle = Contact::new().public_bundle();
    let replacements = [
        (vec!["nonce"], json!("78".repeat(16))),
        (
            vec!["bundle", "identity_key"],
            json!(other_bundle.identity_key),
        ),
        (
            vec!["bundle", "one_time_key"],
            json!(other_bundle.one_time_key),
        ),
        (vec!["write", "relay_url"], json!("https://other.example/")),
        (vec!["write", "queue_id"], json!("9a".repeat(16))),
        (vec!["write", "token"], json!("bc".repeat(32))),
    ];
    for (path, replacement) in replacements {
        let mut changed = value.clone();
        let mut target = &mut changed;
        for component in path {
            target = &mut target[component];
        }
        *target = replacement;
        let changed = from_json(&changed).unwrap();
        assert!(matches!(
            changed.verify(&expected),
            Err(InvitationError::FingerprintMismatch)
        ));
    }
    let mut changed_kind = value;
    changed_kind["kind"] = json!("reply");
    changed_kind["offer_fingerprint"] = json!("de".repeat(32));
    assert!(matches!(
        from_json(&changed_kind).unwrap().verify(&expected),
        Err(InvitationError::FingerprintMismatch)
    ));
}

#[test]
fn reply_binds_full_parent_offer_and_not_just_its_public_keys() {
    let original = offer();
    let parent = original.fingerprint().unwrap();
    let reply = Invitation::reply(
        "78".repeat(16),
        Contact::new().public_bundle(),
        endpoint(),
        parent.clone(),
    )
    .unwrap();
    assert_eq!(reply.kind(), InvitationKind::Reply);
    assert_eq!(reply.offer_fingerprint(), Some(parent.as_str()));
    let expected = reply.fingerprint().unwrap();
    let mut changed_parent = artifact(&reply);
    changed_parent["offer_fingerprint"] = json!("9a".repeat(32));
    assert!(matches!(
        from_json(&changed_parent).unwrap().verify(&expected),
        Err(InvitationError::FingerprintMismatch)
    ));
    let mut changed_offer = artifact(&original);
    changed_offer["write"]["token"] = json!("bc".repeat(32));
    assert_ne!(
        from_json(&changed_offer).unwrap().fingerprint().unwrap(),
        parent
    );
}

#[test]
fn json_member_order_and_whitespace_do_not_change_typed_fingerprint() {
    let original = offer();
    let value = artifact(&original);
    let reversed = format!(
        "{{ \"write\": {}, \"bundle\": {}, \"nonce\": {}, \"kind\": {}, \"protocol\": {} }}",
        value["write"], value["bundle"], value["nonce"], value["kind"], value["protocol"]
    );
    let reordered = from_raw_json(&reversed).unwrap();
    assert_eq!(
        reordered.fingerprint().unwrap(),
        original.fingerprint().unwrap()
    );
    assert_eq!(reordered.encode().unwrap(), original.encode().unwrap());
}

#[test]
fn unknown_and_duplicate_fields_are_rejected_at_each_nested_level() {
    let value = artifact(&offer());
    for path in [
        vec!["read_token"],
        vec!["write", "read_token"],
        vec!["bundle", "extra"],
    ] {
        let mut changed = value.clone();
        let mut target = &mut changed;
        for component in path {
            target = &mut target[component];
        }
        *target = json!("secret-read-capability");
        assert_invalid(&changed);
    }
    for (key, nested) in [
        ("nonce", None),
        ("token", Some("write")),
        ("identity_key", Some("bundle")),
    ] {
        let mut duplicated = value.clone();
        let object = nested.map_or(&value, |name| &value[name]);
        let duplicate_json = format!(
            "{{\"{key}\":{},{}",
            object[key],
            serde_json::to_string(object)
                .unwrap()
                .trim_start_matches('{')
        );
        let encoded = if let Some(name) = nested {
            // Insert the raw nested JSON without reparsing away duplicate keys.
            duplicated[name] = json!("DUPLICATE_PLACEHOLDER");
            serde_json::to_string(&duplicated)
                .unwrap()
                .replace("\"DUPLICATE_PLACEHOLDER\"", &duplicate_json)
        } else {
            duplicate_json
        };
        assert!(matches!(
            from_raw_json(&encoded),
            Err(InvitationError::Invalid)
        ));
    }
}

#[test]
fn versions_roles_and_parent_combinations_are_strict() {
    let value = artifact(&offer());
    for (field, replacement) in [
        ("protocol", json!("KotoPizdelka.invitation.v2")),
        ("kind", json!("contact")),
        ("nonce", json!("AF".repeat(16))),
        ("nonce", json!("12".repeat(15))),
        ("offer_fingerprint", json!("34".repeat(32))),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        assert_invalid(&changed);
    }
    let mut invalid_bundle = value.clone();
    invalid_bundle["bundle"]["protocol"] = json!("unknown");
    assert_invalid(&invalid_bundle);
    invalid_bundle = value.clone();
    invalid_bundle["bundle"]["identity_key"] = json!("not-a-key");
    assert_invalid(&invalid_bundle);
    let mut missing_parent = value.clone();
    missing_parent["kind"] = json!("reply");
    assert_invalid(&missing_parent);
    missing_parent["offer_fingerprint"] = Value::Null;
    assert_invalid(&missing_parent);
    missing_parent["offer_fingerprint"] = json!("AF".repeat(32));
    assert_invalid(&missing_parent);
    assert!(matches!(
        Invitation::decode("koto-invite:v2:AA"),
        Err(InvitationError::Invalid)
    ));
}

#[test]
fn malformed_base64_trailing_json_and_oversize_text_are_rejected() {
    for encoded in ["", "!", "AA=", "AA==", "A", "AB", "AA\n"] {
        assert!(matches!(
            Invitation::decode(&format!("{PREFIX}{encoded}")),
            Err(InvitationError::Invalid)
        ));
    }
    let valid_json = serde_json::to_string(&artifact(&offer())).unwrap();
    assert!(matches!(
        from_raw_json(&format!("{valid_json} {{}}")),
        Err(InvitationError::Invalid)
    ));
    assert!(matches!(
        Invitation::decode(&"x".repeat(8193)),
        Err(InvitationError::TooLarge)
    ));
    assert!(matches!(
        Invitation::decode(&format!(
            "{PREFIX}{}",
            URL_SAFE_NO_PAD.encode(vec![b' '; 6145])
        )),
        Err(InvitationError::TooLarge)
    ));
}

#[test]
fn exported_shape_contains_one_write_capability_and_no_receive_credentials() {
    let value = artifact(&offer());
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 5);
    let endpoint = object["write"].as_object().unwrap();
    assert_eq!(endpoint.len(), 3);
    assert!(endpoint.contains_key("relay_url"));
    assert!(endpoint.contains_key("queue_id"));
    assert!(endpoint.contains_key("token"));
    assert!(!object.contains_key("receive"));
    assert!(!object.contains_key("read_token"));
}

#[test]
fn codec_checks_endpoint_format_and_only_allows_literal_loopback_http() {
    let value = artifact(&offer());
    for url in [
        "http://relay.example/",
        "http://localhost/",
        "https://relay.example/v1/",
        "https://user:pass@relay.example/",
        "https://relay.example/?query=secret",
        "https://relay.example/#secret",
    ] {
        let mut changed = value.clone();
        changed["write"]["relay_url"] = json!(url);
        assert_invalid(&changed);
    }
    for url in ["http://127.0.0.1:8000/", "http://[::1]:8000/"] {
        let mut changed = value.clone();
        changed["write"]["relay_url"] = json!(url);
        assert!(from_json(&changed).is_ok());
    }
    let mut invalid_token = value.clone();
    invalid_token["write"]["token"] = json!("AF".repeat(32));
    assert_invalid(&invalid_token);
    let mut invalid_queue = value;
    invalid_queue["write"]["queue_id"] = json!("12".repeat(15));
    assert_invalid(&invalid_queue);
}

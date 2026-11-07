//! Real HTTP coverage for the single-link invitation flow. Capabilities,
//! invitation links and encrypted setup frames are kept inside these fixtures
//! and deliberately have no Debug output.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::{to_bytes, Body},
    http::{header, Method, Request, StatusCode},
    middleware::{self, Next},
    response::IntoResponse,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use messenger_client::{invitations::Invitation, ClientWorker, Error};
use messenger_core::{Contact, Envelope, StorageKey};
use messenger_relay::{router, AppState, Queue, Store};
use messenger_store::Direction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOOTSTRAP_PREFIX: &[u8] = b"koto-setup:v2:";
const CONTROL_PREFIX: &[u8] = b"koto-control:v2:";

#[derive(Default)]
struct Faults {
    invite_response: AtomicBool,
    reply_response: AtomicBool,
    ack_response: AtomicBool,
    control_response: AtomicBool,
}

struct ObservedRequest {
    method: Method,
    path: String,
    authorization: String,
    body: Value,
}

struct Server {
    url: String,
    task: JoinHandle<()>,
    requests: Arc<Mutex<Vec<ObservedRequest>>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn has_prefix(envelope: &Envelope, prefix: &[u8]) -> bool {
    STANDARD
        .decode(&envelope.payload)
        .is_ok_and(|bytes| bytes.starts_with(prefix))
}

async fn serve(directory: &Path, faults: Arc<Faults>) -> (Server, String) {
    let mut store = Store::open(directory.join("relay.sqlite").to_str().unwrap()).unwrap();
    let ticket = store.issue_invitation_ticket(86400).unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let app = router(AppState::new(store, ADMIN)).layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let observed = Arc::clone(&observed);
            let faults = Arc::clone(&faults);
            async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 256 * 1024).await.unwrap();
                let json: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                let envelope = serde_json::from_value::<Envelope>(json.clone()).ok();
                let message_post =
                    parts.method == Method::POST && parts.uri.path().ends_with("/messages");
                let reply_post = message_post
                    && envelope
                        .as_ref()
                        .is_some_and(|envelope| has_prefix(envelope, BOOTSTRAP_PREFIX));
                let control_post = message_post
                    && envelope
                        .as_ref()
                        .is_some_and(|envelope| has_prefix(envelope, CONTROL_PREFIX));
                let ack = parts.method == Method::DELETE;
                let invite_post =
                    parts.method == Method::POST && parts.uri.path() == "/v1/queues/invite";
                observed.lock().unwrap().push(ObservedRequest {
                    method: parts.method.clone(),
                    path: parts.uri.path().to_owned(),
                    authorization: parts
                        .headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_owned(),
                    body: json,
                });
                let response = next
                    .run(Request::from_parts(parts, Body::from(bytes)))
                    .await;
                // Commit first, then hide the response: this is an ambiguous
                // network outcome rather than a server-side rejected request.
                let lose_reply = reply_post
                    && response.status() == StatusCode::ACCEPTED
                    && faults.reply_response.swap(false, Ordering::SeqCst);
                let lose_control = control_post
                    && response.status() == StatusCode::ACCEPTED
                    && faults.control_response.swap(false, Ordering::SeqCst);
                let lose_ack = ack
                    && response.status() == StatusCode::NO_CONTENT
                    && faults.ack_response.swap(false, Ordering::SeqCst);
                let lose_invite = invite_post
                    && response.status() == StatusCode::CREATED
                    && faults.invite_response.swap(false, Ordering::SeqCst);
                if lose_reply || lose_control || lose_ack || lose_invite {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                response
            }
        },
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        Server {
            url,
            task,
            requests,
        },
        ticket,
    )
}

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}
fn worker(directory: &Path, name: &str) -> ClientWorker {
    ClientWorker::open(directory.join(name), StorageKey::generate(), true).unwrap()
}
fn only_contact(worker: &mut ClientWorker) -> String {
    let ids = worker.store().contact_ids().unwrap();
    assert_eq!(ids.len(), 1);
    ids[0].clone()
}
fn stage(worker: &ClientWorker, contact: &str) -> String {
    worker
        .quick_invitation_status(contact)
        .unwrap()
        .unwrap()
        .stage
        .to_owned()
}
fn history_len(worker: &mut ClientWorker, contact: &str) -> usize {
    worker.store().history(contact, 0).unwrap().len()
}
fn captured_envelopes(server: &Server, prefix: &[u8]) -> Vec<Envelope> {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|request| request.method == Method::POST && request.path.ends_with("/messages"))
        .filter_map(|request| serde_json::from_value::<Envelope>(request.body.clone()).ok())
        .filter(|envelope| has_prefix(envelope, prefix))
        .collect()
}
fn owner_queue(server: &Server) -> Queue {
    let requests = server.requests.lock().unwrap();
    let proposal = requests
        .iter()
        .find_map(|request| request.body.get("queue"))
        .unwrap();
    serde_json::from_value(proposal.clone()).unwrap()
}
fn fixture_http() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap()
}

// An adversarial link holder can encrypt a Reply too. Construct an actual v2
// wire artifact to exercise candidate validation, rather than mocking it.
#[derive(Serialize, Deserialize)]
struct LinkFixture {
    protocol: String,
    offer: Invitation,
    secret: String,
    recipient_ticket: String,
    expires_at: i64,
}
fn decode_link(link: &str) -> LinkFixture {
    let fragment = link.strip_prefix("kotopizdelka://invite#").unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fragment).unwrap()).unwrap()
}
fn forge_reply(link: &str, reply: Invitation) -> Envelope {
    let link = decode_link(link);
    let id = "00000000000000000000000000000001".to_owned();
    let mut digest = Sha256::new();
    digest.update(b"KotoPizdelka.quick-invitation-digest.v2\0");
    digest.update(serde_json::to_vec(&link).unwrap());
    let mut aad = b"KotoPizdelka.quick-reply.v2\0".to_vec();
    aad.extend_from_slice(hex::encode(digest.finalize()).as_bytes());
    aad.extend_from_slice(id.as_bytes());
    let key = hex::decode(link.secret).unwrap();
    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let nonce = [7u8; 24];
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &serde_json::to_vec(&reply).unwrap(),
                aad: &aad,
            },
        )
        .unwrap();
    let mut wire = BOOTSTRAP_PREFIX.to_vec();
    wire.extend_from_slice(&nonce);
    wire.extend(ciphertext);
    Envelope {
        id,
        payload: STANDARD.encode(wire),
    }
}
async fn inject(server: &Server, queue: &Queue, envelope: &Envelope) {
    let response = fixture_http()
        .post(format!("{}/v1/queues/{}/messages", server.url, queue.id))
        .bearer_auth(&queue.write_token)
        .json(envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}
async fn resend_captured(server: &Server, envelope: &Envelope) {
    let (path, authorization) = {
        let requests = server.requests.lock().unwrap();
        let request = requests
            .iter()
            .find(|request| request.body.get("id").and_then(Value::as_str) == Some(&envelope.id))
            .unwrap();
        (request.path.clone(), request.authorization.clone())
    };
    let response = fixture_http()
        .post(format!("{}{}", server.url, path))
        .header(header::AUTHORIZATION, authorization)
        .json(envelope)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

#[tokio::test]
async fn one_link_requires_explicit_approval_then_exchanges_chat_without_history_controls() {
    let directory = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(directory.path(), Arc::new(Faults::default())).await;
    let mut owner = worker(directory.path(), "owner.sqlite");
    let mut recipient = worker(directory.path(), "recipient.sqlite");
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let accepted = recipient
        .accept_quick_invitation(&invite.link)
        .await
        .unwrap();
    assert!(
        !owner
            .quick_invitation_status(&invite.contact)
            .unwrap()
            .unwrap()
            .verified
    );
    assert!(
        !recipient
            .quick_invitation_status(&accepted.contact)
            .unwrap()
            .unwrap()
            .verified
    );
    assert!(recipient
        .store()
        .enqueue(&accepted.contact, "No message before approval")
        .is_err());
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(stage(&owner, &invite.contact), "quick_confirmation");
    assert!(owner
        .store()
        .enqueue(&invite.contact, "No message before approval")
        .is_err());
    assert_eq!(history_len(&mut owner, &invite.contact), 0);
    assert_eq!(history_len(&mut recipient, &accepted.contact), 0);
    owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    assert_eq!(stage(&owner, &invite.contact), "ready");
    assert_eq!(stage(&recipient, &accepted.contact), "ready");
    assert_eq!(history_len(&mut owner, &invite.contact), 0);
    assert_eq!(history_len(&mut recipient, &accepted.contact), 0);

    let owner_check = owner.quick_verification(&invite.contact).unwrap();
    let recipient_check = recipient.quick_verification(&accepted.contact).unwrap();
    assert!(owner_check.fingerprint == recipient_check.fingerprint);
    assert_eq!(owner_check.fingerprint.len(), 64);
    assert!(!owner_check.verified && !recipient_check.verified);
    let wrong = if owner_check.fingerprint.starts_with('0') {
        "1".repeat(64)
    } else {
        "0".repeat(64)
    };
    assert!(owner.mark_quick_verified(&invite.contact, &wrong).is_err());
    assert!(!owner.quick_verification(&invite.contact).unwrap().verified);
    owner
        .mark_quick_verified(&invite.contact, &owner_check.fingerprint)
        .unwrap();
    assert!(owner.quick_verification(&invite.contact).unwrap().verified);
    assert!(owner.take_incoming_contacts().is_empty());
    assert!(recipient.take_incoming_contacts().is_empty());
    // Independent comparison is local evidence, not a flag broadcast to peers.
    assert!(
        !recipient
            .quick_verification(&accepted.contact)
            .unwrap()
            .verified
    );

    recipient
        .store()
        .enqueue(
            &accepted.contact,
            "Recipient can send first after confirmation",
        )
        .unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    owner
        .store()
        .enqueue(&invite.contact, "Owner can answer")
        .unwrap();
    owner.sync(&invite.contact).await.unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    assert_eq!(owner.take_incoming_contacts(), vec![invite.contact.clone()]);
    assert_eq!(
        recipient.take_incoming_contacts(),
        vec![accepted.contact.clone()]
    );
    owner.sync(&invite.contact).await.unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    assert!(owner.take_incoming_contacts().is_empty());
    assert!(recipient.take_incoming_contacts().is_empty());
    let owner_history = owner.store().history(&invite.contact, 0).unwrap();
    let recipient_history = recipient.store().history(&accepted.contact, 0).unwrap();
    assert_eq!(owner_history.len(), 2);
    assert_eq!(recipient_history.len(), 2);
    assert_eq!(owner_history[0].direction, Direction::Incoming);
    assert_eq!(owner_history[1].direction, Direction::Outgoing);
    assert_eq!(recipient_history[0].direction, Direction::Outgoing);
    assert_eq!(recipient_history[1].direction, Direction::Incoming);
    assert!(owner_history[0].text == recipient_history[0].text);
    assert!(owner_history[1].text == recipient_history[1].text);
    assert_eq!(owner.store().contact_ids().unwrap().len(), 1);
    assert_eq!(recipient.store().contact_ids().unwrap().len(), 1);
    assert!(recipient
        .accept_quick_invitation(&invite.link)
        .await
        .is_err());
    assert_eq!(recipient.store().contact_ids().unwrap().len(), 1);
}

#[tokio::test]
async fn ambiguous_reply_and_candidate_ack_survive_reopen_with_exact_reply_and_one_candidate() {
    let directory = tempfile::tempdir().unwrap();
    let faults = Arc::new(Faults::default());
    faults.reply_response.store(true, Ordering::SeqCst);
    let (server, ticket) = serve(directory.path(), Arc::clone(&faults)).await;
    let owner_path = directory.path().join("owner.sqlite");
    let recipient_path = directory.path().join("recipient.sqlite");
    let owner_key = StorageKey::generate();
    let recipient_key = StorageKey::generate();
    let mut owner = ClientWorker::open(&owner_path, copy_key(&owner_key), true).unwrap();
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let mut recipient =
        ClientWorker::open(&recipient_path, copy_key(&recipient_key), true).unwrap();
    assert!(recipient
        .accept_quick_invitation(&invite.link)
        .await
        .is_err());
    let recipient_id = only_contact(&mut recipient);
    let first_reply = captured_envelopes(&server, BOOTSTRAP_PREFIX);
    assert_eq!(first_reply.len(), 1);
    drop(recipient);
    let mut recipient =
        ClientWorker::open(&recipient_path, copy_key(&recipient_key), true).unwrap();
    recipient.sync(&recipient_id).await.unwrap();
    let retried = captured_envelopes(&server, BOOTSTRAP_PREFIX);
    assert_eq!(retried.len(), 2);
    assert!(retried[0].id == retried[1].id);
    assert!(retried[0].payload == retried[1].payload);

    faults.ack_response.store(true, Ordering::SeqCst);
    assert!(owner.sync(&invite.contact).await.is_err());
    assert_eq!(stage(&owner, &invite.contact), "quick_confirmation");
    drop(owner);
    let mut owner = ClientWorker::open(&owner_path, copy_key(&owner_key), true).unwrap();
    assert_eq!(stage(&owner, &invite.contact), "quick_confirmation");
    owner.sync(&invite.contact).await.unwrap();
    owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .unwrap();
    recipient.sync(&recipient_id).await.unwrap();
    let agreed = owner
        .quick_verification(&invite.contact)
        .unwrap()
        .fingerprint;
    assert!(
        agreed
            == recipient
                .quick_verification(&recipient_id)
                .unwrap()
                .fingerprint
    );
    resend_captured(&server, &first_reply[0]).await;
    owner.sync(&invite.contact).await.unwrap();
    assert!(
        agreed
            == owner
                .quick_verification(&invite.contact)
                .unwrap()
                .fingerprint
    );
    assert_eq!(stage(&owner, &invite.contact), "ready");
    assert_eq!(owner.store().contact_ids().unwrap().len(), 1);
    assert_eq!(history_len(&mut owner, &invite.contact), 0);
    assert_eq!(history_len(&mut recipient, &recipient_id), 0);
}

#[tokio::test]
async fn approval_control_retry_is_durable_and_precedes_first_user_message() {
    let directory = tempfile::tempdir().unwrap();
    let faults = Arc::new(Faults::default());
    let (server, ticket) = serve(directory.path(), Arc::clone(&faults)).await;
    let owner_path = directory.path().join("owner.sqlite");
    let owner_key = StorageKey::generate();
    let mut owner = ClientWorker::open(&owner_path, copy_key(&owner_key), true).unwrap();
    let mut recipient = worker(directory.path(), "recipient.sqlite");
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let accepted = recipient
        .accept_quick_invitation(&invite.link)
        .await
        .unwrap();
    owner.sync(&invite.contact).await.unwrap();
    faults.control_response.store(true, Ordering::SeqCst);
    assert!(owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .is_err());
    let first_control = captured_envelopes(&server, CONTROL_PREFIX);
    assert_eq!(first_control.len(), 1);
    drop(owner);
    let mut owner = ClientWorker::open(&owner_path, copy_key(&owner_key), true).unwrap();
    let chat = owner
        .store()
        .enqueue(
            &invite.contact,
            "Regular first message follows the durable control",
        )
        .unwrap();
    owner.sync(&invite.contact).await.unwrap();
    let controls = captured_envelopes(&server, CONTROL_PREFIX);
    assert_eq!(controls.len(), 2);
    assert!(controls[0].id == controls[1].id);
    assert!(controls[0].payload == controls[1].payload);
    {
        let requests = server.requests.lock().unwrap();
        let control_position = requests
            .iter()
            .rposition(|request| {
                request.body.get("id").and_then(Value::as_str) == Some(&controls[1].id)
            })
            .unwrap();
        let chat_position = requests
            .iter()
            .position(|request| request.body.get("id").and_then(Value::as_str) == Some(&chat.id))
            .unwrap();
        assert!(control_position < chat_position);
    }
    recipient.sync(&accepted.contact).await.unwrap();
    assert_eq!(stage(&recipient, &accepted.contact), "ready");
    assert_eq!(history_len(&mut recipient, &accepted.contact), 1);
    resend_captured(&server, &first_control[0]).await;
    recipient.sync(&accepted.contact).await.unwrap();
    assert_eq!(history_len(&mut recipient, &accepted.contact), 1);
    recipient
        .store()
        .enqueue(
            &accepted.contact,
            "The control retry did not reset the session",
        )
        .unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(history_len(&mut owner, &invite.contact), 2);
    assert_eq!(history_len(&mut recipient, &accepted.contact), 2);
}

#[tokio::test]
async fn malformed_bootstrap_before_reply_and_late_after_readiness_cannot_poison_the_queue() {
    let directory = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(directory.path(), Arc::new(Faults::default())).await;
    let mut owner = worker(directory.path(), "owner.sqlite");
    let mut recipient = worker(directory.path(), "recipient.sqlite");
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let queue = owner_queue(&server);
    let malformed = Envelope {
        id: "0123456789abcdef0123456789abcdef".into(),
        payload: STANDARD.encode(b"koto-setup:v2:invalid-ciphertext"),
    };
    inject(&server, &queue, &malformed).await;
    let accepted = recipient
        .accept_quick_invitation(&invite.link)
        .await
        .unwrap();
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(stage(&owner, &invite.contact), "quick_confirmation");
    owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    let late_malformed = Envelope {
        id: "fedcba9876543210fedcba9876543210".into(),
        payload: malformed.payload,
    };
    inject(&server, &queue, &late_malformed).await;
    recipient
        .store()
        .enqueue(
            &accepted.contact,
            "A valid chat follows an invalid setup frame",
        )
        .unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(stage(&owner, &invite.contact), "ready");
    let history = owner.store().history(&invite.contact, 0).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].direction, Direction::Incoming);
    assert!(history[0].text == "A valid chat follows an invalid setup frame");
    assert_eq!(owner.sync(&invite.contact).await.unwrap().received, 0);
    assert_eq!(history_len(&mut owner, &invite.contact), 1);
}

#[tokio::test]
async fn quick_setup_keeps_the_existing_single_worker_profile_lock() {
    let directory = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(directory.path(), Arc::new(Faults::default())).await;
    let path = directory.path().join("owner.sqlite");
    let key = StorageKey::generate();
    let mut owner = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    assert!(matches!(
        ClientWorker::open(&path, copy_key(&key), true),
        Err(Error::AlreadyRunning)
    ));
    drop(owner);
    let mut reopened = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    assert_eq!(reopened.store().contact_ids().unwrap().len(), 1);
}

#[tokio::test]
async fn authenticated_reply_pointing_to_another_reserved_queue_is_dropped_before_valid_reply() {
    let directory = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(directory.path(), Arc::new(Faults::default())).await;
    let mut owner = worker(directory.path(), "owner.sqlite");
    let mut recipient = worker(directory.path(), "recipient.sqlite");
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let receiving = owner_queue(&server);
    let second_ticket = Store::open(directory.path().join("relay.sqlite").to_str().unwrap())
        .unwrap()
        .issue_invitation_ticket(86400)
        .unwrap();
    let second = owner
        .create_quick_invitation(&server.url, &second_ticket)
        .await
        .unwrap();
    let first_link = decode_link(&invite.link);
    let second_link = decode_link(&second.link);
    let bad_reply = Invitation::reply(
        "00000000000000000000000000000001".into(),
        Contact::new().public_bundle(),
        second_link.offer.write_endpoint().clone(),
        first_link.offer.fingerprint().unwrap(),
    )
    .unwrap();
    inject(&server, &receiving, &forge_reply(&invite.link, bad_reply)).await;
    let accepted = recipient
        .accept_quick_invitation(&invite.link)
        .await
        .unwrap();
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(stage(&owner, &invite.contact), "quick_confirmation");
    assert_eq!(stage(&owner, &second.contact), "quick_pending");
    owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .unwrap();
    recipient.sync(&accepted.contact).await.unwrap();
    assert!(
        owner
            .quick_verification(&invite.contact)
            .unwrap()
            .fingerprint
            == recipient
                .quick_verification(&accepted.contact)
                .unwrap()
                .fingerprint
    );
    assert_eq!(owner.store().contact_ids().unwrap().len(), 2);
    assert_eq!(history_len(&mut owner, &invite.contact), 0);
}

#[tokio::test]
async fn ordinary_ticket_is_rejected_and_saved_invitation_resumes_with_invite_ticket_without_new_contact(
) {
    let directory = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(directory.path(), Arc::new(Faults::default())).await;
    let ordinary = Store::open(directory.path().join("relay.sqlite").to_str().unwrap())
        .unwrap()
        .issue_ticket(86400)
        .unwrap();
    let key = StorageKey::generate();
    let path = directory.path().join("recover.sqlite");
    let mut owner = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    assert!(matches!(
        owner.create_quick_invitation(&server.url, &ordinary).await,
        Err(Error::InvitationProvisionRejected(403))
    ));
    let id = only_contact(&mut owner);
    assert_eq!(stage(&owner, &id), "quick_queue_pending");
    let original_proposal = server
        .requests
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.path == "/v1/queues/invite")
        .unwrap()
        .body
        .clone();
    drop(owner);
    let mut owner = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    let invitation = owner
        .provision_quick_invitation(&id, Some(&ticket))
        .await
        .unwrap();
    assert_eq!(invitation.contact, id);
    assert_eq!(only_contact(&mut owner), id);
    assert_eq!(stage(&owner, &id), "quick_pending");
    {
        let saved = server.requests.lock().unwrap();
        assert!(saved
            .iter()
            .filter(|r| r.path == "/v1/queues/invite")
            .all(|r| r.body == original_proposal));
    }
    let mut recipient = worker(directory.path(), "delete-recipient.sqlite");
    let accepted = recipient
        .accept_quick_invitation(&invitation.link)
        .await
        .unwrap();
    recipient.store().delete_contact(&accepted.contact).unwrap();
    let count = server.requests.lock().unwrap().len();
    assert!(matches!(
        recipient.accept_quick_invitation(&invitation.link).await,
        Err(Error::Store(messenger_store::Error::SetupReplay))
    ));
    assert_eq!(server.requests.lock().unwrap().len(), count);
    assert_eq!(stage(&owner, &id), "quick_pending");
}

#[tokio::test]
async fn ticket_replacement_reconciles_lost_success_before_spending_new_ticket() {
    let directory = tempfile::tempdir().unwrap();
    let faults = Arc::new(Faults::default());
    faults.invite_response.store(true, Ordering::SeqCst);
    let (server, ticket) = serve(directory.path(), faults).await;
    let mut owner = worker(directory.path(), "lost-create.sqlite");
    assert!(matches!(
        owner.create_quick_invitation(&server.url, &ticket).await,
        Err(Error::InvitationProvisionRejected(503))
    ));
    let id = only_contact(&mut owner);
    let fresh = Store::open(directory.path().join("relay.sqlite").to_str().unwrap())
        .unwrap()
        .issue_invitation_ticket(86400)
        .unwrap();
    let recovered = owner
        .provision_quick_invitation(&id, Some(&fresh))
        .await
        .unwrap();
    assert_eq!(recovered.contact, id);
    assert_eq!(stage(&owner, &id), "quick_pending");
    assert!(server
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| !r.authorization.contains(&fresh)));
    // The unused replacement ticket remains available for another invitation.
    assert!(owner
        .create_quick_invitation(&server.url, &fresh)
        .await
        .is_ok());
    assert_eq!(owner.store().contact_ids().unwrap().len(), 2);
}

#[tokio::test]
async fn names_flow_over_existing_encrypted_queues_without_chat_or_unread_noise() {
    let dir = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(dir.path(), Arc::new(Faults::default())).await;
    let mut owner = worker(dir.path(), "named-owner");
    let mut peer = worker(dir.path(), "named-peer");
    owner.store().set_nickname("Учёный Кот").unwrap();
    peer.store().set_nickname("Барсик").unwrap();
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let accepted = peer.accept_quick_invitation(&invite.link).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .unwrap();
    let report = peer.sync(&accepted.contact).await.unwrap();
    assert!(report.profile_changed);
    assert_eq!(report.received, 0);
    peer.sync(&accepted.contact).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(
        peer.store()
            .contact_names(&accepted.contact)
            .unwrap()
            .nickname,
        "Учёный Кот"
    );
    assert_eq!(
        owner
            .store()
            .contact_names(&invite.contact)
            .unwrap()
            .nickname,
        "Барсик"
    );
    assert_eq!(history_len(&mut peer, &accepted.contact), 0);
    assert!(owner.take_incoming_contacts().is_empty());
    assert!(peer.take_incoming_contacts().is_empty());
    assert_eq!(owner.store().unread_count(&invite.contact).unwrap(), 0);
    owner
        .store()
        .set_contact_alias(&invite.contact, "Друг из школы")
        .unwrap();
    peer.store().set_nickname("Кот в отпуске").unwrap();
    peer.sync(&accepted.contact).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    let names = owner.store().contact_names(&invite.contact).unwrap();
    assert_eq!(names.nickname, "Кот в отпуске");
    assert_eq!(names.alias, "Друг из школы");
    let count = captured_envelopes(&server, b"koto-profile:v1:").len();
    peer.sync(&accepted.contact).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    assert_eq!(
        captured_envelopes(&server, b"koto-profile:v1:").len(),
        count
    );
    peer.store().enqueue(&accepted.contact, "hello").unwrap();
    peer.sync(&accepted.contact).await.unwrap();
    assert_eq!(owner.sync(&invite.contact).await.unwrap().received, 1);
    assert_eq!(owner.store().unread_count(&invite.contact).unwrap(), 1);
    assert_eq!(
        owner.store().history(&invite.contact, 0).unwrap()[0].text,
        "hello"
    );
    // The server sees ciphertext and transport purpose, never either label.
    for request in server.requests.lock().unwrap().iter() {
        let body = request.body.to_string();
        assert!(
            !body.contains("Барсик")
                && !body.contains("Учёный Кот")
                && !body.contains("Кот в отпуске")
        );
    }
}

#[tokio::test]
async fn nickname_update_does_not_block_a_full_text_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let (server, ticket) = serve(dir.path(), Arc::new(Faults::default())).await;
    let mut owner = worker(dir.path(), "full-owner");
    let mut peer = worker(dir.path(), "full-peer");
    let invite = owner
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let accepted = peer.accept_quick_invitation(&invite.link).await.unwrap();
    owner.sync(&invite.contact).await.unwrap();
    owner
        .confirm_quick_invitation(&invite.contact)
        .await
        .unwrap();
    peer.sync(&accepted.contact).await.unwrap();
    for _ in 0..256 {
        owner
            .store()
            .enqueue(&invite.contact, "queued text")
            .unwrap();
    }
    owner.store().set_nickname("Кот с очередью").unwrap();
    assert_eq!(owner.sync(&invite.contact).await.unwrap().sent, 100);
    assert_eq!(peer.sync(&accepted.contact).await.unwrap().received, 100);
    for _ in 0..3 {
        owner.sync(&invite.contact).await.unwrap();
        peer.sync(&accepted.contact).await.unwrap();
    }
    assert_eq!(
        peer.store()
            .contact_names(&accepted.contact)
            .unwrap()
            .nickname,
        "Кот с очередью"
    );
    assert!(owner
        .store()
        .pending_outbox(&invite.contact)
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn delivery_status_survives_offline_receiver_ack_loss_and_reopen_without_notification_noise()
{
    use messenger_store::{DeliveryStatus, DELIVERY_PREFIX};
    let d = tempfile::tempdir().unwrap();
    let faults = Arc::new(Faults::default());
    let (server, ticket) = serve(d.path(), Arc::clone(&faults)).await;
    let ak = StorageKey::generate();
    let bk = StorageKey::generate();
    let ap = d.path().join("delivery-owner");
    let bp = d.path().join("delivery-recipient");
    let mut a = ClientWorker::open(&ap, copy_key(&ak), true).unwrap();
    let mut b = ClientWorker::open(&bp, copy_key(&bk), true).unwrap();
    let invite = a
        .create_quick_invitation(&server.url, &ticket)
        .await
        .unwrap();
    let accepted = b.accept_quick_invitation(&invite.link).await.unwrap();
    a.sync(&invite.contact).await.unwrap();
    a.confirm_quick_invitation(&invite.contact).await.unwrap();
    b.sync(&accepted.contact).await.unwrap();
    let id = a
        .store()
        .enqueue(&invite.contact, "await the sleeping cat")
        .unwrap()
        .id;
    assert_eq!(
        a.store().history(&invite.contact, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Queued)
    );
    drop(b);
    a.sync(&invite.contact).await.unwrap();
    assert_eq!(
        a.store().history(&invite.contact, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Server)
    );
    a.sync(&invite.contact).await.unwrap();
    assert_eq!(
        a.store().history(&invite.contact, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Server)
    );
    let mut b = ClientWorker::open(&bp, copy_key(&bk), true).unwrap();
    faults.ack_response.store(true, Ordering::SeqCst);
    assert!(b.sync(&accepted.contact).await.is_err());
    assert_eq!(b.store().unread_count(&accepted.contact).unwrap(), 1);
    assert_eq!(b.take_incoming_contacts(), vec![accepted.contact.clone()]);
    let saved = b
        .store()
        .pending_outbox(&accepted.contact)
        .unwrap()
        .into_iter()
        .find(|e| has_prefix(e, DELIVERY_PREFIX))
        .unwrap();
    drop(b);
    let mut b = ClientWorker::open(&bp, copy_key(&bk), true).unwrap();
    let report = b.sync(&accepted.contact).await.unwrap();
    assert_eq!(report.sent, 0);
    assert_eq!(report.received, 0);
    assert!(b.take_incoming_contacts().is_empty());
    let receipt = captured_envelopes(&server, DELIVERY_PREFIX);
    assert_eq!(receipt.len(), 1);
    assert_eq!(receipt[0].payload, saved.payload);
    faults.ack_response.store(true, Ordering::SeqCst);
    assert!(a.sync(&invite.contact).await.is_err());
    assert_eq!(
        a.store().history(&invite.contact, 0).unwrap()[0].delivery,
        Some(DeliveryStatus::Delivered)
    );
    assert!(a.take_incoming_contacts().is_empty());
    drop(a);
    let mut a = ClientWorker::open(&ap, copy_key(&ak), true).unwrap();
    a.sync(&invite.contact).await.unwrap();
    let h = a.store().history(&invite.contact, 0).unwrap();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].id, id);
    assert_eq!(h[0].delivery, Some(DeliveryStatus::Delivered));
    assert_eq!(a.store().unread_count(&invite.contact).unwrap(), 0);
    assert!(a.take_incoming_contacts().is_empty());
}

//! Invitation fixtures trust fingerprints inside this controlled test process.
//! A real user must verify them through an independent trusted channel.
//! Queue credentials, exported invitations and fingerprints are never printed.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    Router,
};
use messenger_client::{invitations::Invitation, ClientWorker, Error, ReceiveQueue};
use messenger_core::{Contact, StorageKey};
use messenger_relay::{router, AppState, Queue, Store};
use messenger_store::{ContactRoute, Direction, QueueEndpoint};
use tokio::{net::TcpListener, task::JoinHandle};

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn worker(directory: &Path, name: &str) -> ClientWorker {
    ClientWorker::open(directory.join(name), StorageKey::generate(), true).unwrap()
}

fn receiving_queue(url: &str, seed: u32) -> ReceiveQueue {
    ReceiveQueue {
        read: QueueEndpoint {
            relay_url: url.to_owned(),
            queue_id: format!("{seed:032x}"),
            token: format!("{:064x}", seed + 1000),
        },
        write: QueueEndpoint {
            relay_url: url.to_owned(),
            queue_id: format!("{seed:032x}"),
            token: format!("{:064x}", seed + 2000),
        },
    }
}

fn https_queue(seed: u32) -> ReceiveQueue {
    receiving_queue("https://relay.example", seed)
}

fn invitation_error(result: messenger_client::Result<impl Sized>) {
    assert!(matches!(result, Err(Error::Invitation(_))));
}

#[test]
fn untrusted_offer_and_reply_fingerprints_leave_profiles_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let mut bob = worker(directory.path(), "bob.sqlite");
    let offer = alice.create_invitation(https_queue(1)).unwrap();
    invitation_error(bob.accept_invitation(&offer.invitation, &"0".repeat(64), https_queue(2)));
    assert!(bob.store().contact_ids().unwrap().is_empty());
    let reply = bob
        .accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(2))
        .unwrap();
    invitation_error(alice.complete_invitation(&offer.contact, &reply.invitation, &"0".repeat(64)));
    assert!(matches!(
        alice.store().route(&offer.contact),
        Err(messenger_store::Error::SetupPending)
    ));
    assert_eq!(alice.store().contact_ids().unwrap().len(), 1);
    alice
        .complete_invitation(&offer.contact, &reply.invitation, &reply.fingerprint)
        .unwrap();
}

#[test]
fn changing_write_capability_invalidates_the_whole_artifact_fingerprint() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let mut bob = worker(directory.path(), "bob.sqlite");
    let offer = alice.create_invitation(https_queue(1)).unwrap();
    let decoded = Invitation::decode(&offer.invitation).unwrap();
    let mut changed = serde_json::to_value(decoded).unwrap();
    changed["write"]["token"] = serde_json::Value::String("f".repeat(64));
    let changed: Invitation = serde_json::from_value(changed).unwrap();
    let changed = changed.encode().unwrap();
    invitation_error(bob.accept_invitation(&changed, &offer.fingerprint, https_queue(2)));
    assert!(bob.store().contact_ids().unwrap().is_empty());
    // The correct artifact is still usable after the rejected import.
    bob.accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(2))
        .unwrap();
}

#[test]
fn reply_for_another_offer_preserves_pending_state_and_allows_a_valid_retry() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let mut bob = worker(directory.path(), "bob.sqlite");
    let mut carol = worker(directory.path(), "carol.sqlite");
    let mut dave = worker(directory.path(), "dave.sqlite");
    let offer = alice.create_invitation(https_queue(1)).unwrap();
    let unrelated = carol.create_invitation(https_queue(3)).unwrap();
    let wrong_reply = bob
        .accept_invitation(
            &unrelated.invitation,
            &unrelated.fingerprint,
            https_queue(2),
        )
        .unwrap();
    assert!(matches!(
        alice.complete_invitation(
            &offer.contact,
            &wrong_reply.invitation,
            &wrong_reply.fingerprint
        ),
        Err(Error::ReplyMismatch)
    ));
    let unchanged = alice.export_invitation(&offer.contact).unwrap();
    assert!(unchanged.invitation == offer.invitation);
    assert!(unchanged.fingerprint == offer.fingerprint);
    assert!(matches!(
        alice.store().route(&offer.contact),
        Err(messenger_store::Error::SetupPending)
    ));
    let valid_reply = dave
        .accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(4))
        .unwrap();
    alice
        .complete_invitation(
            &offer.contact,
            &valid_reply.invitation,
            &valid_reply.fingerprint,
        )
        .unwrap();
    alice
        .store()
        .enqueue(
            &offer.contact,
            "The valid retry starts the initiator session",
        )
        .unwrap();
}

#[test]
fn pending_offer_and_exact_reply_can_be_exported_after_profile_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let alice_path = directory.path().join("alice.sqlite");
    let bob_path = directory.path().join("bob.sqlite");
    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    let offer = alice.create_invitation(https_queue(1)).unwrap();
    drop(alice);
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    let exported_offer = alice.export_invitation(&offer.contact).unwrap();
    assert!(exported_offer.invitation == offer.invitation);
    assert!(exported_offer.fingerprint == offer.fingerprint);
    let mut bob = ClientWorker::open(&bob_path, copy_key(&bob_key), true).unwrap();
    let reply = bob
        .accept_invitation(
            &exported_offer.invitation,
            &exported_offer.fingerprint,
            https_queue(2),
        )
        .unwrap();
    drop(bob);
    let mut bob = ClientWorker::open(&bob_path, copy_key(&bob_key), true).unwrap();
    let exported_reply = bob.export_invitation(&reply.contact).unwrap();
    assert!(exported_reply.invitation == reply.invitation);
    assert!(exported_reply.fingerprint == reply.fingerprint);
    assert!(matches!(
        bob.accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(3)),
        Err(Error::Store(messenger_store::Error::SetupReplay))
    ));
    assert_eq!(bob.store().contact_ids().unwrap().len(), 1);
    alice
        .complete_invitation(
            &offer.contact,
            &exported_reply.invitation,
            &exported_reply.fingerprint,
        )
        .unwrap();
    drop(alice);
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    alice
        .store()
        .enqueue(&offer.contact, "Session survived a completed setup reopen")
        .unwrap();
    let still_same_reply = bob.export_invitation(&reply.contact).unwrap();
    assert!(still_same_reply.invitation == reply.invitation);
}

#[test]
fn replayed_offer_and_repeated_completion_do_not_create_or_reset_contacts() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let mut bob = worker(directory.path(), "bob.sqlite");
    let offer = alice.create_invitation(https_queue(1)).unwrap();
    let reply = bob
        .accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(2))
        .unwrap();
    assert!(matches!(
        bob.accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(3)),
        Err(Error::Store(messenger_store::Error::SetupReplay))
    ));
    assert_eq!(bob.store().contact_ids().unwrap().len(), 1);
    alice
        .complete_invitation(&offer.contact, &reply.invitation, &reply.fingerprint)
        .unwrap();
    let first = alice
        .store()
        .enqueue(&offer.contact, "Queued before replay")
        .unwrap();
    assert!(matches!(
        alice.complete_invitation(&offer.contact, &reply.invitation, &reply.fingerprint),
        Err(Error::InvitationCompleted)
    ));
    assert_eq!(alice.store().contact_ids().unwrap().len(), 1);
    let pending = alice.store().pending_outbox(&offer.contact).unwrap();
    assert_eq!(pending.len(), 1);
    assert!(pending[0].id == first.id && pending[0].payload == first.payload);
}

#[test]
fn exported_offer_and_reply_include_write_capability_and_exclude_own_read_token() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let mut bob = worker(directory.path(), "bob.sqlite");
    let alice_queue = https_queue(1);
    let bob_queue = https_queue(2);
    let alice_read = alice_queue.read.token.clone();
    let alice_write = alice_queue.write.token.clone();
    let bob_read = bob_queue.read.token.clone();
    let bob_write = bob_queue.write.token.clone();
    let offer = alice.create_invitation(alice_queue).unwrap();
    let reply = bob
        .accept_invitation(&offer.invitation, &offer.fingerprint, bob_queue)
        .unwrap();
    for (artifact, own_read, own_write) in [
        (&offer.invitation, &alice_read, &alice_write),
        (&reply.invitation, &bob_read, &bob_write),
    ] {
        let decoded = Invitation::decode(artifact).unwrap();
        let json = serde_json::to_string(&decoded).unwrap();
        assert!(!json.contains(own_read));
        assert!(json.contains(own_write));
    }
}

#[test]
fn receiving_queue_cannot_be_reused_even_through_an_equivalent_url() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    alice.create_invitation(https_queue(1)).unwrap();
    let mut reused = https_queue(1);
    reused.read.relay_url = "https://relay.example:443/".into();
    reused.write.relay_url = "https://relay.example/".into();
    assert!(matches!(
        alice.create_invitation(reused),
        Err(Error::QueueAlreadyUsed)
    ));
    assert_eq!(alice.store().contact_ids().unwrap().len(), 1);
}

#[test]
fn legacy_contact_send_and_receiving_queues_cannot_be_reused_for_new_invitations() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let contact = alice.store().insert_contact(Contact::new()).unwrap();
    let mut receive = https_queue(1).read;
    receive.relay_url = "https://RELAY.example:443/".into();
    alice
        .store()
        .set_route(
            &contact,
            &ContactRoute {
                receive,
                send: https_queue(2).write,
            },
        )
        .unwrap();
    for seed in [1, 2] {
        let mut used = https_queue(seed);
        used.read.relay_url = "https://RELAY.example:443/".into();
        assert!(matches!(
            alice.create_invitation(used),
            Err(Error::QueueAlreadyUsed)
        ));
    }
    assert_eq!(alice.store().contact_ids().unwrap().len(), 1);
}

#[test]
fn invalid_receiving_pairs_and_nonlocal_http_leave_no_contact() {
    let directory = tempfile::tempdir().unwrap();
    let mut client = worker(directory.path(), "client.sqlite");
    let mut wrong_id = https_queue(1);
    wrong_id.write.queue_id = "f".repeat(32);
    let mut wrong_relay = https_queue(1);
    wrong_relay.write.relay_url = "https://other-relay.example".into();
    let mut identical_tokens = https_queue(1);
    identical_tokens.write.token = identical_tokens.read.token.clone();
    let mut unexpected_path = https_queue(1);
    unexpected_path.write.relay_url = "https://relay.example/secret".into();
    for queue in [
        wrong_id,
        wrong_relay,
        identical_tokens,
        unexpected_path,
        receiving_queue("http://example.com", 1),
        receiving_queue("http://localhost:8787", 1),
    ] {
        assert!(client.create_invitation(queue).is_err());
        assert!(client.store().contact_ids().unwrap().is_empty());
    }
    let mut no_http = ClientWorker::open(
        directory.path().join("no-http.sqlite"),
        StorageKey::generate(),
        false,
    )
    .unwrap();
    assert!(no_http
        .create_invitation(receiving_queue("http://127.0.0.1:8787", 1))
        .is_err());
    assert!(no_http.store().contact_ids().unwrap().is_empty());
}

#[test]
fn peer_send_queue_cannot_equal_the_local_receiving_queue() {
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let mut bob = worker(directory.path(), "bob.sqlite");
    let offer = alice.create_invitation(https_queue(1)).unwrap();
    assert!(bob
        .accept_invitation(&offer.invitation, &offer.fingerprint, https_queue(1))
        .is_err());
    assert!(bob.store().contact_ids().unwrap().is_empty());
}

struct Server {
    url: String,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(app: Router) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Server { url, task }
}

#[tokio::test]
async fn pending_offer_sync_returns_before_any_http_request() {
    let requests = Arc::new(AtomicUsize::new(0));
    let captured = Arc::clone(&requests);
    let app = Router::new()
        .fallback(|| async { StatusCode::NO_CONTENT })
        .layer(middleware::from_fn(
            move |request: Request<Body>, next: Next| {
                let captured = Arc::clone(&captured);
                async move {
                    captured.fetch_add(1, Ordering::SeqCst);
                    let response: Response = next.run(request).await;
                    response
                }
            },
        ));
    let server = serve(app).await;
    let directory = tempfile::tempdir().unwrap();
    let mut alice = worker(directory.path(), "alice.sqlite");
    let offer = alice
        .create_invitation(receiving_queue(&server.url, 1))
        .unwrap();
    assert!(matches!(
        alice.sync(&offer.contact).await,
        Err(Error::Store(messenger_store::Error::SetupPending))
    ));
    assert_eq!(requests.load(Ordering::SeqCst), 0);
}

async fn provision(server: &Server) -> ReceiveQueue {
    let response = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}/v1/queues", server.url))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let queue: Queue = response.json().await.unwrap();
    ReceiveQueue {
        read: QueueEndpoint {
            relay_url: server.url.clone(),
            queue_id: queue.id.clone(),
            token: queue.read_token,
        },
        write: QueueEndpoint {
            relay_url: server.url.clone(),
            queue_id: queue.id,
            token: queue.write_token,
        },
    }
}

#[tokio::test]
async fn accepted_invitation_delivers_first_message_and_reply_after_profile_reopens() {
    let directory = tempfile::tempdir().unwrap();
    let relay_path = directory.path().join("relay.sqlite");
    let state = AppState::new(Store::open(relay_path.to_str().unwrap()).unwrap(), ADMIN);
    let server = serve(router(state)).await;
    let alice_queue = provision(&server).await;
    let bob_queue = provision(&server).await;
    let alice_path = directory.path().join("alice.sqlite");
    let bob_path = directory.path().join("bob.sqlite");
    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    let offer = alice.create_invitation(alice_queue).unwrap();
    drop(alice);
    let mut bob = ClientWorker::open(&bob_path, copy_key(&bob_key), true).unwrap();
    let reply = bob
        .accept_invitation(&offer.invitation, &offer.fingerprint, bob_queue)
        .unwrap();
    // Only the offerer initiates. The responder cannot invent an outgoing
    // session before receiving the offerer's first encrypted message.
    assert!(bob.store().enqueue(&reply.contact, "Too early").is_err());
    assert!(bob.store().history(&reply.contact, 0).unwrap().is_empty());
    drop(bob);
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    alice
        .complete_invitation(&offer.contact, &reply.invitation, &reply.fingerprint)
        .unwrap();
    alice
        .store()
        .enqueue(&offer.contact, "First authenticated invitation message")
        .unwrap();
    drop(alice);
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    assert_eq!(alice.sync(&offer.contact).await.unwrap().sent, 1);
    drop(alice);
    let mut bob = ClientWorker::open(&bob_path, copy_key(&bob_key), true).unwrap();
    let incoming = bob.sync(&reply.contact).await.unwrap();
    assert_eq!(incoming.received, 1);
    assert_eq!(incoming.acked, 1);
    bob.store()
        .enqueue(
            &reply.contact,
            "Reply after invitation session establishment",
        )
        .unwrap();
    drop(bob);
    let mut bob = ClientWorker::open(&bob_path, copy_key(&bob_key), true).unwrap();
    assert_eq!(bob.sync(&reply.contact).await.unwrap().sent, 1);
    drop(bob);
    let mut alice = ClientWorker::open(&alice_path, copy_key(&alice_key), true).unwrap();
    let response = alice.sync(&offer.contact).await.unwrap();
    assert_eq!(response.received, 1);
    assert_eq!(response.acked, 2);
    assert!(response.delivery_changed);
    let history = alice.store().history(&offer.contact, 0).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].direction, Direction::Outgoing);
    assert_eq!(history[0].text, "First authenticated invitation message");
    assert_eq!(history[1].direction, Direction::Incoming);
    assert_eq!(
        history[1].text,
        "Reply after invitation session establishment"
    );
    assert_eq!(
        alice.store().pending_outbox(&offer.contact).unwrap().len(),
        1
    ); // reply delivery control
    assert_eq!(
        history[0].delivery,
        Some(messenger_store::DeliveryStatus::Delivered)
    );
    assert!(alice
        .store()
        .pending_acks(&offer.contact)
        .unwrap()
        .is_empty());
    let repeated = alice.sync(&offer.contact).await.unwrap();
    assert_eq!(
        repeated.sent + repeated.received + repeated.duplicates + repeated.acked,
        0
    );
}

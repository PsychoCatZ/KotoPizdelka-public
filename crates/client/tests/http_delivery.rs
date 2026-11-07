//! Exercise the HTTP worker over real loopback TCP, including ambiguous network
//! outcomes. All capabilities are fixture-only and are never printed.
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use messenger_client::{ClientWorker, Error};
use messenger_core::{Contact, Envelope, StorageKey};
use messenger_relay::{router, AppState, Messages, Queue, Store};
use messenger_store::{ContactRoute, QueueEndpoint};
use serde_json::json;
use tokio::{net::TcpListener, task::JoinHandle};

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
fn relay(dir: &Path) -> Router {
    let path = dir.join("relay.sqlite");
    router(AppState::new(
        Store::open(path.to_str().unwrap()).unwrap(),
        ADMIN,
    ))
}
fn fixture_http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}
async fn create_queue(server: &Server) -> Queue {
    let response = fixture_http()
        .post(format!("{}/v1/queues", server.url))
        .bearer_auth(ADMIN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json().await.unwrap()
}
async fn queued(server: &Server, queue: &Queue) -> Messages {
    let response = fixture_http()
        .get(format!("{}/v1/queues/{}/messages", server.url, queue.id))
        .bearer_auth(&queue.read_token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
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
fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}
fn contacts() -> (Contact, Contact) {
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
fn route(url: &str, send: &Queue, receive: &Queue) -> ContactRoute {
    ContactRoute {
        send: QueueEndpoint {
            relay_url: url.to_owned(),
            queue_id: send.id.clone(),
            token: send.write_token.clone(),
        },
        receive: QueueEndpoint {
            relay_url: url.to_owned(),
            queue_id: receive.id.clone(),
            token: receive.read_token.clone(),
        },
    }
}
struct Peers {
    alice: ClientWorker,
    bob: ClientWorker,
    alice_id: String,
    bob_id: String,
    alice_key: StorageKey,
    bob_key: StorageKey,
}
fn peers(dir: &Path, url: &str, a_queue: &Queue, b_queue: &Queue) -> Peers {
    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();
    let mut alice =
        ClientWorker::open(dir.join("alice.sqlite"), copy_key(&alice_key), true).unwrap();
    let mut bob = ClientWorker::open(dir.join("bob.sqlite"), copy_key(&bob_key), true).unwrap();
    let (a, b) = contacts();
    let alice_id = alice.store().insert_contact(a).unwrap();
    let bob_id = bob.store().insert_contact(b).unwrap();
    alice
        .store()
        .set_route(&alice_id, &route(url, b_queue, a_queue))
        .unwrap();
    bob.store()
        .set_route(&bob_id, &route(url, a_queue, b_queue))
        .unwrap();
    Peers {
        alice,
        bob,
        alice_id,
        bob_id,
        alice_key,
        bob_key,
    }
}
fn reopen(worker: ClientWorker, path: &Path, key: &StorageKey) -> ClientWorker {
    drop(worker);
    ClientWorker::open(path, copy_key(key), true).unwrap()
}
fn isolated_worker(dir: &Path, url: &str, allow_http: bool) -> (ClientWorker, String) {
    let mut worker = ClientWorker::open(
        dir.join("client.sqlite"),
        StorageKey::generate(),
        allow_http,
    )
    .unwrap();
    let contact_id = worker.store().insert_contact(Contact::new()).unwrap();
    let endpoint = QueueEndpoint {
        relay_url: url.to_owned(),
        queue_id: "1".repeat(32),
        token: "2".repeat(64),
    };
    worker
        .store()
        .set_route(
            &contact_id,
            &ContactRoute {
                send: endpoint.clone(),
                receive: endpoint,
            },
        )
        .unwrap();
    (worker, contact_id)
}

#[tokio::test]
async fn offline_delivery_and_reply_survive_client_reopen_over_real_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(relay(dir.path())).await;
    let a_queue = create_queue(&server).await;
    let b_queue = create_queue(&server).await;
    let mut peers = peers(dir.path(), &server.url, &a_queue, &b_queue);
    let envelope = peers
        .alice
        .store()
        .enqueue(&peers.alice_id, "Desktop to offline Android")
        .unwrap();
    let sent = peers.alice.sync(&peers.alice_id).await.unwrap();
    assert_eq!(sent.sent, 1);
    assert_eq!(sent.received, 0);
    let pending = queued(&server, &b_queue).await;
    assert_eq!(pending.messages.len(), 1);
    assert_eq!(pending.messages[0].id, envelope.id);
    assert_eq!(pending.messages[0].payload, envelope.payload);
    peers.bob = reopen(peers.bob, &dir.path().join("bob.sqlite"), &peers.bob_key);
    let received = peers.bob.sync(&peers.bob_id).await.unwrap();
    assert_eq!(received.received, 1);
    assert_eq!(received.acked, 1);
    assert!(queued(&server, &b_queue).await.messages.is_empty());
    assert_eq!(
        peers.bob.store().history(&peers.bob_id, 0).unwrap()[0].text,
        "Desktop to offline Android"
    );
    peers
        .bob
        .store()
        .enqueue(&peers.bob_id, "Android reply after recovery")
        .unwrap();
    assert_eq!(peers.bob.sync(&peers.bob_id).await.unwrap().sent, 1);
    peers.alice = reopen(
        peers.alice,
        &dir.path().join("alice.sqlite"),
        &peers.alice_key,
    );
    assert_eq!(peers.alice.sync(&peers.alice_id).await.unwrap().received, 1);
    let history = peers.alice.store().history(&peers.alice_id, 0).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].text, "Android reply after recovery");
    assert!(queued(&server, &a_queue).await.messages.is_empty());
}

#[tokio::test]
async fn accepted_post_with_failed_response_retries_exact_saved_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let failed_once = Arc::new(AtomicBool::new(false));
    let fault = Arc::clone(&failed_once);
    let app = relay(dir.path()).layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let fault = Arc::clone(&fault);
            async move {
                let is_send =
                    request.method() == Method::POST && request.uri().path().ends_with("/messages");
                let mut response = next.run(request).await;
                if is_send && !fault.swap(true, Ordering::SeqCst) {
                    *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
                }
                response
            }
        },
    ));
    let server = serve(app).await;
    let a_queue = create_queue(&server).await;
    let b_queue = create_queue(&server).await;
    let mut peers = peers(dir.path(), &server.url, &a_queue, &b_queue);
    let envelope = peers
        .alice
        .store()
        .enqueue(&peers.alice_id, "Ambiguous POST result")
        .unwrap();
    assert!(matches!(
        peers.alice.sync(&peers.alice_id).await,
        Err(Error::UnexpectedStatus(503))
    ));
    assert_eq!(
        peers
            .alice
            .store()
            .pending_outbox(&peers.alice_id)
            .unwrap()
            .len(),
        1
    );
    peers.alice = reopen(
        peers.alice,
        &dir.path().join("alice.sqlite"),
        &peers.alice_key,
    );
    assert_eq!(peers.alice.sync(&peers.alice_id).await.unwrap().sent, 1);
    let pending = queued(&server, &b_queue).await;
    assert_eq!(pending.messages.len(), 1);
    assert_eq!(pending.messages[0].id, envelope.id);
    assert_eq!(pending.messages[0].payload, envelope.payload);
    assert!(peers
        .alice
        .store()
        .pending_outbox(&peers.alice_id)
        .unwrap()
        .is_empty());
    assert_eq!(peers.bob.sync(&peers.bob_id).await.unwrap().received, 1);
    assert_eq!(
        peers.bob.store().history(&peers.bob_id, 0).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn failed_ack_keeps_durable_inbox_and_retries_before_get_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let failed_once = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let fault = Arc::clone(&failed_once);
    let observed = Arc::clone(&requests);
    let app = relay(dir.path()).layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let fault = Arc::clone(&fault);
            let observed = Arc::clone(&observed);
            async move {
                observed.lock().unwrap().push(request.method().clone());
                if request.method() == Method::DELETE && !fault.swap(true, Ordering::SeqCst) {
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
                next.run(request).await
            }
        },
    ));
    let server = serve(app).await;
    let a_queue = create_queue(&server).await;
    let b_queue = create_queue(&server).await;
    let mut peers = peers(dir.path(), &server.url, &a_queue, &b_queue);
    let envelope = peers
        .alice
        .store()
        .enqueue(&peers.alice_id, "Persist inbox before ACK")
        .unwrap();
    peers.alice.sync(&peers.alice_id).await.unwrap();
    assert!(matches!(
        peers.bob.sync(&peers.bob_id).await,
        Err(Error::UnexpectedStatus(503))
    ));
    assert_eq!(
        peers.bob.store().history(&peers.bob_id, 0).unwrap().len(),
        1
    );
    assert_eq!(
        peers.bob.store().pending_acks(&peers.bob_id).unwrap(),
        vec![envelope.id]
    );
    assert_eq!(
        peers.bob.take_incoming_contacts(),
        vec![peers.bob_id.clone()]
    );
    assert!(peers.bob.take_incoming_contacts().is_empty());
    peers.bob = reopen(peers.bob, &dir.path().join("bob.sqlite"), &peers.bob_key);
    requests.lock().unwrap().clear();
    let retried = peers.bob.sync(&peers.bob_id).await.unwrap();
    assert_eq!(retried.acked, 1);
    assert_eq!(retried.received, 0);
    assert!(peers.bob.take_incoming_contacts().is_empty());
    assert_eq!(
        *requests.lock().unwrap(),
        vec![Method::DELETE, Method::POST, Method::GET]
    );
    assert!(peers
        .bob
        .store()
        .pending_acks(&peers.bob_id)
        .unwrap()
        .is_empty());
    assert_eq!(
        peers.bob.store().history(&peers.bob_id, 0).unwrap().len(),
        1
    );
}

#[tokio::test]
async fn forged_inbound_envelope_is_not_acknowledged_or_added_to_inbox() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(relay(dir.path())).await;
    let a_queue = create_queue(&server).await;
    let b_queue = create_queue(&server).await;
    let mut peers = peers(dir.path(), &server.url, &a_queue, &b_queue);
    let mut forged = peers
        .alice
        .store()
        .enqueue(&peers.alice_id, "ciphertext will be replaced")
        .unwrap();
    forged.payload = "AQ==".to_owned();
    inject(&server, &b_queue, &forged).await;
    assert!(matches!(
        peers.bob.sync(&peers.bob_id).await,
        Err(Error::Store(_))
    ));
    assert!(peers
        .bob
        .store()
        .history(&peers.bob_id, 0)
        .unwrap()
        .is_empty());
    assert!(peers
        .bob
        .store()
        .pending_acks(&peers.bob_id)
        .unwrap()
        .is_empty());
    assert_eq!(queued(&server, &b_queue).await.messages.len(), 1);
}

#[tokio::test]
async fn rejected_write_capability_leaves_exact_outbox_pending() {
    let dir = tempfile::tempdir().unwrap();
    let server = serve(relay(dir.path())).await;
    let a_queue = create_queue(&server).await;
    let b_queue = create_queue(&server).await;
    let key = StorageKey::generate();
    let mut alice =
        ClientWorker::open(dir.path().join("alice.sqlite"), copy_key(&key), true).unwrap();
    let (contact, _) = contacts();
    let id = alice.store().insert_contact(contact).unwrap();
    let mut bad_route = route(&server.url, &b_queue, &a_queue);
    bad_route.send.token = b_queue.read_token.clone();
    alice.store().set_route(&id, &bad_route).unwrap();
    let envelope = alice
        .store()
        .enqueue(&id, "Unauthorised POST must remain pending")
        .unwrap();
    assert!(matches!(
        alice.sync(&id).await,
        Err(Error::UnexpectedStatus(404))
    ));
    alice = reopen(alice, &dir.path().join("alice.sqlite"), &key);
    let pending = alice.store().pending_outbox(&id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, envelope.id);
    assert_eq!(pending[0].payload, envelope.payload);
    assert!(queued(&server, &b_queue).await.messages.is_empty());
}

#[test]
fn worker_lock_prevents_two_workers_and_is_released_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("worker.sqlite");
    let key = StorageKey::generate();
    let worker = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    assert!(matches!(
        ClientWorker::open(&path, copy_key(&key), true),
        Err(Error::AlreadyRunning)
    ));
    drop(worker);
    assert!(ClientWorker::open(&path, copy_key(&key), true).is_ok());
}

#[tokio::test]
async fn hostile_get_responses_are_bounded_and_never_acknowledged() {
    enum Expected {
        TooLarge,
        Invalid,
    }
    let cases = [
        (vec![b' '; 9 * 1024 * 1024 + 1], Expected::TooLarge, false),
        (vec![b' '; 9 * 1024 * 1024 + 1], Expected::TooLarge, true),
        (serde_json::to_vec(&json!({"messages": (0..101).map(|_| json!({"id":"1".repeat(32),"payload":"AQ=="})).collect::<Vec<_>>()})).unwrap(), Expected::Invalid, false),
        (b"{malformed JSON".to_vec(), Expected::Invalid, false),
    ];
    for (body, expected, stream) in cases {
        let dir = tempfile::tempdir().unwrap();
        let ack_hits = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&ack_hits);
        let app = Router::new().fallback(move |request: Request<Body>| {
            let body = body.clone();
            let observed = Arc::clone(&observed);
            async move {
                if request.method() == Method::DELETE {
                    observed.fetch_add(1, Ordering::SeqCst);
                    return StatusCode::NO_CONTENT.into_response();
                }
                let response = Response::builder()
                    .status(200)
                    .header("content-type", "application/json");
                if stream {
                    // Unknown stream size forces chunked HTTP, so the worker
                    // must enforce its limit while reading, without a length hint.
                    let bytes = axum::body::Bytes::from(body);
                    let chunks: Vec<_> = (0..bytes.len())
                        .step_by(64 * 1024)
                        .map(|offset| {
                            Ok::<_, std::convert::Infallible>(
                                bytes.slice(offset..(offset + 64 * 1024).min(bytes.len())),
                            )
                        })
                        .collect();
                    response
                        .header("transfer-encoding", "chunked")
                        .body(Body::from_stream(futures_util::stream::iter(chunks)))
                        .unwrap()
                } else {
                    response.body(Body::from(body)).unwrap()
                }
            }
        });
        let server = serve(app).await;
        let (mut worker, id) = isolated_worker(dir.path(), &server.url, true);
        let result = worker.sync(&id).await;
        match expected {
            Expected::TooLarge => assert!(matches!(result, Err(Error::ResponseTooLarge))),
            Expected::Invalid => assert!(matches!(result, Err(Error::InvalidResponse))),
        }
        assert!(worker.store().history(&id, 0).unwrap().is_empty());
        assert!(worker.store().pending_acks(&id).unwrap().is_empty());
        assert_eq!(ack_hits.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn redirect_target_never_receives_a_request_or_bearer_capability() {
    let dir = tempfile::tempdir().unwrap();
    let target_hits = Arc::new(AtomicUsize::new(0));
    let target_auth = Arc::new(AtomicBool::new(false));
    let hits = Arc::clone(&target_hits);
    let auth = Arc::clone(&target_auth);
    let target = serve(Router::new().fallback(move |request: Request<Body>| {
        let hits = Arc::clone(&hits);
        let auth = Arc::clone(&auth);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            auth.store(
                request.headers().contains_key("authorization"),
                Ordering::SeqCst,
            );
            StatusCode::NO_CONTENT
        }
    }))
    .await;
    let destination = format!("{}/capture", target.url);
    let source = serve(Router::new().fallback(move || {
        let destination = destination.clone();
        async move {
            Response::builder()
                .status(307)
                .header("location", destination)
                .body(Body::empty())
                .unwrap()
        }
    }))
    .await;
    let (mut worker, id) = isolated_worker(dir.path(), &source.url, true);
    assert!(matches!(
        worker.sync(&id).await,
        Err(Error::UnexpectedStatus(307))
    ));
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);
    assert!(!target_auth.load(Ordering::SeqCst));
}

#[tokio::test]
async fn plaintext_http_is_rejected_by_default_before_any_request() {
    let dir = tempfile::tempdir().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&hits);
    let server = serve(Router::new().route(
        "/{*path}",
        get(move || {
            let observed = Arc::clone(&observed);
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                "{\"messages\":[]}"
            }
        }),
    ))
    .await;
    let (mut worker, id) = isolated_worker(dir.path(), &server.url, false);
    assert!(matches!(
        worker.sync(&id).await,
        Err(Error::InvalidEndpoint)
    ));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

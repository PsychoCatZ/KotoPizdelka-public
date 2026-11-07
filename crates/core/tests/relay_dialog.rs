//! Exercise the real relay router + SQLite without listening on a public port.
//! This is not yet a crash-safe client database or a real two-device test.
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use messenger_core::{Contact, Envelope, StorageKey};
use messenger_relay::{router, AppState, Messages, Queue, Store};
use serde_json::{json, Value};
use tower::ServiceExt;

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Vec<u8>) {
    let body = body
        .map(|v| serde_json::to_vec(&v).unwrap())
        .unwrap_or_default();
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    (
        status,
        to_bytes(response.into_body(), 128 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
}

async fn queue(app: &Router) -> Queue {
    let (status, bytes) = call(app, "POST", "/v1/queues", ADMIN, None).await;
    assert_eq!(status, 201);
    serde_json::from_slice(&bytes).unwrap()
}

async fn receive(app: &Router, queue: &Queue) -> Vec<Envelope> {
    let uri = format!("/v1/queues/{}/messages", queue.id);
    let (status, bytes) = call(app, "GET", &uri, &queue.read_token, None).await;
    assert_eq!(status, 200);
    let messages: Messages = serde_json::from_slice(&bytes).unwrap();
    messages
        .messages
        .into_iter()
        .map(|m| Envelope {
            id: m.id,
            payload: m.payload,
        })
        .collect()
}

async fn send(app: &Router, queue: &Queue, envelope: &Envelope) {
    let uri = format!("/v1/queues/{}/messages", queue.id);
    let (status, _) = call(app, "POST", &uri, &queue.write_token, Some(json!(envelope))).await;
    assert_eq!(status, 202);
}

async fn ack(app: &Router, queue: &Queue, envelope: &Envelope) {
    let uri = format!("/v1/queues/{}/messages/{}", queue.id, envelope.id);
    let (status, _) = call(app, "DELETE", &uri, &queue.read_token, None).await;
    assert_eq!(status, 204);
}

#[tokio::test]
async fn encrypted_offline_delivery_survives_relay_and_core_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let path_str = path.to_str().unwrap();
    let app = router(AppState::new(Store::open(path_str).unwrap(), ADMIN));
    let a_queue = queue(&app).await;
    let b_queue = queue(&app).await;
    let mut alice = Contact::new();
    let mut bob = Contact::new();
    let a_bundle = alice.public_bundle();
    let b_bundle = bob.public_bundle();
    alice
        .bind_peer(b_bundle.clone(), &b_bundle.fingerprint().unwrap())
        .unwrap();
    bob.bind_peer(a_bundle.clone(), &a_bundle.fingerprint().unwrap())
        .unwrap();
    alice.start_session().unwrap();

    let text = "Сообщение ожидает получателя, пока тот офлайн.";
    let first = alice.encrypt(text).unwrap();
    send(&app, &b_queue, &first).await;
    // Retry exact ciphertext, without encrypting the same outgoing message again.
    send(&app, &b_queue, &first).await;
    let a_key = StorageKey::generate();
    let b_key = StorageKey::generate();
    let a_snapshot = alice.snapshot(&a_key).unwrap();
    let b_snapshot = bob.snapshot(&b_key).unwrap();
    drop(alice);
    drop(bob);
    drop(app);

    let app = router(AppState::new(Store::open(path_str).unwrap(), ADMIN));
    let mut alice = Contact::restore(&a_snapshot, &a_key).unwrap();
    let mut bob = Contact::restore(&b_snapshot, &b_key).unwrap();
    let pending = receive(&app, &b_queue).await;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, first.id);
    assert_eq!(pending[0].payload, first.payload);
    assert_eq!(bob.decrypt(&pending[0]).unwrap(), text);
    // Export accepted state before ACK. A real client must transact inbox + state.
    let received_state = bob.snapshot(&b_key).unwrap();
    ack(&app, &b_queue, &pending[0]).await;
    assert!(receive(&app, &b_queue).await.is_empty());
    drop(bob);
    let mut bob = Contact::restore(&received_state, &b_key).unwrap();
    assert!(bob.decrypt(&pending[0]).is_err());

    let response_text = "Ответ после восстановления состояния.";
    let reply = bob.encrypt(response_text).unwrap();
    send(&app, &a_queue, &reply).await;
    let received = receive(&app, &a_queue).await;
    assert_eq!(alice.decrypt(&received[0]).unwrap(), response_text);
    ack(&app, &a_queue, &received[0]).await;
    assert!(receive(&app, &a_queue).await.is_empty());

    // Neither SQLite nor its WAL receives the original plaintext from this path.
    for file in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        for plain in [text, response_text] {
            assert!(!bytes.windows(plain.len()).any(|w| w == plain.as_bytes()));
        }
    }
}

//! Real Axum relay router + three independent SQLite stores. Exercise failures
//! across relay responses and client commits without a public listening socket.
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use messenger_core::{Contact, Envelope, StorageKey};
use messenger_relay::{router, AppState, Messages, Queue, Store};
use messenger_store::{AcceptStatus, ClientStore};
use serde_json::{json, Value};
use tower::ServiceExt;

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    token: &str,
    value: Option<Value>,
) -> (u16, Vec<u8>) {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(
            value
                .map(|v| serde_json::to_vec(&v).unwrap())
                .unwrap_or_default(),
        ))
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
    let (status, body) = call(app, "POST", "/v1/queues", ADMIN, None).await;
    assert_eq!(status, 201);
    serde_json::from_slice(&body).unwrap()
}
async fn send(app: &Router, queue: &Queue, envelope: &Envelope) {
    let uri = format!("/v1/queues/{}/messages", queue.id);
    assert_eq!(
        call(app, "POST", &uri, &queue.write_token, Some(json!(envelope)))
            .await
            .0,
        202
    );
}
async fn receive(app: &Router, queue: &Queue) -> Vec<Envelope> {
    let uri = format!("/v1/queues/{}/messages", queue.id);
    let (status, body) = call(app, "GET", &uri, &queue.read_token, None).await;
    assert_eq!(status, 200);
    let messages: Messages = serde_json::from_slice(&body).unwrap();
    messages
        .messages
        .into_iter()
        .map(|m| Envelope {
            id: m.id,
            payload: m.payload,
        })
        .collect()
}
async fn ack(app: &Router, queue: &Queue, id: &str) {
    let uri = format!("/v1/queues/{}/messages/{id}", queue.id);
    assert_eq!(
        call(app, "DELETE", &uri, &queue.read_token, None).await.0,
        204
    );
}

#[tokio::test]
async fn sender_retry_receiver_redelivery_and_ack_retry_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let relay_path = dir.path().join("relay.sqlite");
    let a_path = dir.path().join("alice.sqlite");
    let b_path = dir.path().join("bob.sqlite");
    let a_key = StorageKey::generate();
    let b_key = StorageKey::generate();
    let mut alice = ClientStore::open(&a_path, StorageKey::from_bytes(*a_key.as_bytes())).unwrap();
    let mut bob = ClientStore::open(&b_path, StorageKey::from_bytes(*b_key.as_bytes())).unwrap();
    let a_id = alice.insert_contact(Contact::new()).unwrap();
    let b_id = bob.insert_contact(Contact::new()).unwrap();
    let a_bundle = alice.public_bundle(&a_id).unwrap();
    let b_bundle = bob.public_bundle(&b_id).unwrap();
    alice
        .bind_peer(&a_id, b_bundle.clone(), &b_bundle.fingerprint().unwrap())
        .unwrap();
    bob.bind_peer(&b_id, a_bundle.clone(), &a_bundle.fingerprint().unwrap())
        .unwrap();
    alice.start_session(&a_id).unwrap();
    let app = router(AppState::new(
        Store::open(relay_path.to_str().unwrap()).unwrap(),
        ADMIN,
    ));
    let a_queue = queue(&app).await;
    let b_queue = queue(&app).await;

    let envelope = alice
        .enqueue(&a_id, "Отправка сохранена до ответа сервера.")
        .unwrap();
    send(&app, &b_queue, &envelope).await;
    // Simulate exit after server 202 but before mark_sent.
    drop(alice);
    drop(bob);
    drop(app);
    let app = router(AppState::new(
        Store::open(relay_path.to_str().unwrap()).unwrap(),
        ADMIN,
    ));
    let mut alice = ClientStore::open(&a_path, StorageKey::from_bytes(*a_key.as_bytes())).unwrap();
    let mut bob = ClientStore::open(&b_path, StorageKey::from_bytes(*b_key.as_bytes())).unwrap();
    assert_eq!(alice.contact_ids().unwrap(), vec![a_id.clone()]);
    assert_eq!(bob.public_bundle(&b_id).unwrap(), b_bundle);
    let pending = alice.pending_outbox(&a_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].payload, envelope.payload);
    send(&app, &b_queue, &pending[0]).await;
    alice.mark_sent(&a_id, &pending[0].id).unwrap();
    assert!(alice.pending_outbox(&a_id).unwrap().is_empty());
    let incoming = receive(&app, &b_queue).await;
    assert_eq!(incoming.len(), 1);
    assert_eq!(bob.accept(&b_id, &incoming[0]).unwrap(), AcceptStatus::New);

    // Simulate exit after inbox + ratchet commit, before HTTP ACK.
    drop(bob);
    let mut bob = ClientStore::open(&b_path, StorageKey::from_bytes(*b_key.as_bytes())).unwrap();
    let repeated = receive(&app, &b_queue).await;
    assert_eq!(
        bob.accept(&b_id, &repeated[0]).unwrap(),
        AcceptStatus::Duplicate
    );
    assert_eq!(bob.history(&b_id, 0).unwrap().len(), 1);
    assert_eq!(bob.pending_acks(&b_id).unwrap(), vec![envelope.id.clone()]);
    ack(&app, &b_queue, &envelope.id).await;
    // Exit after relay 204 but before marking the local ACK complete.
    drop(bob);
    let mut bob = ClientStore::open(&b_path, StorageKey::from_bytes(*b_key.as_bytes())).unwrap();
    let to_ack = bob.pending_acks(&b_id).unwrap();
    assert_eq!(to_ack, vec![envelope.id.clone()]);
    ack(&app, &b_queue, &to_ack[0]).await;
    bob.mark_acked(&b_id, &to_ack[0]).unwrap();
    assert!(receive(&app, &b_queue).await.is_empty());
    assert!(bob.pending_acks(&b_id).unwrap().is_empty());

    let reply = bob
        .enqueue(&b_id, "Ответ после нескольких восстановлений.")
        .unwrap();
    send(&app, &a_queue, &reply).await;
    bob.mark_sent(&b_id, &reply.id).unwrap();
    let response = receive(&app, &a_queue).await;
    assert_eq!(
        alice.accept(&a_id, &response[0]).unwrap(),
        AcceptStatus::New
    );
    ack(&app, &a_queue, &reply.id).await;
    alice.mark_acked(&a_id, &reply.id).unwrap();
    let history = alice.history(&a_id, 0).unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].text, "Ответ после нескольких восстановлений.");
}

//! Durable queue provisioning over real loopback TCP. Fixture capabilities and
//! tickets are never printed; all trusted fingerprints are local test fixtures.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::{to_bytes, Body, Bytes},
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use messenger_client::{
    invitations::{Invitation, InvitationKind},
    ClientWorker, Error, ReceiveQueue,
};
use messenger_core::StorageKey;
use messenger_relay::{router, AppState, Store};
use messenger_store::QueueEndpoint;
use serde_json::{json, Value};
use tokio::{net::TcpListener, task::JoinHandle};

const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TICKET: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}
fn worker(dir: &Path, name: &str) -> ClientWorker {
    ClientWorker::open(dir.join(name), StorageKey::generate(), true).unwrap()
}
fn queue(url: &str, seed: u32) -> ReceiveQueue {
    ReceiveQueue {
        read: QueueEndpoint {
            relay_url: url.into(),
            queue_id: format!("{seed:032x}"),
            token: format!("{:064x}", seed + 1000),
        },
        write: QueueEndpoint {
            relay_url: url.into(),
            queue_id: format!("{seed:032x}"),
            token: format!("{:064x}", seed + 2000),
        },
    }
}
fn pending_state(worker: &mut ClientWorker) -> (String, Value) {
    let records = worker.store().setup_records().unwrap();
    assert_eq!(records.len(), 1);
    let (id, setup) = &records[0];
    (id.clone(), serde_json::from_slice(&setup.payload).unwrap())
}
fn proposal(state: &Value) -> Value {
    json!({
        "id": state["receive"]["queue_id"],
        "read_token": state["receive"]["token"],
        "write_token": state["artifact"]["write"]["token"],
    })
}
fn assert_encrypted_files(directory: &Path, secrets: &[&str]) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("client.sqlite") || name.ends_with(".worker.lock") {
            continue;
        }
        let bytes = std::fs::read(entry.path()).unwrap();
        for secret in secrets {
            assert!(!bytes
                .windows(secret.len())
                .any(|candidate| candidate == secret.as_bytes()));
        }
    }
}

#[test]
fn legacy_manual_setup_has_no_job_and_keeps_its_original_export() {
    let dir = tempfile::tempdir().unwrap();
    let mut client = worker(dir.path(), "client.sqlite");
    let saved = client
        .create_invitation(queue("https://relay.example", 1))
        .unwrap();
    let (_, state) = pending_state(&mut client);
    // This is exactly the previous milestone's serialized shape. The new
    // optional field is absent, rather than requiring a migration or null.
    assert!(state.get("provisioning").is_none());
    let status = client.invitation_status(&saved.contact).unwrap();
    assert!(!status.ready && !status.provisioning);
    assert!(client.export_invitation(&saved.contact).unwrap().invitation == saved.invitation);
}

#[tokio::test]
async fn lost_created_response_reopens_and_retries_exact_encrypted_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay_store = Store::open(dir.path().join("relay.sqlite").to_str().unwrap()).unwrap();
    let ticket = relay_store.issue_ticket(3600).unwrap();
    let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
    let observed = Arc::clone(&captured);
    let failed = Arc::new(AtomicBool::new(false));
    let fault = Arc::clone(&failed);
    let app = router(AppState::new(relay_store, ADMIN)).layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let observed = Arc::clone(&observed);
            let fault = Arc::clone(&fault);
            async move {
                let is_redeem = request.uri().path() == "/v1/queues/redeem";
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 4096).await.unwrap();
                if is_redeem {
                    observed
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&bytes).unwrap());
                }
                let response = next
                    .run(Request::from_parts(parts, Body::from(bytes)))
                    .await;
                if is_redeem && !fault.swap(true, Ordering::SeqCst) {
                    assert_eq!(response.status(), StatusCode::CREATED);
                    // The relay transaction already committed, but its success
                    // body cannot reach the client: an ambiguous HTTP outcome.
                    let broken = futures_util::stream::once(async {
                        Err::<Bytes, _>(std::io::Error::other("fixture connection failure"))
                    });
                    return Response::builder()
                        .status(StatusCode::CREATED)
                        .body(Body::from_stream(broken))
                        .unwrap();
                }
                response
            }
        },
    ));
    let server = serve(app).await;
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut client = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    assert!(matches!(
        client
            .create_invitation_with_ticket(&server.url, &ticket)
            .await,
        Err(Error::RequestFailed)
    ));
    let (id, state) = pending_state(&mut client);
    let status = client.invitation_status(&id).unwrap();
    assert_eq!(status.kind, InvitationKind::Offer);
    assert!(!status.ready && status.provisioning);
    assert!(matches!(
        client.export_invitation(&id),
        Err(Error::QueueProvisionPending)
    ));
    assert!(matches!(
        client.sync(&id).await,
        Err(Error::QueueProvisionPending)
    ));
    assert_eq!(captured.lock().unwrap().len(), 1);
    assert!(captured.lock().unwrap()[0] == proposal(&state));
    assert_encrypted_files(
        dir.path(),
        &[
            &ticket,
            state["receive"]["token"].as_str().unwrap(),
            state["artifact"]["write"]["token"].as_str().unwrap(),
        ],
    );
    let own_offer: Invitation = serde_json::from_value(state["artifact"].clone()).unwrap();
    let mut peer = worker(dir.path(), "peer.sqlite");
    let reply = peer
        .accept_invitation(
            &own_offer.encode().unwrap(),
            &own_offer.fingerprint().unwrap(),
            queue("https://relay.example", 1),
        )
        .unwrap();
    assert!(matches!(
        client.complete_invitation(&id, &reply.invitation, &reply.fingerprint),
        Err(Error::QueueProvisionPending)
    ));
    drop(client);
    let mut client = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    let saved = client.provision_queue(&id, None).await.unwrap();
    assert!(saved.invitation == own_offer.encode().unwrap());
    assert!(saved.fingerprint == own_offer.fingerprint().unwrap());
    assert!(saved.contact == id);
    assert_eq!(client.store().contact_ids().unwrap().len(), 1);
    assert!(!client.invitation_status(&id).unwrap().provisioning);
    {
        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        assert!(captured[0] == captured[1]);
    }
    assert!(client.provision_queue(&id, None).await.unwrap().invitation == saved.invitation);
}

#[tokio::test]
async fn changed_ticket_commits_before_failed_retry_and_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&hits);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    let server = serve(Router::new().fallback(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        let captured = Arc::clone(&captured);
        async move {
            let authorization = request.headers()[header::AUTHORIZATION]
                .to_str()
                .unwrap()
                .to_owned();
            let body: Value =
                serde_json::from_slice(&to_bytes(request.into_body(), 4096).await.unwrap())
                    .unwrap();
            captured.lock().unwrap().push((authorization, body.clone()));
            match observed.fetch_add(1, Ordering::SeqCst) {
                0 => StatusCode::UNAUTHORIZED.into_response(),
                1 => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                _ => (StatusCode::CREATED, axum::Json(json!({"id":body["id"]}))).into_response(),
            }
        }
    }))
    .await;
    let path = dir.path().join("client.sqlite");
    let key = StorageKey::generate();
    let mut client = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    assert!(matches!(
        client
            .create_invitation_with_ticket(&server.url, TICKET)
            .await,
        Err(Error::UnexpectedStatus(401))
    ));
    let (id, original) = pending_state(&mut client);
    let replacement = "c".repeat(64);
    assert!(matches!(
        client.provision_queue(&id, Some(&replacement)).await,
        Err(Error::UnexpectedStatus(503))
    ));
    let (_, updated) = pending_state(&mut client);
    assert!(updated["provisioning"]["ticket"] == replacement);
    assert!(proposal(&updated) == proposal(&original));
    assert_encrypted_files(dir.path(), &[TICKET, &replacement]);
    drop(client);
    let mut client = ClientWorker::open(&path, copy_key(&key), true).unwrap();
    client.provision_queue(&id, None).await.unwrap();
    let requests = requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].0 == format!("Bearer {TICKET}"));
    assert!(requests[1].0 == format!("Bearer {replacement}"));
    assert!(requests[2].0 == requests[1].0);
    assert!(requests
        .iter()
        .all(|(_, body)| *body == proposal(&original)));
}

#[tokio::test]
async fn committed_relay_queue_survives_local_sql_failure_and_expired_ticket_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let relay_path = dir.path().join("relay.sqlite");
    let client_path = dir.path().join("client.sqlite");
    let mut relay_store = Store::open(relay_path.to_str().unwrap()).unwrap();
    let original_ticket = relay_store.issue_ticket(3600).unwrap();
    let replacement_ticket = relay_store.issue_ticket(3600).unwrap();
    let captured = Arc::new(Mutex::new(Vec::<Value>::new()));
    let observed = Arc::clone(&captured);
    let failed = Arc::new(AtomicBool::new(false));
    let fault = Arc::clone(&failed);
    let target = client_path.clone();
    let app = router(AppState::new(relay_store, ADMIN)).layer(middleware::from_fn(
        move |request: Request<Body>, next: Next| {
            let observed = Arc::clone(&observed);
            let fault = Arc::clone(&fault);
            let target = target.clone();
            async move {
                let (parts, body) = request.into_parts();
                let bytes = to_bytes(body, 4096).await.unwrap();
                observed
                    .lock()
                    .unwrap()
                    .push(serde_json::from_slice(&bytes).unwrap());
                let response = next
                    .run(Request::from_parts(parts, Body::from(bytes)))
                    .await;
                if response.status() == StatusCode::CREATED && !fault.swap(true, Ordering::SeqCst) {
                    // The relay committed successfully. Fail precisely the
                    // subsequent client transaction clearing its encrypted job.
                    rusqlite::Connection::open(target)
                        .unwrap()
                        .execute_batch(
                            "CREATE TRIGGER fail_provision_clear BEFORE UPDATE ON routes
                             BEGIN SELECT RAISE(FAIL, 'fixture storage fault'); END;",
                        )
                        .unwrap();
                }
                response
            }
        },
    ));
    let server = serve(app).await;
    let key = StorageKey::generate();
    let mut client = ClientWorker::open(&client_path, copy_key(&key), true).unwrap();
    assert!(matches!(
        client
            .create_invitation_with_ticket(&server.url, &original_ticket)
            .await,
        Err(Error::Store(messenger_store::Error::Database))
    ));
    let (id, original) = pending_state(&mut client);
    assert!(client.invitation_status(&id).unwrap().provisioning);
    rusqlite::Connection::open(&client_path)
        .unwrap()
        .execute_batch("DROP TRIGGER fail_provision_clear")
        .unwrap();
    // Expiry is injected directly without a sleep. The replacement ticket is
    // still live, and must reclaim the already existing queue with EXACT caps.
    let original_hash: Vec<u8> = {
        use sha2::{Digest, Sha256};
        Sha256::digest(original_ticket.as_bytes()).to_vec()
    };
    rusqlite::Connection::open(&relay_path)
        .unwrap()
        .execute(
            "UPDATE queue_tickets SET expires=0 WHERE ticket_hash=?",
            [original_hash],
        )
        .unwrap();
    drop(client);
    let mut client = ClientWorker::open(&client_path, copy_key(&key), true).unwrap();
    assert!(matches!(
        client.provision_queue(&id, None).await,
        Err(Error::UnexpectedStatus(401))
    ));
    client
        .provision_queue(&id, Some(&replacement_ticket))
        .await
        .unwrap();
    assert!(!client.invitation_status(&id).unwrap().provisioning);
    assert_eq!(client.store().contact_ids().unwrap().len(), 1);
    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), 3);
    assert!(captured.iter().all(|body| *body == proposal(&original)));
    let queue_count: usize = rusqlite::Connection::open(&relay_path)
        .unwrap()
        .query_row("SELECT count(*) FROM queues", [], |row| row.get(0))
        .unwrap();
    assert_eq!(queue_count, 1);
}

#[tokio::test]
async fn untrusted_offer_wrong_kind_bad_endpoints_and_replay_do_not_spend_ticket() {
    let dir = tempfile::tempdir().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&hits);
    let server = serve(Router::new().fallback(move |request: Request<Body>| {
        let observed = Arc::clone(&observed);
        async move {
            observed.fetch_add(1, Ordering::SeqCst);
            let body: Value =
                serde_json::from_slice(&to_bytes(request.into_body(), 4096).await.unwrap())
                    .unwrap();
            (StatusCode::CREATED, axum::Json(json!({"id":body["id"]})))
        }
    }))
    .await;
    let mut alice = worker(dir.path(), "alice.sqlite");
    let mut bob = worker(dir.path(), "bob.sqlite");
    let mut third = worker(dir.path(), "third.sqlite");
    let offer = alice
        .create_invitation(queue("https://relay.example", 1))
        .unwrap();
    assert!(matches!(
        bob.accept_invitation_with_ticket(&offer.invitation, &"0".repeat(64), &server.url, TICKET)
            .await,
        Err(Error::Invitation(_))
    ));
    let reply = third
        .accept_invitation(
            &offer.invitation,
            &offer.fingerprint,
            queue("https://relay.example", 2),
        )
        .unwrap();
    assert!(matches!(
        bob.accept_invitation_with_ticket(
            &reply.invitation,
            &reply.fingerprint,
            &server.url,
            TICKET
        )
        .await,
        Err(Error::Invitation(_))
    ));
    let decoded = Invitation::decode(&offer.invitation).unwrap();
    let mut invalid = serde_json::to_value(decoded).unwrap();
    invalid["write"]["relay_url"] = json!("http://relay.example");
    // The public encoder correctly refuses this invalid endpoint itself.
    // Construct raw hostile import text to exercise the receiving boundary.
    let invalid = format!(
        "koto-invite:v1:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invalid).unwrap())
    );
    assert!(matches!(
        bob.accept_invitation_with_ticket(&invalid, &offer.fingerprint, &server.url, TICKET)
            .await,
        Err(Error::Invitation(_))
    ));
    assert!(matches!(
        bob.create_invitation_with_ticket("http://localhost:8888", TICKET)
            .await,
        Err(Error::InvalidEndpoint)
    ));
    assert!(matches!(
        bob.create_invitation_with_ticket(&server.url, "BAD").await,
        Err(Error::InvalidEndpoint)
    ));
    assert!(bob.store().contact_ids().unwrap().is_empty());
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let accepted = bob
        .accept_invitation_with_ticket(&offer.invitation, &offer.fingerprint, &server.url, TICKET)
        .await
        .unwrap();
    let status = bob.invitation_status(&accepted.contact).unwrap();
    assert_eq!(status.kind, InvitationKind::Reply);
    assert!(status.ready && !status.provisioning);
    assert!(matches!(
        bob.accept_invitation_with_ticket(
            &offer.invitation,
            &offer.fingerprint,
            &server.url,
            TICKET
        )
        .await,
        Err(Error::Store(messenger_store::Error::SetupReplay))
    ));
    assert_eq!(bob.store().contact_ids().unwrap().len(), 1);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn hostile_created_responses_are_bounded_strict_and_keep_jobs_pending() {
    #[derive(Clone, Copy)]
    enum Case {
        Length,
        Chunked,
        Malformed,
        WrongId,
        ExtraField,
    }
    for case in [
        Case::Length,
        Case::Chunked,
        Case::Malformed,
        Case::WrongId,
        Case::ExtraField,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let server = serve(
            Router::new().fallback(move |request: Request<Body>| async move {
                let body: Value =
                    serde_json::from_slice(&to_bytes(request.into_body(), 4096).await.unwrap())
                        .unwrap();
                let bytes = match case {
                    Case::Length | Case::Chunked => vec![b' '; 4097],
                    Case::Malformed => b"{invalid JSON".to_vec(),
                    Case::WrongId => serde_json::to_vec(&json!({"id":"0".repeat(32)})).unwrap(),
                    Case::ExtraField => serde_json::to_vec(
                        &json!({"id":body["id"],"read_token":"hostile response"}),
                    )
                    .unwrap(),
                };
                let body = if matches!(case, Case::Chunked) {
                    Body::from_stream(futures_util::stream::iter(vec![Ok::<
                        _,
                        std::convert::Infallible,
                    >(
                        Bytes::from(bytes)
                    )]))
                } else {
                    Body::from(bytes)
                };
                Response::builder()
                    .status(StatusCode::CREATED)
                    .body(body)
                    .unwrap()
            }),
        )
        .await;
        let mut client = worker(dir.path(), "client.sqlite");
        let result = client
            .create_invitation_with_ticket(&server.url, TICKET)
            .await;
        match case {
            Case::Length | Case::Chunked => assert!(matches!(result, Err(Error::ResponseTooLarge))),
            _ => assert!(matches!(result, Err(Error::InvalidResponse))),
        }
        let (id, _) = pending_state(&mut client);
        assert!(client.invitation_status(&id).unwrap().provisioning);
        assert!(matches!(
            client.export_invitation(&id),
            Err(Error::QueueProvisionPending)
        ));
    }
}

#[tokio::test]
async fn redirects_never_forward_ticket_and_http_requires_explicit_literal_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let destination_hits = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&destination_hits);
    let destination = serve(Router::new().fallback(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        async { StatusCode::CREATED }
    }))
    .await;
    let url = destination.url.clone();
    let server = serve(Router::new().fallback(move || {
        let url = url.clone();
        async move {
            Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(header::LOCATION, url)
                .body(Body::empty())
                .unwrap()
        }
    }))
    .await;
    let mut client = worker(dir.path(), "client.sqlite");
    assert!(matches!(
        client
            .create_invitation_with_ticket(&server.url, TICKET)
            .await,
        Err(Error::UnexpectedStatus(307))
    ));
    assert_eq!(destination_hits.load(Ordering::SeqCst), 0);
    let mut normal = ClientWorker::open(
        dir.path().join("normal.sqlite"),
        StorageKey::generate(),
        false,
    )
    .unwrap();
    assert!(matches!(
        normal
            .create_invitation_with_ticket(&server.url, TICKET)
            .await,
        Err(Error::InvalidEndpoint)
    ));
    assert!(normal.store().contact_ids().unwrap().is_empty());
    assert!(matches!(
        client
            .create_invitation_with_ticket("https://name:secret@relay.example", TICKET)
            .await,
        Err(Error::InvalidEndpoint)
    ));
}

#[tokio::test]
async fn two_ticket_provisioned_profiles_exchange_messages_through_verified_invitation() {
    let dir = tempfile::tempdir().unwrap();
    let mut relay_store = Store::open(dir.path().join("relay.sqlite").to_str().unwrap()).unwrap();
    let alice_ticket = relay_store.issue_ticket(3600).unwrap();
    let bob_ticket = relay_store.issue_ticket(3600).unwrap();
    let server = serve(router(AppState::new(relay_store, ADMIN))).await;
    let mut alice = worker(dir.path(), "alice.sqlite");
    let mut bob = worker(dir.path(), "bob.sqlite");
    let offer = alice
        .create_invitation_with_ticket(&server.url, &alice_ticket)
        .await
        .unwrap();
    let reply = bob
        .accept_invitation_with_ticket(
            &offer.invitation,
            &offer.fingerprint,
            &server.url,
            &bob_ticket,
        )
        .await
        .unwrap();
    alice
        .complete_invitation(&offer.contact, &reply.invitation, &reply.fingerprint)
        .unwrap();
    alice
        .store()
        .enqueue(
            &offer.contact,
            "A ticket creates one private receiving queue",
        )
        .unwrap();
    assert_eq!(alice.sync(&offer.contact).await.unwrap().sent, 1);
    assert_eq!(bob.sync(&reply.contact).await.unwrap().received, 1);
    bob.store()
        .enqueue(
            &reply.contact,
            "The responder can reply after the first incoming message",
        )
        .unwrap();
    assert_eq!(bob.sync(&reply.contact).await.unwrap().sent, 1);
    assert_eq!(alice.sync(&offer.contact).await.unwrap().received, 1);
}

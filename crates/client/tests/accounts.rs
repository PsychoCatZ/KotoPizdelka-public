use messenger_client::{ClientWorker, Error};
use messenger_core::StorageKey;
use messenger_relay::{router, AppState, Store};
fn copy(k: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*k.as_bytes())
}
#[tokio::test]
async fn registration_approval_automatic_keys_offline_delivery_and_restart() {
    let d = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("http://{}", listener.local_addr().unwrap());
    let state = AppState::new(
        Store::open(d.path().join("relay").to_str().unwrap()).unwrap(),
        &"a".repeat(64),
    );
    let task = tokio::spawn(async move {
        axum::serve(listener, router(state)).await.unwrap();
    });
    let ka = StorageKey::generate();
    let kb = StorageKey::generate();
    let mut a = ClientWorker::open(d.path().join("a"), copy(&ka), true).unwrap();
    let mut b = ClientWorker::open(d.path().join("b"), copy(&kb), true).unwrap();
    a.authenticate_account(&relay, "Alice_Cat", "correct horse cat".into(), true)
        .await
        .unwrap();
    b.authenticate_account(&relay, "Bob_Cat", "correct horse bob".into(), true)
        .await
        .unwrap();
    assert_eq!(a.find_account("BOB_CAT").await.unwrap().login, "bob_cat");
    let result = a.add_account("bob_cat").await.unwrap();
    let req = result.requests[0].id.clone();
    a.add_account("bob_cat").await.unwrap();
    assert_eq!(a.store().account_jobs().unwrap().len(), 1);
    b.sync_account().await.unwrap();
    assert!(b.store().contact_ids().unwrap().is_empty());
    let mut wrong =
        ClientWorker::open(d.path().join("wrong"), StorageKey::generate(), true).unwrap();
    assert!(matches!(
        wrong
            .authenticate_account(&relay, "alice_cat", "correct horse cat".into(), false)
            .await,
        Err(Error::AccountRejected(409))
    ));
    b.decide_account(&req, true).await.unwrap();
    drop(a);
    drop(b);
    let mut a = ClientWorker::open(d.path().join("a"), copy(&ka), true).unwrap();
    let mut b = ClientWorker::open(d.path().join("b"), copy(&kb), true).unwrap();
    for _ in 0..4 {
        a.sync_account().await.unwrap();
        b.sync_account().await.unwrap();
    }
    let ca = a.store().contact_ids().unwrap();
    let cb = b.store().contact_ids().unwrap();
    assert_eq!(ca.len(), 1);
    assert_eq!(cb.len(), 1);
    assert_eq!(
        a.quick_invitation_status(&ca[0]).unwrap().unwrap().stage,
        "ready"
    );
    assert_eq!(
        b.quick_invitation_status(&cb[0]).unwrap().unwrap().stage,
        "ready"
    );
    drop(b);
    a.store().enqueue(&ca[0], "Привет, стая!").unwrap();
    a.sync(&ca[0]).await.unwrap();
    let mut b = ClientWorker::open(d.path().join("b"), copy(&kb), true).unwrap();
    b.sync(&cb[0]).await.unwrap();
    assert_eq!(
        b.store().history(&cb[0], 0).unwrap()[0].text,
        "Привет, стая!"
    );
    b.sync(&cb[0]).await.unwrap();
    assert_eq!(b.store().history(&cb[0], 0).unwrap().len(), 1);
    a.logout_account().await.unwrap();
    a.authenticate_account(&relay, "alice_cat", "correct horse cat".into(), false)
        .await
        .unwrap();
    assert_eq!(a.store().contact_ids().unwrap(), ca);
    a.store().delete_contact(&ca[0]).unwrap();
    assert!(a.store().account_jobs().unwrap()[0].deleted);
    a.sync_account().await.unwrap();
    assert!(a.store().contact_ids().unwrap().is_empty());
    task.abort();
}

#[tokio::test]
async fn lost_success_responses_retry_exact_account_identity_and_handshake() {
    use axum::{
        body::Body,
        http::Request,
        middleware::{self, Next},
        response::Response,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    async fn fault(
        axum::extract::State(stage): axum::extract::State<Arc<AtomicUsize>>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let path = request.uri().path().to_owned();
        let method = request.method().clone();
        let response = next.run(request).await;
        if method == reqwest::Method::POST && response.status().is_success() {
            let wanted = match stage.load(Ordering::SeqCst) {
                0 => path.ends_with("/register"),
                1 => path == "/v1/queues/invite",
                2 => path.ends_with("/offer"),
                _ => false,
            };
            if wanted {
                stage.fetch_add(1, Ordering::SeqCst);
                return Response::builder().status(503).body(Body::empty()).unwrap();
            }
        }
        response
    }
    let d = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("http://{}", listener.local_addr().unwrap());
    let stage = Arc::new(AtomicUsize::new(0));
    let app = router(AppState::new(
        Store::open(d.path().join("relay").to_str().unwrap()).unwrap(),
        &"a".repeat(64),
    ))
    .layer(middleware::from_fn_with_state(stage.clone(), fault));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let ka = StorageKey::generate();
    let kb = StorageKey::generate();
    let mut a = ClientWorker::open(d.path().join("a"), copy(&ka), true).unwrap();
    assert!(a
        .authenticate_account(&relay, "alice_cat", "correct horse cat".into(), true)
        .await
        .is_err());
    let identity = a.store().account().unwrap().unwrap().identity.public_key();
    drop(a);
    let mut a = ClientWorker::open(d.path().join("a"), copy(&ka), true).unwrap();
    a.authenticate_account(&relay, "alice_cat", "correct horse cat".into(), true)
        .await
        .unwrap();
    assert_eq!(
        a.store().account().unwrap().unwrap().identity.public_key(),
        identity
    );
    let mut b = ClientWorker::open(d.path().join("b"), copy(&kb), true).unwrap();
    b.authenticate_account(&relay, "bobby_cat", "correct horse bob".into(), true)
        .await
        .unwrap();
    let id = a.add_account("bobby_cat").await.unwrap().requests[0]
        .id
        .clone();
    b.sync_account().await.unwrap();
    b.decide_account(&id, true).await.unwrap();
    assert!(a.sync_account().await.is_err());
    let contact = a.store().contact_ids().unwrap()[0].clone();
    drop(a);
    let mut a = ClientWorker::open(d.path().join("a"), copy(&ka), true).unwrap();
    assert!(a.sync_account().await.is_err());
    drop(a);
    let mut a = ClientWorker::open(d.path().join("a"), copy(&ka), true).unwrap();
    for _ in 0..4 {
        a.sync_account().await.unwrap();
        b.sync_account().await.unwrap();
    }
    assert_eq!(stage.load(Ordering::SeqCst), 3);
    assert_eq!(a.store().contact_ids().unwrap(), vec![contact.clone()]);
    assert_eq!(
        a.quick_invitation_status(&contact).unwrap().unwrap().stage,
        "ready"
    );
    assert_eq!(b.store().contact_ids().unwrap().len(), 1);
    task.abort();
}

#[tokio::test]
async fn account_link_recovers_lost_ticket_and_queue_responses_after_restart() {
    use axum::{
        body::Body,
        http::Request,
        middleware::{self, Next},
        response::Response,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    async fn fault(
        axum::extract::State(stage): axum::extract::State<Arc<AtomicUsize>>,
        request: Request<Body>,
        next: Next,
    ) -> Response {
        let path = request.uri().path().to_owned();
        let response = next.run(request).await;
        let wanted = match stage.load(Ordering::SeqCst) {
            0 => path == "/v1/accounts/link-ticket",
            1 => path == "/v1/queues/invite",
            _ => false,
        };
        if wanted && response.status().is_success() {
            stage.fetch_add(1, Ordering::SeqCst);
            return Response::builder().status(503).body(Body::empty()).unwrap();
        }
        response
    }
    let d = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("http://{}", listener.local_addr().unwrap());
    let stage = Arc::new(AtomicUsize::new(0));
    let app = router(AppState::new(
        Store::open(d.path().join("relay").to_str().unwrap()).unwrap(),
        &"a".repeat(64),
    ))
    .layer(middleware::from_fn_with_state(stage.clone(), fault));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let key = StorageKey::generate();
    let mut a = ClientWorker::open(d.path().join("a"), copy(&key), true).unwrap();
    assert!(matches!(
        a.create_account_link().await,
        Err(Error::AccountClosed)
    ));
    a.authenticate_account(&relay, "alice_cat", "correct horse cat".into(), true)
        .await
        .unwrap();
    assert!(a.create_account_link().await.is_err());
    let id = a.store().contact_ids().unwrap()[0].clone();
    drop(a);
    let mut a = ClientWorker::open(d.path().join("a"), copy(&key), true).unwrap();
    assert!(a.provision_quick_invitation(&id, None).await.is_err());
    drop(a);
    let mut a = ClientWorker::open(d.path().join("a"), copy(&key), true).unwrap();
    let link = a.provision_quick_invitation(&id, None).await.unwrap();
    assert_eq!(stage.load(Ordering::SeqCst), 2);
    assert_eq!(a.store().contact_ids().unwrap(), vec![id.clone()]);
    // A recipient does not need an account or an operator ticket.
    let mut b = ClientWorker::open(d.path().join("b"), StorageKey::generate(), true).unwrap();
    let reply = b.accept_quick_invitation(&link.link).await.unwrap();
    b.sync(&reply.contact).await.unwrap();
    a.sync(&id).await.unwrap();
    assert_eq!(
        a.quick_invitation_status(&id).unwrap().unwrap().stage,
        "quick_confirmation"
    );
    a.confirm_quick_invitation(&id).await.unwrap();
    a.sync(&id).await.unwrap();
    b.sync(&reply.contact).await.unwrap();
    assert_eq!(
        b.quick_invitation_status(&reply.contact)
            .unwrap()
            .unwrap()
            .stage,
        "ready"
    );
    a.store().enqueue(&id, "Кот пришёл по QR!").unwrap();
    a.sync(&id).await.unwrap();
    b.sync(&reply.contact).await.unwrap();
    assert_eq!(
        b.store().history(&reply.contact, 0).unwrap()[0].text,
        "Кот пришёл по QR!"
    );
    task.abort();
}

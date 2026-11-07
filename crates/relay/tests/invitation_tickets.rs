use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use messenger_relay::{router, AppState, InvitationQueueProposal, QueueProposal, Store};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

fn secret() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn queue(number: usize) -> QueueProposal {
    QueueProposal {
        id: format!("{number:032x}"),
        read_token: secret(),
        write_token: secret(),
    }
}
fn proposal(number: usize) -> InvitationQueueProposal {
    InvitationQueueProposal {
        queue: queue(number),
        recipient_ticket: secret(),
        expires_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 300,
    }
}
fn app(path: &Path) -> Router {
    router(AppState::new(
        Store::open(path.to_str().unwrap()).unwrap(),
        &"f".repeat(64),
    ))
}
fn issue(path: &Path) -> String {
    Store::open(path.to_str().unwrap())
        .unwrap()
        .issue_invitation_ticket(600)
        .unwrap()
}
fn body(proposal: &InvitationQueueProposal) -> String {
    format!(
        r#"{{"queue":{{"id":"{}","read_token":"{}","write_token":"{}"}},"recipient_ticket":"{}","expires_at":{}}}"#,
        proposal.queue.id,
        proposal.queue.read_token,
        proposal.queue.write_token,
        proposal.recipient_ticket,
        proposal.expires_at
    )
}
fn queue_body(queue: &QueueProposal) -> String {
    format!(
        r#"{{"id":"{}","read_token":"{}","write_token":"{}"}}"#,
        queue.id, queue.read_token, queue.write_token
    )
}
async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: String,
) -> (StatusCode, Vec<u8>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(bearer) = bearer {
        builder = builder.header("authorization", format!("Bearer {bearer}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    (
        response.status(),
        to_bytes(response.into_body(), 1024).await.unwrap().to_vec(),
    )
}
fn assert_error(result: (StatusCode, Vec<u8>), status: StatusCode) {
    assert_eq!(result.0, status);
    assert!(result.1.is_empty(), "errors must not echo secret material");
}

#[tokio::test]
async fn one_owner_ticket_provisions_two_directional_queues_without_admin_or_recipient_operator_ticket(
) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.sqlite");
    let ticket = issue(&path);
    let invitation = proposal(1);
    let recipient = queue(2);
    {
        let app = app(&path);
        let created = request(
            &app,
            "POST",
            "/v1/queues/invite",
            Some(&ticket),
            body(&invitation),
        )
        .await;
        assert_eq!(created.0, StatusCode::CREATED);
        assert_eq!(
            created.1,
            format!(r#"{{"id":"{}"}}"#, invitation.queue.id).as_bytes()
        );
    }
    let app = app(&path);
    // Retrying after a lost response and process restart reuses the same pair.
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/queues/invite",
            Some(&ticket),
            body(&invitation)
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/queues/redeem",
            Some(&invitation.recipient_ticket),
            queue_body(&recipient)
        )
        .await
        .0,
        StatusCode::CREATED
    );
    assert_error(
        request(
            &app,
            "POST",
            "/v1/queues/invite",
            Some(&invitation.recipient_ticket),
            body(&proposal(3)),
        )
        .await,
        StatusCode::FORBIDDEN,
    );
    assert_error(
        request(
            &app,
            "POST",
            "/v1/queues/redeem",
            Some(&invitation.recipient_ticket),
            queue_body(&queue(3)),
        )
        .await,
        StatusCode::CONFLICT,
    );
    for queue in [&invitation.queue, &recipient] {
        let uri = format!("/v1/queues/{}/messages", queue.id);
        assert_eq!(
            request(
                &app,
                "POST",
                &uri,
                Some(&queue.write_token),
                r#"{"id":"00000000000000000000000000000001","payload":"AQ=="}"#.into()
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        let received = request(&app, "GET", &uri, Some(&queue.read_token), String::new()).await;
        assert_eq!(received.0, StatusCode::OK);
        assert_eq!(
            received.1,
            br#"{"messages":[{"id":"00000000000000000000000000000001","payload":"AQ=="}]}"#
        );
        assert_error(
            request(&app, "GET", &uri, Some(&queue.write_token), String::new()).await,
            StatusCode::NOT_FOUND,
        );
    }
    let db = Connection::open(&path).unwrap();
    let count: i64 = db
        .query_row("SELECT count(*) FROM queues", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 2);
}

#[tokio::test]
async fn malformed_invitation_and_wrong_scope_leave_parent_usable_and_errors_empty() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.sqlite");
    let ticket = issue(&path);
    let invitation = proposal(1);
    let app = app(&path);
    let extra = body(&invitation).replace("\"expires_at\":", "\"extra\":true,\"expires_at\":");
    let nested_extra =
        body(&invitation).replace("\"read_token\":", "\"extra\":true,\"read_token\":");
    for invalid in [
        String::new(),
        "{".into(),
        "null".into(),
        "[]".into(),
        "{}".into(),
        extra,
        nested_extra,
        body(&invitation).replace(&invitation.recipient_ticket, "short"),
        body(&invitation).replace(&invitation.queue.id, "short"),
        body(&invitation).replace(&invitation.queue.write_token, &invitation.queue.read_token),
        body(&invitation).replace(&invitation.recipient_ticket, &ticket),
        body(&invitation).replace(
            &format!("\"expires_at\":{}", invitation.expires_at),
            "\"expires_at\":0",
        ),
    ] {
        assert_error(
            request(&app, "POST", "/v1/queues/invite", Some(&ticket), invalid).await,
            StatusCode::BAD_REQUEST,
        );
    }
    let unknown = secret();
    let admin = "f".repeat(64);
    for bearer in [
        None,
        Some("short"),
        Some(unknown.as_str()),
        Some(admin.as_str()),
        Some(invitation.queue.read_token.as_str()),
    ] {
        assert_error(
            request(&app, "POST", "/v1/queues/invite", bearer, body(&invitation)).await,
            StatusCode::UNAUTHORIZED,
        );
    }
    let ordinary = Store::open(path.to_str().unwrap())
        .unwrap()
        .issue_ticket(600)
        .unwrap();
    assert_error(
        request(
            &app,
            "POST",
            "/v1/queues/invite",
            Some(&ordinary),
            body(&invitation),
        )
        .await,
        StatusCode::FORBIDDEN,
    );
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/queues/invite",
            Some(&ticket),
            body(&invitation)
        )
        .await
        .0,
        StatusCode::CREATED
    );
    // Nested field order and whitespace do not alter idempotence.
    let reordered = format!(
        r#"{{ "expires_at":{}, "recipient_ticket":"{}", "queue":{{"write_token":"{}", "read_token":"{}", "id":"{}"}} }}"#,
        invitation.expires_at,
        invitation.recipient_ticket,
        invitation.queue.write_token,
        invitation.queue.read_token,
        invitation.queue.id
    );
    assert_eq!(
        request(&app, "POST", "/v1/queues/invite", Some(&ticket), reordered)
            .await
            .0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn persisted_database_and_wal_have_hashes_but_no_ticket_secrets_or_explicit_pair_links() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.sqlite");
    let parent = issue(&path);
    let invitation = proposal(1);
    let app = app(&path);
    assert_eq!(
        request(
            &app,
            "POST",
            "/v1/queues/invite",
            Some(&parent),
            body(&invitation)
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let db = Connection::open(&path).unwrap();
    let recipient_hash = Sha256::digest(invitation.recipient_ticket.as_bytes()).to_vec();
    let (scope, expires, consumed): (bool, i64, Option<Vec<u8>>) = db
        .query_row(
            "SELECT can_invite,expires,proposal_digest FROM queue_tickets WHERE ticket_hash=?",
            params![recipient_hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert!(!scope);
    assert_eq!(expires, invitation.expires_at);
    assert!(consumed.is_none());
    let mut columns = db.prepare("PRAGMA table_info(queue_tickets)").unwrap();
    let names: Vec<String> = columns
        .query_map([], |row| row.get(1))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        names,
        ["ticket_hash", "expires", "proposal_digest", "can_invite"]
    );
    let mut scanned = 0;
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        scanned += 1;
        let bytes = std::fs::read(path).unwrap();
        for secret in [
            &parent,
            &invitation.recipient_ticket,
            &invitation.queue.read_token,
            &invitation.queue.write_token,
        ] {
            let decoded = hex::decode(secret).unwrap();
            assert!(!bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
            assert!(!bytes.windows(decoded.len()).any(|window| window == decoded));
        }
    }
    assert!(scanned >= 2, "expected an active WAL/SHM besides SQLite");
}

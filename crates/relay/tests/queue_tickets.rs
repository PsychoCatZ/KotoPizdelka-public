use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use messenger_relay::{router, AppState, Store};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;
use tower::ServiceExt;

const ADMIN: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

struct Proposal {
    id: String,
    read_token: String,
    write_token: String,
}

impl Proposal {
    fn new(id: usize) -> Self {
        Self {
            id: format!("{id:032x}"),
            read_token: capability(),
            write_token: capability(),
        }
    }

    fn body(&self) -> String {
        format!(
            r#"{{"id":"{}","read_token":"{}","write_token":"{}"}}"#,
            self.id, self.read_token, self.write_token
        )
    }

    fn response(&self) -> Vec<u8> {
        format!(r#"{{"id":"{}"}}"#, self.id).into_bytes()
    }
}

fn capability() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn open(path: &Path) -> Store {
    Store::open(path.to_str().unwrap()).unwrap()
}

fn issue(path: &Path) -> String {
    open(path).issue_ticket(600).unwrap()
}

fn app(path: &Path) -> Router {
    router(AppState::new(open(path), ADMIN))
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
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024).await.unwrap();
    (status, bytes.to_vec())
}

async fn redeem(app: &Router, ticket: &str, body: String) -> (StatusCode, Vec<u8>) {
    request(app, "POST", "/v1/queues/redeem", Some(ticket), body).await
}

fn assert_error(result: (StatusCode, Vec<u8>), expected: StatusCode) {
    assert_eq!(result.0, expected);
    assert!(
        result.1.is_empty(),
        "error responses must not echo request data"
    );
}

fn assert_created(result: (StatusCode, Vec<u8>), proposal: &Proposal) {
    assert_eq!(result.0, StatusCode::CREATED);
    // The successful response contains a public queue ID, never capabilities.
    assert_eq!(result.1, proposal.response());
}

fn queue_count(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM queues", [], |row| row.get(0))
        .unwrap()
}

#[tokio::test]
async fn lost_response_retry_survives_store_reopen_and_keeps_capabilities_separate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(1);
    {
        let app = app(&path);
        // The client discards the reply, then restarts with its original proposal.
        assert_eq!(
            redeem(&app, &ticket, proposal.body()).await.0,
            StatusCode::CREATED
        );
    }
    let app = app(&path);
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    assert_eq!(queue_count(&path), 1);

    let uri = format!("/v1/queues/{}/messages", proposal.id);
    let received = request(&app, "GET", &uri, Some(&proposal.read_token), String::new()).await;
    assert_eq!(received.0, StatusCode::OK);
    assert_eq!(received.1, br#"{"messages":[]}"#);
    assert_error(
        request(
            &app,
            "GET",
            &uri,
            Some(&proposal.write_token),
            String::new(),
        )
        .await,
        StatusCode::NOT_FOUND,
    );
    assert_error(
        request(
            &app,
            "POST",
            &uri,
            Some(&proposal.read_token),
            r#"{"id":"00000000000000000000000000000001","payload":"AQ=="}"#.into(),
        )
        .await,
        StatusCode::NOT_FOUND,
    );
    let sent = request(
        &app,
        "POST",
        &uri,
        Some(&proposal.write_token),
        r#"{"id":"00000000000000000000000000000001","payload":"AQ=="}"#.into(),
    )
    .await;
    assert_eq!(sent.0, StatusCode::ACCEPTED);
}

#[tokio::test]
async fn consumed_ticket_binds_all_proposal_fields_but_not_json_formatting() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(2);
    let app = app(&path);
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    let reformatted = format!(
        "{{\n  \"write_token\": \"{}\", \"id\": \"{}\",\n  \"read_token\": \"{}\"\n}}",
        proposal.write_token, proposal.id, proposal.read_token
    );
    assert_created(redeem(&app, &ticket, reformatted).await, &proposal);

    for changed in [
        Proposal {
            id: format!("{:032x}", 3),
            read_token: proposal.read_token.clone(),
            write_token: proposal.write_token.clone(),
        },
        Proposal {
            id: proposal.id.clone(),
            read_token: capability(),
            write_token: proposal.write_token.clone(),
        },
        Proposal {
            id: proposal.id.clone(),
            read_token: proposal.read_token.clone(),
            write_token: capability(),
        },
    ] {
        assert_error(
            redeem(&app, &ticket, changed.body()).await,
            StatusCode::CONFLICT,
        );
    }
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    assert_eq!(queue_count(&path), 1);
}

#[tokio::test]
async fn malformed_json_and_capabilities_do_not_consume_ticket() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(4);
    let app = app(&path);
    let extra_field = format!(
        r#"{{"id":"{}","read_token":"{}","write_token":"{}","extra":true}}"#,
        proposal.id, proposal.read_token, proposal.write_token
    );
    let malformed = [
        String::new(),
        "{".into(),
        "null".into(),
        "[]".into(),
        "{}".into(),
        extra_field,
        format!(
            r#"{{"id":"short","read_token":"{}","write_token":"{}"}}"#,
            proposal.read_token, proposal.write_token
        ),
        format!(
            r#"{{"id":"{}","read_token":"{}","write_token":"short"}}"#,
            proposal.id, proposal.read_token
        ),
        format!(
            r#"{{"id":"{}","read_token":"{}","write_token":"{}"}}"#,
            proposal.id, proposal.read_token, proposal.read_token
        ),
        format!(
            r#"{{"id":"{}","read_token":"{}","write_token":"{}"}}"#,
            proposal.id,
            "A".repeat(64),
            proposal.write_token
        ),
        format!(
            r#"{{"id":"{}","read_token":false,"write_token":"{}"}}"#,
            proposal.id, proposal.write_token
        ),
    ];
    for body in malformed {
        assert_error(redeem(&app, &ticket, body).await, StatusCode::BAD_REQUEST);
        assert_eq!(queue_count(&path), 0);
    }
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
}

#[tokio::test]
async fn queue_capabilities_admin_and_unknown_credentials_cannot_redeem_tickets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let existing = Proposal::new(5);
    let app = app(&path);
    assert_created(redeem(&app, &ticket, existing.body()).await, &existing);
    let new = Proposal::new(6);
    let unknown = capability();
    let uppercase = "A".repeat(64);
    for credential in [
        None,
        Some(""),
        Some("short"),
        Some(uppercase.as_str()),
        Some(unknown.as_str()),
        Some(ADMIN),
        Some(existing.read_token.as_str()),
        Some(existing.write_token.as_str()),
    ] {
        assert_error(
            request(&app, "POST", "/v1/queues/redeem", credential, new.body()).await,
            StatusCode::UNAUTHORIZED,
        );
    }
    assert_eq!(queue_count(&path), 1);
    let new_ticket = issue(&path);
    assert_created(redeem(&app, &new_ticket, new.body()).await, &new);
}

#[tokio::test]
async fn expired_response_can_be_recovered_with_new_ticket_and_exact_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let old_ticket = issue(&path);
    let proposal = Proposal::new(7);
    let app = app(&path);
    assert_created(redeem(&app, &old_ticket, proposal.body()).await, &proposal);
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE queue_tickets SET expires=0", [])
        .unwrap();
    assert_error(
        redeem(&app, &old_ticket, proposal.body()).await,
        StatusCode::UNAUTHORIZED,
    );

    let fresh_ticket = issue(&path);
    assert_created(
        redeem(&app, &fresh_ticket, proposal.body()).await,
        &proposal,
    );
    assert_created(
        redeem(&app, &fresh_ticket, proposal.body()).await,
        &proposal,
    );
    assert_eq!(queue_count(&path), 1);

    let other_ticket = issue(&path);
    let mismatched = Proposal {
        id: proposal.id.clone(),
        read_token: proposal.read_token.clone(),
        write_token: capability(),
    };
    assert_error(
        redeem(&app, &other_ticket, mismatched.body()).await,
        StatusCode::CONFLICT,
    );
    let other = Proposal::new(8);
    assert_created(redeem(&app, &other_ticket, other.body()).await, &other);
    assert_eq!(queue_count(&path), 2);
}

#[tokio::test]
async fn expired_unredeemed_ticket_cannot_create_a_queue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    Connection::open(&path)
        .unwrap()
        .execute("UPDATE queue_tickets SET expires=0", [])
        .unwrap();
    let app = app(&path);
    let proposal = Proposal::new(9);
    assert_error(
        redeem(&app, &ticket, proposal.body()).await,
        StatusCode::UNAUTHORIZED,
    );
    assert_eq!(queue_count(&path), 0);
}

#[tokio::test]
async fn full_queue_quota_does_not_consume_ticket_or_break_exact_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(1000);
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    for id in 0..256 {
        tx.execute(
            "INSERT INTO queues(id,write_hash,read_hash) VALUES(?,?,?)",
            params![format!("{id:032x}"), vec![0_u8; 32], vec![1_u8; 32]],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let app = app(&path);
    assert_error(
        redeem(&app, &ticket, proposal.body()).await,
        StatusCode::TOO_MANY_REQUESTS,
    );
    assert_eq!(queue_count(&path), 256);
    db.execute("DELETE FROM queues WHERE id=?", [format!("{:032x}", 0)])
        .unwrap();
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    assert_eq!(queue_count(&path), 256);
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    let fresh_ticket = issue(&path);
    assert_created(
        redeem(&app, &fresh_ticket, proposal.body()).await,
        &proposal,
    );
    assert_eq!(queue_count(&path), 256);
}

#[tokio::test]
async fn failed_sql_insert_rolls_back_ticket_consumption() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(10);
    let db = Connection::open(&path).unwrap();
    db.execute_batch(
        "CREATE TRIGGER reject_queue BEFORE INSERT ON queues BEGIN
             SELECT RAISE(ABORT, 'forced test failure');
         END;",
    )
    .unwrap();
    let app = app(&path);
    assert_error(
        redeem(&app, &ticket, proposal.body()).await,
        StatusCode::INTERNAL_SERVER_ERROR,
    );
    assert_eq!(queue_count(&path), 0);
    db.execute_batch("DROP TRIGGER reject_queue").unwrap();
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    assert_eq!(queue_count(&path), 1);
}

#[tokio::test]
async fn consumed_ticket_never_recreates_deleted_queue() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(11);
    let app = app(&path);
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    let deleted = request(
        &app,
        "DELETE",
        &format!("/v1/queues/{}", proposal.id),
        Some(&proposal.read_token),
        String::new(),
    )
    .await;
    assert_eq!(deleted.0, StatusCode::NO_CONTENT);
    assert_error(
        redeem(&app, &ticket, proposal.body()).await,
        StatusCode::NOT_FOUND,
    );
    assert_eq!(queue_count(&path), 0);
    let fresh_ticket = issue(&path);
    assert_created(
        redeem(&app, &fresh_ticket, proposal.body()).await,
        &proposal,
    );
    assert_eq!(queue_count(&path), 1);
}

#[tokio::test]
async fn sqlite_and_wal_store_only_hashes_of_tickets_and_capabilities() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("relay.sqlite");
    let ticket = issue(&path);
    let proposal = Proposal::new(12);
    let app = app(&path);
    assert_created(redeem(&app, &ticket, proposal.body()).await, &proposal);
    // Read with the relay connection alive, so WAL files are included in the scan.
    let db = Connection::open(&path).unwrap();
    let ticket_hash: Vec<u8> = db
        .query_row("SELECT ticket_hash FROM queue_tickets", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(ticket_hash == Sha256::digest(ticket.as_bytes()).as_slice());
    let (read_hash, write_hash): (Vec<u8>, Vec<u8>) = db
        .query_row("SELECT read_hash,write_hash FROM queues", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert!(read_hash == Sha256::digest(proposal.read_token.as_bytes()).as_slice());
    assert!(write_hash == Sha256::digest(proposal.write_token.as_bytes()).as_slice());

    let mut scanned_files = 0;
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let path = entry.unwrap().path();
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(path).unwrap();
        scanned_files += 1;
        for secret in [&ticket, &proposal.read_token, &proposal.write_token] {
            let decoded = hex::decode(secret).unwrap();
            assert!(!bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
            assert!(!bytes.windows(decoded.len()).any(|window| window == decoded));
        }
    }
    assert!(
        scanned_files >= 2,
        "expected database plus an active WAL or SHM file"
    );
}

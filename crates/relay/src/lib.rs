pub mod accounts;
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;

const TTL: i64 = 7 * 24 * 3600;
const MAX_PAYLOAD: usize = 65536;
const MAX_QUEUES: i64 = 256;
const MAX_RECORDS: i64 = 1024;
const QUEUE_BYTES: i64 = 4 * 1024 * 1024;
const TOTAL_BYTES: i64 = 32 * 1024 * 1024;
const MAX_TICKETS: i64 = 1024;
const MAX_TICKET_TTL: i64 = 24 * 3600;

#[derive(Debug)]
pub struct Error(StatusCode);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR)
    }
}
type Result<T> = std::result::Result<T, Error>;

fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}
fn random_hex(n: usize) -> String {
    let mut bytes = vec![0; n];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub fn valid_admin_token(value: &str) -> bool {
    valid_hex(value, 64)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs() as i64
}
fn token(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("")
}

#[derive(Serialize, Deserialize)]
pub struct Queue {
    pub id: String,
    pub write_token: String,
    pub read_token: String,
}
/// Client-generated queue credentials, persisted locally before redemption.
/// Capability-bearing types deliberately do not implement `Debug`.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct QueueProposal {
    pub id: String,
    pub read_token: String,
    pub write_token: String,
}
impl QueueProposal {
    fn valid(&self) -> bool {
        valid_hex(&self.id, 32)
            && valid_hex(&self.read_token, 64)
            && valid_hex(&self.write_token, 64)
            && self.read_token != self.write_token
    }
    fn digest(&self) -> Vec<u8> {
        // Fixed field sizes and ordering make this independent of JSON encoding.
        let mut digest = Sha256::new();
        digest.update(b"private-messenger.queue-proposal.v1\0");
        digest.update(self.id.as_bytes());
        digest.update(self.read_token.as_bytes());
        digest.update(self.write_token.as_bytes());
        digest.finalize().to_vec()
    }
}
/// An owner-issued invitation ticket can provision one queue and delegate a
/// single, non-delegating queue ticket. All secrets originate on the client.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct InvitationQueueProposal {
    pub queue: QueueProposal,
    pub recipient_ticket: String,
    pub expires_at: i64,
}
impl InvitationQueueProposal {
    fn digest(&self) -> Vec<u8> {
        let mut digest = Sha256::new();
        digest.update(b"private-messenger.invitation-queue-proposal.v1\0");
        digest.update(self.queue.digest());
        digest.update(self.recipient_ticket.as_bytes());
        digest.update(self.expires_at.to_be_bytes());
        digest.finalize().to_vec()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemedQueue {
    pub id: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Message {
    pub id: String,
    pub payload: String,
}
#[derive(Serialize, Deserialize)]
pub struct Messages {
    pub messages: Vec<Message>,
}

pub struct Store {
    db: Connection,
}
impl Store {
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS queues (
                id TEXT PRIMARY KEY, write_hash BLOB NOT NULL, read_hash BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                queue TEXT NOT NULL REFERENCES queues(id) ON DELETE CASCADE,
                id TEXT NOT NULL, payload BLOB, digest BLOB NOT NULL, expires INTEGER NOT NULL,
                UNIQUE(queue,id));
            CREATE INDEX IF NOT EXISTS expiry ON messages(expires);
            CREATE INDEX IF NOT EXISTS delivery ON messages(queue,seq);
            CREATE TABLE IF NOT EXISTS queue_tickets (
                ticket_hash BLOB PRIMARY KEY, expires INTEGER NOT NULL,
                proposal_digest BLOB,
                can_invite INTEGER NOT NULL DEFAULT 0 CHECK(can_invite IN (0,1)));
            CREATE INDEX IF NOT EXISTS ticket_expiry ON queue_tickets(expires);",
        )?;
        // Serialize migration with other Store handles. Existing tickets retain
        // their original one-queue authority; only explicit local issuance can
        // grant permission to delegate a second ticket.
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has_scope = {
            let mut columns = tx.prepare("PRAGMA table_info(queue_tickets)")?;
            let names = columns.query_map([], |row| row.get::<_, String>(1))?;
            names
                .collect::<rusqlite::Result<Vec<_>>>()?
                .iter()
                .any(|name| name == "can_invite")
        };
        if !has_scope {
            tx.execute_batch("ALTER TABLE queue_tickets ADD COLUMN can_invite INTEGER NOT NULL DEFAULT 0 CHECK(can_invite IN (0,1));")?;
        }
        tx.commit()?;
        accounts::schema(&db)?;
        Ok(Self { db })
    }
    fn prune(&self, timestamp: i64) -> Result<()> {
        self.db
            .execute("DELETE FROM messages WHERE expires<=?", [timestamp])?;
        self.db
            .execute("DELETE FROM queue_tickets WHERE expires<=?", [timestamp])?;
        Ok(())
    }
    /// Issue a one-queue ticket using local access to the relay database.
    /// The returned secret is never stored in plaintext in SQLite.
    pub fn issue_ticket(&mut self, ttl_seconds: i64) -> Result<String> {
        self.issue_ticket_with_clock(ttl_seconds, now)
    }
    /// Explicit local authority to create an invitation: one inviter queue plus
    /// one recipient ticket. The recipient cannot delegate further tickets.
    pub fn issue_invitation_ticket(&mut self, ttl_seconds: i64) -> Result<String> {
        self.issue_scoped_ticket_with_clock(ttl_seconds, true, now)
    }
    #[cfg(test)]
    fn issue_ticket_at(&mut self, ttl_seconds: i64, timestamp: i64) -> Result<String> {
        self.issue_ticket_with_clock(ttl_seconds, || timestamp)
    }
    fn issue_ticket_with_clock(
        &mut self,
        ttl_seconds: i64,
        clock: impl FnOnce() -> i64,
    ) -> Result<String> {
        self.issue_scoped_ticket_with_clock(ttl_seconds, false, clock)
    }
    fn issue_scoped_ticket_with_clock(
        &mut self,
        ttl_seconds: i64,
        can_invite: bool,
        clock: impl FnOnce() -> i64,
    ) -> Result<String> {
        if !(1..=MAX_TICKET_TTL).contains(&ttl_seconds) {
            return Err(Error(StatusCode::BAD_REQUEST));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Read the clock after obtaining the write lock: contention must not
        // shorten the promised TTL or allow redemption using a stale time.
        let timestamp = clock();
        let expires = timestamp
            .checked_add(ttl_seconds)
            .ok_or(Error(StatusCode::BAD_REQUEST))?;
        tx.execute("DELETE FROM queue_tickets WHERE expires<=?", [timestamp])?;
        let count: i64 = tx.query_row("SELECT count(*) FROM queue_tickets", [], |r| r.get(0))?;
        if count >= MAX_TICKETS {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS));
        }
        let ticket = random_hex(32);
        tx.execute(
            "INSERT INTO queue_tickets(ticket_hash,expires,can_invite) VALUES(?,?,?)",
            params![hash(ticket.as_bytes()), expires, can_invite],
        )?;
        tx.commit()?;
        Ok(ticket)
    }
    #[cfg(test)]
    fn redeem(
        &mut self,
        ticket: &str,
        proposal: QueueProposal,
        timestamp: i64,
    ) -> Result<RedeemedQueue> {
        self.redeem_with_clock(ticket, proposal, || timestamp)
    }
    fn redeem_with_clock(
        &mut self,
        ticket: &str,
        proposal: QueueProposal,
        clock: impl FnOnce() -> i64,
    ) -> Result<RedeemedQueue> {
        if !valid_hex(ticket, 64) {
            return Err(Error(StatusCode::UNAUTHORIZED));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = clock();
        let ticket_hash = hash(ticket.as_bytes());
        let record: Option<(i64, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT expires,proposal_digest FROM queue_tickets WHERE ticket_hash=?",
                [&ticket_hash],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((_, consumed)) = record.filter(|(expires, _)| *expires > timestamp) else {
            return Err(Error(StatusCode::UNAUTHORIZED));
        };
        // Authenticate the ticket before returning any queue conflict information.
        if !proposal.valid() {
            return Err(Error(StatusCode::BAD_REQUEST));
        }
        let digest = proposal.digest();
        if consumed
            .as_ref()
            .is_some_and(|previous| !bool::from(previous.ct_eq(&digest)))
        {
            return Err(Error(StatusCode::CONFLICT));
        }
        Self::ensure_queue(&tx, &proposal, consumed.is_some())?;
        if consumed.is_none() {
            tx.execute(
                "UPDATE queue_tickets SET proposal_digest=? WHERE ticket_hash=?",
                params![digest, ticket_hash],
            )?;
        }
        tx.commit()?;
        // Queue identifiers are already public relay addresses; no capabilities
        // or ticket appear in the response or the persisted proposal digest.
        Ok(RedeemedQueue { id: proposal.id })
    }
    fn ensure_queue(tx: &Transaction<'_>, proposal: &QueueProposal, consumed: bool) -> Result<()> {
        let read_hash = hash(proposal.read_token.as_bytes());
        let write_hash = hash(proposal.write_token.as_bytes());
        let existing: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT read_hash,write_hash FROM queues WHERE id=?",
                [&proposal.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match existing {
            Some((read, write)) => {
                if !bool::from(read.ct_eq(&read_hash) & write.ct_eq(&write_hash)) {
                    return Err(Error(StatusCode::CONFLICT));
                }
            }
            None if consumed => {
                // An exact retry must never resurrect a queue its owner deleted.
                return Err(Error(StatusCode::NOT_FOUND));
            }
            None => {
                let count: i64 = tx.query_row("SELECT count(*) FROM queues", [], |r| r.get(0))?;
                if count >= MAX_QUEUES {
                    return Err(Error(StatusCode::TOO_MANY_REQUESTS));
                }
                tx.execute(
                    "INSERT INTO queues(id,write_hash,read_hash) VALUES(?,?,?)",
                    params![proposal.id, write_hash, read_hash],
                )?;
            }
        }
        Ok(())
    }
    fn invite_with_clock(
        &mut self,
        ticket: &str,
        proposal: InvitationQueueProposal,
        clock: impl FnOnce() -> i64,
    ) -> Result<RedeemedQueue> {
        if !valid_hex(ticket, 64) {
            return Err(Error(StatusCode::UNAUTHORIZED));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = clock();
        let ticket_hash = hash(ticket.as_bytes());
        let record: Option<(i64, Option<Vec<u8>>, bool)> = tx
            .query_row(
                "SELECT expires,proposal_digest,can_invite FROM queue_tickets WHERE ticket_hash=?",
                [&ticket_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((parent_expires, consumed, can_invite)) =
            record.filter(|(expires, _, _)| *expires > timestamp)
        else {
            return Err(Error(StatusCode::UNAUTHORIZED));
        };
        if !can_invite {
            return Err(Error(StatusCode::FORBIDDEN));
        }
        if !proposal.queue.valid()
            || !valid_hex(&proposal.recipient_ticket, 64)
            || proposal.recipient_ticket == ticket
            || proposal.recipient_ticket == proposal.queue.read_token
            || proposal.recipient_ticket == proposal.queue.write_token
            || proposal.expires_at <= timestamp
            || proposal.expires_at > parent_expires
            || proposal.expires_at
                > timestamp
                    .checked_add(MAX_TICKET_TTL)
                    .ok_or(Error(StatusCode::BAD_REQUEST))?
        {
            return Err(Error(StatusCode::BAD_REQUEST));
        }
        let digest = proposal.digest();
        if consumed
            .as_ref()
            .is_some_and(|previous| !bool::from(previous.ct_eq(&digest)))
        {
            return Err(Error(StatusCode::CONFLICT));
        }
        let recipient_hash = hash(proposal.recipient_ticket.as_bytes());
        let recipient: Option<(i64, bool)> = tx
            .query_row(
                "SELECT expires,can_invite FROM queue_tickets WHERE ticket_hash=?",
                [&recipient_hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if consumed.is_some() {
            // An exact retry acknowledges existing state, never reissues a
            // deleted recipient ticket or clears its redemption digest.
            let Some((expires, can_invite)) = recipient else {
                return Err(Error(StatusCode::NOT_FOUND));
            };
            if expires != proposal.expires_at || can_invite {
                return Err(Error(StatusCode::CONFLICT));
            }
        } else {
            if recipient.is_some() {
                return Err(Error(StatusCode::CONFLICT));
            }
            tx.execute("DELETE FROM queue_tickets WHERE expires<=?", [timestamp])?;
            let count: i64 =
                tx.query_row("SELECT count(*) FROM queue_tickets", [], |row| row.get(0))?;
            if count >= MAX_TICKETS {
                return Err(Error(StatusCode::TOO_MANY_REQUESTS));
            }
        }
        Self::ensure_queue(&tx, &proposal.queue, consumed.is_some())?;
        if consumed.is_none() {
            tx.execute(
                "INSERT INTO queue_tickets(ticket_hash,expires,can_invite) VALUES(?,?,0)",
                params![recipient_hash, proposal.expires_at],
            )?;
            tx.execute(
                "UPDATE queue_tickets SET proposal_digest=? WHERE ticket_hash=?",
                params![digest, ticket_hash],
            )?;
        }
        tx.commit()?;
        Ok(RedeemedQueue {
            id: proposal.queue.id,
        })
    }
    fn auth(&self, queue: &str, capability: &str, read: bool) -> Result<()> {
        // The column names are fixed constants, never input from the caller.
        let sql = if read {
            "SELECT read_hash FROM queues WHERE id=?"
        } else {
            "SELECT write_hash FROM queues WHERE id=?"
        };
        let stored: Option<Vec<u8>> = self.db.query_row(sql, [queue], |r| r.get(0)).optional()?;
        let supplied = hash(capability.as_bytes());
        if stored.is_some_and(|h| bool::from(h.ct_eq(&supplied))) {
            Ok(())
        } else {
            Err(Error(StatusCode::NOT_FOUND))
        }
    }
    fn create(&self) -> Result<Queue> {
        // Keep the existing admin endpoint, while serializing its quota check
        // with ticket redemption performed through other Store handles.
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM queues", [], |r| r.get(0))?;
        if count >= MAX_QUEUES {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS));
        }
        let queue = Queue {
            id: random_hex(16),
            write_token: random_hex(32),
            read_token: random_hex(32),
        };
        tx.execute(
            "INSERT INTO queues VALUES (?,?,?)",
            params![
                queue.id,
                hash(queue.write_token.as_bytes()),
                hash(queue.read_token.as_bytes())
            ],
        )?;
        tx.commit()?;
        Ok(queue)
    }
    fn send(
        &mut self,
        queue: &str,
        capability: &str,
        message: Message,
        timestamp: i64,
    ) -> Result<()> {
        self.auth(queue, capability, false)?;
        if !valid_hex(&message.id, 32) {
            return Err(Error(StatusCode::BAD_REQUEST));
        }
        let payload = STANDARD
            .decode(&message.payload)
            .map_err(|_| Error(StatusCode::BAD_REQUEST))?;
        if payload.is_empty() || payload.len() > MAX_PAYLOAD {
            return Err(Error(StatusCode::PAYLOAD_TOO_LARGE));
        }
        self.prune(timestamp)?;
        let digest = hash(&payload);
        let tx = self.db.transaction()?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT digest FROM messages WHERE queue=? AND id=?",
                params![queue, message.id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = existing {
            return if previous == digest {
                Ok(())
            } else {
                Err(Error(StatusCode::CONFLICT))
            };
        }
        let (records, bytes): (i64, i64) = tx.query_row(
            "SELECT count(*),coalesce(sum(length(payload)),0) FROM messages WHERE queue=?",
            [queue],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let total: i64 = tx.query_row(
            "SELECT coalesce(sum(length(payload)),0) FROM messages",
            [],
            |r| r.get(0),
        )?;
        let size = payload.len() as i64;
        if records >= MAX_RECORDS || bytes + size > QUEUE_BYTES || total + size > TOTAL_BYTES {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS));
        }
        tx.execute(
            "INSERT INTO messages(queue,id,payload,digest,expires) VALUES(?,?,?,?,?)",
            params![queue, message.id, payload, digest, timestamp + TTL],
        )?;
        tx.commit()?;
        Ok(())
    }
    fn receive(&self, queue: &str, capability: &str, timestamp: i64) -> Result<Messages> {
        self.auth(queue, capability, true)?;
        self.prune(timestamp)?;
        let mut statement = self.db.prepare("SELECT id,payload FROM messages WHERE queue=? AND payload IS NOT NULL ORDER BY seq LIMIT 100")?;
        let rows = statement.query_map([queue], |r| {
            let payload: Vec<u8> = r.get(1)?;
            Ok(Message {
                id: r.get(0)?,
                payload: STANDARD.encode(payload),
            })
        })?;
        Ok(Messages {
            messages: rows.collect::<rusqlite::Result<Vec<_>>>()?,
        })
    }
    fn ack(&self, queue: &str, capability: &str, message: &str, timestamp: i64) -> Result<()> {
        self.auth(queue, capability, true)?;
        self.prune(timestamp)?;
        self.db.execute(
            "UPDATE messages SET payload=NULL WHERE queue=? AND id=?",
            params![queue, message],
        )?;
        Ok(())
    }
    fn remove(&self, queue: &str, capability: &str) -> Result<()> {
        self.auth(queue, capability, true)?;
        self.db.execute("DELETE FROM queues WHERE id=?", [queue])?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<Store>>,
    admin_hash: Arc<Vec<u8>>,
    auth_budget: Arc<Mutex<accounts::AuthBudget>>,
    password_workers: Arc<tokio::sync::Semaphore>,
}
impl AppState {
    pub fn new(store: Store, admin: &str) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            admin_hash: Arc::new(hash(admin.as_bytes())),
            auth_budget: Arc::new(Mutex::new(accounts::AuthBudget::default())),
            password_workers: accounts::password_workers(),
        }
    }
    async fn run<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = store
                .lock()
                .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?;
            operation(&mut db)
        })
        .await
        .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?
    }
    pub async fn cleanup(&self) -> Result<()> {
        self.run(|s| s.prune(now())).await
    }
}

async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Queue>)> {
    if !bool::from(
        state
            .admin_hash
            .as_slice()
            .ct_eq(&hash(token(&headers).as_bytes())),
    ) {
        return Err(Error(StatusCode::UNAUTHORIZED));
    }
    Ok((StatusCode::CREATED, Json(state.run(|s| s.create()).await?)))
}
async fn redeem(
    State(state): State<AppState>,
    headers: HeaderMap,
    proposal: std::result::Result<Json<QueueProposal>, JsonRejection>,
) -> Result<(StatusCode, Json<RedeemedQueue>)> {
    let ticket = token(&headers).to_owned();
    if !valid_hex(&ticket, 64) {
        return Err(Error(StatusCode::UNAUTHORIZED));
    }
    // Avoid returning JSON parser details, field names, or capability material.
    let Json(proposal) = proposal.map_err(|_| Error(StatusCode::BAD_REQUEST))?;
    let result = state
        .run(move |s| s.redeem_with_clock(&ticket, proposal, now))
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
async fn invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    proposal: std::result::Result<Json<InvitationQueueProposal>, JsonRejection>,
) -> Result<(StatusCode, Json<RedeemedQueue>)> {
    let ticket = token(&headers).to_owned();
    if !valid_hex(&ticket, 64) {
        return Err(Error(StatusCode::UNAUTHORIZED));
    }
    let Json(proposal) = proposal.map_err(|_| Error(StatusCode::BAD_REQUEST))?;
    let result = state
        .run(move |store| store.invite_with_clock(&ticket, proposal, now))
        .await?;
    Ok((StatusCode::CREATED, Json(result)))
}
async fn send(
    State(state): State<AppState>,
    Path(queue): Path<String>,
    headers: HeaderMap,
    Json(message): Json<Message>,
) -> Result<StatusCode> {
    let capability = token(&headers).to_owned();
    state
        .run(move |s| s.send(&queue, &capability, message, now()))
        .await?;
    Ok(StatusCode::ACCEPTED)
}
async fn receive(
    State(state): State<AppState>,
    Path(queue): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Messages>> {
    let capability = token(&headers).to_owned();
    Ok(Json(
        state
            .run(move |s| s.receive(&queue, &capability, now()))
            .await?,
    ))
}
async fn ack(
    State(state): State<AppState>,
    Path((queue, message)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let capability = token(&headers).to_owned();
    state
        .run(move |s| s.ack(&queue, &capability, &message, now()))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn remove(
    State(state): State<AppState>,
    Path(queue): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode> {
    let capability = token(&headers).to_owned();
    state.run(move |s| s.remove(&queue, &capability)).await?;
    Ok(StatusCode::NO_CONTENT)
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(accounts::routes())
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/v1/queues", post(create))
        .route("/v1/queues/redeem", post(redeem))
        .route("/v1/queues/invite", post(invite))
        .route("/v1/queues/{queue}", delete(remove))
        .route("/v1/queues/{queue}/messages", post(send).get(receive))
        .route("/v1/queues/{queue}/messages/{message}", delete(ack))
        .layer(DefaultBodyLimit::max(96 * 1024))
        .with_state(state)
}

#[cfg(test)]
mod ticket_tests {
    use super::*;
    use std::sync::Barrier;

    fn proposal(number: usize) -> QueueProposal {
        QueueProposal {
            id: format!("{number:032x}"),
            read_token: "a".repeat(64),
            write_token: "b".repeat(64),
        }
    }

    #[test]
    fn ticket_ttl_bounds_and_expiry_cutoff() {
        let mut store = Store::open(":memory:").unwrap();
        for ttl in [i64::MIN, -1, 0, MAX_TICKET_TTL + 1, i64::MAX] {
            assert_eq!(
                store.issue_ticket_at(ttl, 100).err().unwrap().0,
                StatusCode::BAD_REQUEST
            );
        }
        let ticket = store.issue_ticket_at(10, 100).unwrap();
        store.redeem(&ticket, proposal(1), 109).unwrap();
        assert_eq!(
            store.redeem(&ticket, proposal(1), 110).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        // Exact retries remain available throughout the complete ticket TTL.
        store.prune(109).unwrap();
        store.redeem(&ticket, proposal(1), 109).unwrap();
        store.prune(110).unwrap();
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM queue_tickets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        assert!(store.issue_ticket_at(MAX_TICKET_TTL, 110).is_ok());
    }

    #[test]
    fn ticket_quota_keeps_unexpired_consumed_tickets() {
        let mut store = Store::open(":memory:").unwrap();
        let ticket = store.issue_ticket_at(100, 100).unwrap();
        store.redeem(&ticket, proposal(1), 101).unwrap();
        for number in 1..MAX_TICKETS {
            store
                .db
                .execute(
                    "INSERT INTO queue_tickets(ticket_hash,expires) VALUES(?,200)",
                    [hash(&number.to_le_bytes())],
                )
                .unwrap();
        }
        assert_eq!(
            store.issue_ticket_at(1, 150).err().unwrap().0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Failed issuance must neither erase consumed records nor block retry.
        store.redeem(&ticket, proposal(1), 199).unwrap();
        store.issue_ticket_at(1, 200).unwrap();
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM queue_tickets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            store.redeem(&ticket, proposal(1), 200).err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn consumed_ticket_does_not_resurrect_deleted_queue() {
        let mut store = Store::open(":memory:").unwrap();
        let ticket = store.issue_ticket_at(10, 100).unwrap();
        let proposed = proposal(1);
        store.redeem(&ticket, proposed.clone(), 101).unwrap();
        store.remove(&proposed.id, &proposed.read_token).unwrap();
        assert_eq!(
            store
                .redeem(&ticket, proposed.clone(), 102)
                .err()
                .unwrap()
                .0,
            StatusCode::NOT_FOUND
        );
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM queues", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let fresh = store.issue_ticket_at(10, 102).unwrap();
        store.redeem(&fresh, proposed, 102).unwrap();
    }

    #[test]
    fn consumed_ticket_checks_current_queue_capabilities() {
        let mut store = Store::open(":memory:").unwrap();
        let ticket = store.issue_ticket_at(10, 100).unwrap();
        store.redeem(&ticket, proposal(1), 101).unwrap();
        store
            .db
            .execute(
                "UPDATE queues SET read_hash=?",
                [hash("c".repeat(64).as_bytes())],
            )
            .unwrap();
        assert_eq!(
            store.redeem(&ticket, proposal(1), 102).err().unwrap().0,
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn ticket_consumption_failure_rolls_back_inserted_queue() {
        let mut store = Store::open(":memory:").unwrap();
        let ticket = store.issue_ticket_at(10, 100).unwrap();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER reject_consumption BEFORE UPDATE ON queue_tickets
                 BEGIN SELECT RAISE(ABORT,'injected failure'); END;",
            )
            .unwrap();
        assert_eq!(
            store.redeem(&ticket, proposal(1), 101).err().unwrap().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM queues", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        store
            .db
            .execute_batch("DROP TRIGGER reject_consumption")
            .unwrap();
        store.redeem(&ticket, proposal(1), 102).unwrap();
    }

    fn concurrent_redemptions(same_body: bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.sqlite");
        let path = path.to_str().unwrap().to_owned();
        let ticket = Store::open(&path)
            .unwrap()
            .issue_ticket_at(100, 100)
            .unwrap();
        let barrier = Arc::new(Barrier::new(8));
        let mut tasks = Vec::new();
        for number in 1..=8 {
            let barrier = barrier.clone();
            let path = path.clone();
            let ticket = ticket.clone();
            tasks.push(std::thread::spawn(move || {
                let mut store = Store::open(&path).unwrap();
                barrier.wait();
                let result =
                    store.redeem(&ticket, proposal(if same_body { 1 } else { number }), 101);
                match result {
                    Ok(queue) => (StatusCode::CREATED, Some(queue.id)),
                    Err(error) => (error.0, None),
                }
            }));
        }
        let results: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
        let successes: Vec<_> = results
            .iter()
            .filter(|(status, _)| *status == StatusCode::CREATED)
            .collect();
        assert_eq!(successes.len(), if same_body { 8 } else { 1 });
        assert!(results.iter().all(|(status, _)| {
            *status == StatusCode::CREATED || *status == StatusCode::CONFLICT
        }));
        let id = successes[0].1.as_ref().unwrap();
        let mut store = Store::open(&path).unwrap();
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM queues", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let number = usize::from_str_radix(id, 16).unwrap();
        assert!(store.redeem(&ticket, proposal(number), 102).is_ok());
    }

    #[test]
    fn concurrent_same_ticket_different_proposals_has_one_winner() {
        concurrent_redemptions(false);
    }

    #[test]
    fn concurrent_exact_retries_create_only_one_queue() {
        concurrent_redemptions(true);
    }

    #[test]
    fn admin_creation_and_ticket_redemption_share_atomic_queue_quota() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.sqlite");
        let path = path.to_str().unwrap().to_owned();
        let mut store = Store::open(&path).unwrap();
        let ticket = store.issue_ticket_at(10, 100).unwrap();
        for number in 1..MAX_QUEUES {
            store
                .db
                .execute(
                    "INSERT INTO queues(id,write_hash,read_hash) VALUES(?,?,?)",
                    params![format!("{number:032x}"), vec![0u8; 32], vec![1u8; 32]],
                )
                .unwrap();
        }
        drop(store);
        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for redeem in [false, true] {
            let path = path.clone();
            let barrier = barrier.clone();
            let ticket = ticket.clone();
            tasks.push(std::thread::spawn(move || {
                let mut store = Store::open(&path).unwrap();
                barrier.wait();
                let result = if redeem {
                    store.redeem(&ticket, proposal(1000), 101).map(|_| ())
                } else {
                    store.create().map(|_| ())
                };
                result.map_or_else(|error| error.0, |_| StatusCode::CREATED)
            }));
        }
        let mut results: Vec<_> = tasks.into_iter().map(|task| task.join().unwrap()).collect();
        results.sort();
        assert_eq!(
            results,
            vec![StatusCode::CREATED, StatusCode::TOO_MANY_REQUESTS]
        );
        let store = Store::open(&path).unwrap();
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM queues", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, MAX_QUEUES);
    }
}

#[cfg(test)]
mod invitation_ticket_tests {
    use super::*;
    use std::sync::Barrier;

    fn proposal(number: usize, expires_at: i64) -> InvitationQueueProposal {
        InvitationQueueProposal {
            queue: QueueProposal {
                id: format!("{number:032x}"),
                read_token: "a".repeat(64),
                write_token: "b".repeat(64),
            },
            recipient_ticket: format!("{number:064x}"),
            expires_at,
        }
    }
    fn issue(store: &mut Store) -> String {
        store
            .issue_scoped_ticket_with_clock(100, true, || 100)
            .unwrap()
    }
    fn invite(
        store: &mut Store,
        ticket: &str,
        proposal: InvitationQueueProposal,
        timestamp: i64,
    ) -> Result<RedeemedQueue> {
        store.invite_with_clock(ticket, proposal, || timestamp)
    }
    fn counts(store: &Store) -> (i64, i64) {
        let queues = store
            .db
            .query_row("SELECT count(*) FROM queues", [], |row| row.get(0))
            .unwrap();
        let tickets = store
            .db
            .query_row("SELECT count(*) FROM queue_tickets", [], |row| row.get(0))
            .unwrap();
        (queues, tickets)
    }
    fn consumed(store: &Store, ticket: &str) -> Option<Vec<u8>> {
        store
            .db
            .query_row(
                "SELECT proposal_digest FROM queue_tickets WHERE ticket_hash=?",
                [hash(ticket.as_bytes())],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn legacy_migration_does_not_expand_existing_ticket_authority() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let ticket = "c".repeat(64);
        let db = Connection::open(&path).unwrap();
        db.execute_batch("CREATE TABLE queue_tickets(ticket_hash BLOB PRIMARY KEY, expires INTEGER NOT NULL, proposal_digest BLOB);").unwrap();
        db.execute(
            "INSERT INTO queue_tickets(ticket_hash,expires) VALUES(?,200)",
            [hash(ticket.as_bytes())],
        )
        .unwrap();
        drop(db);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            invite(&mut store, &ticket, proposal(1, 190), 101)
                .err()
                .unwrap()
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(counts(&store), (0, 1));
        store.redeem(&ticket, proposal(1, 190).queue, 101).unwrap();
        assert_eq!(counts(&store), (1, 1));
        drop(store);
        // Reopening leaves consumed legacy records and their scope intact.
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        store.redeem(&ticket, proposal(1, 190).queue, 102).unwrap();
        assert_eq!(
            invite(&mut store, &ticket, proposal(1, 190), 102)
                .err()
                .unwrap()
                .0,
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn invitation_delegates_one_queue_and_never_recursive_authority() {
        let mut store = Store::open(":memory:").unwrap();
        let ordinary = store.issue_ticket_at(100, 100).unwrap();
        assert_eq!(
            invite(&mut store, &ordinary, proposal(1, 190), 101)
                .err()
                .unwrap()
                .0,
            StatusCode::FORBIDDEN
        );
        let parent = issue(&mut store);
        let invitation = proposal(1, 190);
        invite(&mut store, &parent, invitation.clone(), 101).unwrap();
        assert_eq!(
            invite(
                &mut store,
                &invitation.recipient_ticket,
                proposal(2, 180),
                102
            )
            .err()
            .unwrap()
            .0,
            StatusCode::FORBIDDEN
        );
        store
            .redeem(&invitation.recipient_ticket, proposal(2, 190).queue, 102)
            .unwrap();
        assert_eq!(
            store
                .redeem(&invitation.recipient_ticket, proposal(3, 190).queue, 103)
                .err()
                .unwrap()
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(counts(&store), (2, 3));
    }

    #[test]
    fn exact_retry_survives_reopen_and_preserves_redeemed_recipient_ticket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite");
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        let parent = issue(&mut store);
        let invitation = proposal(1, 190);
        invite(&mut store, &parent, invitation.clone(), 101).unwrap();
        store
            .redeem(&invitation.recipient_ticket, proposal(2, 190).queue, 102)
            .unwrap();
        let redeemed_digest = consumed(&store, &invitation.recipient_ticket).unwrap();
        drop(store);
        let mut store = Store::open(path.to_str().unwrap()).unwrap();
        assert_eq!(
            invite(&mut store, &parent, invitation.clone(), 103)
                .unwrap()
                .id,
            invitation.queue.id
        );
        assert_eq!(
            consumed(&store, &invitation.recipient_ticket).unwrap(),
            redeemed_digest
        );
        assert_eq!(counts(&store), (2, 2));
        let mut changed = Vec::new();
        let mut other = invitation.clone();
        other.queue.id = format!("{:032x}", 3);
        changed.push(other);
        let mut other = invitation.clone();
        other.queue.read_token = "c".repeat(64);
        changed.push(other);
        let mut other = invitation.clone();
        other.queue.write_token = "d".repeat(64);
        changed.push(other);
        let mut other = invitation.clone();
        other.recipient_ticket = "e".repeat(64);
        changed.push(other);
        let mut other = invitation.clone();
        other.expires_at -= 1;
        changed.push(other);
        for changed in changed {
            assert_eq!(
                invite(&mut store, &parent, changed, 104).err().unwrap().0,
                StatusCode::CONFLICT
            );
        }
        // The same parent cannot also redeem a standalone queue.
        assert_eq!(
            store
                .redeem(&parent, invitation.queue, 104)
                .err()
                .unwrap()
                .0,
            StatusCode::CONFLICT
        );
    }

    #[test]
    fn deadline_is_bounded_by_parent_and_retries_never_extend_it() {
        let mut store = Store::open(":memory:").unwrap();
        let parent = issue(&mut store);
        for expiry in [i64::MIN, 0, 101, 201, i64::MAX] {
            assert_eq!(
                invite(&mut store, &parent, proposal(1, expiry), 101)
                    .err()
                    .unwrap()
                    .0,
                StatusCode::BAD_REQUEST
            );
            assert_eq!(counts(&store), (0, 1));
            assert!(consumed(&store, &parent).is_none());
        }
        let invitation = proposal(1, 190);
        invite(&mut store, &parent, invitation.clone(), 101).unwrap();
        invite(&mut store, &parent, invitation.clone(), 189).unwrap();
        assert_eq!(
            invite(&mut store, &parent, invitation.clone(), 190)
                .err()
                .unwrap()
                .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            store
                .redeem(&invitation.recipient_ticket, proposal(2, 190).queue, 190)
                .err()
                .unwrap()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            invite(&mut store, &parent, invitation, 200)
                .err()
                .unwrap()
                .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(counts(&store), (1, 2));
    }

    #[test]
    fn recipient_collision_and_queue_collision_do_not_consume_parent() {
        let mut store = Store::open(":memory:").unwrap();
        let parent = issue(&mut store);
        let other = store.issue_ticket_at(100, 100).unwrap();
        let mut invitation = proposal(1, 190);
        invitation.recipient_ticket = other;
        assert_eq!(
            invite(&mut store, &parent, invitation, 101)
                .err()
                .unwrap()
                .0,
            StatusCode::CONFLICT
        );
        for collision in [&parent, &"a".repeat(64), &"b".repeat(64)] {
            let mut invitation = proposal(1, 190);
            invitation.recipient_ticket = collision.clone();
            assert_eq!(
                invite(&mut store, &parent, invitation, 101)
                    .err()
                    .unwrap()
                    .0,
                StatusCode::BAD_REQUEST
            );
        }
        let conflicting = store.issue_ticket_at(100, 100).unwrap();
        let mut existing = proposal(1, 190).queue;
        existing.read_token = "d".repeat(64);
        store.redeem(&conflicting, existing, 101).unwrap();
        assert_eq!(
            invite(&mut store, &parent, proposal(1, 190), 101)
                .err()
                .unwrap()
                .0,
            StatusCode::CONFLICT
        );
        assert!(consumed(&store, &parent).is_none());
        invite(&mut store, &parent, proposal(2, 190), 102).unwrap();
        assert_eq!(counts(&store), (2, 4));
    }

    #[test]
    fn both_quotas_and_sql_failures_roll_back_whole_invitation() {
        for failure in ["tickets", "queues", "recipient_insert", "parent_update"] {
            let mut store = Store::open(":memory:").unwrap();
            let parent = issue(&mut store);
            if failure == "tickets" {
                for number in 1..MAX_TICKETS {
                    store
                        .db
                        .execute(
                            "INSERT INTO queue_tickets(ticket_hash,expires) VALUES(?,200)",
                            [hash(&number.to_le_bytes())],
                        )
                        .unwrap();
                }
            } else if failure == "queues" {
                for number in 1..=MAX_QUEUES {
                    store
                        .db
                        .execute(
                            "INSERT INTO queues(id,write_hash,read_hash) VALUES(?,?,?)",
                            params![format!("{number:032x}"), vec![0u8; 32], vec![1u8; 32]],
                        )
                        .unwrap();
                }
            } else if failure == "recipient_insert" {
                store.db.execute_batch("CREATE TRIGGER reject_child BEFORE INSERT ON queue_tickets BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
            } else {
                store.db.execute_batch("CREATE TRIGGER reject_parent BEFORE UPDATE ON queue_tickets BEGIN SELECT RAISE(ABORT,'forced failure'); END;").unwrap();
            }
            let before = counts(&store);
            let expected = if failure == "tickets" || failure == "queues" {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            assert_eq!(
                invite(&mut store, &parent, proposal(1000, 190), 101)
                    .err()
                    .unwrap()
                    .0,
                expected,
                "{failure}"
            );
            assert_eq!(counts(&store), before, "{failure}");
            assert!(consumed(&store, &parent).is_none(), "{failure}");
            match failure {
                "tickets" => {
                    store
                        .db
                        .execute(
                            "DELETE FROM queue_tickets WHERE ticket_hash=?",
                            [hash(&1_i64.to_le_bytes())],
                        )
                        .unwrap();
                }
                "queues" => {
                    store
                        .db
                        .execute("DELETE FROM queues WHERE id=?", [format!("{:032x}", 1)])
                        .unwrap();
                }
                "recipient_insert" => {
                    store.db.execute_batch("DROP TRIGGER reject_child").unwrap();
                }
                _ => {
                    store
                        .db
                        .execute_batch("DROP TRIGGER reject_parent")
                        .unwrap();
                }
            }
            invite(&mut store, &parent, proposal(1000, 190), 102).unwrap();
        }
    }

    #[test]
    fn exact_retry_never_resurrects_deleted_queue_or_recipient_ticket() {
        for delete_queue in [false, true] {
            let mut store = Store::open(":memory:").unwrap();
            let parent = issue(&mut store);
            let invitation = proposal(1, 190);
            invite(&mut store, &parent, invitation.clone(), 101).unwrap();
            if delete_queue {
                store
                    .remove(&invitation.queue.id, &invitation.queue.read_token)
                    .unwrap();
            } else {
                store
                    .db
                    .execute(
                        "DELETE FROM queue_tickets WHERE ticket_hash=?",
                        [hash(invitation.recipient_ticket.as_bytes())],
                    )
                    .unwrap();
            }
            let before = counts(&store);
            assert_eq!(
                invite(&mut store, &parent, invitation, 102)
                    .err()
                    .unwrap()
                    .0,
                StatusCode::NOT_FOUND
            );
            assert_eq!(counts(&store), before);
        }
    }

    fn race(same_body: bool) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("relay.sqlite")
            .to_str()
            .unwrap()
            .to_owned();
        let parent = issue(&mut Store::open(&path).unwrap());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();
        for number in 1..=8 {
            let path = path.clone();
            let parent = parent.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let mut store = Store::open(&path).unwrap();
                barrier.wait();
                invite(
                    &mut store,
                    &parent,
                    proposal(if same_body { 1 } else { number }, 190),
                    101,
                )
                .map_or_else(|error| error.0, |_| StatusCode::CREATED)
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            if same_body { 8 } else { 1 }
        );
        assert!(results
            .iter()
            .all(|status| *status == StatusCode::CREATED || *status == StatusCode::CONFLICT));
        assert_eq!(counts(&Store::open(&path).unwrap()), (1, 2));
    }
    #[test]
    fn concurrent_different_invitations_have_one_winner() {
        race(false);
    }
    #[test]
    fn concurrent_exact_retries_create_one_queue_and_one_recipient_ticket() {
        race(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    fn message(n: usize, size: usize) -> Message {
        Message {
            id: format!("{n:032x}"),
            payload: STANDARD.encode(vec![42; size]),
        }
    }
    #[test]
    fn capabilities_are_separate_and_unknown_queues_hidden() {
        let mut s = Store::open(":memory:").unwrap();
        let q = s.create().unwrap();
        assert_eq!(
            s.send(&q.id, &q.read_token, message(1, 10), 0)
                .unwrap_err()
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            s.receive(&q.id, &q.write_token, 0).err().unwrap().0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            s.receive("unknown", &q.read_token, 0).err().unwrap().0,
            StatusCode::NOT_FOUND
        );
        assert!(s.remove(&q.id, &q.write_token).is_err());
    }
    #[test]
    fn duplicates_ack_and_expiry() {
        let mut s = Store::open(":memory:").unwrap();
        let q = s.create().unwrap();
        s.send(&q.id, &q.write_token, message(1, 10), 100).unwrap();
        s.send(&q.id, &q.write_token, message(1, 10), 101).unwrap();
        assert_eq!(
            s.send(&q.id, &q.write_token, message(1, 11), 102)
                .unwrap_err()
                .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            s.receive(&q.id, &q.read_token, 103).unwrap().messages.len(),
            1
        );
        s.ack(&q.id, &q.read_token, &message(1, 10).id, 104)
            .unwrap();
        s.send(&q.id, &q.write_token, message(1, 10), 105).unwrap();
        assert!(s
            .receive(&q.id, &q.read_token, 105)
            .unwrap()
            .messages
            .is_empty());
        s.send(&q.id, &q.write_token, message(2, 10), 106).unwrap();
        assert!(s
            .receive(&q.id, &q.read_token, 106 + TTL)
            .unwrap()
            .messages
            .is_empty());
    }
    #[test]
    fn persists_and_deletes_queue() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sqlite");
        let path = path.to_str().unwrap();
        let q = {
            let mut s = Store::open(path).unwrap();
            let q = s.create().unwrap();
            s.send(&q.id, &q.write_token, message(1, 10), 10).unwrap();
            q
        };
        let s = Store::open(path).unwrap();
        assert_eq!(
            s.receive(&q.id, &q.read_token, 11).unwrap().messages.len(),
            1
        );
        s.remove(&q.id, &q.read_token).unwrap();
        assert!(s.receive(&q.id, &q.read_token, 11).is_err());
        let count: i64 =
            s.db.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn payload_and_queue_byte_limits() {
        let mut s = Store::open(":memory:").unwrap();
        let q = s.create().unwrap();
        assert_eq!(
            s.send(&q.id, &q.write_token, message(0, MAX_PAYLOAD + 1), 0)
                .unwrap_err()
                .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        for n in 0..64 {
            s.send(&q.id, &q.write_token, message(n, MAX_PAYLOAD), 0)
                .unwrap();
        }
        assert_eq!(
            s.send(&q.id, &q.write_token, message(64, 1), 0)
                .unwrap_err()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        s.ack(&q.id, &q.read_token, &message(0, 1).id, 1).unwrap();
        s.send(&q.id, &q.write_token, message(64, 1), 1).unwrap();
    }
    #[test]
    fn record_and_queue_count_limits() {
        let mut s = Store::open(":memory:").unwrap();
        let q = s.create().unwrap();
        for n in 0..MAX_RECORDS as usize {
            s.send(&q.id, &q.write_token, message(n, 1), 0).unwrap();
        }
        assert_eq!(
            s.send(&q.id, &q.write_token, message(1024, 1), 0)
                .unwrap_err()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        for _ in 1..MAX_QUEUES {
            s.create().unwrap();
        }
        assert_eq!(s.create().err().unwrap().0, StatusCode::TOO_MANY_REQUESTS);
    }
    #[tokio::test]
    async fn http_delivery_and_ack_with_cross_queue_denial() {
        let s = Store::open(":memory:").unwrap();
        let q = s.create().unwrap();
        let other = s.create().unwrap();
        let app = router(AppState::new(s, &"a".repeat(64)));
        let uri = format!("/v1/queues/{}/messages", q.id);
        let message = message(1, 10);
        let body = format!(
            r#"{{"id":"{}","payload":"{}"}}"#,
            message.id, message.payload
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("authorization", format!("Bearer {}", other.write_token))
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&uri)
                    .header("authorization", format!("Bearer {}", q.write_token))
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("authorization", format!("Bearer {}", q.read_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let json = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(json.contains(&message.payload));
        let ack_uri = format!("{}/{}", uri, message.id);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&ack_uri)
                    .header("authorization", format!("Bearer {}", q.read_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(&uri)
                    .header("authorization", format!("Bearer {}", q.read_token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        assert_eq!(&bytes[..], br#"{"messages":[]}"#);
    }
    #[test]
    fn global_quota_and_malformed_envelopes() {
        let mut s = Store::open(":memory:").unwrap();
        let q = s.create().unwrap();
        let mut bad = message(1, 1);
        bad.id = "invalid".into();
        assert_eq!(
            s.send(&q.id, &q.write_token, bad, 0).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        let mut bad = message(1, 1);
        bad.payload = "invalid!".into();
        assert_eq!(
            s.send(&q.id, &q.write_token, bad, 0).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        for _ in 0..8 {
            let fill = s.create().unwrap();
            for n in 0..64 {
                s.send(&fill.id, &fill.write_token, message(n, MAX_PAYLOAD), 0)
                    .unwrap();
            }
        }
        assert_eq!(
            s.send(&q.id, &q.write_token, message(1, 1), 0)
                .unwrap_err()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        s.send(&q.id, &q.write_token, message(1, 1), TTL).unwrap();
    }
    #[tokio::test]
    async fn http_authorization_and_body_limit() {
        let app = router(AppState::new(
            Store::open(":memory:").unwrap(),
            &"a".repeat(64),
        ));
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/queues")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/queues")
                    .header("authorization", format!("Bearer {}", "a".repeat(64)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/queues/unknown/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(" ".repeat(100 * 1024)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}

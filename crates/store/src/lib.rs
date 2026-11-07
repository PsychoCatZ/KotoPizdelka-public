//! Durable, encrypted contact state and message records. Transport must call
//! enqueue before sending, accept before ACK, and retry exact saved envelopes.
//! The caller supplies a stable random storage key from outside the database.
//! This protects crash recovery, not malicious rollback or a compromised device.

mod accounts;
pub mod backup;
pub use accounts::{AccountJob, AccountState};
mod delivery;
mod names;
pub use delivery::{DeliveryStatus, DELIVERY_PREFIX};
pub use messenger_core::valid_nickname;
pub use names::{ContactNames, ProfileName};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use messenger_core::{Contact, Envelope, PublicBundle, StorageKey};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

const DOMAIN: &str = "private-messenger.client-store.v1";
const KEY_CHECK: &[u8] = b"private-messenger client storage key check";
const MAX_CONTACTS: i64 = 128;
const MAX_RETIRED: i64 = 4096;
const MAX_HISTORY: i64 = 10_000;
const MAX_PENDING: i64 = 256;
const MAX_TOTAL_BYTES: i64 = 64 * 1024 * 1024;
const MAX_BLOB: usize = 2 * 1024 * 1024;
const MAX_ENVELOPE_PAYLOAD: usize = (64 * 1024usize).div_ceil(3) * 4;
const PAGE_SIZE: usize = 100;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("client database operation failed")]
    Database,
    #[error("restored conversation is archived; create a fresh invitation")]
    Archived,
    #[error("invalid client store or incorrect storage key")]
    InvalidStore,
    #[error("invalid or corrupted stored record")]
    InvalidRecord,
    #[error("contact or message was not found")]
    NotFound,
    #[error("invalid local identifier")]
    InvalidId,
    #[error("message ID was reused with a different envelope")]
    Conflict,
    #[error("client store quota exceeded")]
    QuotaExceeded,
    #[error("contact route has already been set")]
    RouteAlreadySet,
    #[error("invalid queue endpoint")]
    InvalidRoute,
    #[error("invalid contact setup data")]
    InvalidSetup,
    #[error("contact setup has already been imported")]
    SetupReplay,
    #[error("contact setup no longer matches the expected state")]
    SetupConflict,
    #[error("contact setup is not yet complete")]
    SetupPending,
    #[error("cryptographic operation failed: {0}")]
    Crypto(#[from] messenger_core::Error),
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptStatus {
    New,
    Duplicate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Incoming,
    Outgoing,
}
pub struct HistoryEntry {
    pub sequence: i64,
    pub direction: Direction,
    pub id: String,
    pub text: String,
    pub unread: bool,
    pub delivery: Option<DeliveryStatus>,
}

/// Queue-specific bearer capability. Intentionally has no Debug implementation.
/// URL parsing and TLS policy are enforced by the network client.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueEndpoint {
    pub relay_url: String,
    pub queue_id: String,
    pub token: String,
}

/// Independent send and receive queues for one contact.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactRoute {
    pub send: QueueEndpoint,
    pub receive: QueueEndpoint,
}

/// Encrypted invitation state and permanent replay marker. No Debug output.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SetupData {
    pub replay_tag: Option<String>,
    pub payload: Vec<u8>,
    pub ready: bool,
}

// Only replay identifiers survive deletion; no messages, private keys or tickets.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetiredContact {
    replay_tag: Option<String>,
    queues: Vec<(String, String)>,
}

/// One atomic compare-and-set transition from pending setup to a bound peer.
pub struct SetupCompletion {
    pub expected: SetupData,
    pub replacement: SetupData,
    pub peer: PublicBundle,
    pub trusted_fingerprint: String,
    pub initiate: bool,
    pub route: ContactRoute,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRoute {
    send: QueueEndpoint,
    receive: QueueEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    setup: Option<SetupData>,
}
impl StoredRoute {
    fn new(route: &ContactRoute, setup: Option<SetupData>) -> Self {
        Self {
            send: route.send.clone(),
            receive: route.receive.clone(),
            setup,
        }
    }
    fn route(&self) -> ContactRoute {
        ContactRoute {
            send: self.send.clone(),
            receive: self.receive.clone(),
        }
    }
}

#[derive(Serialize)]
struct MessageRef<'a> {
    envelope: &'a Envelope,
    text: &'a str,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageRecord {
    envelope: Envelope,
    text: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    delivered: bool,
}

fn random_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
fn valid_id(id: &str) -> bool {
    valid_hex(id, 32)
}
fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_route(route: &ContactRoute) -> bool {
    [&route.send, &route.receive].into_iter().all(|endpoint| {
        !endpoint.relay_url.is_empty()
            && endpoint.relay_url.len() <= 2048
            && valid_id(&endpoint.queue_id)
            && valid_hex(&endpoint.token, 64)
    })
}
fn valid_setup(setup: &SetupData) -> bool {
    setup.payload.len() <= 8192
        && setup
            .replay_tag
            .as_deref()
            .is_none_or(|tag| valid_hex(tag, 64))
}
fn same_endpoint(left: &QueueEndpoint, right: &QueueEndpoint) -> bool {
    left.relay_url == right.relay_url
        && left.queue_id == right.queue_id
        && left.token == right.token
}
fn ids(contact: &str, message: Option<&str>) -> Result<()> {
    if !valid_id(contact) || message.is_some_and(|id| !valid_id(id)) {
        return Err(Error::InvalidId);
    }
    Ok(())
}
fn aad(db_id: &str, purpose: &str, contact: &str, message: &str) -> Vec<u8> {
    // Identifiers are fixed-size hex; purpose is always an internal constant.
    format!("{DOMAIN}|{db_id}|{purpose}|{contact}|{message}").into_bytes()
}
fn seal(
    key: &StorageKey,
    db_id: &str,
    purpose: &str,
    contact: &str,
    message: &str,
    plain: &[u8],
) -> Result<Vec<u8>> {
    if plain.len() + 41 > MAX_BLOB {
        return Err(Error::QuotaExceeded);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::InvalidRecord)?;
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad(db_id, purpose, contact, message),
            },
        )
        .map_err(|_| Error::InvalidRecord)?;
    let mut bytes = vec![1];
    bytes.extend(nonce);
    bytes.extend(ciphertext);
    Ok(bytes)
}
fn unseal(
    key: &StorageKey,
    db_id: &str,
    purpose: &str,
    contact: &str,
    message: &str,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < 41 || blob.len() > MAX_BLOB || blob[0] != 1 {
        return Err(Error::InvalidRecord);
    }
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| Error::InvalidRecord)?;
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&blob[1..25]),
            Payload {
                msg: &blob[25..],
                aad: &aad(db_id, purpose, contact, message),
            },
        )
        .map_err(|_| Error::InvalidRecord)?;
    Ok(Zeroizing::new(plain))
}
fn decode_record(
    key: &StorageKey,
    db_id: &str,
    direction: &str,
    contact: &str,
    message: &str,
    blob: &[u8],
) -> Result<MessageRecord> {
    let plain = unseal(key, db_id, direction, contact, message, blob)?;
    let record: MessageRecord = serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
    if record.envelope.id != message {
        return Err(Error::InvalidRecord);
    }
    Ok(record)
}
fn decode_route(key: &StorageKey, db_id: &str, id: &str, blob: &[u8]) -> Result<StoredRoute> {
    ids(id, None).map_err(|_| Error::InvalidRecord)?;
    let plain = unseal(key, db_id, "route", id, "", blob)?;
    let route: StoredRoute = serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
    if !valid_route(&route.route()) || route.setup.as_ref().is_some_and(|s| !valid_setup(s)) {
        return Err(Error::InvalidRecord);
    }
    Ok(route)
}
fn load_route(db: &Connection, key: &StorageKey, db_id: &str, id: &str) -> Result<StoredRoute> {
    let blob: Option<Vec<u8>> = db
        .query_row("SELECT record FROM routes WHERE contact=?", [id], |r| {
            r.get(0)
        })
        .optional()?;
    decode_route(key, db_id, id, &blob.ok_or(Error::NotFound)?)
}
fn load_setups(db: &Connection, key: &StorageKey, db_id: &str) -> Result<Vec<(String, SetupData)>> {
    // Inspect the database-controlled sizes before fetching opaque blobs. The
    // LIMIT also bounds an inconsistent store with more rows than its quota.
    let mut query =
        db.prepare("SELECT contact,length(record) FROM routes ORDER BY rowid LIMIT ?")?;
    let rows = query.query_map([MAX_CONTACTS + 1], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (id, size) = row?;
        if records.len() >= MAX_CONTACTS as usize || !(41..=MAX_BLOB as i64).contains(&size) {
            return Err(Error::InvalidRecord);
        }
        records.push(id);
    }
    records
        .into_iter()
        .filter_map(|id| match load_route(db, key, db_id, &id) {
            Ok(route) => route.setup.map(|setup| Ok((id, setup))),
            Err(error) => Some(Err(error)),
        })
        .collect()
}
fn load_retired(db: &Connection, key: &StorageKey, db_id: &str) -> Result<Vec<RetiredContact>> {
    let mut query = db.prepare("SELECT id,length(record) FROM retired_contacts LIMIT ?")?;
    let ids = query
        .query_map([MAX_RETIRED + 1], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if ids.len() > MAX_RETIRED as usize {
        return Err(Error::InvalidRecord);
    }
    ids.into_iter()
        .map(|(id, size)| {
            if !valid_id(&id) || !(41..=8192).contains(&size) {
                return Err(Error::InvalidRecord);
            }
            let blob: Vec<u8> = db.query_row(
                "SELECT record FROM retired_contacts WHERE id=?",
                [&id],
                |r| r.get(0),
            )?;
            let plain = unseal(key, db_id, "retired", &id, "", &blob)?;
            let record: RetiredContact =
                serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
            if record
                .replay_tag
                .as_ref()
                .is_some_and(|tag| !valid_hex(tag, 64))
                || record.queues.len() > 2
                || record
                    .queues
                    .iter()
                    .any(|(url, id)| url.is_empty() || url.len() > 2048 || !valid_id(id))
            {
                return Err(Error::InvalidRecord);
            }
            Ok(record)
        })
        .collect()
}
fn load_contact(tx: &Transaction<'_>, key: &StorageKey, db_id: &str, id: &str) -> Result<Contact> {
    if tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM archived_contacts WHERE id=?)",
        [id],
        |r| r.get::<_, bool>(0),
    )? {
        return Err(Error::Archived);
    }
    let blob: Option<Vec<u8>> = tx
        .query_row("SELECT state FROM contacts WHERE id=?", [id], |r| r.get(0))
        .optional()?;
    let blob = blob.ok_or(Error::NotFound)?;
    let snapshot = unseal(key, db_id, "contact", id, "", &blob)?;
    Contact::restore(&snapshot, key).map_err(|_| Error::InvalidRecord)
}
fn save_contact(
    tx: &Transaction<'_>,
    key: &StorageKey,
    db_id: &str,
    id: &str,
    contact: &Contact,
) -> Result<()> {
    let snapshot = contact.snapshot(key)?;
    let blob = seal(key, db_id, "contact", id, "", &snapshot)?;
    if tx.execute("UPDATE contacts SET state=? WHERE id=?", params![blob, id])? != 1 {
        return Err(Error::NotFound);
    }
    Ok(())
}
fn check_quota(tx: &Transaction<'_>, contact: &str, direction: &str) -> Result<()> {
    let count: i64 = tx.query_row(
        "SELECT count(*) FROM messages WHERE contact=?",
        [contact],
        |r| r.get(0),
    )?;
    let pending: i64 = tx.query_row(
        "SELECT count(*) FROM messages WHERE contact=? AND direction=? AND pending=1",
        params![contact, direction],
        |r| r.get(0),
    )?;
    if count >= MAX_HISTORY || pending >= MAX_PENDING {
        return Err(Error::QuotaExceeded);
    }
    Ok(())
}
fn check_total_bytes(tx: &Transaction<'_>) -> Result<()> {
    let bytes: i64 = tx.query_row("SELECT (SELECT coalesce(sum(length(record)),0) FROM messages) + (SELECT coalesce(sum(length(state)),0) FROM contacts) + (SELECT coalesce(sum(length(record)),0) FROM routes) + (SELECT coalesce(sum(length(record)),0) FROM retired_contacts) + (SELECT coalesce(sum(length(record)),0) FROM profile_name) + (SELECT coalesce(sum(length(record)),0) FROM contact_names) + (SELECT coalesce(sum(length(record)),0) FROM account_state) + (SELECT coalesce(sum(length(record)),0) FROM account_jobs)", [], |r| r.get(0))?;
    if bytes > MAX_TOTAL_BYTES {
        return Err(Error::QuotaExceeded);
    }
    Ok(())
}

pub struct ClientStore {
    db: Connection,
    key: StorageKey,
    db_id: String,
}
impl ClientStore {
    pub fn open(path: impl AsRef<Path>, key: StorageKey) -> Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='store_meta')",
            [],
            |r| r.get(0),
        )?;
        let db_id = if !exists {
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )?;
            if count != 0 {
                return Err(Error::InvalidStore);
            }
            tx.execute_batch("CREATE TABLE store_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1), version INTEGER NOT NULL, db_id TEXT NOT NULL, key_check BLOB NOT NULL);
                CREATE TABLE contacts(id TEXT PRIMARY KEY, state BLOB NOT NULL);
                CREATE TABLE messages(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    contact TEXT NOT NULL REFERENCES contacts(id),
                    direction TEXT NOT NULL CHECK(direction IN ('in','out')),
                    id TEXT NOT NULL, record BLOB NOT NULL,
                    pending INTEGER NOT NULL CHECK(pending IN (0,1)),
                    unread INTEGER NOT NULL DEFAULT 0 CHECK(unread IN (0,1) AND (unread=0 OR direction='in')),
                    UNIQUE(contact,direction,id));
                CREATE INDEX pending_messages ON messages(contact,direction,pending,seq);
                CREATE TABLE routes(contact TEXT PRIMARY KEY REFERENCES contacts(id), record BLOB NOT NULL);
                CREATE TABLE retired_contacts(id TEXT PRIMARY KEY, record BLOB NOT NULL);
                CREATE INDEX unread_messages ON messages(contact,direction,unread,seq);")?;
            let db_id = random_id();
            let check = seal(&key, &db_id, "key-check", "", "", KEY_CHECK)?;
            tx.execute(
                "INSERT INTO store_meta VALUES(1,5,?,?)",
                params![db_id, check],
            )?;
            db_id
        } else {
            let meta: Option<(i64, String, Vec<u8>)> = tx
                .query_row(
                    "SELECT version,db_id,key_check FROM store_meta WHERE singleton=1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let (version, db_id, check) = meta.ok_or(Error::InvalidStore)?;
            if !matches!(version, 1..=8) || !valid_id(&db_id) {
                return Err(Error::InvalidStore);
            }
            let plain = unseal(&key, &db_id, "key-check", "", "", &check)
                .map_err(|_| Error::InvalidStore)?;
            if plain.as_slice() != KEY_CHECK {
                return Err(Error::InvalidStore);
            }
            tx.prepare("SELECT id,state FROM contacts LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
            tx.prepare("SELECT seq,contact,direction,id,record,pending FROM messages LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
            if version == 1 {
                // The key and original schema have been verified above. Both the
                // routes table and version marker are committed atomically.
                tx.execute_batch("CREATE TABLE routes(contact TEXT PRIMARY KEY REFERENCES contacts(id), record BLOB NOT NULL);")?;
                if tx.execute(
                    "UPDATE store_meta SET version=2 WHERE singleton=1 AND version=1",
                    [],
                )? != 1
                {
                    return Err(Error::InvalidStore);
                }
            }
            // A v2 store with missing routes is corrupt; do not recreate it.
            tx.prepare("SELECT contact,record FROM routes LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
            if version < 3 {
                tx.execute_batch("CREATE TABLE retired_contacts(id TEXT PRIMARY KEY, record BLOB NOT NULL); UPDATE store_meta SET version=3 WHERE singleton=1;")?;
            }
            tx.prepare("SELECT id,record FROM retired_contacts LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
            if version < 4 {
                // Existing history is read at upgrade; only subsequently accepted
                // incoming messages become unread. This migration is key-checked
                // and committed atomically with the version marker.
                tx.execute_batch("ALTER TABLE messages ADD COLUMN unread INTEGER NOT NULL DEFAULT 0 CHECK(unread IN (0,1) AND (unread=0 OR direction='in')); CREATE INDEX unread_messages ON messages(contact,direction,unread,seq); UPDATE store_meta SET version=4 WHERE singleton=1;")?;
            }
            tx.prepare("SELECT unread FROM messages LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
            db_id
        };
        // Names and profile-control records are sealed with the existing key.
        // No changes occur until key verification and all older migrations pass.
        if !exists
            || tx.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))? < 5
        {
            tx.execute_batch("ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'text' CHECK(kind IN ('text','profile')); CREATE TABLE profile_name(singleton INTEGER PRIMARY KEY CHECK(singleton=1), record BLOB NOT NULL); CREATE TABLE contact_names(contact TEXT PRIMARY KEY REFERENCES contacts(id), record BLOB NOT NULL); UPDATE store_meta SET version=5 WHERE singleton=1;")?;
        }
        tx.prepare("SELECT kind FROM messages LIMIT 0")
            .map_err(|_| Error::InvalidStore)?;
        tx.prepare("SELECT record FROM profile_name LIMIT 0")
            .map_err(|_| Error::InvalidStore)?;
        tx.prepare("SELECT contact,record FROM contact_names LIMIT 0")
            .map_err(|_| Error::InvalidStore)?;
        if tx.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))? < 6 {
            // Preserve sequence identities, encrypted records and AUTOINCREMENT's
            // high-water mark, including previously deleted final messages.
            let high: i64 = tx.query_row(
                "SELECT coalesce((SELECT seq FROM sqlite_sequence WHERE name='messages'),0)",
                [],
                |r| r.get(0),
            )?;
            tx.execute_batch("CREATE TABLE messages_v6(seq INTEGER PRIMARY KEY AUTOINCREMENT,
                contact TEXT NOT NULL REFERENCES contacts(id), direction TEXT NOT NULL CHECK(direction IN ('in','out')),
                id TEXT NOT NULL, record BLOB NOT NULL, pending INTEGER NOT NULL CHECK(pending IN (0,1)),
                unread INTEGER NOT NULL DEFAULT 0 CHECK(unread IN (0,1) AND (unread=0 OR direction='in')),
                kind TEXT NOT NULL DEFAULT 'text' CHECK(kind IN ('text','profile','delivery')), UNIQUE(contact,direction,id));
                INSERT INTO messages_v6 SELECT seq,contact,direction,id,record,pending,unread,kind FROM messages;
                DROP TABLE messages; ALTER TABLE messages_v6 RENAME TO messages;
                CREATE INDEX pending_messages ON messages(contact,direction,pending,seq);
                CREATE INDEX unread_messages ON messages(contact,direction,unread,seq);
                UPDATE store_meta SET version=6 WHERE singleton=1;")?;
            tx.execute(
                "UPDATE sqlite_sequence SET seq=max(seq,?) WHERE name='messages'",
                [high],
            )?;
        }
        if tx.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))? < 7 {
            tx.execute_batch("CREATE TABLE IF NOT EXISTS account_state(singleton INTEGER PRIMARY KEY CHECK(singleton=1), record BLOB NOT NULL); CREATE TABLE IF NOT EXISTS account_jobs(id TEXT PRIMARY KEY, record BLOB NOT NULL); UPDATE store_meta SET version=7 WHERE singleton=1;")?;
        } else {
            tx.prepare("SELECT singleton,record FROM account_state LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
            tx.prepare("SELECT id,record FROM account_jobs LIMIT 0")
                .map_err(|_| Error::InvalidStore)?;
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS archived_contacts(id TEXT PRIMARY KEY REFERENCES contacts(id) ON DELETE CASCADE); UPDATE store_meta SET version=8 WHERE singleton=1;")?;
        tx.commit()?;
        // WAL changes the database persistently; only enable it after successful
        // key verification. Wrong-key opens must not change an existing mode.
        db.execute_batch("PRAGMA journal_mode=WAL;")?;
        Ok(Self { db, key, db_id })
    }
    fn retired_records(&self) -> Result<Vec<RetiredContact>> {
        load_retired(&self.db, &self.key, &self.db_id)
    }
    pub fn has_setup_replay(&self, tag: &str) -> Result<bool> {
        if !valid_hex(tag, 64) {
            return Err(Error::InvalidSetup);
        }
        Ok(load_setups(&self.db, &self.key, &self.db_id)?
            .iter()
            .any(|(_, setup)| setup.replay_tag.as_deref() == Some(tag))
            || self
                .retired_records()?
                .iter()
                .any(|record| record.replay_tag.as_deref() == Some(tag)))
    }
    pub fn retired_queues(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .retired_records()?
            .into_iter()
            .flat_map(|record| record.queues)
            .collect())
    }
    /// Atomically removes this device's history, outbox, keys and route. Minimal
    /// sealed replay markers keep deleted invitations/queues from being reused.
    pub fn delete_contact(&mut self, id: &str) -> Result<()> {
        ids(id, None)?;
        let account_jobs = self.account_jobs()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for mut job in account_jobs {
            if job.contact.as_deref() == Some(id) {
                job.deleted = true;
                let plain =
                    Zeroizing::new(serde_json::to_vec(&job).map_err(|_| Error::InvalidRecord)?);
                let record = seal(&self.key, &self.db_id, "account-job", &job.id, "", &plain)?;
                tx.execute(
                    "UPDATE account_jobs SET record=? WHERE id=?",
                    params![record, job.id],
                )?;
            }
        }
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM contacts WHERE id=?)",
            [id],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::NotFound);
        }
        let retired = match load_route(&tx, &self.key, &self.db_id, id) {
            Ok(record) => Some(RetiredContact {
                replay_tag: record
                    .setup
                    .as_ref()
                    .and_then(|setup| setup.replay_tag.clone()),
                queues: vec![
                    (record.route().send.relay_url, record.route().send.queue_id),
                    (
                        record.route().receive.relay_url,
                        record.route().receive.queue_id,
                    ),
                ],
            }),
            Err(Error::NotFound) => None,
            Err(error) => return Err(error),
        };
        if let Some(retired) = retired {
            let count: i64 =
                tx.query_row("SELECT count(*) FROM retired_contacts", [], |r| r.get(0))?;
            if count >= MAX_RETIRED {
                return Err(Error::QuotaExceeded);
            }
            let plain =
                Zeroizing::new(serde_json::to_vec(&retired).map_err(|_| Error::InvalidRecord)?);
            let record = seal(&self.key, &self.db_id, "retired", id, "", &plain)?;
            tx.execute(
                "INSERT INTO retired_contacts VALUES(?,?)",
                params![id, record],
            )?;
        }
        tx.execute("DELETE FROM messages WHERE contact=?", [id])?;
        tx.execute("DELETE FROM routes WHERE contact=?", [id])?;
        tx.execute("DELETE FROM contact_names WHERE contact=?", [id])?;
        tx.execute("DELETE FROM contacts WHERE id=?", [id])?;
        tx.commit()?;
        Ok(())
    }
    pub fn insert_contact(&mut self, contact: Contact) -> Result<String> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM contacts", [], |r| r.get(0))?;
        if count >= MAX_CONTACTS {
            return Err(Error::QuotaExceeded);
        }
        let id = random_id();
        let snapshot = contact.snapshot(&self.key)?;
        let state = seal(&self.key, &self.db_id, "contact", &id, "", &snapshot)?;
        tx.execute("INSERT INTO contacts VALUES(?,?)", params![id, state])?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(id)
    }
    /// Persists a fresh contact, its private route and invitation state together.
    /// A retained replay marker prevents importing the same invitation twice.
    pub fn insert_setup_contact(
        &mut self,
        contact: Contact,
        route: &ContactRoute,
        setup: &SetupData,
    ) -> Result<String> {
        if !valid_route(route) {
            return Err(Error::InvalidRoute);
        }
        if !valid_setup(setup) {
            return Err(Error::InvalidSetup);
        }
        if let Some(tag) = &setup.replay_tag {
            if self.has_setup_replay(tag)? {
                return Err(Error::SetupReplay);
            }
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM contacts", [], |r| r.get(0))?;
        if count >= MAX_CONTACTS {
            return Err(Error::QuotaExceeded);
        }
        if let Some(tag) = &setup.replay_tag {
            if load_setups(&tx, &self.key, &self.db_id)?
                .iter()
                .any(|(_, previous)| previous.replay_tag.as_ref() == Some(tag))
                || load_retired(&tx, &self.key, &self.db_id)?
                    .iter()
                    .any(|previous| previous.replay_tag.as_ref() == Some(tag))
            {
                return Err(Error::SetupReplay);
            }
        }
        let id = random_id();
        let snapshot = contact.snapshot(&self.key)?;
        let state = seal(&self.key, &self.db_id, "contact", &id, "", &snapshot)?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&StoredRoute::new(route, Some(setup.clone())))
                .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "route", &id, "", &plain)?;
        tx.execute("INSERT INTO contacts VALUES(?,?)", params![id, state])?;
        tx.execute(
            "INSERT INTO routes(contact,record) VALUES(?,?)",
            params![id, record],
        )?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(id)
    }
    /// Returns invitation state from a single bounded database snapshot.
    pub fn setup_records(&self) -> Result<Vec<(String, SetupData)>> {
        let tx = self.db.unchecked_transaction()?;
        let records = load_setups(&tx, &self.key, &self.db_id)?;
        tx.commit()?;
        Ok(records)
    }
    /// Replaces only the encrypted setup payload if its current state matches.
    /// The replay marker, readiness, queue capabilities and contact state stay
    /// unchanged. Durable setup jobs can use this before and after network I/O.
    pub fn update_setup_data(
        &mut self,
        id: &str,
        expected: &SetupData,
        replacement: &SetupData,
    ) -> Result<()> {
        ids(id, None)?;
        if !valid_setup(expected) || !valid_setup(replacement) {
            return Err(Error::InvalidSetup);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Check the authenticated contact record in the same write transaction,
        // without resaving it or advancing its ratchet.
        load_contact(&tx, &self.key, &self.db_id, id)?;
        let mut stored = load_route(&tx, &self.key, &self.db_id, id)?;
        let setup = stored.setup.as_ref().ok_or(Error::SetupConflict)?;
        if setup != expected
            || setup.replay_tag != replacement.replay_tag
            || setup.ready != replacement.ready
        {
            return Err(Error::SetupConflict);
        }
        stored.setup = Some(replacement.clone());
        let plain = Zeroizing::new(serde_json::to_vec(&stored).map_err(|_| Error::InvalidRecord)?);
        let record = seal(&self.key, &self.db_id, "route", id, "", &plain)?;
        if tx.execute(
            "UPDATE routes SET record=? WHERE contact=?",
            params![record, id],
        )? != 1
        {
            return Err(Error::NotFound);
        }
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    /// Updates an invitation's contact, route and setup as one compare-and-set
    /// transaction. A trusted Rust caller may bind keys and save the exact
    /// encrypted setup control together with the advanced ratchet, without
    /// inserting a user message into history or the message outbox.
    ///
    /// The permanent replay marker and local receive capability cannot change;
    /// an already-ready contact cannot return to pending setup. Closure errors,
    /// invalid replacements and quota or SQL failures commit no changes.
    pub fn update_setup_contact_atomic<T>(
        &mut self,
        id: &str,
        expected: &SetupData,
        update: impl FnOnce(&mut Contact, &mut SetupData, &mut ContactRoute) -> Result<T>,
    ) -> Result<T> {
        ids(id, None)?;
        if !valid_setup(expected) {
            return Err(Error::InvalidSetup);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut contact = load_contact(&tx, &self.key, &self.db_id, id)?;
        let stored = load_route(&tx, &self.key, &self.db_id, id)?;
        let mut setup = stored.setup.clone().ok_or(Error::SetupConflict)?;
        if setup != *expected {
            return Err(Error::SetupConflict);
        }
        let mut route = stored.route();
        let result = update(&mut contact, &mut setup, &mut route)?;
        if setup.replay_tag != expected.replay_tag
            || (expected.ready && !setup.ready)
            || !same_endpoint(&route.receive, &stored.receive)
        {
            return Err(Error::SetupConflict);
        }
        if !valid_setup(&setup) {
            return Err(Error::InvalidSetup);
        }
        if !valid_route(&route) {
            return Err(Error::InvalidRoute);
        }
        let plain = Zeroizing::new(
            serde_json::to_vec(&StoredRoute::new(&route, Some(setup)))
                .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "route", id, "", &plain)?;
        save_contact(&tx, &self.key, &self.db_id, id, &contact)?;
        if tx.execute(
            "UPDATE routes SET record=? WHERE contact=?",
            params![record, id],
        )? != 1
        {
            return Err(Error::NotFound);
        }
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(result)
    }
    /// Binds a peer and replaces pending setup only if its sealed state matches.
    /// The local read capability and permanent replay marker cannot change.
    pub fn complete_setup_contact(&mut self, id: &str, completion: SetupCompletion) -> Result<()> {
        ids(id, None)?;
        if !valid_route(&completion.route) {
            return Err(Error::InvalidRoute);
        }
        if !valid_setup(&completion.expected) || !valid_setup(&completion.replacement) {
            return Err(Error::InvalidSetup);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut contact = load_contact(&tx, &self.key, &self.db_id, id)?;
        let stored = load_route(&tx, &self.key, &self.db_id, id)?;
        let setup = stored.setup.as_ref().ok_or(Error::SetupConflict)?;
        if *setup != completion.expected
            || setup.ready
            || !completion.replacement.ready
            || setup.replay_tag != completion.replacement.replay_tag
            || !same_endpoint(&stored.receive, &completion.route.receive)
        {
            return Err(Error::SetupConflict);
        }
        contact.bind_peer(completion.peer, &completion.trusted_fingerprint)?;
        if completion.initiate {
            contact.start_session()?;
        }
        let plain = Zeroizing::new(
            serde_json::to_vec(&StoredRoute::new(
                &completion.route,
                Some(completion.replacement),
            ))
            .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "route", id, "", &plain)?;
        save_contact(&tx, &self.key, &self.db_id, id, &contact)?;
        if tx.execute(
            "UPDATE routes SET record=? WHERE contact=?",
            params![record, id],
        )? != 1
        {
            return Err(Error::NotFound);
        }
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn contact_ids(&self) -> Result<Vec<String>> {
        let mut query = self
            .db
            .prepare("SELECT id FROM contacts ORDER BY rowid LIMIT ?")?;
        let rows = query.query_map([MAX_CONTACTS + 1], |row| row.get(0))?;
        let ids = rows.collect::<rusqlite::Result<Vec<String>>>()?;
        if ids.len() > MAX_CONTACTS as usize {
            return Err(Error::InvalidRecord);
        }
        Ok(ids)
    }
    /// Sets immutable queue capabilities for a contact. Rotation is unsupported.
    pub fn set_route(&mut self, contact: &str, route: &ContactRoute) -> Result<()> {
        ids(contact, None)?;
        if !valid_route(route) {
            return Err(Error::InvalidRoute);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        load_contact(&tx, &self.key, &self.db_id, contact)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM routes WHERE contact=?)",
            [contact],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Error::RouteAlreadySet);
        }
        let plain = Zeroizing::new(
            serde_json::to_vec(&StoredRoute::new(route, None)).map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "route", contact, "", &plain)?;
        tx.execute(
            "INSERT INTO routes(contact,record) VALUES(?,?)",
            params![contact, record],
        )?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn is_archived(&self, contact: &str) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM archived_contacts WHERE id=?)",
            [contact],
            |r| r.get(0),
        )?)
    }
    pub fn route(&self, contact: &str) -> Result<ContactRoute> {
        if self.is_archived(contact)? {
            return Err(Error::Archived);
        }
        ids(contact, None)?;
        let route = load_route(&self.db, &self.key, &self.db_id, contact)?;
        if route.setup.as_ref().is_some_and(|setup| !setup.ready) {
            return Err(Error::SetupPending);
        }
        Ok(route.route())
    }
    pub fn public_bundle(&mut self, id: &str) -> Result<PublicBundle> {
        ids(id, None)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Deferred)?;
        let bundle = load_contact(&tx, &self.key, &self.db_id, id)?.public_bundle();
        tx.commit()?;
        Ok(bundle)
    }
    pub fn bind_peer(
        &mut self,
        id: &str,
        peer: PublicBundle,
        trusted_fingerprint: &str,
    ) -> Result<()> {
        self.change_contact(id, |contact| contact.bind_peer(peer, trusted_fingerprint))
    }
    pub fn start_session(&mut self, id: &str) -> Result<()> {
        self.change_contact(id, Contact::start_session)
    }
    fn change_contact(
        &mut self,
        id: &str,
        change: impl FnOnce(&mut Contact) -> messenger_core::Result<()>,
    ) -> Result<()> {
        ids(id, None)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut contact = load_contact(&tx, &self.key, &self.db_id, id)?;
        change(&mut contact)?;
        save_contact(&tx, &self.key, &self.db_id, id, &contact)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn enqueue(&mut self, contact: &str, text: &str) -> Result<Envelope> {
        ids(contact, None)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut state = load_contact(&tx, &self.key, &self.db_id, contact)?;
        check_quota(&tx, contact, "out")?;
        let envelope = state.encrypt(text)?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&MessageRef {
                envelope: &envelope,
                text,
            })
            .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "out", contact, &envelope.id, &plain)?;
        tx.execute(
            "INSERT INTO messages(contact,direction,id,record,pending) VALUES(?,'out',?,?,1)",
            params![contact, envelope.id, record],
        )?;
        save_contact(&tx, &self.key, &self.db_id, contact, &state)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(envelope)
    }
    pub fn accept(&mut self, contact: &str, envelope: &Envelope) -> Result<AcceptStatus> {
        self.accept_text(contact, envelope, false)
    }
    /// Inbox, ratchet and exact encrypted delivery reply commit together.
    pub fn accept_with_delivery(
        &mut self,
        contact: &str,
        envelope: &Envelope,
    ) -> Result<AcceptStatus> {
        self.accept_text(contact, envelope, true)
    }
    fn accept_text(
        &mut self,
        contact: &str,
        envelope: &Envelope,
        receipt: bool,
    ) -> Result<AcceptStatus> {
        ids(contact, Some(&envelope.id))?;
        // Bound untrusted input before looking up or decoding any stored record.
        if envelope.payload.len() > MAX_ENVELOPE_PAYLOAD {
            return Err(Error::Crypto(messenger_core::Error::TooLarge));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<Vec<u8>> = tx
            .query_row(
                "SELECT record FROM messages WHERE contact=? AND direction='in' AND id=?",
                params![contact, envelope.id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(blob) = previous {
            let record = decode_record(&self.key, &self.db_id, "in", contact, &envelope.id, &blob)?;
            if record.envelope.payload != envelope.payload {
                return Err(Error::Conflict);
            }
            // Even if a prior ACK was recorded locally, repeated relay delivery
            // schedules another ACK without trying to consume ratchet keys again.
            tx.execute(
                "UPDATE messages SET pending=1 WHERE contact=? AND direction='in' AND id=?",
                params![contact, envelope.id],
            )?;
            tx.commit()?;
            return Ok(AcceptStatus::Duplicate);
        }
        let mut state = load_contact(&tx, &self.key, &self.db_id, contact)?;
        check_quota(&tx, contact, "in")?;
        let text = Zeroizing::new(state.decrypt(envelope)?);
        let plain = Zeroizing::new(
            serde_json::to_vec(&MessageRef {
                envelope,
                text: &text,
            })
            .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "in", contact, &envelope.id, &plain)?;
        tx.execute(
            "INSERT INTO messages(contact,direction,id,record,pending,unread) VALUES(?,'in',?,?,1,1)",
            params![contact, envelope.id, record],
        )?;
        if receipt {
            delivery::queue_receipt(
                &tx,
                &self.key,
                &self.db_id,
                contact,
                &mut state,
                &envelope.id,
            )?;
        }
        save_contact(&tx, &self.key, &self.db_id, contact, &state)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(AcceptStatus::New)
    }
    pub fn pending_outbox(&self, contact: &str) -> Result<Vec<Envelope>> {
        ids(contact, None)?;
        let mut query = self.db.prepare("SELECT id,record FROM messages WHERE contact=? AND direction='out' AND pending=1 ORDER BY seq LIMIT ?")?;
        let rows = query.query_map(params![contact, PAGE_SIZE], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (id, blob) = row?;
            Ok(decode_record(&self.key, &self.db_id, "out", contact, &id, &blob)?.envelope)
        })
        .collect()
    }
    pub fn pending_acks(&self, contact: &str) -> Result<Vec<String>> {
        ids(contact, None)?;
        let mut query = self.db.prepare("SELECT id,record FROM messages WHERE contact=? AND direction='in' AND pending=1 ORDER BY seq LIMIT ?")?;
        let rows = query.query_map(params![contact, PAGE_SIZE], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|row| {
            let (id, blob) = row?;
            decode_record(&self.key, &self.db_id, "in", contact, &id, &blob)?;
            Ok(id)
        })
        .collect()
    }
    pub fn mark_sent(&mut self, contact: &str, message: &str) -> Result<()> {
        self.mark_done(contact, message, "out")
    }
    pub fn mark_acked(&mut self, contact: &str, message: &str) -> Result<()> {
        self.mark_done(contact, message, "in")
    }
    fn mark_done(&mut self, contact: &str, message: &str, direction: &str) -> Result<()> {
        ids(contact, Some(message))?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let blob: Option<Vec<u8>> = tx
            .query_row(
                "SELECT record FROM messages WHERE contact=? AND direction=? AND id=?",
                params![contact, direction, message],
                |r| r.get(0),
            )
            .optional()?;
        decode_record(
            &self.key,
            &self.db_id,
            direction,
            contact,
            message,
            &blob.ok_or(Error::NotFound)?,
        )?;
        tx.execute(
            "UPDATE messages SET pending=0 WHERE contact=? AND direction=? AND id=?",
            params![contact, direction, message],
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Local-only UI count, independent of ACK state and network retries.
    pub fn unread_count(&self, contact: &str) -> Result<usize> {
        ids(contact, None)?;
        let exists: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM contacts WHERE id=?)",
            [contact],
            |r| r.get(0),
        )?;
        if !exists {
            return Err(Error::NotFound);
        }
        let count: i64 = self.db.query_row(
            "SELECT count(*) FROM messages WHERE contact=? AND direction='in' AND kind='text' AND unread=1",
            [contact],
            |r| r.get(0),
        )?;
        usize::try_from(count).map_err(|_| Error::InvalidRecord)
    }
    /// Marks only the exact displayed incoming rows; does not ACK or emit
    /// receipts. A concurrent unseen arrival must never be cleared by a cursor.
    pub fn mark_read(&mut self, contact: &str, sequences: &[i64]) -> Result<()> {
        ids(contact, None)?;
        if sequences.is_empty()
            || sequences.len() > PAGE_SIZE
            || sequences
                .iter()
                .any(|seq| !(1..=9_007_199_254_740_991).contains(seq))
        {
            return Err(Error::InvalidId);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        for sequence in sequences {
            let direction: Option<String> = tx
                .query_row(
                    "SELECT direction FROM messages WHERE contact=? AND seq=?",
                    params![contact, sequence],
                    |r| r.get(0),
                )
                .optional()?;
            match direction.as_deref() {
                Some("in") => {}
                Some(_) => return Err(Error::InvalidId),
                None => return Err(Error::NotFound),
            }
            tx.execute("UPDATE messages SET unread=0 WHERE contact=? AND direction='in' AND seq=? AND unread=1", params![contact,sequence])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn history(&self, contact: &str, after_sequence: i64) -> Result<Vec<HistoryEntry>> {
        ids(contact, None)?;
        if after_sequence < 0 {
            return Err(Error::InvalidId);
        }
        let mut query = self.db.prepare("SELECT seq,direction,id,record,unread,pending FROM messages WHERE contact=? AND kind='text' AND seq>? ORDER BY seq LIMIT ?")?;
        let rows = query.query_map(params![contact, after_sequence, PAGE_SIZE], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, bool>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (sequence, direction, id, blob, unread, pending) = row?;
            let record = decode_record(&self.key, &self.db_id, &direction, contact, &id, &blob)?;
            let direction = match direction.as_str() {
                "in" => Direction::Incoming,
                "out" => Direction::Outgoing,
                _ => return Err(Error::InvalidRecord),
            };
            Ok(HistoryEntry {
                sequence,
                direction,
                id,
                text: record.text,
                unread,
                delivery: (direction == Direction::Outgoing).then_some(if record.delivered {
                    DeliveryStatus::Delivered
                } else if pending {
                    DeliveryStatus::Queued
                } else {
                    DeliveryStatus::Server
                }),
            })
        })
        .collect()
    }
}

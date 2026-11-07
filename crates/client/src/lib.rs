//! HTTP delivery for the experimental personal messenger.
//! One worker owns a database lock for its lifetime. Queue routes are loaded
//! from encrypted storage; retries always reuse persisted envelopes.
//! HTTPS is required, except explicit direct HTTP to literal loopback IPs.

pub mod accounts;
pub mod backup;
pub mod invitations;
mod quick;
mod setup;
pub use quick::{QuickInvitation, QuickStatus, QuickVerification};
pub use setup::{CreatedInvitation, InvitationStatus, ReceiveQueue};

use messenger_core::{Envelope, StorageKey};
use messenger_store::{AcceptStatus, ClientStore, ContactRoute, QueueEndpoint};
use reqwest::{
    header::{HeaderValue, ACCEPT, AUTHORIZATION},
    redirect::Policy,
    Client, Response, StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions, TryLockError},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Host;

const MAX_RESPONSE_BYTES: usize = 9 * 1024 * 1024;
const MAX_MESSAGES: usize = 100;
const MAX_PAYLOAD: usize = (64 * 1024usize).div_ceil(3) * 4;
const MAX_PROVISION_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("account HTTP status {0}")]
    AccountRejected(u16),
    #[error("account is not signed in")]
    AccountClosed,
    #[error("account identity belongs to another profile")]
    AccountIdentityMismatch,
    #[error("invalid or disallowed relay endpoint")]
    InvalidEndpoint,
    #[error("HTTP request failed")]
    RequestFailed,
    #[error("unexpected relay HTTP status {0}")]
    UnexpectedStatus(u16),
    #[error("invitation provisioning rejected with HTTP status {0}")]
    InvitationProvisionRejected(u16),
    #[error("invalid relay response")]
    InvalidResponse,
    #[error("relay response exceeded its size limit")]
    ResponseTooLarge,
    #[error("another client worker owns this database")]
    AlreadyRunning,
    #[error("local client file operation failed")]
    LocalIo,
    #[error("client storage failed: {0}")]
    Store(#[from] messenger_store::Error),
    #[error("system key storage failed: {0}")]
    Platform(#[from] messenger_platform::Error),
    #[error("invitation validation failed: {0}")]
    Invitation(#[from] invitations::InvitationError),
    #[error("local receiving queue has already been used")]
    QueueAlreadyUsed,
    #[error("reply does not belong to this invitation")]
    ReplyMismatch,
    #[error("invitation has already been completed")]
    InvitationCompleted,
    #[error("receiving queue provisioning is pending")]
    QueueProvisionPending,
    #[error("invalid quick invitation or setup frame")]
    QuickInvitationInvalid,
    #[error("quick invitation has expired")]
    QuickInvitationExpired,
    #[error("quick invitation is waiting for explicit confirmation")]
    QuickConfirmationPending,
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct SyncReport {
    pub sent: usize,
    pub received: usize,
    pub duplicates: usize,
    pub acked: usize,
    pub profile_changed: bool,
    pub delivery_changed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Messages {
    messages: Vec<Envelope>,
}

#[derive(Serialize)]
struct QueueProposal<'a> {
    id: &'a str,
    read_token: &'a str,
    write_token: &'a str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionedQueue {
    id: String,
}

fn valid_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

struct Endpoint {
    url: Url,
    bearer: HeaderValue,
    direct_loopback: bool,
}
impl Endpoint {
    fn parse(value: &QueueEndpoint, allow_loopback_http: bool) -> Result<Self> {
        if value.relay_url.len() > 2048
            || !valid_hex(&value.queue_id, 32)
            || !valid_hex(&value.token, 64)
        {
            return Err(Error::InvalidEndpoint);
        }
        let mut url = Url::parse(&value.relay_url).map_err(|_| Error::InvalidEndpoint)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host().is_none()
        {
            return Err(Error::InvalidEndpoint);
        }
        let literal_loopback = match url.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        let direct_loopback = url.scheme() == "http" && allow_loopback_http && literal_loopback;
        if url.scheme() != "https" && !direct_loopback {
            return Err(Error::InvalidEndpoint);
        }
        url.set_path(&format!("/v1/queues/{}/messages", value.queue_id));
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", value.token))
            .map_err(|_| Error::InvalidEndpoint)?;
        bearer.set_sensitive(true);
        Ok(Self {
            url,
            bearer,
            direct_loopback,
        })
    }
    fn ack_url(&self, id: &str) -> Result<Url> {
        if !valid_hex(id, 32) {
            return Err(Error::InvalidResponse);
        }
        let mut url = self.url.clone();
        let path = format!("{}/{id}", url.path());
        url.set_path(&path);
        Ok(url)
    }
}

struct Transport {
    https: Client,
    loopback: Client,
    allow_loopback_http: bool,
}
impl Transport {
    fn new(allow_loopback_http: bool) -> Result<Self> {
        let builder = || {
            Client::builder()
                .redirect(Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
        };
        // HTTPS uses the normal system proxy policy and native certificate
        // roots. The explicit loopback exception must stay on this machine.
        let https = builder().build().map_err(|_| Error::RequestFailed)?;
        let loopback = builder()
            .no_proxy()
            .build()
            .map_err(|_| Error::RequestFailed)?;
        Ok(Self {
            https,
            loopback,
            allow_loopback_http,
        })
    }
    fn client(&self, endpoint: &Endpoint) -> &Client {
        if endpoint.direct_loopback {
            &self.loopback
        } else {
            &self.https
        }
    }
    async fn provision(&self, queue: &ReceiveQueue, ticket: &str) -> Result<()> {
        if !valid_hex(ticket, 64) {
            return Err(Error::InvalidEndpoint);
        }
        let endpoint = Endpoint::parse(&queue.read, self.allow_loopback_http)?;
        let mut url = endpoint.url.clone();
        url.set_path("/v1/queues/redeem");
        let mut bearer = HeaderValue::from_str(&format!("Bearer {ticket}"))
            .map_err(|_| Error::InvalidEndpoint)?;
        bearer.set_sensitive(true);
        let mut response = self
            .client(&endpoint)
            .post(url)
            .header(AUTHORIZATION, bearer)
            .header(ACCEPT, "application/json")
            .json(&QueueProposal {
                id: &queue.read.queue_id,
                read_token: &queue.read.token,
                write_token: &queue.write.token,
            })
            .send()
            .await
            .map_err(|_| Error::RequestFailed)?;
        require_status(&response, StatusCode::CREATED)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_PROVISION_RESPONSE_BYTES as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::RequestFailed)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_PROVISION_RESPONSE_BYTES {
                return Err(Error::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let result: ProvisionedQueue =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if result.id != queue.read.queue_id {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
    async fn send(&self, endpoint: &Endpoint, envelope: &Envelope) -> Result<()> {
        let response = self
            .client(endpoint)
            .post(endpoint.url.clone())
            .header(AUTHORIZATION, endpoint.bearer.clone())
            .json(envelope)
            .send()
            .await
            .map_err(|_| Error::RequestFailed)?;
        require_status(&response, StatusCode::ACCEPTED)
    }
    async fn ack(&self, endpoint: &Endpoint, id: &str) -> Result<()> {
        let response = self
            .client(endpoint)
            .delete(endpoint.ack_url(id)?)
            .header(AUTHORIZATION, endpoint.bearer.clone())
            .send()
            .await
            .map_err(|_| Error::RequestFailed)?;
        require_status(&response, StatusCode::NO_CONTENT)
    }
    async fn receive(&self, endpoint: &Endpoint) -> Result<Vec<Envelope>> {
        let mut response = self
            .client(endpoint)
            .get(endpoint.url.clone())
            .header(AUTHORIZATION, endpoint.bearer.clone())
            .header(ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| Error::RequestFailed)?;
        require_status(&response, StatusCode::OK)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(Error::ResponseTooLarge);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::RequestFailed)? {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(Error::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        let page: Messages = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if page.messages.len() > MAX_MESSAGES
            || page.messages.iter().any(|message| {
                !valid_hex(&message.id, 32)
                    || message.payload.is_empty()
                    || message.payload.len() > MAX_PAYLOAD
            })
        {
            return Err(Error::InvalidResponse);
        }
        Ok(page.messages)
    }
}

fn require_status(response: &Response, expected: StatusCode) -> Result<()> {
    if response.status() != expected {
        return Err(Error::UnexpectedStatus(response.status().as_u16()));
    }
    Ok(())
}

fn canonical_database(path: &Path) -> Result<PathBuf> {
    if path.as_os_str() == ":memory:" {
        return Err(Error::LocalIo);
    }
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let name = path.file_name().ok_or(Error::LocalIo)?;
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
            let parent = parent.unwrap_or_else(|| Path::new("."));
            Ok(parent
                .canonicalize()
                .map_err(|_| Error::LocalIo)?
                .join(name))
        }
        Err(_) => Err(Error::LocalIo),
    }
}

fn acquire_worker_lock(path: &Path) -> Result<File> {
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".worker.lock");
    let guard = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(PathBuf::from(lock_name))
        .map_err(|_| Error::LocalIo)?;
    guard.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => Error::AlreadyRunning,
        TryLockError::Error(_) => Error::LocalIo,
    })?;
    Ok(guard)
}

/// The application must use this worker for every HTTP sync of the database.
/// The lock is advisory: direct writes through other ClientStore handles are
/// possible, but starting another conforming worker fails until this one drops.
/// Hard links and hostile local filesystem changes are outside this guarantee.
pub struct ClientWorker {
    incoming_contacts: Vec<String>,
    store: ClientStore,
    transport: Transport,
    _guard: File,
}
impl ClientWorker {
    pub fn open(
        path: impl AsRef<Path>,
        key: StorageKey,
        allow_loopback_http: bool,
    ) -> Result<Self> {
        let path = canonical_database(path.as_ref())?;
        let guard = acquire_worker_lock(&path)?;
        let transport = Transport::new(allow_loopback_http)?;
        let store = ClientStore::open(path, key)?;
        Ok(Self {
            incoming_contacts: Vec::new(),
            store,
            transport,
            _guard: guard,
        })
    }

    /// Opens a persistent profile with its Windows DPAPI or Android Keystore key.
    /// The worker lock covers key publication AND database initialization.
    /// On other platforms this fails before creating any profile files.
    pub fn open_system(path: impl AsRef<Path>, allow_loopback_http: bool) -> Result<Self> {
        messenger_platform::ensure_supported()?;
        let path = canonical_database(path.as_ref())?;
        let guard = acquire_worker_lock(&path)?;
        let transport = Transport::new(allow_loopback_http)?;
        backup::finish_pending(&path)?;
        let key = messenger_platform::load_or_create(&path)?;
        let store = ClientStore::open(path, key)?;
        Ok(Self {
            incoming_contacts: Vec::new(),
            store,
            transport,
            _guard: guard,
        })
    }

    /// Drains only newly committed inbox progress from this worker lifetime.
    /// Duplicate delivery, history, profile and setup controls never enter it.
    /// The app actor drains after every command, including failures/timeouts.
    pub fn take_incoming_contacts(&mut self) -> Vec<String> {
        std::mem::take(&mut self.incoming_contacts)
    }
    fn record_incoming(&mut self, contact: &str) {
        if self.incoming_contacts.len() < MAX_MESSAGES
            && !self.incoming_contacts.iter().any(|id| id == contact)
        {
            self.incoming_contacts.push(contact.into());
        }
    }
    pub fn store(&mut self) -> &mut ClientStore {
        &mut self.store
    }

    /// Performs one bounded pass. Retry explicitly after an error; already
    /// committed progress survives. Sends and ACKs are sequential, not parallel.
    pub async fn sync(&mut self, contact: &str) -> Result<SyncReport> {
        if self.store.is_archived(contact)? {
            return Err(messenger_store::Error::Archived.into());
        }
        if self.quick_invitation_status(contact)?.is_some() {
            return self.sync_quick(contact).await;
        }
        self.ensure_queue_provisioned(contact)?;
        let ContactRoute { send, receive } = self.store.route(contact)?;
        // Validate BOTH endpoints before issuing any request. One immutable
        // snapshot of the route is used for the complete pass.
        let send = Endpoint::parse(&send, self.transport.allow_loopback_http)?;
        let receive = Endpoint::parse(&receive, self.transport.allow_loopback_http)?;
        let mut report = SyncReport::default();
        for id in self.store.pending_acks(contact)? {
            self.transport.ack(&receive, &id).await?;
            self.store.mark_acked(contact, &id)?;
            report.acked += 1;
        }
        for envelope in self.store.pending_outbox(contact)? {
            self.transport.send(&send, &envelope).await?;
            self.store.mark_sent(contact, &envelope.id)?;
            let raw = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &envelope.payload,
            )
            .unwrap_or_default();
            if !raw.starts_with(messenger_store::DELIVERY_PREFIX) {
                report.sent += 1;
            }
        }
        for envelope in self.transport.receive(&receive).await? {
            let raw = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &envelope.payload,
            )
            .unwrap_or_default();
            let delivery = raw.starts_with(messenger_store::DELIVERY_PREFIX);
            let accepted = if delivery {
                self.store.accept_delivery(contact, &envelope)?
            } else {
                self.store.accept_with_delivery(contact, &envelope)?
            };
            match accepted {
                AcceptStatus::New => {
                    if delivery {
                        report.delivery_changed = true;
                    } else {
                        report.received += 1;
                        self.record_incoming(contact);
                    }
                }
                AcceptStatus::Duplicate => report.duplicates += 1,
            }
            self.transport.ack(&receive, &envelope.id).await?;
            self.store.mark_acked(contact, &envelope.id)?;
            report.acked += 1;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod endpoint_tests {
    use super::*;

    fn endpoint(url: &str) -> QueueEndpoint {
        QueueEndpoint {
            relay_url: url.into(),
            queue_id: "a".repeat(32),
            token: "b".repeat(64),
        }
    }

    #[test]
    fn loopback_http_is_explicit_and_literal() {
        assert!(Endpoint::parse(&endpoint("http://127.0.0.1:8787"), false).is_err());
        assert!(Endpoint::parse(&endpoint("http://127.0.0.1:8787"), true).is_ok());
        assert!(Endpoint::parse(&endpoint("http://[::1]:8787"), true).is_ok());
        assert!(Endpoint::parse(&endpoint("http://localhost:8787"), true).is_err());
        assert!(Endpoint::parse(&endpoint("http://example.com"), true).is_err());
        assert!(Endpoint::parse(&endpoint("http://192.168.1.1"), true).is_err());
        assert!(Endpoint::parse(&endpoint("https://example.com"), false).is_ok());
    }

    #[test]
    fn urls_cannot_supply_auth_paths_or_extra_fields() {
        for url in [
            "https://name:password@example.com",
            "https://example.com/path",
            "https://example.com/?token=secret",
            "https://example.com/#secret",
            "file:///tmp/example",
        ] {
            assert!(Endpoint::parse(&endpoint(url), true).is_err());
        }
        let value = Endpoint::parse(&endpoint("https://example.com"), false).unwrap();
        assert!(value.bearer.is_sensitive());
        assert!(value.ack_url("../escape").is_err());
    }
}

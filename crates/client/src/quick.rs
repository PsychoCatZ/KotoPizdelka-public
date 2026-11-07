//! Capability-based, explicitly identity-unverified invitation setup.
//! Secrets remain in a custom-scheme fragment and encrypted local setup.
//! A single leaf ticket admits one queue; possession does not prove identity.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use messenger_core::{Contact, Envelope};
use messenger_store::{AcceptStatus, ContactRoute, QueueEndpoint, SetupData};
use rand::{rngs::OsRng, RngCore};
use reqwest::{
    header::{HeaderValue, ACCEPT, AUTHORIZATION},
    StatusCode,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    invitations::{Invitation, InvitationKind},
    valid_hex, ClientWorker, Endpoint, Error, ProvisionedQueue, QueueProposal, ReceiveQueue,
    Result, SyncReport, Transport, MAX_PROVISION_RESPONSE_BYTES,
};

const LINK_PREFIX: &str = "kotopizdelka://invite#";
const LINK_PROTOCOL: &str = "KotoPizdelka.quick-invitation.v2";
const STATE_PROTOCOL: &str = "KotoPizdelka.quick-state.v2";
const REPLY_PREFIX: &str = "koto-setup:v2:";
const PROFILE_PREFIX: &[u8] = b"koto-profile:v1:";
const CONTROL_PREFIX: &str = "koto-control:v2:";
const MAX_LINK: usize = 2300;
const MAX_REPLY: usize = 4096;
const INVITATION_TTL: i64 = 3600;

/// Export is sensitive. Never Debug/log/persist in renderer storage.
pub struct QuickInvitation {
    pub contact: String,
    pub link: String,
    pub expires_at: i64,
}

pub struct QuickStatus {
    pub stage: &'static str,
    pub verified: bool,
}

pub struct QuickVerification {
    pub fingerprint: String,
    pub verified: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    protocol: String,
    offer: Invitation,
    secret: String,
    recipient_ticket: String,
    expires_at: i64,
}

impl Drop for Link {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.recipient_ticket.zeroize();
    }
}

impl Link {
    fn validate(&self) -> Result<()> {
        if self.protocol != LINK_PROTOCOL
            || self.offer.kind() != InvitationKind::Offer
            || !valid_hex(&self.secret, 64)
            || !valid_hex(&self.recipient_ticket, 64)
            || self.secret == self.recipient_ticket
            || self.expires_at <= 0
        {
            return Err(Error::QuickInvitationInvalid);
        }
        self.offer.fingerprint()?;
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| Error::QuickInvitationInvalid)
    }
    fn encode(&self) -> Result<String> {
        let link = format!(
            "{LINK_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(Zeroizing::new(self.bytes()?))
        );
        if link.len() > MAX_LINK {
            return Err(Error::QuickInvitationInvalid);
        }
        Ok(link)
    }
    fn decode(value: &str) -> Result<Self> {
        if value.len() > MAX_LINK {
            return Err(Error::QuickInvitationInvalid);
        }
        let fragment = value
            .strip_prefix(LINK_PREFIX)
            .ok_or(Error::QuickInvitationInvalid)?;
        if fragment.is_empty()
            || !fragment
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(Error::QuickInvitationInvalid);
        }
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(fragment)
                .map_err(|_| Error::QuickInvitationInvalid)?,
        );
        let link: Self =
            serde_json::from_slice(&bytes).map_err(|_| Error::QuickInvitationInvalid)?;
        link.validate()?;
        link.encode()?;
        Ok(link)
    }
    fn digest(&self) -> Result<String> {
        let mut h = Sha256::new();
        h.update(b"KotoPizdelka.quick-invitation-digest.v2\0");
        h.update(Zeroizing::new(self.bytes()?));
        Ok(hex::encode(h.finalize()))
    }
    fn aad(&self, id: &str) -> Result<Vec<u8>> {
        if !valid_hex(id, 32) {
            return Err(Error::QuickInvitationInvalid);
        }
        let mut aad = b"KotoPizdelka.quick-reply.v2\0".to_vec();
        aad.extend_from_slice(self.digest()?.as_bytes());
        aad.extend_from_slice(id.as_bytes());
        Ok(aad)
    }
    fn seal_reply(&self, reply: &Invitation) -> Result<Envelope> {
        let id = random_hex(16);
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let key =
            Zeroizing::new(hex::decode(&self.secret).map_err(|_| Error::QuickInvitationInvalid)?);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::QuickInvitationInvalid)?;
        let plain =
            Zeroizing::new(serde_json::to_vec(reply).map_err(|_| Error::QuickInvitationInvalid)?);
        let mut wire = REPLY_PREFIX.as_bytes().to_vec();
        wire.extend_from_slice(&nonce);
        wire.extend(
            cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &plain,
                        aad: &self.aad(&id)?,
                    },
                )
                .map_err(|_| Error::QuickInvitationInvalid)?,
        );
        let payload = STANDARD.encode(wire);
        if payload.len() > MAX_REPLY {
            return Err(Error::QuickInvitationInvalid);
        }
        Ok(Envelope { id, payload })
    }
    fn open_reply(&self, envelope: &Envelope) -> Result<Invitation> {
        if envelope.payload.len() > MAX_REPLY {
            return Err(Error::QuickInvitationInvalid);
        }
        let bytes = STANDARD
            .decode(&envelope.payload)
            .map_err(|_| Error::QuickInvitationInvalid)?;
        let wire = bytes
            .strip_prefix(REPLY_PREFIX.as_bytes())
            .ok_or(Error::QuickInvitationInvalid)?;
        if wire.len() < 40 {
            return Err(Error::QuickInvitationInvalid);
        }
        let key =
            Zeroizing::new(hex::decode(&self.secret).map_err(|_| Error::QuickInvitationInvalid)?);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key).map_err(|_| Error::QuickInvitationInvalid)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&wire[..24]),
                    Payload {
                        msg: &wire[24..],
                        aad: &self.aad(&envelope.id)?,
                    },
                )
                .map_err(|_| Error::QuickInvitationInvalid)?,
        );
        let reply: Invitation =
            serde_json::from_slice(&plain).map_err(|_| Error::QuickInvitationInvalid)?;
        self.validate_reply(&reply)?;
        Ok(reply)
    }
    fn validate_reply(&self, reply: &Invitation) -> Result<()> {
        if reply.kind() != InvitationKind::Reply
            || reply.offer_fingerprint() != Some(self.offer.fingerprint()?.as_str())
        {
            return Err(Error::QuickInvitationInvalid);
        }
        reply.fingerprint()?;
        let a = Endpoint::parse(self.offer.write_endpoint(), true)?;
        let b = Endpoint::parse(reply.write_endpoint(), true)?;
        if a.url.origin() != b.url.origin()
            || a.url == b.url
            || self.offer.bundle().identity_key == reply.bundle().identity_key
        {
            return Err(Error::QuickInvitationInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Role {
    Owner,
    Recipient,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    protocol: String,
    link: Link,
    role: Role,
    receive: QueueEndpoint,
    own_write: QueueEndpoint,
    provisioning_ticket: Option<String>,
    reply: Option<Invitation>,
    reply_envelope: Option<Envelope>,
    reply_sent: bool,
    control: Option<Envelope>,
    control_sent: bool,
    control_received: Option<Envelope>,
    verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_request: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_ticket_login: Option<String>,
}

fn random_hex(bytes: usize) -> String {
    let mut value = Zeroizing::new(vec![0u8; bytes]);
    OsRng.fill_bytes(&mut value);
    hex::encode(&*value)
}
fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::QuickInvitationInvalid)
        .and_then(|v| i64::try_from(v.as_secs()).map_err(|_| Error::QuickInvitationInvalid))
}
fn payload(state: &State) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(state).map_err(|_| Error::QuickInvitationInvalid)?;
    if bytes.len() > 8192 {
        return Err(Error::QuickInvitationInvalid);
    }
    Ok(bytes)
}

fn pending_payload(state: &State) -> Result<Vec<u8>> {
    let bytes = payload(state)?;
    // The exact first encrypted control is later saved alongside the ratchet.
    // Reserve its bounded size before publishing or admitting a candidate.
    if bytes.len() > 8192 - 2048 {
        return Err(Error::QuickInvitationInvalid);
    }
    Ok(bytes)
}

pub(crate) fn is_quick_setup(data: &SetupData) -> Result<bool> {
    #[derive(Deserialize)]
    struct Header {
        protocol: Option<String>,
    }
    let header: Header =
        serde_json::from_slice(&data.payload).map_err(|_| messenger_store::Error::InvalidRecord)?;
    Ok(header.protocol.as_deref() == Some(STATE_PROTOCOL))
}

impl Transport {
    async fn provision_invitation(
        &self,
        queue: &ReceiveQueue,
        ticket: &str,
        link: &Link,
    ) -> Result<()> {
        #[derive(Serialize)]
        struct Proposal<'a> {
            queue: QueueProposal<'a>,
            recipient_ticket: &'a str,
            expires_at: i64,
        }
        if !valid_hex(ticket, 64) {
            return Err(Error::InvalidEndpoint);
        }
        let endpoint = Endpoint::parse(&queue.read, self.allow_loopback_http)?;
        let mut url = endpoint.url.clone();
        url.set_path("/v1/queues/invite");
        let mut bearer = HeaderValue::from_str(&format!("Bearer {ticket}"))
            .map_err(|_| Error::InvalidEndpoint)?;
        bearer.set_sensitive(true);
        let mut response = self
            .client(&endpoint)
            .post(url)
            .header(AUTHORIZATION, bearer)
            .header(ACCEPT, "application/json")
            .json(&Proposal {
                queue: QueueProposal {
                    id: &queue.read.queue_id,
                    read_token: &queue.read.token,
                    write_token: &queue.write.token,
                },
                recipient_ticket: &link.recipient_ticket,
                expires_at: link.expires_at,
            })
            .send()
            .await
            .map_err(|_| Error::RequestFailed)?;
        if response.status() != StatusCode::CREATED {
            return Err(Error::InvitationProvisionRejected(
                response.status().as_u16(),
            ));
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_PROVISION_RESPONSE_BYTES as u64)
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
        let created: ProvisionedQueue =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if created.id != queue.read.queue_id {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
}

impl ClientWorker {
    fn quick_state(&self, contact: &str) -> Result<Option<(SetupData, State)>> {
        for (id, setup) in self.store.setup_records()? {
            if id != contact || !is_quick_setup(&setup)? {
                continue;
            }
            let state: State = serde_json::from_slice(&setup.payload)
                .map_err(|_| messenger_store::Error::InvalidRecord)?;
            state.link.validate()?;
            state.link.encode()?;
            if setup.replay_tag.as_deref() != Some(state.link.digest()?.as_str())
                || state.protocol != STATE_PROTOCOL
                || state.account_ticket_login.as_ref().is_some_and(|login| {
                    state.role != Role::Owner
                        || state.provisioning_ticket.is_none()
                        || crate::accounts::normalize_login(login).as_deref()
                            != Some(login.as_str())
                })
                || state
                    .provisioning_ticket
                    .as_ref()
                    .is_some_and(|t| !valid_hex(t, 64))
            {
                return Err(messenger_store::Error::InvalidRecord.into());
            }
            self.validate_pair(&ReceiveQueue {
                read: state.receive.clone(),
                write: state.own_write.clone(),
            })?;
            Endpoint::parse(
                state.link.offer.write_endpoint(),
                self.transport.allow_loopback_http,
            )?;
            if let Some(reply) = &state.reply {
                state.link.validate_reply(reply)?;
                Endpoint::parse(reply.write_endpoint(), self.transport.allow_loopback_http)?;
            }
            if state.role == Role::Owner
                && state.own_write.queue_id != state.link.offer.write_endpoint().queue_id
            {
                return Err(messenger_store::Error::InvalidRecord.into());
            }
            if state.role == Role::Recipient && state.reply.is_none() {
                return Err(messenger_store::Error::InvalidRecord.into());
            }
            if setup.ready
                && (state.reply.is_none()
                    || state.provisioning_ticket.is_some()
                    || (state.role == Role::Owner && state.control.is_none())
                    || (state.role == Role::Recipient && state.control_received.is_none()))
            {
                return Err(messenger_store::Error::InvalidRecord.into());
            }
            return Ok(Some((setup, state)));
        }
        Ok(None)
    }
    fn save_quick(&mut self, contact: &str, setup: &SetupData, state: &State) -> Result<()> {
        let mut replacement = setup.clone();
        replacement.payload = Zeroizing::new(payload(state)?).to_vec();
        self.store.update_setup_data(contact, setup, &replacement)?;
        Ok(())
    }
    pub(crate) fn quick_used_queues(&self) -> Result<Vec<QueueEndpoint>> {
        let mut endpoints = Vec::new();
        for (id, setup) in self.store.setup_records()? {
            if is_quick_setup(&setup)? {
                let (_, state) = self
                    .quick_state(&id)?
                    .ok_or(messenger_store::Error::InvalidRecord)?;
                endpoints.push(state.own_write);
                endpoints.push(state.link.offer.write_endpoint().clone());
                if let Some(reply) = state.reply {
                    endpoints.push(reply.write_endpoint().clone());
                }
            }
        }
        Ok(endpoints)
    }
    pub fn quick_invitation_status(&self, contact: &str) -> Result<Option<QuickStatus>> {
        let Some((setup, state)) = self.quick_state(contact)? else {
            return Ok(None);
        };
        let expired = now()? >= state.link.expires_at;
        let stage = if setup.ready {
            "ready"
        } else if expired && (state.role == Role::Owner || state.provisioning_ticket.is_some()) {
            "quick_expired"
        } else if state.provisioning_ticket.is_some() {
            "quick_queue_pending"
        } else if state.role == Role::Recipient {
            "quick_waiting"
        } else if state.reply.is_some() {
            "quick_confirmation"
        } else {
            "quick_pending"
        };
        Ok(Some(QuickStatus {
            stage,
            verified: state.verified,
        }))
    }
    pub fn export_quick_invitation(&self, contact: &str) -> Result<QuickInvitation> {
        let Some((_, state)) = self.quick_state(contact)? else {
            return Err(Error::QuickInvitationInvalid);
        };
        if state.provisioning_ticket.is_some() {
            return Err(Error::QueueProvisionPending);
        }
        Ok(QuickInvitation {
            contact: contact.into(),
            link: state.link.encode()?,
            expires_at: state.link.expires_at,
        })
    }
    pub(crate) fn account_contact(&self, request: &str) -> Result<Option<String>> {
        for id in self.store.contact_ids()? {
            if let Some((_, state)) = self.quick_state(&id)? {
                if state.account_request.as_deref() == Some(request) {
                    return Ok(Some(id));
                }
            }
        }
        Ok(None)
    }
    pub async fn create_quick_invitation(
        &mut self,
        relay_url: &str,
        ticket: &str,
    ) -> Result<QuickInvitation> {
        self.create_account_quick(relay_url, ticket, None).await
    }
    pub(crate) async fn create_account_quick(
        &mut self,
        relay_url: &str,
        ticket: &str,
        origin: Option<&str>,
    ) -> Result<QuickInvitation> {
        self.create_quick_inner(relay_url, ticket, origin, None)
            .await
    }
    pub(crate) async fn create_account_link_quick(
        &mut self,
        relay_url: &str,
        ticket: &str,
        login: &str,
    ) -> Result<QuickInvitation> {
        self.create_quick_inner(relay_url, ticket, None, Some(login))
            .await
    }
    async fn create_quick_inner(
        &mut self,
        relay_url: &str,
        ticket: &str,
        origin: Option<&str>,
        account_ticket_login: Option<&str>,
    ) -> Result<QuickInvitation> {
        let queue = self.proposal_queue(relay_url, ticket)?;
        self.ensure_fresh_queue(&queue.write)?;
        let contact = Contact::new();
        let offer =
            Invitation::offer(random_hex(16), contact.public_bundle(), queue.write.clone())?;
        let link = Link {
            protocol: LINK_PROTOCOL.into(),
            offer,
            secret: random_hex(32),
            recipient_ticket: random_hex(32),
            expires_at: now()?
                .checked_add(if origin.is_some() {
                    23 * 3600
                } else {
                    INVITATION_TTL
                })
                .ok_or(Error::QuickInvitationInvalid)?,
        };
        link.encode()?;
        let state = State {
            protocol: STATE_PROTOCOL.into(),
            link,
            role: Role::Owner,
            receive: queue.read.clone(),
            own_write: queue.write.clone(),
            provisioning_ticket: Some(ticket.into()),
            reply: None,
            reply_envelope: None,
            reply_sent: false,
            control: None,
            control_sent: false,
            control_received: None,
            verified: false,
            account_request: origin.map(str::to_owned),
            account_ticket_login: account_ticket_login.map(str::to_owned),
        };
        let setup = SetupData {
            replay_tag: Some(state.link.digest()?),
            payload: pending_payload(&state)?,
            ready: false,
        };
        let route = ContactRoute {
            send: queue.write,
            receive: queue.read,
        };
        let id = self.store.insert_setup_contact(contact, &route, &setup)?;
        self.resume_quick_provision(&id).await?;
        self.export_quick_invitation(&id)
    }
    pub async fn accept_quick_invitation(&mut self, value: &str) -> Result<QuickInvitation> {
        self.accept_account_quick(value, None, None).await
    }
    pub(crate) async fn accept_account_quick(
        &mut self,
        value: &str,
        origin: Option<&str>,
        expected_relay: Option<&str>,
    ) -> Result<QuickInvitation> {
        let link = Link::decode(value)?;
        if expected_relay.is_some_and(|r| {
            r.trim_end_matches('/') != link.offer.write_endpoint().relay_url.trim_end_matches('/')
        }) {
            return Err(Error::QuickInvitationInvalid);
        }
        let timestamp = now()?;
        if timestamp >= link.expires_at {
            return Err(Error::QuickInvitationExpired);
        }
        if link.expires_at > timestamp.saturating_add(24 * 3600) {
            return Err(Error::QuickInvitationInvalid);
        }
        let peer = Endpoint::parse(
            link.offer.write_endpoint(),
            self.transport.allow_loopback_http,
        )?;
        let tag = link.digest()?;
        if self.store.has_setup_replay(&tag)? {
            return Err(messenger_store::Error::SetupReplay.into());
        }
        self.ensure_fresh_queue(link.offer.write_endpoint())?;
        let queue = self.proposal_queue(
            &link.offer.write_endpoint().relay_url,
            &link.recipient_ticket,
        )?;
        self.ensure_fresh_queue(&queue.write)?;
        if Endpoint::parse(&queue.write, self.transport.allow_loopback_http)?
            .url
            .origin()
            != peer.url.origin()
        {
            return Err(Error::QuickInvitationInvalid);
        }
        let mut contact = Contact::new();
        contact
            .bind_peer_from_invitation(link.offer.bundle().clone())
            .map_err(messenger_store::Error::from)?;
        let reply = Invitation::reply(
            random_hex(16),
            contact.public_bundle(),
            queue.write.clone(),
            link.offer.fingerprint()?,
        )?;
        let reply_envelope = link.seal_reply(&reply)?;
        let ticket = link.recipient_ticket.clone();
        let state = State {
            protocol: STATE_PROTOCOL.into(),
            link,
            role: Role::Recipient,
            receive: queue.read.clone(),
            own_write: queue.write.clone(),
            provisioning_ticket: Some(ticket),
            reply: Some(reply),
            reply_envelope: Some(reply_envelope),
            reply_sent: false,
            control: None,
            control_sent: false,
            control_received: None,
            verified: false,
            account_request: origin.map(str::to_owned),
            account_ticket_login: None,
        };
        let route = ContactRoute {
            send: state.link.offer.write_endpoint().clone(),
            receive: queue.read,
        };
        let setup = SetupData {
            replay_tag: Some(tag),
            payload: pending_payload(&state)?,
            ready: false,
        };
        let id = self.store.insert_setup_contact(contact, &route, &setup)?;
        self.sync_quick(&id).await?;
        self.export_quick_invitation(&id)
    }
    /// Keeps the exact saved proposal, even when replacing a rejected ticket.
    pub async fn provision_quick_invitation(
        &mut self,
        contact: &str,
        ticket: Option<&str>,
    ) -> Result<QuickInvitation> {
        let Some((setup, mut state)) = self.quick_state(contact)? else {
            return Err(Error::QuickInvitationInvalid);
        };
        if let Some(ticket) = ticket {
            if !valid_hex(ticket, 64) {
                return Err(Error::InvalidEndpoint);
            }
            if state.role != Role::Owner || setup.ready || state.provisioning_ticket.is_none() {
                return Err(Error::InvitationCompleted);
            }
            if now()? >= state.link.expires_at {
                return Err(Error::QuickInvitationExpired);
            }
            // First reconcile the old ticket. A lost success response must not
            // be replaced with a fresh redemption for an already created queue.
            match self.resume_quick_provision(contact).await {
                Ok(()) => return self.export_quick_invitation(contact),
                Err(Error::InvitationProvisionRejected(400 | 401 | 403)) => {}
                Err(error) => return Err(error),
            }
            state.provisioning_ticket = Some(ticket.into());
            self.save_quick(contact, &setup, &state)?;
        }
        self.resume_quick_provision(contact).await?;
        self.export_quick_invitation(contact)
    }
    async fn resume_quick_provision(&mut self, contact: &str) -> Result<()> {
        let Some((setup, mut state)) = self.quick_state(contact)? else {
            return Err(Error::QuickInvitationInvalid);
        };
        let Some(ticket) = state.provisioning_ticket.as_deref() else {
            return Ok(());
        };
        if now()? >= state.link.expires_at {
            return Err(Error::QuickInvitationExpired);
        }
        if let Some(login) = &state.account_ticket_login {
            self.authorize_account_link(&state.receive.relay_url, login, ticket)
                .await?;
        }
        let queue = ReceiveQueue {
            read: state.receive.clone(),
            write: state.own_write.clone(),
        };
        if state.role == Role::Owner {
            self.transport
                .provision_invitation(&queue, ticket, &state.link)
                .await?;
        } else {
            self.transport.provision(&queue, ticket).await?;
        }
        state.provisioning_ticket = None;
        state.account_ticket_login = None;
        self.save_quick(contact, &setup, &state)
    }
    pub async fn confirm_quick_invitation(&mut self, contact: &str) -> Result<()> {
        let Some((setup, mut state)) = self.quick_state(contact)? else {
            return Err(Error::QuickInvitationInvalid);
        };
        if setup.ready {
            if state.role != Role::Owner {
                return Err(Error::QuickConfirmationPending);
            }
            self.sync_quick(contact).await?;
            return Ok(());
        }
        if now()? >= state.link.expires_at {
            return Err(Error::QuickInvitationExpired);
        }
        if state.role != Role::Owner || state.provisioning_ticket.is_some() {
            return Err(Error::QuickConfirmationPending);
        }
        let reply = state.reply.clone().ok_or(Error::QuickConfirmationPending)?;
        state.link.validate_reply(&reply)?;
        let invite_digest = state.link.digest()?;
        let reply_digest = reply.fingerprint()?;
        self.store
            .update_setup_contact_atomic(contact, &setup, |crypto, replacement, route| {
                crypto.bind_peer_from_invitation(reply.bundle().clone())?;
                crypto.start_session()?;
                let mut envelope = crypto.encrypt_setup_control(&invite_digest, &reply_digest)?;
                let mut wire = CONTROL_PREFIX.as_bytes().to_vec();
                wire.extend(
                    STANDARD
                        .decode(&envelope.payload)
                        .map_err(|_| messenger_store::Error::InvalidRecord)?,
                );
                envelope.payload = STANDARD.encode(wire);
                state.control = Some(envelope);
                route.send = reply.write_endpoint().clone();
                replacement.ready = true;
                replacement.payload =
                    payload(&state).map_err(|_| messenger_store::Error::InvalidSetup)?;
                Ok(())
            })?;
        self.sync_quick(contact).await?;
        Ok(())
    }
    pub fn quick_verification(&self, contact: &str) -> Result<QuickVerification> {
        let Some((setup, state)) = self.quick_state(contact)? else {
            return Err(Error::QuickInvitationInvalid);
        };
        if !setup.ready {
            return Err(Error::QuickConfirmationPending);
        }
        let reply = state
            .reply
            .as_ref()
            .ok_or(Error::QuickConfirmationPending)?;
        let mut h = Sha256::new();
        h.update(b"KotoPizdelka.peer-comparison.v2\0");
        h.update(state.link.digest()?.as_bytes());
        h.update(reply.fingerprint()?.as_bytes());
        Ok(QuickVerification {
            fingerprint: hex::encode(h.finalize()),
            verified: state.verified,
        })
    }
    pub fn mark_quick_verified(&mut self, contact: &str, fingerprint: &str) -> Result<()> {
        if !valid_hex(fingerprint, 64)
            || self.quick_verification(contact)?.fingerprint != fingerprint
        {
            return Err(Error::QuickInvitationInvalid);
        }
        let (setup, mut state) = self
            .quick_state(contact)?
            .ok_or(Error::QuickInvitationInvalid)?;
        state.verified = true;
        self.save_quick(contact, &setup, &state)
    }
    pub(crate) async fn sync_quick(&mut self, contact: &str) -> Result<SyncReport> {
        self.resume_quick_provision(contact).await?;
        let (mut setup, mut state) = self
            .quick_state(contact)?
            .ok_or(Error::QuickInvitationInvalid)?;
        let receive = Endpoint::parse(&state.receive, self.transport.allow_loopback_http)?;
        let mut report = SyncReport::default();
        if state.role == Role::Recipient && !state.reply_sent {
            let endpoint = Endpoint::parse(
                state.link.offer.write_endpoint(),
                self.transport.allow_loopback_http,
            )?;
            self.transport
                .send(
                    &endpoint,
                    state
                        .reply_envelope
                        .as_ref()
                        .ok_or(Error::QuickInvitationInvalid)?,
                )
                .await?;
            state.reply_sent = true;
            self.save_quick(contact, &setup, &state)?;
            (setup, state) = self
                .quick_state(contact)?
                .ok_or(Error::QuickInvitationInvalid)?;
        }
        if setup.ready {
            let route = self.store.route(contact)?;
            let send = Endpoint::parse(&route.send, self.transport.allow_loopback_http)?;
            if state.role == Role::Owner && !state.control_sent {
                self.transport
                    .send(
                        &send,
                        state
                            .control
                            .as_ref()
                            .ok_or(Error::QuickInvitationInvalid)?,
                    )
                    .await?;
                state.control_sent = true;
                self.save_quick(contact, &setup, &state)?;
                (setup, state) = self
                    .quick_state(contact)?
                    .ok_or(Error::QuickInvitationInvalid)?;
            }
            // A full text outbox must still drain. Optional profile publication
            // can retry on the next pass once pending capacity is available.
            match self.store.enqueue_profile(contact) {
                Ok(()) | Err(messenger_store::Error::QuotaExceeded) => {}
                Err(error) => return Err(error.into()),
            }
            for id in self.store.pending_acks(contact)? {
                self.transport.ack(&receive, &id).await?;
                self.store.mark_acked(contact, &id)?;
                report.acked += 1;
            }
            for envelope in self.store.pending_outbox(contact)? {
                self.transport.send(&send, &envelope).await?;
                self.store.mark_sent(contact, &envelope.id)?;
                let raw = STANDARD.decode(&envelope.payload).unwrap_or_default();
                if !raw.starts_with(PROFILE_PREFIX)
                    && !raw.starts_with(messenger_store::DELIVERY_PREFIX)
                {
                    report.sent += 1;
                }
            }
        }
        for envelope in self.transport.receive(&receive).await? {
            let mut ack = true;
            let raw = STANDARD.decode(&envelope.payload).unwrap_or_default();
            let is_reply = raw.starts_with(REPLY_PREFIX.as_bytes());
            let is_control = raw.starts_with(CONTROL_PREFIX.as_bytes());
            if is_reply {
                if state.role == Role::Owner && !setup.ready && now()? < state.link.expires_at {
                    if let Ok(reply) = state.link.open_reply(&envelope) {
                        Endpoint::parse(
                            reply.write_endpoint(),
                            self.transport.allow_loopback_http,
                        )?;
                        if state.reply.is_none() {
                            match self.ensure_fresh_queue(reply.write_endpoint()) {
                                Ok(()) => {
                                    let mut candidate = state.clone();
                                    candidate.reply = Some(reply);
                                    candidate.reply_envelope = Some(envelope.clone());
                                    if pending_payload(&candidate).is_ok() {
                                        self.save_quick(contact, &setup, &candidate)?;
                                        (setup, state) = self
                                            .quick_state(contact)?
                                            .ok_or(Error::QuickInvitationInvalid)?;
                                    }
                                }
                                Err(Error::QueueAlreadyUsed | Error::InvalidEndpoint) => {}
                                Err(error) => return Err(error),
                            }
                        }
                    }
                }
                // Invalid/duplicate/late Reply frames never enter chat history.
            } else if let Some(wire) = raw.strip_prefix(CONTROL_PREFIX.as_bytes()) {
                if state.role == Role::Recipient && !setup.ready {
                    let digest = state.link.digest()?;
                    let reply_digest = state
                        .reply
                        .as_ref()
                        .ok_or(Error::QuickInvitationInvalid)?
                        .fingerprint()?;
                    let inner = Envelope {
                        id: envelope.id.clone(),
                        payload: STANDARD.encode(wire),
                    };
                    let transition = self.store.update_setup_contact_atomic(
                        contact,
                        &setup,
                        |crypto, replacement, _route| {
                            crypto.decrypt_setup_control(&inner, &digest, &reply_digest)?;
                            state.control_received = Some(envelope.clone());
                            replacement.ready = true;
                            replacement.payload = payload(&state)
                                .map_err(|_| messenger_store::Error::InvalidSetup)?;
                            Ok(())
                        },
                    );
                    match transition {
                        Ok(()) => {
                            (setup, state) = self
                                .quick_state(contact)?
                                .ok_or(Error::QuickInvitationInvalid)?;
                        }
                        Err(messenger_store::Error::Crypto(
                            messenger_core::Error::InvalidMessage | messenger_core::Error::TooLarge,
                        )) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                // Replayed control is ACKed using durable readiness, no ratchet retry.
            } else if raw.starts_with(messenger_store::DELIVERY_PREFIX) {
                if setup.ready {
                    match self.store.accept_delivery(contact, &envelope) {
                        Ok(AcceptStatus::New) => report.delivery_changed = true,
                        Ok(AcceptStatus::Duplicate) => {}
                        Err(messenger_store::Error::Crypto(
                            messenger_core::Error::InvalidMessage | messenger_core::Error::TooLarge,
                        )) => {}
                        Err(error) => return Err(error.into()),
                    }
                } else if state.role == Role::Recipient {
                    ack = false;
                }
            } else if raw.starts_with(PROFILE_PREFIX) {
                if setup.ready {
                    match self.store.accept_profile(contact, &envelope) {
                        Ok(AcceptStatus::New) => report.profile_changed = true,
                        Ok(AcceptStatus::Duplicate) => {}
                        Err(messenger_store::Error::Crypto(
                            messenger_core::Error::InvalidMessage | messenger_core::Error::TooLarge,
                        )) => {}
                        Err(error) => return Err(error.into()),
                    }
                } else if state.role == Role::Recipient {
                    ack = false;
                }
            } else if setup.ready {
                match self.store.accept_with_delivery(contact, &envelope) {
                    Ok(AcceptStatus::New) => {
                        report.received += 1;
                        self.record_incoming(contact);
                    }
                    Ok(AcceptStatus::Duplicate) => report.duplicates += 1,
                    Err(messenger_store::Error::Crypto(
                        messenger_core::Error::InvalidMessage | messenger_core::Error::TooLarge,
                    )) => {}
                    Err(e) => return Err(e.into()),
                }
            } else if state.role == Role::Recipient {
                // Do not discard a legitimate chat envelope delivered before its control.
                ack = false;
            }
            if ack {
                self.transport.ack(&receive, &envelope.id).await?;
                // Setup frames have no message rows; ordinary persisted messages do.
                if !is_reply && !is_control && setup.ready {
                    match self.store.mark_acked(contact, &envelope.id) {
                        Ok(()) | Err(messenger_store::Error::NotFound) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
                report.acked += 1;
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn link() -> Link {
        Link {
            protocol: LINK_PROTOCOL.into(),
            offer: Invitation::offer(
                random_hex(16),
                Contact::new().public_bundle(),
                QueueEndpoint {
                    relay_url: "https://relay.example".into(),
                    queue_id: random_hex(16),
                    token: random_hex(32),
                },
            )
            .unwrap(),
            secret: random_hex(32),
            recipient_ticket: random_hex(32),
            expires_at: now().unwrap() + 3600,
        }
    }
    fn reply(link: &Link) -> Invitation {
        Invitation::reply(
            random_hex(16),
            Contact::new().public_bundle(),
            QueueEndpoint {
                relay_url: "https://relay.example".into(),
                queue_id: random_hex(16),
                token: random_hex(32),
            },
            link.offer.fingerprint().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn link_codec_is_bounded_and_reply_binds_whole_invite_and_envelope_id() {
        let original = link();
        let encoded = original.encode().unwrap();
        assert!(encoded.len() <= MAX_LINK);
        let decoded = Link::decode(&encoded).unwrap();
        assert!(original.digest().unwrap() == decoded.digest().unwrap());
        let value = reply(&original);
        let encrypted = original.seal_reply(&value).unwrap();
        assert!(
            original
                .open_reply(&encrypted)
                .unwrap()
                .fingerprint()
                .unwrap()
                == value.fingerprint().unwrap()
        );
        let renamed = Envelope {
            id: random_hex(16),
            payload: encrypted.payload.clone(),
        };
        assert!(original.open_reply(&renamed).is_err());
        let mut changed = original.clone();
        changed.expires_at += 1;
        assert!(changed.open_reply(&encrypted).is_err());
        let mut changed = original.clone();
        changed.recipient_ticket = random_hex(32);
        assert!(changed.open_reply(&encrypted).is_err());
        let mut changed = original.clone();
        changed.secret = random_hex(32);
        assert!(changed.open_reply(&encrypted).is_err());
        for bad in [
            encoded.replace("kotopizdelka:", "https:"),
            format!("{encoded}?x=1"),
            format!("{encoded}%20"),
            format!("{LINK_PREFIX}{}", "a".repeat(MAX_LINK)),
        ] {
            assert!(Link::decode(&bad).is_err());
        }
    }
}

//! A two-way, manually verified exchange with durable scoped queue provisioning.
//! The application must obtain both full fingerprints through a trusted channel.

use messenger_core::Contact;
use messenger_store::{ContactRoute, QueueEndpoint, SetupCompletion, SetupData};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    invitations::{Invitation, InvitationKind},
    valid_hex, ClientWorker, Endpoint, Error, Result,
};

/// Both capabilities for a fresh local queue. Only `write` is exported.
/// The low-level manual exchange accepts an already provisioned queue;
/// the ticket helpers create one without exposing a relay admin token.
pub struct ReceiveQueue {
    pub read: QueueEndpoint,
    pub write: QueueEndpoint,
}

/// Deliberately has no Debug: the export contains a write capability.
pub struct CreatedInvitation {
    pub contact: String,
    pub invitation: String,
    pub fingerprint: String,
}

/// Public setup progress without invitations, capabilities or ticket values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationStatus {
    pub kind: InvitationKind,
    pub ready: bool,
    pub provisioning: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionJob {
    ticket: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalState {
    artifact: Invitation,
    receive: QueueEndpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provisioning: Option<ProvisionJob>,
}

fn nonce() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn capability() -> String {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn encoded_state(state: &LocalState) -> Result<Vec<u8>> {
    serde_json::to_vec(state).map_err(|_| messenger_store::Error::InvalidRecord.into())
}

impl ClientWorker {
    fn parse_local_state(&self, data: &SetupData) -> Result<LocalState> {
        let state: LocalState = serde_json::from_slice(&data.payload)
            .map_err(|_| messenger_store::Error::InvalidRecord)?;
        let fingerprint = state
            .artifact
            .fingerprint()
            .map_err(|_| messenger_store::Error::InvalidRecord)?;
        let tag = match state.artifact.kind() {
            InvitationKind::Offer => fingerprint.as_str(),
            InvitationKind::Reply => state
                .artifact
                .offer_fingerprint()
                .ok_or(messenger_store::Error::InvalidRecord)?,
        };
        if data.replay_tag.as_deref() != Some(tag)
            || (state.artifact.kind() == InvitationKind::Reply && !data.ready)
            || state
                .provisioning
                .as_ref()
                .is_some_and(|job| !valid_hex(&job.ticket, 64))
        {
            return Err(messenger_store::Error::InvalidRecord.into());
        }
        self.validate_pair(&ReceiveQueue {
            read: state.receive.clone(),
            write: state.artifact.write_endpoint().clone(),
        })?;
        Ok(state)
    }

    pub(crate) fn validate_pair(&self, queue: &ReceiveQueue) -> Result<()> {
        let read = Endpoint::parse(&queue.read, self.transport.allow_loopback_http)?;
        let write = Endpoint::parse(&queue.write, self.transport.allow_loopback_http)?;
        if read.url != write.url || queue.read.token == queue.write.token {
            return Err(Error::InvalidEndpoint);
        }
        Ok(())
    }

    /// Queues have no demultiplexing: one directional queue belongs to one
    /// contact. The lifetime worker lock serializes these preflight checks.
    pub(crate) fn ensure_fresh_queue(&self, endpoint: &QueueEndpoint) -> Result<()> {
        let candidate = Endpoint::parse(endpoint, self.transport.allow_loopback_http)?;
        for (relay_url, queue_id) in self.store.retired_queues()? {
            let retired = QueueEndpoint {
                relay_url,
                queue_id,
                token: "0".repeat(64),
            };
            if Endpoint::parse(&retired, self.transport.allow_loopback_http)?.url == candidate.url {
                return Err(Error::QueueAlreadyUsed);
            }
        }
        for used in self.quick_used_queues()? {
            if Endpoint::parse(&used, self.transport.allow_loopback_http)?.url == candidate.url {
                return Err(Error::QueueAlreadyUsed);
            }
        }
        for (_, data) in self.store.setup_records()? {
            if crate::quick::is_quick_setup(&data)? {
                continue;
            }
            let state = self.parse_local_state(&data)?;
            let local = Endpoint::parse(
                state.artifact.write_endpoint(),
                self.transport.allow_loopback_http,
            )?;
            if local.url == candidate.url {
                return Err(Error::QueueAlreadyUsed);
            }
        }
        // Include contacts created through the earlier low-level route API.
        // A pending setup's private local queue was checked above.
        for id in self.store.contact_ids()? {
            let route = match self.store.route(&id) {
                Ok(route) => route,
                Err(messenger_store::Error::NotFound | messenger_store::Error::SetupPending) => {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            for used in [&route.send, &route.receive] {
                let used = Endpoint::parse(used, self.transport.allow_loopback_http)?;
                if used.url == candidate.url {
                    return Err(Error::QueueAlreadyUsed);
                }
            }
        }
        Ok(())
    }

    fn local_state(&self, contact: &str) -> Result<(SetupData, LocalState)> {
        for (id, data) in self.store.setup_records()? {
            if id == contact {
                let state = self.parse_local_state(&data)?;
                return Ok((data, state));
            }
        }
        Err(messenger_store::Error::NotFound.into())
    }

    pub(crate) fn ensure_queue_provisioned(&self, contact: &str) -> Result<()> {
        for (id, data) in self.store.setup_records()? {
            if crate::quick::is_quick_setup(&data)? {
                continue;
            }
            if id == contact && self.parse_local_state(&data)?.provisioning.is_some() {
                return Err(Error::QueueProvisionPending);
            }
        }
        Ok(())
    }

    /// Returns only setup progress; raw queue read capabilities remain private.
    pub fn invitation_status(&self, contact: &str) -> Result<InvitationStatus> {
        let (data, state) = self.local_state(contact)?;
        Ok(InvitationStatus {
            kind: state.artifact.kind(),
            ready: data.ready,
            provisioning: state.provisioning.is_some(),
        })
    }

    pub(crate) fn proposal_queue(&self, relay_url: &str, ticket: &str) -> Result<ReceiveQueue> {
        if !valid_hex(ticket, 64) {
            return Err(Error::InvalidEndpoint);
        }
        let queue_id = nonce();
        let queue = ReceiveQueue {
            read: QueueEndpoint {
                relay_url: relay_url.into(),
                queue_id: queue_id.clone(),
                token: capability(),
            },
            write: QueueEndpoint {
                relay_url: relay_url.into(),
                queue_id,
                token: capability(),
            },
        };
        self.validate_pair(&queue)?;
        Ok(queue)
    }

    /// Saves the exact queue proposal and scoped ticket in the same encrypted
    /// transaction as the new contact, then attempts redemption. An HTTP error
    /// leaves a discoverable pending contact that `provision_queue` can resume.
    pub async fn create_invitation_with_ticket(
        &mut self,
        relay_url: &str,
        ticket: &str,
    ) -> Result<CreatedInvitation> {
        let queue = self.proposal_queue(relay_url, ticket)?;
        let created = self.create_invitation_inner(
            queue,
            Some(ProvisionJob {
                ticket: ticket.into(),
            }),
        )?;
        self.provision_queue(&created.contact, None).await
    }

    /// The complete offer, independent fingerprint, endpoint and replay checks
    /// run before saving or spending the ticket. Failed HTTP is resumable.
    pub async fn accept_invitation_with_ticket(
        &mut self,
        offer: &str,
        trusted_offer_fingerprint: &str,
        relay_url: &str,
        ticket: &str,
    ) -> Result<CreatedInvitation> {
        let queue = self.proposal_queue(relay_url, ticket)?;
        let created = self.accept_invitation_inner(
            offer,
            trusted_offer_fingerprint,
            queue,
            Some(ProvisionJob {
                ticket: ticket.into(),
            }),
        )?;
        self.provision_queue(&created.contact, None).await
    }

    /// Retries the same saved queue id and capabilities. A replacement ticket
    /// is committed through an exact compare-and-swap before any HTTP request.
    /// An already provisioned contact simply re-exports its original artifact.
    pub async fn provision_queue(
        &mut self,
        contact: &str,
        new_ticket: Option<&str>,
    ) -> Result<CreatedInvitation> {
        if new_ticket.is_some_and(|ticket| !valid_hex(ticket, 64)) {
            return Err(Error::InvalidEndpoint);
        }
        let (mut setup, mut state) = self.local_state(contact)?;
        let Some(job) = state.provisioning.as_mut() else {
            return self.export_invitation(contact);
        };
        if let Some(ticket) = new_ticket {
            job.ticket = ticket.into();
            let mut replacement = setup.clone();
            replacement.payload = Zeroizing::new(encoded_state(&state)?).to_vec();
            self.store
                .update_setup_data(contact, &setup, &replacement)?;
            setup = replacement;
        }
        let job = state
            .provisioning
            .as_ref()
            .ok_or(messenger_store::Error::InvalidRecord)?;
        let queue = ReceiveQueue {
            read: state.receive.clone(),
            write: state.artifact.write_endpoint().clone(),
        };
        self.transport.provision(&queue, &job.ticket).await?;
        state.provisioning = None;
        let mut replacement = setup.clone();
        replacement.payload = Zeroizing::new(encoded_state(&state)?).to_vec();
        self.store
            .update_setup_data(contact, &setup, &replacement)?;
        self.export_invitation(contact)
    }

    /// Saves an unbound contact and its receiving capabilities atomically.
    /// Its route is unavailable to sync until a verified Reply completes it.
    pub fn create_invitation(&mut self, queue: ReceiveQueue) -> Result<CreatedInvitation> {
        self.create_invitation_inner(queue, None)
    }

    fn create_invitation_inner(
        &mut self,
        queue: ReceiveQueue,
        provisioning: Option<ProvisionJob>,
    ) -> Result<CreatedInvitation> {
        self.validate_pair(&queue)?;
        self.ensure_fresh_queue(&queue.write)?;
        let contact = Contact::new();
        let artifact = Invitation::offer(nonce(), contact.public_bundle(), queue.write.clone())?;
        let fingerprint = artifact.fingerprint()?;
        let invitation = artifact.encode()?;
        let state = LocalState {
            artifact,
            receive: queue.read.clone(),
            provisioning,
        };
        let payload = Zeroizing::new(encoded_state(&state)?);
        let setup = SetupData {
            ready: false,
            replay_tag: Some(fingerprint.clone()),
            payload: payload.to_vec(),
        };
        let route = ContactRoute {
            // A private placeholder. ClientStore refuses to return this route
            // while setup is pending, so it cannot be used for delivery.
            send: queue.write,
            receive: queue.read,
        };
        let contact = self.store.insert_setup_contact(contact, &route, &setup)?;
        Ok(CreatedInvitation {
            contact,
            invitation,
            fingerprint,
        })
    }

    /// The trusted fingerprint must authenticate the whole Offer, including
    /// its write endpoint, through a channel independent of an untrusted export.
    /// The responder waits for the offerer's first encrypted message.
    pub fn accept_invitation(
        &mut self,
        offer: &str,
        trusted_offer_fingerprint: &str,
        queue: ReceiveQueue,
    ) -> Result<CreatedInvitation> {
        self.accept_invitation_inner(offer, trusted_offer_fingerprint, queue, None)
    }

    fn accept_invitation_inner(
        &mut self,
        offer: &str,
        trusted_offer_fingerprint: &str,
        queue: ReceiveQueue,
        provisioning: Option<ProvisionJob>,
    ) -> Result<CreatedInvitation> {
        let offer = Invitation::decode(offer)?
            .verify(trusted_offer_fingerprint)?
            .into_invitation();
        if offer.kind() != InvitationKind::Offer {
            return Err(crate::invitations::InvitationError::Invalid.into());
        }
        self.validate_pair(&queue)?;
        Endpoint::parse(offer.write_endpoint(), self.transport.allow_loopback_http)?;
        let offer_fingerprint = offer.fingerprint()?;
        // The store repeats this check inside the insertion transaction. This
        // early check avoids reporting queue reuse for an exact replay.
        if self
            .store
            .setup_records()?
            .iter()
            .any(|(_, data)| data.replay_tag.as_deref() == Some(&offer_fingerprint))
        {
            return Err(messenger_store::Error::SetupReplay.into());
        }
        self.ensure_fresh_queue(&queue.write)?;
        self.ensure_fresh_queue(offer.write_endpoint())?;
        let own = Endpoint::parse(&queue.write, self.transport.allow_loopback_http)?;
        let peer = Endpoint::parse(offer.write_endpoint(), self.transport.allow_loopback_http)?;
        if own.url == peer.url {
            return Err(Error::QueueAlreadyUsed);
        }
        let mut contact = Contact::new();
        contact
            .bind_peer(
                offer.bundle().clone(),
                &offer
                    .bundle()
                    .fingerprint()
                    .map_err(messenger_store::Error::from)?,
            )
            .map_err(messenger_store::Error::from)?;
        let artifact = Invitation::reply(
            nonce(),
            contact.public_bundle(),
            queue.write,
            offer_fingerprint.clone(),
        )?;
        let invitation = artifact.encode()?;
        let fingerprint = artifact.fingerprint()?;
        let state = LocalState {
            artifact,
            receive: queue.read.clone(),
            provisioning,
        };
        let payload = Zeroizing::new(encoded_state(&state)?);
        let setup = SetupData {
            ready: true,
            replay_tag: Some(offer_fingerprint),
            payload: payload.to_vec(),
        };
        let route = ContactRoute {
            send: offer.write_endpoint().clone(),
            receive: queue.read,
        };
        let contact = self.store.insert_setup_contact(contact, &route, &setup)?;
        Ok(CreatedInvitation {
            contact,
            invitation,
            fingerprint,
        })
    }

    /// Completes only a pending Offer; the exact parent fingerprint is checked
    /// before atomically binding the peer, starting Olm and installing its route.
    pub fn complete_invitation(
        &mut self,
        contact: &str,
        reply: &str,
        trusted_reply_fingerprint: &str,
    ) -> Result<()> {
        let reply = Invitation::decode(reply)?
            .verify(trusted_reply_fingerprint)?
            .into_invitation();
        if reply.kind() != InvitationKind::Reply {
            return Err(crate::invitations::InvitationError::Invalid.into());
        }
        let (setup, state) = self.local_state(contact)?;
        if state.provisioning.is_some() {
            return Err(Error::QueueProvisionPending);
        }
        if setup.ready {
            return Err(Error::InvitationCompleted);
        }
        if state.artifact.kind() != InvitationKind::Offer
            || reply.offer_fingerprint() != Some(state.artifact.fingerprint()?.as_str())
        {
            return Err(Error::ReplyMismatch);
        }
        if self
            .store
            .public_bundle(contact)?
            .fingerprint()
            .map_err(messenger_store::Error::from)?
            != state
                .artifact
                .bundle()
                .fingerprint()
                .map_err(messenger_store::Error::from)?
        {
            return Err(messenger_store::Error::InvalidRecord.into());
        }
        self.ensure_fresh_queue(reply.write_endpoint())?;
        let route = ContactRoute {
            send: reply.write_endpoint().clone(),
            receive: state.receive,
        };
        let mut replacement = setup.clone();
        replacement.ready = true;
        self.store.complete_setup_contact(
            contact,
            SetupCompletion {
                expected: setup,
                replacement,
                peer: reply.bundle().clone(),
                trusted_fingerprint: reply
                    .bundle()
                    .fingerprint()
                    .map_err(messenger_store::Error::from)?,
                initiate: true,
                route,
            },
        )?;
        Ok(())
    }

    /// Re-exports the same saved artifact after a crash or restart. Completed
    /// records also remain stored to prevent replay; no pruning is implemented.
    pub fn export_invitation(&mut self, contact: &str) -> Result<CreatedInvitation> {
        let (_, state) = self.local_state(contact)?;
        if state.provisioning.is_some() {
            return Err(Error::QueueProvisionPending);
        }
        if self
            .store
            .public_bundle(contact)?
            .fingerprint()
            .map_err(messenger_store::Error::from)?
            != state
                .artifact
                .bundle()
                .fingerprint()
                .map_err(messenger_store::Error::from)?
        {
            return Err(messenger_store::Error::InvalidRecord.into());
        }
        Ok(CreatedInvitation {
            contact: contact.to_owned(),
            invitation: state.artifact.encode()?,
            fingerprint: state.artifact.fingerprint()?,
        })
    }
}

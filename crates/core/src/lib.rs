//! Experimental, per-contact Olm integration. No transport, UI or durable store.
//! Public bundles can be pinned from an invitation, but independently verifying
//! their owner's identity requires a trusted channel outside that invitation.
//! A future client must persist state and the exact outgoing envelope atomically
//! before transmission, and persist inbox + state before acknowledging delivery.

pub mod accounts;
use base64::{engine::general_purpose::STANDARD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vodozemac::{
    olm::{Account, AccountPickle, OlmMessage, Session, SessionConfig, SessionPickle},
    Curve25519PublicKey,
};
use zeroize::Zeroizing;

const PROTOCOL: &str = "private-messenger.olm-v1.spike-1";
const SETUP_CONTROL_PROTOCOL: &str = "private-messenger.setup-control.v1";
const SNAPSHOT_AAD: &[u8] = b"private-messenger.contact-snapshot.v1";
const MAX_TEXT: usize = 24 * 1024;
const MAX_WIRE: usize = 64 * 1024;
const MAX_SNAPSHOT: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid or unsupported public bundle")]
    InvalidBundle,
    #[error("contact fingerprint does not match trusted fingerprint")]
    FingerprintMismatch,
    #[error("peer has already been bound")]
    PeerAlreadyBound,
    #[error("peer has not been verified")]
    PeerNotVerified,
    #[error("session has already been started")]
    SessionAlreadyStarted,
    #[error("session has not been started")]
    SessionNotStarted,
    #[error("session could not be established")]
    SessionCreation,
    #[error("message is too large")]
    TooLarge,
    #[error("invalid, forged or replayed message")]
    InvalidMessage,
    #[error("message could not be encrypted")]
    Encryption,
    #[error("invalid snapshot or incorrect storage key")]
    InvalidSnapshot,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Public invitation-specific keys. Not a globally reused account identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublicBundle {
    pub protocol: String,
    pub identity_key: String,
    pub one_time_key: String,
}
impl PublicBundle {
    fn keys(&self) -> Result<(Curve25519PublicKey, Curve25519PublicKey)> {
        if self.protocol != PROTOCOL || self.identity_key.len() > 44 || self.one_time_key.len() > 44
        {
            return Err(Error::InvalidBundle);
        }
        let identity = Curve25519PublicKey::from_base64(&self.identity_key)
            .map_err(|_| Error::InvalidBundle)?;
        let one_time = Curve25519PublicKey::from_base64(&self.one_time_key)
            .map_err(|_| Error::InvalidBundle)?;
        if identity.to_bytes() == [0; 32] || one_time.to_bytes() == [0; 32] {
            return Err(Error::InvalidBundle);
        }
        Ok((identity, one_time))
    }
    /// Compare through an independent channel. A digest supplied alongside an
    /// untrusted bundle does not authenticate its owner.
    pub fn fingerprint(&self) -> Result<String> {
        let (identity, one_time) = self.keys()?;
        let mut digest = Sha256::new();
        digest.update(PROTOCOL.as_bytes());
        digest.update(identity.to_bytes());
        digest.update(one_time.to_bytes());
        Ok(hex::encode(digest.finalize()))
    }
}

/// Same JSON shape as the relay contract; payload contains only Olm wire data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub id: String,
    pub payload: String,
}

#[derive(Serialize)]
struct OutgoingPlaintext<'a> {
    protocol: &'a str,
    id: &'a str,
    text: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plaintext {
    protocol: String,
    id: String,
    text: String,
}

/// A display label, not proof of a person's identity. Bounded before storage/IPC.
pub fn valid_nickname(value: &str) -> bool {
    value.len() <= 192 && value.chars().count() <= 48 && value == value.trim()
        && !value.chars().any(|c| c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{200b}' | '\u{200e}' | '\u{200f}' | '\u{feff}'))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerProfile {
    pub protocol: String,
    pub id: String,
    pub nickname: String,
    pub revision: u64,
}

#[derive(Serialize)]
struct OutgoingSetupControl<'a> {
    protocol: &'a str,
    id: &'a str,
    offer_fingerprint: &'a str,
    reply_fingerprint: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupControl {
    protocol: String,
    id: String,
    offer_fingerprint: String,
    reply_fingerprint: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryReceipt {
    protocol: String,
    id: String,
    message_id: String,
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Random at-rest encryption key. Intentionally lacks Debug and Serialize.
/// A real client must keep it in an OS-backed key store, not beside its data.
pub struct StorageKey(Zeroizing<[u8; 32]>);
impl StorageKey {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedContact {
    protocol: String,
    account: AccountPickle,
    session: Option<SessionPickle>,
    local: PublicBundle,
    peer: Option<PublicBundle>,
}

/// A separate instance for each contact. This in-memory API is not a client
/// database and is not a replacement for crash-safe persistence.
pub struct Contact {
    account: Account,
    session: Option<Session>,
    local: PublicBundle,
    peer: Option<PublicBundle>,
}
impl Default for Contact {
    fn default() -> Self {
        Self::new()
    }
}
impl Contact {
    pub fn new() -> Self {
        let mut account = Account::new();
        account.generate_one_time_keys(1);
        let key = *account
            .one_time_keys()
            .values()
            .next()
            .expect("one-time key was generated");
        let local = PublicBundle {
            protocol: PROTOCOL.into(),
            identity_key: account.curve25519_key().to_base64(),
            one_time_key: key.to_base64(),
        };
        account.mark_keys_as_published();
        Self {
            account,
            session: None,
            local,
            peer: None,
        }
    }
    pub fn public_bundle(&self) -> PublicBundle {
        self.local.clone()
    }
    /// The expected fingerprint must originate from a trusted independent channel.
    pub fn bind_peer(&mut self, bundle: PublicBundle, expected_fingerprint: &str) -> Result<()> {
        if self.peer.is_some() {
            return Err(Error::PeerAlreadyBound);
        }
        if bundle.fingerprint()? != expected_fingerprint {
            return Err(Error::FingerprintMismatch);
        }
        self.bind_peer_from_invitation(bundle)
    }
    /// Pins the per-contact keys received in an invitation. This validates the
    /// keys and prevents rebinding, but DOES NOT independently verify the human
    /// identity of their owner. Clients must retain that distinction in the UI.
    pub fn bind_peer_from_invitation(&mut self, bundle: PublicBundle) -> Result<()> {
        if self.peer.is_some() {
            return Err(Error::PeerAlreadyBound);
        }
        if bundle.keys()?.0 == self.account.curve25519_key() {
            return Err(Error::InvalidBundle);
        }
        self.peer = Some(bundle);
        Ok(())
    }
    /// Exactly one participant initiates; simultaneous initiation is unsupported.
    pub fn start_session(&mut self) -> Result<()> {
        if self.session.is_some() {
            return Err(Error::SessionAlreadyStarted);
        }
        let (identity, one_time) = self.peer.as_ref().ok_or(Error::PeerNotVerified)?.keys()?;
        self.session = Some(
            self.account
                .create_outbound_session(SessionConfig::version_1(), identity, one_time)
                .map_err(|_| Error::SessionCreation)?,
        );
        Ok(())
    }
    pub fn encrypt(&mut self, text: &str) -> Result<Envelope> {
        if text.len() > MAX_TEXT {
            return Err(Error::TooLarge);
        }
        self.encrypt_plaintext(|id| {
            serde_json::to_vec(&OutgoingPlaintext {
                protocol: PROTOCOL,
                id,
                text,
            })
            .map_err(|_| Error::Encryption)
        })
    }
    /// Profile controls use the same authenticated ratchet as chat, but a
    /// different purpose. They can never be mistaken for user text.
    pub fn encrypt_profile(&mut self, nickname: &str, revision: u64) -> Result<Envelope> {
        if !valid_nickname(nickname) || !(1..=9_007_199_254_740_991).contains(&revision) {
            return Err(Error::InvalidMessage);
        }
        self.encrypt_plaintext(|id| {
            serde_json::to_vec(&PeerProfile {
                protocol: "KotoPizdelka.peer-profile.v1".into(),
                id: id.into(),
                nickname: nickname.into(),
                revision,
            })
            .map_err(|_| Error::Encryption)
        })
    }
    pub fn decrypt_profile(&mut self, envelope: &Envelope) -> Result<PeerProfile> {
        self.decrypt_plaintext(envelope, |bytes| {
            let profile: PeerProfile =
                serde_json::from_slice(bytes).map_err(|_| Error::InvalidMessage)?;
            if profile.protocol != "KotoPizdelka.peer-profile.v1"
                || profile.id != envelope.id
                || !valid_nickname(&profile.nickname)
                || !(1..=9_007_199_254_740_991).contains(&profile.revision)
            {
                return Err(Error::InvalidMessage);
            }
            Ok(profile)
        })
    }
    /// Delivery confirms durable receipt by the pinned peer, never reading.
    pub fn encrypt_delivery(&mut self, message_id: &str) -> Result<Envelope> {
        if !valid_hex(message_id, 32) {
            return Err(Error::InvalidMessage);
        }
        self.encrypt_plaintext(|id| {
            serde_json::to_vec(&DeliveryReceipt {
                protocol: "KotoPizdelka.delivery.v1".into(),
                id: id.into(),
                message_id: message_id.into(),
            })
            .map_err(|_| Error::Encryption)
        })
    }
    pub fn decrypt_delivery(&mut self, envelope: &Envelope) -> Result<String> {
        self.decrypt_plaintext(envelope, |bytes| {
            let receipt: DeliveryReceipt =
                serde_json::from_slice(bytes).map_err(|_| Error::InvalidMessage)?;
            if receipt.protocol != "KotoPizdelka.delivery.v1"
                || receipt.id != envelope.id
                || !valid_hex(&receipt.message_id, 32)
            {
                return Err(Error::InvalidMessage);
            }
            Ok(receipt.message_id)
        })
    }
    /// Encrypts a typed setup control, separate from user messages. The two
    /// fingerprints identify the canonical invitation and Reply artifacts;
    /// they are not independently verified human identity fingerprints.
    pub fn encrypt_setup_control(
        &mut self,
        offer_fingerprint: &str,
        reply_fingerprint: &str,
    ) -> Result<Envelope> {
        if !valid_hex(offer_fingerprint, 64) || !valid_hex(reply_fingerprint, 64) {
            return Err(Error::InvalidMessage);
        }
        self.encrypt_plaintext(|id| {
            serde_json::to_vec(&OutgoingSetupControl {
                protocol: SETUP_CONTROL_PROTOCOL,
                id,
                offer_fingerprint,
                reply_fingerprint,
            })
            .map_err(|_| Error::Encryption)
        })
    }
    fn encrypt_plaintext(
        &mut self,
        plaintext: impl FnOnce(&str) -> Result<Vec<u8>>,
    ) -> Result<Envelope> {
        let session = self.session.as_ref().ok_or(Error::SessionNotStarted)?;
        let mut candidate = Session::from_pickle(session.pickle());
        let mut id = [0; 16];
        OsRng.fill_bytes(&mut id);
        let id = hex::encode(id);
        let serialized = Zeroizing::new(plaintext(&id)?);
        let message = candidate
            .encrypt(serialized.as_slice())
            .map_err(|_| Error::Encryption)?;
        let wire = serde_json::to_vec(&message).map_err(|_| Error::Encryption)?;
        if wire.len() > MAX_WIRE {
            return Err(Error::TooLarge);
        }
        let envelope = Envelope {
            id,
            payload: STANDARD.encode(wire),
        };
        self.session = Some(candidate);
        Ok(envelope)
    }
    pub fn decrypt(&mut self, envelope: &Envelope) -> Result<String> {
        self.decrypt_plaintext(envelope, |decrypted| {
            let plain: Plaintext =
                serde_json::from_slice(decrypted).map_err(|_| Error::InvalidMessage)?;
            if plain.protocol != PROTOCOL || plain.id != envelope.id || plain.text.len() > MAX_TEXT
            {
                return Err(Error::InvalidMessage);
            }
            Ok(plain.text)
        })
    }
    /// Authenticates setup control purpose, envelope ID, and both invitation
    /// fingerprints before committing any account or ratchet changes. A text
    /// envelope cannot be accepted as a setup control, or vice versa.
    pub fn decrypt_setup_control(
        &mut self,
        envelope: &Envelope,
        offer_fingerprint: &str,
        reply_fingerprint: &str,
    ) -> Result<()> {
        if !valid_hex(offer_fingerprint, 64) || !valid_hex(reply_fingerprint, 64) {
            return Err(Error::InvalidMessage);
        }
        self.decrypt_plaintext(envelope, |decrypted| {
            let plain: SetupControl =
                serde_json::from_slice(decrypted).map_err(|_| Error::InvalidMessage)?;
            if plain.protocol != SETUP_CONTROL_PROTOCOL
                || plain.id != envelope.id
                || plain.offer_fingerprint != offer_fingerprint
                || plain.reply_fingerprint != reply_fingerprint
            {
                return Err(Error::InvalidMessage);
            }
            Ok(())
        })
    }
    fn decrypt_plaintext<T>(
        &mut self,
        envelope: &Envelope,
        validate: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let peer = self.peer.as_ref().ok_or(Error::PeerNotVerified)?;
        if !valid_hex(&envelope.id, 32) {
            return Err(Error::InvalidMessage);
        }
        if envelope.payload.len() > MAX_WIRE.div_ceil(3) * 4 {
            return Err(Error::TooLarge);
        }
        let wire = STANDARD
            .decode(&envelope.payload)
            .map_err(|_| Error::InvalidMessage)?;
        if wire.len() > MAX_WIRE {
            return Err(Error::TooLarge);
        }
        let message: OlmMessage =
            serde_json::from_slice(&wire).map_err(|_| Error::InvalidMessage)?;
        let mut candidate_account = Account::from_pickle(self.account.pickle());
        let (candidate, decrypted) = if let Some(session) = &self.session {
            // Olm's Session::decrypt otherwise ignores the outer PreKey keys.
            if let OlmMessage::PreKey(prekey) = &message {
                if prekey.session_keys() != session.session_keys() {
                    return Err(Error::InvalidMessage);
                }
            }
            let mut candidate = Session::from_pickle(session.pickle());
            let decrypted = candidate
                .decrypt(&message)
                .map_err(|_| Error::InvalidMessage)?;
            (candidate, decrypted)
        } else {
            let OlmMessage::PreKey(prekey) = &message else {
                return Err(Error::InvalidMessage);
            };
            let result = candidate_account
                .create_inbound_session(SessionConfig::version_1(), peer.keys()?.0, prekey)
                .map_err(|_| Error::InvalidMessage)?;
            (result.session, result.plaintext)
        };
        let decrypted = Zeroizing::new(decrypted);
        let result = validate(&decrypted)?;
        self.account = candidate_account;
        self.session = Some(candidate);
        Ok(result)
    }
    /// Encrypts and authenticates the ENTIRE state, including peer binding.
    /// Does not prevent restoration of an old, otherwise valid snapshot.
    pub fn snapshot(&self, key: &StorageKey) -> Result<Vec<u8>> {
        let saved = SavedContact {
            protocol: PROTOCOL.into(),
            account: self.account.pickle(),
            session: self.session.as_ref().map(Session::pickle),
            local: self.local.clone(),
            peer: self.peer.clone(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&saved).map_err(|_| Error::InvalidSnapshot)?);
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| Error::InvalidSnapshot)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: SNAPSHOT_AAD,
                },
            )
            .map_err(|_| Error::InvalidSnapshot)?;
        let mut bytes = vec![1];
        bytes.extend(nonce);
        bytes.extend(ciphertext);
        if bytes.len() > MAX_SNAPSHOT {
            return Err(Error::TooLarge);
        }
        Ok(bytes)
    }
    pub fn restore(snapshot: &[u8], key: &StorageKey) -> Result<Self> {
        if snapshot.len() < 41 || snapshot.len() > MAX_SNAPSHOT || snapshot[0] != 1 {
            return Err(Error::InvalidSnapshot);
        }
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes())
            .map_err(|_| Error::InvalidSnapshot)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&snapshot[1..25]),
                    Payload {
                        msg: &snapshot[25..],
                        aad: SNAPSHOT_AAD,
                    },
                )
                .map_err(|_| Error::InvalidSnapshot)?,
        );
        let saved: SavedContact =
            serde_json::from_slice(&plain).map_err(|_| Error::InvalidSnapshot)?;
        if saved.protocol != PROTOCOL {
            return Err(Error::InvalidSnapshot);
        }
        let account = Account::from_pickle(saved.account);
        let (local_identity, local_otk) = saved.local.keys().map_err(|_| Error::InvalidSnapshot)?;
        if local_identity != account.curve25519_key() {
            return Err(Error::InvalidSnapshot);
        }
        let peer_keys = saved
            .peer
            .as_ref()
            .map(PublicBundle::keys)
            .transpose()
            .map_err(|_| Error::InvalidSnapshot)?;
        if peer_keys.is_some_and(|(identity, _)| identity == local_identity) {
            return Err(Error::InvalidSnapshot);
        }
        let session = saved.session.map(Session::from_pickle);
        if let Some(session) = &session {
            let (peer_identity, peer_otk) = peer_keys.ok_or(Error::InvalidSnapshot)?;
            let keys = session.session_keys();
            let initiator = keys.identity_key == local_identity && keys.one_time_key == peer_otk;
            let responder = keys.identity_key == peer_identity && keys.one_time_key == local_otk;
            if session.session_config() != SessionConfig::version_1() || !(initiator || responder) {
                return Err(Error::InvalidSnapshot);
            }
        }
        Ok(Self {
            account,
            session,
            local: saved.local,
            peer: saved.peer,
        })
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    fn ratchet_state(contact: &Contact) -> Vec<u8> {
        serde_json::to_vec(&(
            contact.account.pickle(),
            contact.session.as_ref().map(Session::pickle),
        ))
        .unwrap()
    }

    #[test]
    fn malformed_typed_controls_do_not_advance_account_or_ratchet() {
        let mut sender = Contact::new();
        let mut receiver = Contact::new();
        sender
            .bind_peer_from_invitation(receiver.public_bundle())
            .unwrap();
        receiver
            .bind_peer_from_invitation(sender.public_bundle())
            .unwrap();
        sender.start_session().unwrap();
        let offer = "a".repeat(64);
        let reply = "b".repeat(64);
        let initial = ratchet_state(&receiver);
        // These invalid payloads are authentically encrypted by the bound peer;
        // checking MACs alone would not provide control-purpose separation.
        for kind in 0..4 {
            let control = sender
                .encrypt_plaintext(|id| {
                    let mut body = serde_json::json!({
                        "protocol": SETUP_CONTROL_PROTOCOL,
                        "id": id,
                        "offer_fingerprint": offer,
                        "reply_fingerprint": reply
                    });
                    match kind {
                        0 => body["protocol"] = "another-control-purpose".into(),
                        1 => body["text"] = "unexpected user text".into(),
                        2 => body["offer_fingerprint"] = "A".repeat(64).into(),
                        _ => body["id"] = "not the envelope ID".into(),
                    }
                    serde_json::to_vec(&body).map_err(|_| Error::Encryption)
                })
                .unwrap();
            assert_eq!(
                receiver.decrypt_setup_control(&control, &offer, &reply),
                Err(Error::InvalidMessage)
            );
            assert_eq!(ratchet_state(&receiver), initial);
        }
        let valid = sender.encrypt_setup_control(&offer, &reply).unwrap();
        receiver
            .decrypt_setup_control(&valid, &offer, &reply)
            .unwrap();
        let established = ratchet_state(&receiver);
        let malformed = sender
            .encrypt_plaintext(|id| {
                serde_json::to_vec(&serde_json::json!({
                    "protocol": SETUP_CONTROL_PROTOCOL,
                    "id": id,
                    "offer_fingerprint": offer,
                    "reply_fingerprint": reply,
                    "unexpected": true
                }))
                .map_err(|_| Error::Encryption)
            })
            .unwrap();
        assert_eq!(
            receiver.decrypt_setup_control(&malformed, &offer, &reply),
            Err(Error::InvalidMessage)
        );
        assert_eq!(ratchet_state(&receiver), established);
        let valid = sender.encrypt_setup_control(&offer, &reply).unwrap();
        receiver
            .decrypt_setup_control(&valid, &offer, &reply)
            .unwrap();
    }

    #[test]
    fn mismatched_peer_in_authenticated_snapshot_is_rejected() {
        let mut contact = Contact::new();
        let peer = Contact::new().public_bundle();
        contact
            .bind_peer(peer.clone(), &peer.fingerprint().unwrap())
            .unwrap();
        contact.start_session().unwrap();
        // Simulate an erroneous migration that mixed two otherwise valid contacts.
        contact.peer = Some(Contact::new().public_bundle());
        let key = StorageKey::generate();
        let snapshot = contact.snapshot(&key).unwrap();
        assert!(matches!(
            Contact::restore(&snapshot, &key),
            Err(Error::InvalidSnapshot)
        ));
    }
}

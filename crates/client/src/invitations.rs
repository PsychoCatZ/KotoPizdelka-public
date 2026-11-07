//! Bounded invitation exchange with an independently authenticated fingerprint.
//!
//! The exported write capability is intentionally sensitive. Its hash binds
//! every invitation field, but authenticates an owner only when the expected
//! fingerprint arrives through an independent trusted channel.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use messenger_core::PublicBundle;
use messenger_store::QueueEndpoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROTOCOL: &str = "KotoPizdelka.invitation.v1";
const PREFIX: &str = "koto-invite:v1:";
const FINGERPRINT_DOMAIN: &[u8] = b"KotoPizdelka.invitation-fingerprint.v1\0";
const MAX_TEXT_BYTES: usize = 8192;
const MAX_JSON_BYTES: usize = 6144;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvitationError {
    #[error("invalid or unsupported invitation")]
    Invalid,
    #[error("invitation exceeded its size limit")]
    TooLarge,
    #[error("invitation fingerprint does not match trusted fingerprint")]
    FingerprintMismatch,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InvitationKind {
    Offer,
    Reply,
}

/// An unverified artifact. Possession of this value grants no trust in its owner.
/// Intentionally does not implement Debug because it contains a write token.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    protocol: String,
    kind: InvitationKind,
    nonce: String,
    bundle: PublicBundle,
    write: QueueEndpoint,
    #[serde(skip_serializing_if = "Option::is_none")]
    offer_fingerprint: Option<String>,
}

/// Constructed only by checking an independently supplied expected fingerprint.
/// Intentionally does not implement Debug or Deserialize.
pub struct VerifiedInvitation(Invitation);

impl VerifiedInvitation {
    pub(crate) fn into_invitation(self) -> Invitation {
        self.0
    }
}

impl Invitation {
    /// The caller must provide a newly generated 128-bit nonce as lowercase hex.
    pub fn offer(
        nonce: String,
        bundle: PublicBundle,
        write: QueueEndpoint,
    ) -> Result<Self, InvitationError> {
        let invitation = Self {
            protocol: PROTOCOL.into(),
            kind: InvitationKind::Offer,
            nonce,
            bundle,
            write,
            offer_fingerprint: None,
        };
        invitation.validate()?;
        Ok(invitation)
    }

    /// Bind the reply to the fingerprint of the entire originating offer.
    pub fn reply(
        nonce: String,
        bundle: PublicBundle,
        write: QueueEndpoint,
        offer_fingerprint: String,
    ) -> Result<Self, InvitationError> {
        let invitation = Self {
            protocol: PROTOCOL.into(),
            kind: InvitationKind::Reply,
            nonce,
            bundle,
            write,
            offer_fingerprint: Some(offer_fingerprint),
        };
        invitation.validate()?;
        Ok(invitation)
    }

    pub fn decode(text: &str) -> Result<Self, InvitationError> {
        if text.len() > MAX_TEXT_BYTES {
            return Err(InvitationError::TooLarge);
        }
        let encoded = text.strip_prefix(PREFIX).ok_or(InvitationError::Invalid)?;
        let json = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| InvitationError::Invalid)?;
        if json.len() > MAX_JSON_BYTES {
            return Err(InvitationError::TooLarge);
        }
        let invitation: Self =
            serde_json::from_slice(&json).map_err(|_| InvitationError::Invalid)?;
        invitation.validate()?;
        Ok(invitation)
    }

    pub fn encode(&self) -> Result<String, InvitationError> {
        let json = self.canonical_json()?;
        let text = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json));
        if text.len() > MAX_TEXT_BYTES {
            return Err(InvitationError::TooLarge);
        }
        Ok(text)
    }

    /// Hashes the typed artifact, so JSON member order does not change the hash.
    /// This digest alone does not authenticate an untrusted invitation.
    pub fn fingerprint(&self) -> Result<String, InvitationError> {
        let json = self.canonical_json()?;
        let mut digest = Sha256::new();
        digest.update(FINGERPRINT_DOMAIN);
        digest.update(json);
        Ok(hex::encode(digest.finalize()))
    }

    pub fn verify(self, trusted_fingerprint: &str) -> Result<VerifiedInvitation, InvitationError> {
        if !crate::valid_hex(trusted_fingerprint, 64) {
            return Err(InvitationError::Invalid);
        }
        if self.fingerprint()? != trusted_fingerprint {
            return Err(InvitationError::FingerprintMismatch);
        }
        Ok(VerifiedInvitation(self))
    }

    pub fn kind(&self) -> InvitationKind {
        self.kind
    }

    pub fn offer_fingerprint(&self) -> Option<&str> {
        self.offer_fingerprint.as_deref()
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn bundle(&self) -> &PublicBundle {
        &self.bundle
    }

    pub fn write_endpoint(&self) -> &QueueEndpoint {
        &self.write
    }

    fn validate(&self) -> Result<(), InvitationError> {
        if self.protocol != PROTOCOL || !crate::valid_hex(&self.nonce, 32) {
            return Err(InvitationError::Invalid);
        }
        match (self.kind, self.offer_fingerprint.as_deref()) {
            (InvitationKind::Offer, None) => {}
            (InvitationKind::Reply, Some(parent)) if crate::valid_hex(parent, 64) => {}
            _ => return Err(InvitationError::Invalid),
        }
        self.bundle
            .fingerprint()
            .map_err(|_| InvitationError::Invalid)?;
        // The codec permits the documented literal-loopback HTTP test form.
        // The worker must enforce its own actual transport policy before use.
        crate::Endpoint::parse(&self.write, true).map_err(|_| InvitationError::Invalid)?;
        Ok(())
    }

    fn canonical_json(&self) -> Result<Vec<u8>, InvitationError> {
        self.validate()?;
        let json = serde_json::to_vec(self).map_err(|_| InvitationError::Invalid)?;
        if json.len() > MAX_JSON_BYTES {
            return Err(InvitationError::TooLarge);
        }
        Ok(json)
    }
}

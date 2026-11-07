//! Account identity protects introductions. Chats retain independent Olm keys.
use super::*;
use vodozemac::Curve25519SecretKey;

/// Login is distinct from a freely chosen display nickname.
pub fn normalize_login(value: &str) -> Option<String> {
    let value = value.to_ascii_lowercase();
    ((3..=32).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'))
    .then_some(value)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AccountIdentity(Curve25519SecretKey);
impl Default for AccountIdentity {
    fn default() -> Self {
        Self(Curve25519SecretKey::new())
    }
}
impl AccountIdentity {
    pub fn public_key(&self) -> String {
        hex::encode(Curve25519PublicKey::from(&self.0).to_bytes())
    }
    fn context(
        &self,
        peer: &str,
        request: &str,
        outgoing: bool,
    ) -> Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
        if peer.len() != 64
            || request.len() != 32
            || !request
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::InvalidBundle);
        }
        let bytes = hex::decode(peer).map_err(|_| Error::InvalidBundle)?;
        let peer_key = Curve25519PublicKey::from_slice(&bytes).map_err(|_| Error::InvalidBundle)?;
        let shared = self
            .0
            .diffie_hellman(&peer_key)
            .ok_or(Error::InvalidBundle)?;
        let mine = self.public_key();
        let (sender, recipient) = if outgoing {
            (mine.as_str(), peer)
        } else {
            (peer, mine.as_str())
        };
        let aad = format!("KotoPizdelka.account-introduction.v1\0{request}\0{sender}\0{recipient}")
            .into_bytes();
        let mut key = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<Sha256>::new(None, shared.as_bytes())
            .expand(&aad, key.as_mut())
            .map_err(|_| Error::Encryption)?;
        Ok((key, aad))
    }
    pub fn seal_introduction(&self, peer: &str, request: &str, link: &str) -> Result<String> {
        if link.len() > 8192 {
            return Err(Error::TooLarge);
        }
        let (key, aad) = self.context(peer, request, true)?;
        let mut nonce = [0; 24];
        OsRng.fill_bytes(&mut nonce);
        let encrypted = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| Error::Encryption)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: link.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Encryption)?;
        Ok(STANDARD.encode([nonce.to_vec(), encrypted].concat()))
    }
    pub fn open_introduction(
        &self,
        peer: &str,
        request: &str,
        packet: &str,
    ) -> Result<Zeroizing<String>> {
        if packet.len() > 11000 {
            return Err(Error::TooLarge);
        }
        let bytes = STANDARD.decode(packet).map_err(|_| Error::InvalidMessage)?;
        if bytes.len() < 40 {
            return Err(Error::InvalidMessage);
        }
        let (key, aad) = self.context(peer, request, false)?;
        let plain = Zeroizing::new(
            XChaCha20Poly1305::new_from_slice(key.as_ref())
                .map_err(|_| Error::Encryption)?
                .decrypt(
                    XNonce::from_slice(&bytes[..24]),
                    Payload {
                        msg: &bytes[24..],
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::InvalidMessage)?,
        );
        String::from_utf8(plain.to_vec())
            .map(Zeroizing::new)
            .map_err(|_| Error::InvalidMessage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn introductions_bind_both_identities_and_request() {
        let alice = AccountIdentity::default();
        let bob = AccountIdentity::default();
        let eve = AccountIdentity::default();
        let request = "a".repeat(32);
        let wire = alice
            .seal_introduction(&bob.public_key(), &request, "private link")
            .unwrap();
        assert_eq!(
            bob.open_introduction(&alice.public_key(), &request, &wire)
                .unwrap()
                .as_str(),
            "private link"
        );
        assert!(eve
            .open_introduction(&alice.public_key(), &request, &wire)
            .is_err());
        assert!(bob
            .open_introduction(&alice.public_key(), &"b".repeat(32), &wire)
            .is_err());
        assert!(bob
            .open_introduction(&eve.public_key(), &request, &wire)
            .is_err());
        assert!(alice
            .seal_introduction(&"0".repeat(64), &request, "link")
            .is_err());
    }
    #[test]
    fn login_rules_are_unambiguous() {
        assert_eq!(normalize_login("My_Cat"), Some("my_cat".into()));
        for value in ["ab", " кот ", "cat/name", "1cat", "cat@", "cat ", ""] {
            assert!(normalize_login(value).is_none());
        }
    }
}

//! Names are local sealed records; peer names arrive in typed Olm controls.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use messenger_core::valid_nickname;

pub const PROFILE_PREFIX: &[u8] = b"koto-profile:v1:";
#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ProfileName {
    pub nickname: String,
    pub revision: u64,
}
#[derive(Default, Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContactNames {
    pub nickname: String,
    pub alias: String,
    pub received_revision: u64,
    pub sent_revision: u64,
}
fn read_profile(db: &Connection, key: &StorageKey, db_id: &str) -> Result<ProfileName> {
    let blob: Option<Vec<u8>> = db
        .query_row(
            "SELECT record FROM profile_name WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .optional()?;
    let Some(blob) = blob else {
        return Ok(ProfileName::default());
    };
    let plain = unseal(key, db_id, "profile-name", "", "", &blob)?;
    let value: ProfileName = serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
    if !valid_nickname(&value.nickname) || value.revision > 9_007_199_254_740_991 {
        return Err(Error::InvalidRecord);
    }
    Ok(value)
}
fn read_names(
    db: &Connection,
    key: &StorageKey,
    db_id: &str,
    contact: &str,
) -> Result<ContactNames> {
    ids(contact, None)?;
    // A missing/deleted contact is not silently recreated by a name update.
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM contacts WHERE id=?)",
        [contact],
        |r| r.get(0),
    )?;
    if !exists {
        return Err(Error::NotFound);
    }
    let blob: Option<Vec<u8>> = db
        .query_row(
            "SELECT record FROM contact_names WHERE contact=?",
            [contact],
            |r| r.get(0),
        )
        .optional()?;
    let Some(blob) = blob else {
        return Ok(ContactNames::default());
    };
    let plain = unseal(key, db_id, "contact-name", contact, "", &blob)?;
    let value: ContactNames = serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
    if !valid_nickname(&value.nickname)
        || !valid_nickname(&value.alias)
        || value.received_revision > 9_007_199_254_740_991
        || value.sent_revision > 9_007_199_254_740_991
    {
        return Err(Error::InvalidRecord);
    }
    Ok(value)
}
fn save_names(
    tx: &Transaction<'_>,
    key: &StorageKey,
    db_id: &str,
    contact: &str,
    names: &ContactNames,
) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(names).map_err(|_| Error::InvalidRecord)?);
    let record = seal(key, db_id, "contact-name", contact, "", &bytes)?;
    tx.execute("INSERT INTO contact_names VALUES(?,?) ON CONFLICT(contact) DO UPDATE SET record=excluded.record", params![contact, record])?;
    Ok(())
}
impl ClientStore {
    pub fn profile_name(&self) -> Result<ProfileName> {
        read_profile(&self.db, &self.key, &self.db_id)
    }
    pub fn contact_names(&self, contact: &str) -> Result<ContactNames> {
        read_names(&self.db, &self.key, &self.db_id, contact)
    }
    pub fn set_nickname(&mut self, nickname: &str) -> Result<()> {
        if !valid_nickname(nickname) {
            return Err(Error::InvalidRecord);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut profile = read_profile(&tx, &self.key, &self.db_id)?;
        if profile.nickname != nickname {
            profile.nickname = nickname.into();
            profile.revision = profile
                .revision
                .checked_add(1)
                .filter(|r| *r <= 9_007_199_254_740_991)
                .ok_or(Error::QuotaExceeded)?;
            let bytes =
                Zeroizing::new(serde_json::to_vec(&profile).map_err(|_| Error::InvalidRecord)?);
            let record = seal(&self.key, &self.db_id, "profile-name", "", "", &bytes)?;
            tx.execute("INSERT INTO profile_name VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET record=excluded.record", [record])?;
        }
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn set_contact_alias(&mut self, contact: &str, alias: &str) -> Result<()> {
        if !valid_nickname(alias) {
            return Err(Error::InvalidRecord);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut names = read_names(&tx, &self.key, &self.db_id, contact)?;
        names.alias = alias.into();
        save_names(&tx, &self.key, &self.db_id, contact, &names)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    /// Queue once per durable profile revision. Retry uses the exact ciphertext.
    /// No nickname means no new frame for users who never configured a profile.
    pub fn enqueue_profile(&mut self, contact: &str) -> Result<()> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let profile = read_profile(&tx, &self.key, &self.db_id)?;
        let mut names = read_names(&tx, &self.key, &self.db_id, contact)?;
        if profile.revision <= names.sent_revision {
            return Ok(());
        }
        let mut state = load_contact(&tx, &self.key, &self.db_id, contact)?;
        check_quota(&tx, contact, "out")?;
        let mut envelope = state.encrypt_profile(&profile.nickname, profile.revision)?;
        let mut wire = PROFILE_PREFIX.to_vec();
        wire.extend(
            STANDARD
                .decode(&envelope.payload)
                .map_err(|_| Error::InvalidRecord)?,
        );
        envelope.payload = STANDARD.encode(wire);
        let bytes = Zeroizing::new(
            serde_json::to_vec(&MessageRef {
                envelope: &envelope,
                text: "",
            })
            .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "out", contact, &envelope.id, &bytes)?;
        tx.execute("INSERT INTO messages(contact,direction,id,record,pending,kind) VALUES(?,'out',?,?,1,'profile')", params![contact, envelope.id, record])?;
        names.sent_revision = profile.revision;
        save_names(&tx, &self.key, &self.db_id, contact, &names)?;
        save_contact(&tx, &self.key, &self.db_id, contact, &state)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    /// Authenticate label, purpose and revision before changing either ratchet
    /// or names. Delayed earlier controls cannot revert a more recent name.
    pub fn accept_profile(&mut self, contact: &str, envelope: &Envelope) -> Result<AcceptStatus> {
        ids(contact, Some(&envelope.id))?;
        if envelope.payload.len() > MAX_ENVELOPE_PAYLOAD {
            return Err(Error::Crypto(messenger_core::Error::TooLarge));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(Vec<u8>, String)> = tx
            .query_row(
                "SELECT record,kind FROM messages WHERE contact=? AND direction='in' AND id=?",
                params![contact, envelope.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((blob, kind)) = previous {
            let record = decode_record(&self.key, &self.db_id, "in", contact, &envelope.id, &blob)?;
            if kind != "profile" || record.envelope.payload != envelope.payload {
                return Err(Error::Conflict);
            }
            tx.execute(
                "UPDATE messages SET pending=1 WHERE contact=? AND direction='in' AND id=?",
                params![contact, envelope.id],
            )?;
            tx.commit()?;
            return Ok(AcceptStatus::Duplicate);
        }
        let raw = STANDARD
            .decode(&envelope.payload)
            .map_err(|_| Error::Crypto(messenger_core::Error::InvalidMessage))?;
        let wire = raw
            .strip_prefix(PROFILE_PREFIX)
            .ok_or(Error::Crypto(messenger_core::Error::InvalidMessage))?;
        let inner = Envelope {
            id: envelope.id.clone(),
            payload: STANDARD.encode(wire),
        };
        let mut state = load_contact(&tx, &self.key, &self.db_id, contact)?;
        let profile = state.decrypt_profile(&inner)?;
        let mut names = read_names(&tx, &self.key, &self.db_id, contact)?;
        check_quota(&tx, contact, "in")?;
        if profile.revision > names.received_revision {
            names.nickname = profile.nickname;
            names.received_revision = profile.revision;
            save_names(&tx, &self.key, &self.db_id, contact, &names)?;
        }
        let bytes = Zeroizing::new(
            serde_json::to_vec(&MessageRef { envelope, text: "" })
                .map_err(|_| Error::InvalidRecord)?,
        );
        let record = seal(&self.key, &self.db_id, "in", contact, &envelope.id, &bytes)?;
        tx.execute("INSERT INTO messages(contact,direction,id,record,pending,kind) VALUES(?,'in',?,?,1,'profile')", params![contact,envelope.id,record])?;
        save_contact(&tx, &self.key, &self.db_id, contact, &state)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(AcceptStatus::New)
    }
}

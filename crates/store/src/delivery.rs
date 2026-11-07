//! Typed delivery replies share the durable chat outbox and Olm ratchet.
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

pub const DELIVERY_PREFIX: &[u8] = b"koto-delivery:v1:";
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Queued,
    Server,
    Delivered,
}

pub(super) fn queue_receipt(
    tx: &Transaction<'_>,
    key: &StorageKey,
    db_id: &str,
    contact: &str,
    state: &mut Contact,
    message: &str,
) -> Result<()> {
    check_quota(tx, contact, "out")?;
    let mut envelope = state.encrypt_delivery(message)?;
    let mut wire = DELIVERY_PREFIX.to_vec();
    wire.extend(
        STANDARD
            .decode(&envelope.payload)
            .map_err(|_| Error::InvalidRecord)?,
    );
    envelope.payload = STANDARD.encode(wire);
    let plain = Zeroizing::new(
        serde_json::to_vec(&MessageRef {
            envelope: &envelope,
            text: "",
        })
        .map_err(|_| Error::InvalidRecord)?,
    );
    let record = seal(key, db_id, "out", contact, &envelope.id, &plain)?;
    tx.execute("INSERT INTO messages(contact,direction,id,record,pending,kind) VALUES(?,'out',?,?,1,'delivery')", params![contact,envelope.id,record])?;
    Ok(())
}
impl ClientStore {
    /// A receipt must authenticate inside the pinned chat session, refer to an
    /// existing outgoing user message, and be saved before its relay ACK.
    pub fn accept_delivery(&mut self, contact: &str, envelope: &Envelope) -> Result<AcceptStatus> {
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
            if kind != "delivery" || record.envelope.payload != envelope.payload {
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
            .strip_prefix(DELIVERY_PREFIX)
            .ok_or(Error::Crypto(messenger_core::Error::InvalidMessage))?;
        let inner = Envelope {
            id: envelope.id.clone(),
            payload: STANDARD.encode(wire),
        };
        let mut state = load_contact(&tx, &self.key, &self.db_id, contact)?;
        let message = state.decrypt_delivery(&inner)?;
        let blob: Option<Vec<u8>>=tx.query_row("SELECT record FROM messages WHERE contact=? AND direction='out' AND kind='text' AND id=?",params![contact,message],|r|r.get(0)).optional()?;
        let Some(blob) = blob else {
            return Err(Error::Crypto(messenger_core::Error::InvalidMessage));
        };
        let mut record = decode_record(&self.key, &self.db_id, "out", contact, &message, &blob)?;
        record.delivered = true;
        let plain = Zeroizing::new(serde_json::to_vec(&record).map_err(|_| Error::InvalidRecord)?);
        let sealed = seal(&self.key, &self.db_id, "out", contact, &message, &plain)?;
        check_quota(&tx, contact, "in")?;
        // A valid peer receipt also proves acceptance when a POST response was lost.
        tx.execute(
            "UPDATE messages SET record=?,pending=0 WHERE contact=? AND direction='out' AND id=?",
            params![sealed, contact, message],
        )?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&MessageRef { envelope, text: "" })
                .map_err(|_| Error::InvalidRecord)?,
        );
        let sealed = seal(&self.key, &self.db_id, "in", contact, &envelope.id, &plain)?;
        tx.execute("INSERT INTO messages(contact,direction,id,record,pending,kind) VALUES(?,'in',?,?,1,'delivery')",params![contact,envelope.id,sealed])?;
        save_contact(&tx, &self.key, &self.db_id, contact, &state)?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(AcceptStatus::New)
    }
}

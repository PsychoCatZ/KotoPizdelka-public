//! Local account identity and session are sealed with the profile storage key.
use super::*;
use messenger_core::accounts::{normalize_login, AccountIdentity};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountState {
    pub login: String,
    pub relay_url: String,
    pub identity: AccountIdentity,
    pub session: String,
    pub registered: bool,
    pub authenticated: bool,
    pub cursor: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountJob {
    pub id: String,
    pub peer_login: String,
    pub peer_key: String,
    pub incoming: bool,
    pub contact: Option<String>,
    pub ticket: Option<String>,
    pub offer: Option<String>,
    pub approved: bool,
    pub deleted: bool,
    pub status: String,
    pub expires_at: i64,
}
impl AccountState {
    fn valid(&self) -> bool {
        normalize_login(&self.login).as_deref() == Some(&self.login)
            && self.relay_url.len() <= 2048
            && valid_hex(&self.session, 64)
    }
}
impl AccountJob {
    fn valid(&self) -> bool {
        valid_id(&self.id)
            && normalize_login(&self.peer_login).as_deref() == Some(&self.peer_login)
            && valid_hex(&self.peer_key, 64)
            && self.contact.as_ref().is_none_or(|c| valid_id(c))
            && self.ticket.as_ref().is_none_or(|t| valid_hex(t, 64))
            && self.offer.as_ref().is_none_or(|o| o.len() <= 11000)
    }
}
impl ClientStore {
    pub fn account(&self) -> Result<Option<AccountState>> {
        let blob: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT record FROM account_state WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()?;
        blob.map(|blob| {
            let plain = unseal(&self.key, &self.db_id, "account", "", "", &blob)?;
            let state: AccountState =
                serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
            if !state.valid() {
                return Err(Error::InvalidRecord);
            }
            Ok(state)
        })
        .transpose()
    }
    pub fn save_account(&mut self, state: &AccountState) -> Result<()> {
        if !state.valid() {
            return Err(Error::InvalidRecord);
        }
        let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| Error::InvalidRecord)?);
        let blob = seal(&self.key, &self.db_id, "account", "", "", &plain)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute("INSERT INTO account_state VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET record=excluded.record",[blob])?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
    pub fn account_jobs(&self) -> Result<Vec<AccountJob>> {
        let mut q = self
            .db
            .prepare("SELECT id,record FROM account_jobs ORDER BY rowid LIMIT 129")?;
        let records = q
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if records.len() > 128 {
            return Err(Error::InvalidRecord);
        }
        records
            .into_iter()
            .map(|(id, blob)| {
                let plain = unseal(&self.key, &self.db_id, "account-job", &id, "", &blob)?;
                let job: AccountJob =
                    serde_json::from_slice(&plain).map_err(|_| Error::InvalidRecord)?;
                if job.id != id || !job.valid() {
                    return Err(Error::InvalidRecord);
                }
                Ok(job)
            })
            .collect()
    }
    pub fn save_account_job(&mut self, job: &AccountJob) -> Result<()> {
        if !job.valid() {
            return Err(Error::InvalidRecord);
        }
        let plain = Zeroizing::new(serde_json::to_vec(job).map_err(|_| Error::InvalidRecord)?);
        let blob = seal(&self.key, &self.db_id, "account-job", &job.id, "", &plain)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row(
            "SELECT count(*) FROM account_jobs WHERE id<>?",
            [&job.id],
            |r| r.get(0),
        )?;
        if count >= 128 {
            return Err(Error::QuotaExceeded);
        }
        tx.execute("INSERT INTO account_jobs VALUES(?,?) ON CONFLICT(id) DO UPDATE SET record=excluded.record",params![job.id,blob])?;
        check_total_bytes(&tx)?;
        tx.commit()?;
        Ok(())
    }
}

//! Password-protected portable archive. Restored ratchets are never resumed.
use super::*;
use argon2::{Algorithm, Argon2, Params, Version};
use std::io::{Read, Write};

const MAGIC: &[u8] = b"KotoPizdelka.profile-backup.v1\0";
pub const MAX_ARCHIVE: usize = 128 * 1024 * 1024;
const SALT: usize = 16;
const NONCE: usize = 24;

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backup password must contain 12 to 128 characters (at most 512 UTF-8 bytes)")]
    Password,
    #[error("invalid backup or incorrect password")]
    Invalid,
    #[error("backup file operation failed")]
    Io,
    #[error("profile backup exceeds its size limit")]
    TooLarge,
    #[error("profile validation failed")]
    Store,
}
impl From<super::Error> for BackupError {
    fn from(_: super::Error) -> Self {
        Self::Store
    }
}
type BResult<T> = std::result::Result<T, BackupError>;
pub fn valid_password(password: &str) -> bool {
    (12..=128).contains(&password.chars().count()) && password.len() <= 512
}
fn derive(password: &str, salt: &[u8]) -> BResult<Zeroizing<[u8; 32]>> {
    if !valid_password(password) {
        return Err(BackupError::Password);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    // Fixed, versioned parameters: an untrusted header cannot request unbounded work.
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| BackupError::Invalid)?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| BackupError::Invalid)?;
    Ok(key)
}
/// Returns an authenticated storage key and database bytes ONLY to native callers.
pub fn decrypt(bytes: &[u8], password: &str) -> BResult<(StorageKey, Zeroizing<Vec<u8>>)> {
    let header = MAGIC.len() + SALT + NONCE;
    if bytes.len() < header + 16 + 32 + 100
        || bytes.len() > MAX_ARCHIVE
        || !bytes.starts_with(MAGIC)
    {
        return Err(BackupError::Invalid);
    }
    let key = derive(password, &bytes[MAGIC.len()..MAGIC.len() + SALT])?;
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| BackupError::Invalid)?
            .decrypt(
                XNonce::from_slice(&bytes[MAGIC.len() + SALT..header]),
                Payload {
                    msg: &bytes[header..],
                    aad: &bytes[..header],
                },
            )
            .map_err(|_| BackupError::Invalid)?,
    );
    if plain.len() < 132 || &plain[32..48] != b"SQLite format 3\0" {
        return Err(BackupError::Invalid);
    }
    let mut raw = Zeroizing::new([0u8; 32]);
    raw.copy_from_slice(&plain[..32]);
    Ok((
        StorageKey::from_bytes(*raw),
        Zeroizing::new(plain[32..].to_vec()),
    ))
}
impl ClientStore {
    pub fn export_backup(&self, password: &str) -> BResult<Vec<u8>> {
        if !valid_password(password) {
            return Err(BackupError::Password);
        }
        let file = tempfile::NamedTempFile::new().map_err(|_| BackupError::Io)?;
        self.db
            .backup(rusqlite::DatabaseName::Main, file.path(), None)
            .map_err(|_| BackupError::Store)?;
        let size = file
            .as_file()
            .metadata()
            .map_err(|_| BackupError::Io)?
            .len() as usize;
        if size > MAX_ARCHIVE - 256 {
            return Err(BackupError::TooLarge);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(32 + size));
        plain.extend_from_slice(self.key.as_bytes());
        file.reopen()
            .map_err(|_| BackupError::Io)?
            .take((MAX_ARCHIVE + 1) as u64)
            .read_to_end(&mut plain)
            .map_err(|_| BackupError::Io)?;
        if plain.len() > MAX_ARCHIVE - 128 {
            return Err(BackupError::TooLarge);
        }
        let mut header = MAGIC.to_vec();
        let mut salt = [0; SALT];
        OsRng.fill_bytes(&mut salt);
        let mut nonce = [0; NONCE];
        OsRng.fill_bytes(&mut nonce);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        let key = derive(password, &salt)?;
        let encrypted = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| BackupError::Invalid)?
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .map_err(|_| BackupError::Invalid)?;
        header.extend_from_slice(&encrypted);
        Ok(header)
    }
    /// Called on a private staging database, never on the running profile.
    pub fn prepare_recovery(&mut self) -> BResult<()> {
        let integrity: String = self
            .db
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .map_err(|_| BackupError::Invalid)?;
        if integrity != "ok" {
            return Err(BackupError::Invalid);
        }
        let broken: bool = self
            .db
            .prepare("PRAGMA foreign_key_check")
            .map_err(|_| BackupError::Invalid)?
            .exists([])
            .map_err(|_| BackupError::Invalid)?;
        if broken {
            return Err(BackupError::Invalid);
        }
        check_total_bytes(
            &self
                .db
                .transaction_with_behavior(TransactionBehavior::Deferred)
                .map_err(super::Error::from)?,
        )?;
        let contacts = self.contact_ids()?;
        for id in &contacts {
            self.contact_names(id)?;
            let blob: Vec<u8> = self
                .db
                .query_row("SELECT state FROM contacts WHERE id=?", [id], |r| r.get(0))
                .map_err(super::Error::from)?;
            let saved = unseal(&self.key, &self.db_id, "contact", id, "", &blob)?;
            Contact::restore(&saved, &self.key).map_err(|_| BackupError::Invalid)?;
            let mut cursor = 0;
            loop {
                let page = self.history(id, cursor)?;
                if page.is_empty() {
                    break;
                }
                cursor = page.last().ok_or(BackupError::Invalid)?.sequence;
            }
        }
        self.profile_name()?;
        self.retired_records()?;
        if let Some(mut state) = self.account()? {
            state.authenticated = false;
            let mut random = [0; 32];
            OsRng.fill_bytes(&mut random);
            state.session = hex::encode(random);
            state.cursor = 0;
            self.save_account(&state)?;
        }
        for mut job in self.account_jobs()? {
            job.deleted = true;
            job.contact = None;
            job.ticket = None;
            job.offer = None;
            self.save_account_job(&job)?;
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(super::Error::from)?;
        tx.execute_batch("INSERT OR IGNORE INTO archived_contacts SELECT id FROM contacts; DELETE FROM routes; UPDATE messages SET pending=0;").map_err(super::Error::from)?;
        tx.commit().map_err(super::Error::from)?;
        self.db
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .map_err(super::Error::from)?;
        Ok(())
    }
}
/// Persist only the still record-encrypted database; the plaintext storage key stays in memory.
pub fn write_database(file: &mut std::fs::File, bytes: &[u8]) -> BResult<()> {
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| BackupError::Io)
}

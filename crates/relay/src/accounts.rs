//! Bounded account directory. Password work never holds the relay database lock.
use super::*;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::collections::HashMap;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;
const SESSION_TTL: i64 = 30 * 24 * 3600;
const REQUEST_TTL: i64 = 7 * 24 * 3600;
const ACCOUNT_CAP: i64 = 256;
const REQUEST_CAP: i64 = 32;

pub(super) fn schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS accounts(
        login TEXT PRIMARY KEY, public_key TEXT NOT NULL UNIQUE, verifier TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS account_sessions(
        token_hash BLOB PRIMARY KEY, login TEXT NOT NULL REFERENCES accounts(login), expires INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS account_session_owner ON account_sessions(login);
        CREATE TABLE IF NOT EXISTS account_requests(
        id TEXT PRIMARY KEY, sender TEXT NOT NULL REFERENCES accounts(login), recipient TEXT NOT NULL REFERENCES accounts(login),
        status TEXT NOT NULL CHECK(status IN ('pending','accepted','rejected')), expires INTEGER NOT NULL,
        ticket_hash BLOB, offer TEXT);
        CREATE INDEX IF NOT EXISTS account_request_sender ON account_requests(sender);
        CREATE INDEX IF NOT EXISTS account_request_recipient ON account_requests(recipient);
        CREATE TABLE IF NOT EXISTS account_link_tickets(
        ticket_hash BLOB PRIMARY KEY, login TEXT NOT NULL REFERENCES accounts(login), issued INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS account_link_ticket_owner ON account_link_tickets(login,issued);")
}
fn login(value: &str) -> Result<String> {
    let v = value.to_ascii_lowercase();
    if !(3..=32).contains(&v.len())
        || !v.as_bytes()[0].is_ascii_lowercase()
        || !v
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    Ok(v)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    pub login: String,
    pub password: String,
    pub public_key: String,
    pub session: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub login: String,
    pub public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewRequest {
    pub id: String,
    pub login: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ContactRequest {
    pub id: String,
    pub peer: User,
    pub incoming: bool,
    pub status: String,
    pub expires_at: i64,
    pub offer: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ticket {
    pub ticket: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub offer: String,
}

/// No IP retention. Both global and per-login budgets bound CPU and memory.
#[derive(Default)]
pub(super) struct AuthBudget {
    window: i64,
    total: usize,
    logins: HashMap<String, usize>,
}
impl AuthBudget {
    fn take(&mut self, key: &str, timestamp: i64) -> Result<()> {
        if timestamp - self.window >= 60 {
            self.window = timestamp;
            self.total = 0;
            self.logins.clear();
        }
        if self.total >= 30 || self.logins.get(key).copied().unwrap_or(0) >= 5 {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS));
        }
        self.total += 1;
        *self.logins.entry(key.into()).or_default() += 1;
        Ok(())
    }
}
pub(super) fn password_workers() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(2))
}
fn authenticate(db: &Connection, cap: &str, timestamp: i64) -> Result<String> {
    if !valid_hex(cap, 64) {
        return Err(Error(StatusCode::UNAUTHORIZED));
    }
    db.query_row(
        "SELECT login FROM account_sessions WHERE token_hash=? AND expires>?",
        params![hash(cap.as_bytes()), timestamp],
        |r| r.get(0),
    )
    .optional()?
    .ok_or(Error(StatusCode::UNAUTHORIZED))
}
fn session(db: &Transaction<'_>, owner: &str, cap: &str, timestamp: i64) -> Result<()> {
    db.execute("DELETE FROM account_sessions WHERE expires<=?", [timestamp])?;
    let n: i64 = db.query_row(
        "SELECT count(*) FROM account_sessions WHERE login=?",
        [owner],
        |r| r.get(0),
    )?;
    let existing: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM account_sessions WHERE token_hash=? AND login=?)",
        params![hash(cap.as_bytes()), owner],
        |r| r.get(0),
    )?;
    if n >= 8 && !existing {
        return Err(Error(StatusCode::TOO_MANY_REQUESTS));
    }
    db.execute("INSERT INTO account_sessions(token_hash,login,expires) VALUES(?,?,?) ON CONFLICT(token_hash) DO UPDATE SET expires=excluded.expires WHERE login=excluded.login",params![hash(cap.as_bytes()),owner,timestamp+SESSION_TTL])?;
    let actual = authenticate(db, cap, timestamp)?;
    if actual != owner {
        return Err(Error(StatusCode::CONFLICT));
    }
    Ok(())
}
async fn credentials(state: AppState, input: Credentials, register: bool) -> Result<Json<User>> {
    let owner = login(&input.login)?;
    let password = Zeroizing::new(input.password);
    if !(10..=128).contains(&password.chars().count())
        || password.len() > 256
        || !valid_hex(&input.public_key, 64)
        || input.public_key == "0".repeat(64)
        || !valid_hex(&input.session, 64)
    {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    state
        .auth_budget
        .lock()
        .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?
        .take(&owner, now())?;
    let permit = state
        .password_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::TOO_MANY_REQUESTS))?;
    let lookup = owner.clone();
    let old: Option<(String, String)> = state
        .run(move |s| {
            Ok(s.db
                .query_row(
                    "SELECT verifier,public_key FROM accounts WHERE login=?",
                    [lookup],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?)
        })
        .await?;
    let existing = old.clone();
    let (verifier, verified) = tokio::task::spawn_blocking(move || -> Result<(String, bool)> {
        let _permit = permit;
        match existing {
            Some((verifier, _)) => {
                let parsed = PasswordHash::new(&verifier)
                    .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?;
                let verified = Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok();
                Ok((verifier, verified))
            }
            None => {
                let salt = SaltString::generate(&mut OsRng);
                let verifier = Argon2::default()
                    .hash_password(password.as_bytes(), &salt)
                    .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))?
                    .to_string();
                Ok((verifier, register))
            }
        }
    })
    .await
    .map_err(|_| Error(StatusCode::INTERNAL_SERVER_ERROR))??;
    if !verified {
        return Err(Error(if register {
            StatusCode::CONFLICT
        } else {
            StatusCode::UNAUTHORIZED
        }));
    }
    let public = input.public_key;
    if old.as_ref().is_some_and(|(_, key)| key != &public) {
        return Err(Error(StatusCode::CONFLICT));
    }
    let cap = input.session;
    let result = state
        .run(move |s| {
            let tx =
                s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            // Compare the verifier read before hashing; a racing registration cannot
            // bind a session using a password verified against a different account.
            let current: Option<(String, String)> = tx
                .query_row(
                    "SELECT verifier,public_key FROM accounts WHERE login=?",
                    [&owner],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if current != old {
                return Err(Error(StatusCode::CONFLICT));
            }
            if current.is_none() {
                if !register {
                    return Err(Error(StatusCode::UNAUTHORIZED));
                }
                let count: i64 = tx.query_row("SELECT count(*) FROM accounts", [], |r| r.get(0))?;
                if count >= ACCOUNT_CAP {
                    return Err(Error(StatusCode::TOO_MANY_REQUESTS));
                }
                tx.execute(
                    "INSERT INTO accounts(login,public_key,verifier) VALUES(?,?,?)",
                    params![owner, public, verifier],
                )?;
            }
            session(&tx, &owner, &cap, now())?;
            tx.commit()?;
            Ok(User {
                login: owner,
                public_key: public,
            })
        })
        .await?;
    Ok(Json(result))
}
async fn register(
    State(s): State<AppState>,
    input: std::result::Result<Json<Credentials>, JsonRejection>,
) -> Result<Json<User>> {
    credentials(
        s,
        input.map_err(|_| Error(StatusCode::BAD_REQUEST))?.0,
        true,
    )
    .await
}
async fn signin(
    State(s): State<AppState>,
    input: std::result::Result<Json<Credentials>, JsonRejection>,
) -> Result<Json<User>> {
    credentials(
        s,
        input.map_err(|_| Error(StatusCode::BAD_REQUEST))?.0,
        false,
    )
    .await
}
async fn logout(State(s): State<AppState>, h: HeaderMap) -> Result<StatusCode> {
    let cap = token(&h).to_owned();
    s.run(move |s| {
        authenticate(&s.db, &cap, now())?;
        s.db.execute(
            "DELETE FROM account_sessions WHERE token_hash=?",
            [hash(cap.as_bytes())],
        )?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn me(State(s): State<AppState>, h: HeaderMap) -> Result<Json<User>> {
    let cap = token(&h).to_owned();
    s.run(move |s| {
        let owner = authenticate(&s.db, &cap, now())?;
        Ok(Json(s.db.query_row(
            "SELECT login,public_key FROM accounts WHERE login=?",
            [owner],
            |r| {
                Ok(User {
                    login: r.get(0)?,
                    public_key: r.get(1)?,
                })
            },
        )?))
    })
    .await
}
async fn find(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<User>> {
    let name = login(&name)?;
    let cap = token(&h).to_owned();
    s.run(move |s| {
        authenticate(&s.db, &cap, now())?;
        Ok(Json(
            s.db.query_row(
                "SELECT login,public_key FROM accounts WHERE login=?",
                [name],
                |r| {
                    Ok(User {
                        login: r.get(0)?,
                        public_key: r.get(1)?,
                    })
                },
            )
            .optional()?
            .ok_or(Error(StatusCode::NOT_FOUND))?,
        ))
    })
    .await
}
async fn request(
    State(s): State<AppState>,
    h: HeaderMap,
    input: std::result::Result<Json<NewRequest>, JsonRejection>,
) -> Result<StatusCode> {
    let input = input.map_err(|_| Error(StatusCode::BAD_REQUEST))?.0;
    let peer = login(&input.login)?;
    if !valid_hex(&input.id, 32) {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    let cap = token(&h).to_owned();
    s.run(move|s|{
        let tx=s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;let owner=authenticate(&tx,&cap,now())?;
        if owner==peer {return Err(Error(StatusCode::BAD_REQUEST));}
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM accounts WHERE login=?)",[&peer],|r|r.get(0))?;
        if !exists {return Err(Error(StatusCode::NOT_FOUND));}
        let old:Option<(String,String)>=tx.query_row("SELECT sender,recipient FROM account_requests WHERE id=?",[&input.id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some(old)=old {if old!=(owner,peer) {return Err(Error(StatusCode::CONFLICT));}return Ok(());}
        tx.execute("DELETE FROM account_requests WHERE expires<=?",[now()])?;
        let count:i64=tx.query_row("SELECT count(*) FROM account_requests WHERE sender=?1 OR recipient=?1 OR sender=?2 OR recipient=?2",params![owner,peer],|r|r.get(0))?;
        if count>=REQUEST_CAP {return Err(Error(StatusCode::TOO_MANY_REQUESTS));}
        tx.execute("INSERT INTO account_requests(id,sender,recipient,status,expires) VALUES(?,?,?,'pending',?)",params![input.id,owner,peer,now()+REQUEST_TTL])?;tx.commit()?;Ok(())
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn list(State(s): State<AppState>, h: HeaderMap) -> Result<Json<Vec<ContactRequest>>> {
    let cap = token(&h).to_owned();
    s.run(move|s|{
        let owner=authenticate(&s.db,&cap,now())?;
        let mut q=s.db.prepare("SELECT r.id,a.login,a.public_key,r.recipient=?1,r.status,r.expires,r.offer FROM account_requests r JOIN accounts a ON a.login=CASE WHEN r.sender=?1 THEN r.recipient ELSE r.sender END WHERE (r.sender=?1 OR r.recipient=?1) AND r.expires>?2 ORDER BY r.rowid LIMIT 32")?;
        let result=q.query_map(params![owner,now()],|r|Ok(ContactRequest{id:r.get(0)?,peer:User{login:r.get(1)?,public_key:r.get(2)?},incoming:r.get(3)?,status:r.get(4)?,expires_at:r.get(5)?,offer:r.get(6)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;Ok(Json(result))
    }).await
}
async fn decision(
    s: AppState,
    h: HeaderMap,
    id: String,
    status: &'static str,
) -> Result<StatusCode> {
    if !valid_hex(&id, 32) {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    let cap = token(&h).to_owned();
    s.run(move |s| {
        let owner = authenticate(&s.db, &cap, now())?;
        let current: Option<String> =
            s.db.query_row(
                "SELECT status FROM account_requests WHERE id=? AND recipient=? AND expires>?",
                params![id, owner, now()],
                |r| r.get(0),
            )
            .optional()?;
        let current = current.ok_or(Error(StatusCode::NOT_FOUND))?;
        if current != status && current != "pending" {
            return Err(Error(StatusCode::CONFLICT));
        }
        s.db.execute(
            "UPDATE account_requests SET status=? WHERE id=?",
            params![status, id],
        )?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn accept(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    decision(s, h, id, "accepted").await
}
async fn reject(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    decision(s, h, id, "rejected").await
}
async fn ticket(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    input: std::result::Result<Json<Ticket>, JsonRejection>,
) -> Result<StatusCode> {
    let ticket = input.map_err(|_| Error(StatusCode::BAD_REQUEST))?.0.ticket;
    if !valid_hex(&id, 32) || !valid_hex(&ticket, 64) {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    let cap = token(&h).to_owned();
    s.run(move|s|{let tx=s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;let owner=authenticate(&tx,&cap,now())?;
        let old:Option<Option<Vec<u8>>>=tx.query_row("SELECT ticket_hash FROM account_requests WHERE id=? AND sender=? AND status='accepted' AND expires>?",params![id,owner,now()],|r|r.get(0)).optional()?;
        let old=old.ok_or(Error(StatusCode::NOT_FOUND))?;let digest=hash(ticket.as_bytes());
        if let Some(old)=old {if old!=digest{return Err(Error(StatusCode::CONFLICT));}return Ok(());}
        let count:i64=tx.query_row("SELECT count(*) FROM queue_tickets WHERE expires>?",[now()],|r|r.get(0))?;
        if count>=MAX_TICKETS{return Err(Error(StatusCode::TOO_MANY_REQUESTS));}
        tx.execute("INSERT INTO queue_tickets(ticket_hash,expires,can_invite) VALUES(?,?,1)",params![digest,now()+MAX_TICKET_TTL])?;
        tx.execute("UPDATE account_requests SET ticket_hash=? WHERE id=?",params![digest,id])?;tx.commit()?;Ok(())
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn offer(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<String>,
    input: std::result::Result<Json<Offer>, JsonRejection>,
) -> Result<StatusCode> {
    let offer = input.map_err(|_| Error(StatusCode::BAD_REQUEST))?.0.offer;
    if !valid_hex(&id, 32)
        || offer.len() > 11000
        || STANDARD.decode(&offer).map_or(true, |b| b.len() < 40)
    {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    let cap = token(&h).to_owned();
    s.run(move|s|{let owner=authenticate(&s.db,&cap,now())?;
        let old:Option<Option<String>>=s.db.query_row("SELECT offer FROM account_requests WHERE id=? AND sender=? AND status='accepted' AND ticket_hash IS NOT NULL AND expires>?",params![id,owner,now()],|r|r.get(0)).optional()?;
        let old=old.ok_or(Error(StatusCode::NOT_FOUND))?;
        if old.as_ref().is_some_and(|o|o!=&offer){return Err(Error(StatusCode::CONFLICT));}
        s.db.execute("UPDATE account_requests SET offer=? WHERE id=?",params![offer,id])?;Ok(())
    }).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Authenticated link creation without an operator ticket. The client chooses
/// and durably seals the secret before this request, so retries are idempotent.
async fn link_ticket(
    State(s): State<AppState>,
    h: HeaderMap,
    input: std::result::Result<Json<Ticket>, JsonRejection>,
) -> Result<StatusCode> {
    let ticket = input.map_err(|_| Error(StatusCode::BAD_REQUEST))?.0.ticket;
    if !valid_hex(&ticket, 64) {
        return Err(Error(StatusCode::BAD_REQUEST));
    }
    let cap = token(&h).to_owned();
    s.run(move |s| {
        let tx =
            s.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let timestamp = now();
        let owner = authenticate(&tx, &cap, timestamp)?;
        let digest = hash(ticket.as_bytes());
        tx.execute(
            "DELETE FROM account_link_tickets WHERE issued<=?",
            [timestamp - MAX_TICKET_TTL],
        )?;
        let old: Option<String> = tx
            .query_row(
                "SELECT login FROM account_link_tickets WHERE ticket_hash=?",
                [&digest],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = old {
            if old != owner {
                return Err(Error(StatusCode::CONFLICT));
            }
            tx.commit()?;
            return Ok(());
        }
        let own: i64 = tx.query_row(
            "SELECT count(*) FROM account_link_tickets WHERE login=?",
            [&owner],
            |r| r.get(0),
        )?;
        let all: i64 = tx.query_row(
            "SELECT count(*) FROM queue_tickets WHERE expires>?",
            [timestamp],
            |r| r.get(0),
        )?;
        if own >= 12 || all >= MAX_TICKETS {
            return Err(Error(StatusCode::TOO_MANY_REQUESTS));
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM queue_tickets WHERE ticket_hash=?)",
            [&digest],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(Error(StatusCode::CONFLICT));
        }
        tx.execute(
            "INSERT INTO queue_tickets(ticket_hash,expires,can_invite) VALUES(?,?,1)",
            params![digest, timestamp + MAX_TICKET_TTL],
        )?;
        tx.execute(
            "INSERT INTO account_link_tickets(ticket_hash,login,issued) VALUES(?,?,?)",
            params![digest, owner, timestamp],
        )?;
        tx.commit()?;
        Ok(())
    })
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/accounts/register", post(register))
        .route("/v1/accounts/login", post(signin))
        .route("/v1/accounts/session", get(me).delete(logout))
        .route("/v1/accounts/link-ticket", post(link_ticket))
        .route("/v1/accounts/users/{login}", get(find))
        .route("/v1/accounts/requests", get(list).post(request))
        .route("/v1/accounts/requests/{id}/accept", post(accept))
        .route("/v1/accounts/requests/{id}/reject", post(reject))
        .route("/v1/accounts/requests/{id}/ticket", post(ticket))
        .route("/v1/accounts/requests/{id}/offer", post(offer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request};
    use tower::ServiceExt;
    async fn call(
        app: Router,
        method: Method,
        path: &str,
        cap: Option<&str>,
        body: &str,
    ) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(cap) = cap {
            req = req.header("authorization", format!("Bearer {cap}"));
        }
        let response = app
            .oneshot(req.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        (
            response.status(),
            to_bytes(response.into_body(), 400000)
                .await
                .unwrap()
                .to_vec(),
        )
    }
    fn input(owner: &str, key: char, session: char, password: &str) -> String {
        format!(
            r#"{{"login":"{owner}","password":"{password}","public_key":"{}","session":"{}"}}"#,
            key.to_string().repeat(64),
            session.to_string().repeat(64)
        )
    }
    #[tokio::test]
    async fn link_tickets_require_session_bound_owner_and_daily_quota() {
        let state = AppState::new(Store::open(":memory:").unwrap(), &"a".repeat(64));
        let app = router(state.clone());
        let cap = "1".repeat(64);
        let other = "2".repeat(64);
        for (name, key, session) in [("alice", '8', '1'), ("bobby", '9', '2')] {
            assert_eq!(
                call(
                    app.clone(),
                    Method::POST,
                    "/v1/accounts/register",
                    None,
                    &input(name, key, session, "correct horse cat")
                )
                .await
                .0,
                StatusCode::OK
            );
        }
        let path = "/v1/accounts/link-ticket";
        let body = format!(r#"{{"ticket":"{}"}}"#, "3".repeat(64));
        assert_eq!(
            call(app.clone(), Method::POST, path, None, &body).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                path,
                Some(&cap),
                r#"{"ticket":"bad"}"#
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            call(app.clone(), Method::POST, path, Some(&cap), &body)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(app.clone(), Method::POST, path, Some(&cap), &body)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(app.clone(), Method::POST, path, Some(&other), &body)
                .await
                .0,
            StatusCode::CONFLICT
        );
        for i in 0..11 {
            let body = format!(r#"{{"ticket":"{:064x}"}}"#, i + 100);
            assert_eq!(
                call(app.clone(), Method::POST, path, Some(&cap), &body)
                    .await
                    .0,
                StatusCode::NO_CONTENT
            );
        }
        let last = format!(r#"{{"ticket":"{:064x}"}}"#, 999);
        assert_eq!(
            call(app.clone(), Method::POST, path, Some(&cap), &last)
                .await
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        // A retry still succeeds at the quota, without issuing another ticket.
        assert_eq!(
            call(app.clone(), Method::POST, path, Some(&cap), &body)
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        let count = state
            .run(|s| {
                Ok(s.db
                    .query_row("SELECT count(*) FROM queue_tickets", [], |r| {
                        r.get::<_, i64>(0)
                    })?)
            })
            .await
            .unwrap();
        assert_eq!(count, 12);
        assert_eq!(
            call(
                app.clone(),
                Method::DELETE,
                "/v1/accounts/session",
                Some(&cap),
                ""
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(app, Method::POST, path, Some(&cap), &body).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[test]
    fn auth_budget_bounds_accounts_and_resets() {
        let mut b = AuthBudget::default();
        for _ in 0..5 {
            b.take("cat", 100).unwrap();
        }
        assert_eq!(
            b.take("cat", 100).unwrap_err().0,
            StatusCode::TOO_MANY_REQUESTS
        );
        for i in 0..25 {
            b.take(&format!("cat{i}"), 100).unwrap();
        }
        assert!(b.take("new", 100).is_err());
        assert!(b.take("cat", 160).is_ok());
        assert_eq!(b.logins.len(), 1);
    }
    #[tokio::test]
    async fn auth_scope_approval_idempotency_revocation_and_old_routes() {
        let state = AppState::new(Store::open(":memory:").unwrap(), &"a".repeat(64));
        let app = router(state.clone());
        let a = "1".repeat(64);
        let b = "2".repeat(64);
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                "/v1/accounts/register",
                None,
                &input("alice", 'b', '1', "ten characters cat")
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                "/v1/accounts/register",
                None,
                &input("alice", 'b', '1', "ten characters cat")
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                "/v1/accounts/register",
                None,
                &input("bobby", 'c', '2', "ten characters bob")
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                "/v1/accounts/login",
                None,
                &input("alice", 'b', '3', "wrong password!")
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                "/v1/accounts/login",
                None,
                &input("alice", 'd', '3', "ten characters cat")
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            call(
                app.clone(),
                Method::GET,
                "/v1/accounts/users/bobby",
                None,
                ""
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let id = "4".repeat(32);
        let create = format!(r#"{{"id":"{id}","login":"bobby"}}"#);
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                "/v1/accounts/requests",
                Some(&a),
                &create
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        let base = format!("/v1/accounts/requests/{id}");
        let ticket = format!(r#"{{"ticket":"{}"}}"#, "5".repeat(64));
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                &format!("{base}/ticket"),
                Some(&a),
                &ticket
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                &format!("{base}/accept"),
                Some(&a),
                ""
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                &format!("{base}/accept"),
                Some(&b),
                ""
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                app.clone(),
                Method::POST,
                &format!("{base}/ticket"),
                Some(&b),
                &ticket
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
        for _ in 0..2 {
            assert_eq!(
                call(
                    app.clone(),
                    Method::POST,
                    &format!("{base}/ticket"),
                    Some(&a),
                    &ticket
                )
                .await
                .0,
                StatusCode::NO_CONTENT
            );
        }
        state
            .run(|s| {
                assert_eq!(
                    s.db.query_row("SELECT count(*) FROM queue_tickets", [], |r| r
                        .get::<_, i64>(0))?,
                    1
                );
                let verifier: String = s.db.query_row(
                    "SELECT verifier FROM accounts WHERE login='alice'",
                    [],
                    |r| r.get(0),
                )?;
                assert!(verifier.starts_with("$argon2id$"));
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            call(
                app.clone(),
                Method::DELETE,
                "/v1/accounts/session",
                Some(&a),
                ""
            )
            .await
            .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(
                app.clone(),
                Method::GET,
                "/v1/accounts/requests",
                Some(&a),
                ""
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(app.clone(), Method::GET, "/health", None, "").await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(app, Method::GET, "/", None, "").await.0,
            StatusCode::NOT_FOUND
        );
    }
}

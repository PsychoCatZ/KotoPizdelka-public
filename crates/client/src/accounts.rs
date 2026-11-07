//! Account APIs use the same HTTPS policy and serialized profile worker as chats.
use super::*;
pub use messenger_core::accounts::normalize_login;
use messenger_core::accounts::AccountIdentity;
use messenger_store::{AccountJob, AccountState};
use zeroize::Zeroizing;
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AccountUser {
    pub login: String,
    pub public_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteRequest {
    id: String,
    peer: AccountUser,
    incoming: bool,
    status: String,
    expires_at: i64,
    offer: Option<String>,
}
#[derive(Serialize)]
pub struct AccountView {
    pub login: Option<String>,
    pub authenticated: bool,
    pub registered: bool,
    pub requests: Vec<AccountRequestView>,
}
#[derive(Serialize)]
pub struct AccountRequestView {
    pub id: String,
    pub login: String,
    pub incoming: bool,
    pub status: String,
    pub contact: Option<String>,
}
fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = Zeroizing::new(vec![0; n]);
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(&*b)
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |t| t.as_secs() as i64)
}
impl ClientWorker {
    pub async fn create_account_link(&mut self) -> Result<crate::quick::QuickInvitation> {
        let account = self.signed_account()?;
        let ticket = random_hex(32);
        self.create_account_link_quick(&account.relay_url, &ticket, &account.login)
            .await
    }

    pub(crate) async fn authorize_account_link(
        &self,
        relay: &str,
        login: &str,
        ticket: &str,
    ) -> Result<()> {
        let account = self.signed_account()?;
        if account.relay_url != relay || account.login != login {
            return Err(Error::AccountClosed);
        }
        self.account_http(
            &account,
            reqwest::Method::POST,
            "/v1/accounts/link-ticket",
            Some(serde_json::json!({"ticket":ticket})),
        )
        .await?;
        Ok(())
    }

    async fn account_http(
        &self,
        state: &AccountState,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let mut endpoint = Endpoint::parse(
            &QueueEndpoint {
                relay_url: state.relay_url.clone(),
                queue_id: "0".repeat(32),
                token: state.session.clone(),
            },
            self.transport.allow_loopback_http,
        )?;
        endpoint.url.set_path(path);
        let mut req = self
            .transport
            .client(&endpoint)
            .request(method, endpoint.url.clone())
            .header(AUTHORIZATION, endpoint.bearer.clone());
        if let Some(body) = body {
            req = req.json(&body);
        }
        let mut response = req.send().await.map_err(|_| Error::RequestFailed)?;
        if !response.status().is_success() {
            return Err(Error::AccountRejected(response.status().as_u16()));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| Error::RequestFailed)? {
            if bytes.len() + chunk.len() > 384 * 1024 {
                return Err(Error::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
    fn signed_account(&self) -> Result<AccountState> {
        self.store
            .account()?
            .filter(|a| a.authenticated)
            .ok_or(Error::AccountClosed)
    }
    pub fn account_view(&self) -> Result<AccountView> {
        let account = self.store.account()?;
        let jobs = self.store.account_jobs()?;
        let mut requests = Vec::new();
        let contacts = self.store.contact_ids()?;
        for j in jobs {
            if j.deleted || j.contact.as_ref().is_some_and(|id| !contacts.contains(id)) {
                continue;
            }
            let ready = j
                .contact
                .as_ref()
                .map(|id| self.quick_invitation_status(id))
                .transpose()?
                .flatten()
                .is_some_and(|s| s.stage == "ready");
            if ready {
                continue;
            }
            let status = if now() >= j.expires_at {
                "expired"
            } else {
                j.status.as_str()
            };
            requests.push(AccountRequestView {
                id: j.id,
                login: j.peer_login,
                incoming: j.incoming,
                status: status.into(),
                contact: j.contact,
            });
        }
        Ok(AccountView {
            login: account.as_ref().map(|a| a.login.clone()),
            registered: account.as_ref().is_some_and(|a| a.registered),
            authenticated: account.is_some_and(|a| a.authenticated),
            requests,
        })
    }
    pub async fn authenticate_account(
        &mut self,
        relay: &str,
        login: &str,
        password: String,
        register: bool,
    ) -> Result<AccountView> {
        let password = Zeroizing::new(password);
        let login = normalize_login(login).ok_or(Error::InvalidResponse)?;
        if !(10..=128).contains(&password.chars().count()) || password.len() > 256 {
            return Err(Error::InvalidResponse);
        }
        let mut state = match self.store.account()? {
            Some(a) => {
                if (a.registered && a.login != login)
                    || a.relay_url.trim_end_matches('/') != relay.trim_end_matches('/')
                {
                    return Err(Error::AccountIdentityMismatch);
                }
                if !a.registered && a.login != login {
                    AccountState {
                        login: login.clone(),
                        ..a
                    }
                } else {
                    a
                }
            }
            None => AccountState {
                login: login.clone(),
                relay_url: relay.into(),
                identity: AccountIdentity::default(),
                session: random_hex(32),
                registered: false,
                authenticated: false,
                cursor: 0,
            },
        };
        // Validate endpoint before committing a candidate; a lost response is
        // retried with the same identity/session. Password is never saved.
        Endpoint::parse(
            &QueueEndpoint {
                relay_url: relay.into(),
                queue_id: "0".repeat(32),
                token: state.session.clone(),
            },
            self.transport.allow_loopback_http,
        )?;
        self.store.save_account(&state)?;
        let bytes=self.account_http(&state,reqwest::Method::POST,if register{"/v1/accounts/register"}else{"/v1/accounts/login"},Some(serde_json::json!({"login":login,"password":password.as_str(),"public_key":state.identity.public_key(),"session":state.session}))).await?;
        let user: AccountUser =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if user.login != state.login || user.public_key != state.identity.public_key() {
            return Err(Error::InvalidResponse);
        }
        state.registered = true;
        state.authenticated = true;
        self.store.save_account(&state)?;
        self.account_view()
    }
    pub async fn logout_account(&mut self) -> Result<AccountView> {
        let mut state = self.signed_account()?;
        self.account_http(
            &state,
            reqwest::Method::DELETE,
            "/v1/accounts/session",
            None,
        )
        .await?;
        state.authenticated = false;
        state.session = random_hex(32);
        self.store.save_account(&state)?;
        self.account_view()
    }
    pub async fn find_account(&self, login: &str) -> Result<AccountUser> {
        let login = normalize_login(login).ok_or(Error::InvalidResponse)?;
        let a = self.signed_account()?;
        let bytes = self
            .account_http(
                &a,
                reqwest::Method::GET,
                &format!("/v1/accounts/users/{login}"),
                None,
            )
            .await?;
        let user: AccountUser =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if user.login != login
            || !valid_hex(&user.public_key, 64)
            || user.public_key == "0".repeat(64)
        {
            return Err(Error::InvalidResponse);
        }
        Ok(user)
    }
    pub async fn add_account(&mut self, login: &str) -> Result<AccountView> {
        let a = self.signed_account()?;
        let peer = self.find_account(login).await?;
        if peer.login == a.login {
            return Err(Error::InvalidResponse);
        }
        let jobs = self.store.account_jobs()?;
        let job = jobs
            .into_iter()
            .find(|j| {
                !j.deleted
                    && !j.incoming
                    && j.peer_login == peer.login
                    && j.status != "rejected"
                    && j.expires_at > now()
            })
            .unwrap_or(AccountJob {
                id: random_hex(16),
                peer_login: peer.login,
                peer_key: peer.public_key,
                incoming: false,
                contact: None,
                ticket: None,
                offer: None,
                approved: true,
                deleted: false,
                status: "pending".into(),
                expires_at: now() + 7 * 24 * 3600,
            });
        self.store.save_account_job(&job)?;
        self.account_http(
            &a,
            reqwest::Method::POST,
            "/v1/accounts/requests",
            Some(serde_json::json!({"id":job.id,"login":job.peer_login})),
        )
        .await?;
        self.account_view()
    }
    pub async fn decide_account(&mut self, id: &str, accept: bool) -> Result<AccountView> {
        if !valid_hex(id, 32) {
            return Err(Error::InvalidResponse);
        }
        let a = self.signed_account()?;
        let mut job = self
            .store
            .account_jobs()?
            .into_iter()
            .find(|j| j.id == id && j.incoming && !j.deleted)
            .ok_or(Error::InvalidResponse)?;
        if job.expires_at <= now() {
            return Err(Error::QuickInvitationExpired);
        }
        job.approved = accept;
        job.status = if accept { "accepted" } else { "rejected" }.into();
        self.store.save_account_job(&job)?;
        self.account_http(
            &a,
            reqwest::Method::POST,
            &format!(
                "/v1/accounts/requests/{id}/{}",
                if accept { "accept" } else { "reject" }
            ),
            None,
        )
        .await?;
        self.account_view()
    }
    pub async fn sync_account(&mut self) -> Result<AccountView> {
        let Some(mut a) = self.store.account()? else {
            return self.account_view();
        };
        if !a.authenticated {
            return self.account_view();
        }
        let bytes = match self
            .account_http(&a, reqwest::Method::GET, "/v1/accounts/requests", None)
            .await
        {
            Err(Error::AccountRejected(401)) => {
                a.authenticated = false;
                self.store.save_account(&a)?;
                return self.account_view();
            }
            v => v?,
        };
        let remote: Vec<RemoteRequest> =
            serde_json::from_slice(&bytes).map_err(|_| Error::InvalidResponse)?;
        if remote.len() > 32 {
            return Err(Error::InvalidResponse);
        }
        let mut jobs = self.store.account_jobs()?;
        for r in &remote {
            if !valid_hex(&r.id, 32)
                || normalize_login(&r.peer.login).as_deref() != Some(&r.peer.login)
                || !valid_hex(&r.peer.public_key, 64)
                || !matches!(r.status.as_str(), "pending" | "accepted" | "rejected")
                || r.offer.as_ref().is_some_and(|o| o.len() > 11000)
            {
                return Err(Error::InvalidResponse);
            }
            if let Some(j) = jobs.iter_mut().find(|j| j.id == r.id) {
                if j.peer_login != r.peer.login
                    || j.peer_key != r.peer.public_key
                    || j.incoming != r.incoming
                {
                    return Err(Error::AccountIdentityMismatch);
                }
                if !(j.incoming && j.status == "rejected" && r.status == "pending") {
                    j.status = r.status.clone();
                }
                self.store.save_account_job(j)?;
            } else if r.incoming {
                let j = AccountJob {
                    id: r.id.clone(),
                    peer_login: r.peer.login.clone(),
                    peer_key: r.peer.public_key.clone(),
                    incoming: true,
                    contact: None,
                    ticket: None,
                    offer: None,
                    approved: false,
                    deleted: false,
                    status: r.status.clone(),
                    expires_at: r.expires_at,
                };
                self.store.save_account_job(&j)?;
                jobs.push(j);
            }
        }
        // One handshake per pass, rotating fairly. Existing chats remain usable
        // while a new recipient is offline or one handshake awaits a retry.
        if !jobs.is_empty() {
            for offset in 0..jobs.len() {
                let index = (a.cursor + offset) % jobs.len();
                let j = &jobs[index];
                if !j.deleted
                    && (j.approved
                        || (j.incoming
                            && j.status == "rejected"
                            && remote.iter().any(|r| r.id == j.id && r.status == "pending")))
                    && j.expires_at > now()
                {
                    a.cursor = (index + 1) % jobs.len();
                    self.store.save_account(&a)?;
                    let remote = remote.iter().find(|r| r.id == j.id);
                    self.advance_account_job(&a, j.clone(), remote).await?;
                    break;
                }
            }
        }
        self.account_view()
    }
    async fn advance_account_job(
        &mut self,
        a: &AccountState,
        mut j: AccountJob,
        remote: Option<&RemoteRequest>,
    ) -> Result<()> {
        if j.incoming && j.status == "rejected" {
            self.account_http(
                a,
                reqwest::Method::POST,
                &format!("/v1/accounts/requests/{}/reject", j.id),
                None,
            )
            .await?;
            return Ok(());
        }
        if j.contact.is_none() {
            j.contact = self.account_contact(&j.id)?;
            self.store.save_account_job(&j)?;
        }
        if let Some(id) = &j.contact {
            if !self.store.contact_ids()?.contains(id) {
                j.deleted = true;
                self.store.save_account_job(&j)?;
                return Ok(());
            }
            if self
                .quick_invitation_status(id)?
                .is_some_and(|s| s.stage == "ready")
            {
                return Ok(());
            }
        }
        let base = format!("/v1/accounts/requests/{}", j.id);
        if j.incoming {
            if remote.is_some_and(|r| r.status == "pending") {
                self.account_http(a, reqwest::Method::POST, &format!("{base}/accept"), None)
                    .await?;
                return Ok(());
            }
            if j.contact.is_none() {
                let Some(packet) = remote.and_then(|r| r.offer.as_ref()) else {
                    return Ok(());
                };
                let link = a
                    .identity
                    .open_introduction(&j.peer_key, &j.id, packet)
                    .map_err(messenger_store::Error::from)?;
                let result = self
                    .accept_account_quick(&link, Some(&j.id), Some(&a.relay_url))
                    .await;
                j.contact = self.account_contact(&j.id)?;
                self.store.save_account_job(&j)?;
                result?;
            }
        } else {
            if remote.is_none() {
                self.account_http(
                    a,
                    reqwest::Method::POST,
                    "/v1/accounts/requests",
                    Some(serde_json::json!({"id":j.id,"login":j.peer_login})),
                )
                .await?;
                return Ok(());
            }
            if remote.is_some_and(|r| r.status != "accepted") {
                return Ok(());
            }
            if j.ticket.is_none() {
                j.ticket = Some(random_hex(32));
                self.store.save_account_job(&j)?;
            }
            self.account_http(
                a,
                reqwest::Method::POST,
                &format!("{base}/ticket"),
                Some(serde_json::json!({"ticket":j.ticket})),
            )
            .await?;
            if j.contact.is_none() {
                let result = self
                    .create_account_quick(
                        &a.relay_url,
                        j.ticket.as_deref().ok_or(Error::InvalidResponse)?,
                        Some(&j.id),
                    )
                    .await;
                j.contact = self.account_contact(&j.id)?;
                self.store.save_account_job(&j)?;
                result?;
            }
            let id = j.contact.as_deref().ok_or(Error::InvalidResponse)?;
            if self
                .quick_invitation_status(id)?
                .is_some_and(|s| s.stage == "quick_queue_pending")
            {
                self.provision_quick_invitation(id, None).await?;
            }
            if j.offer.is_none() {
                let link = self.export_quick_invitation(id)?.link;
                j.offer = Some(
                    a.identity
                        .seal_introduction(&j.peer_key, &j.id, &link)
                        .map_err(messenger_store::Error::from)?,
                );
                self.store.save_account_job(&j)?;
            }
            self.account_http(
                a,
                reqwest::Method::POST,
                &format!("{base}/offer"),
                Some(serde_json::json!({"offer":j.offer})),
            )
            .await?;
        }
        if let Some(id) = &j.contact {
            let names = self.store.contact_names(id)?;
            if names.alias.is_empty() {
                self.store.set_contact_alias(id, &j.peer_login)?;
            }
            self.sync_quick(id).await?;
            if !j.incoming
                && self
                    .quick_invitation_status(id)?
                    .is_some_and(|s| s.stage == "quick_confirmation")
            {
                self.confirm_quick_invitation(id).await?;
            }
        }
        Ok(())
    }
}

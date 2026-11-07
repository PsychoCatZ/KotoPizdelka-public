//! The desktop application's bounded, serialized command service.
//!
//! A dedicated thread owns the database worker and a Tokio runtime. The UI
//! receives only display data and explicitly exported invitations; profile paths,
//! storage keys and receiving capabilities never cross this command boundary.

use messenger_client::{invitations::InvitationKind, ClientWorker, CreatedInvitation};
use messenger_store::Direction;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

const CLOSED: &str = "Сначала открой профиль.";
const UNAVAILABLE: &str = "Служба профиля недоступна. Перезапусти приложение.";
const BUSY: &str = "Профиль занят. Дождись текущих операций и повтори попытку.";
const TIMED_OUT: &str =
    "Операция заняла слишком много времени. Сохранённый прогресс доступен; повтори попытку.";
const INVALID: &str = "Проверь данные: формат или размер не подходит.";
const SETUP_PENDING: &str = "Сначала заверши обмен приглашениями и дождись первого сообщения.";
pub const DEFAULT_RELAY: &str = "https://relay.example.invalid";
fn default_relay(value: &str) -> &str {
    if value.is_empty() {
        DEFAULT_RELAY
    } else {
        value
    }
}
const MAX_TEXT: usize = 24 * 1024;
const MAX_INVITATION: usize = 8192;
const MAX_QUICK_LINK: usize = 2300;
const OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// No filesystem paths, administrative tokens or plaintext storage keys.
/// Sensitive fields deliberately have no Debug implementation.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Only native file-picker commands construct these; IPC deserialization rejects paths.
    #[serde(skip_deserializing)]
    VerifyProfile {
        path: PathBuf,
        password: String,
    },
    #[serde(skip_deserializing)]
    ExportProfile {
        path: PathBuf,
        password: String,
    },
    #[serde(skip_deserializing)]
    RestoreProfile {
        path: PathBuf,
        password: String,
    },
    #[serde(deserialize_with = "empty_command")]
    AccountStatus,
    #[serde(deserialize_with = "empty_command")]
    SyncAccount,
    #[serde(deserialize_with = "empty_command")]
    LogoutAccount,
    AuthenticateAccount {
        login: String,
        password: String,
        register: bool,
    },
    FindAccount {
        login: String,
    },
    AddAccount {
        login: String,
    },
    DecideAccount {
        id: String,
        accept: bool,
    },
    #[serde(deserialize_with = "empty_command")]
    Status,
    #[serde(deserialize_with = "empty_command")]
    OpenProfile,
    #[serde(deserialize_with = "empty_command")]
    Contacts,
    SetNickname {
        nickname: String,
    },
    SetContactAlias {
        contact: String,
        alias: String,
    },
    History {
        contact: String,
        after_sequence: i64,
    },
    Enqueue {
        contact: String,
        text: String,
    },
    Sync {
        contact: String,
    },
    CreateInvitation {
        #[serde(default)]
        relay_url: String,
        ticket: String,
    },
    AcceptInvitation {
        offer: String,
        trusted_fingerprint: String,
        relay_url: String,
        ticket: String,
    },
    CompleteInvitation {
        contact: String,
        reply: String,
        trusted_fingerprint: String,
    },
    ExportInvitation {
        contact: String,
    },
    ProvisionQueue {
        contact: String,
        ticket: Option<String>,
    },
    CreateQuick {
        #[serde(default)]
        relay_url: String,
        ticket: String,
    },
    #[serde(deserialize_with = "empty_command")]
    CreateAccountLink,
    AcceptQuick {
        link: String,
    },
    ExportQuick {
        contact: String,
    },
    ConfirmQuick {
        contact: String,
    },
    Verification {
        contact: String,
    },
    MarkRead {
        contact: String,
        sequences: Vec<i64>,
    },
    DeleteContact {
        contact: String,
    },
    ProvisionQuick {
        contact: String,
        ticket: Option<String>,
    },
    MarkVerified {
        contact: String,
        fingerprint: String,
    },
}

fn empty_command<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<(), D::Error> {
    // Serde's ordinary internally tagged unit variants ignore extra fields even
    // with deny_unknown_fields on the enum. An empty struct validates them.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    Empty::deserialize(deserializer).map(|_| ())
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Account {
        view: messenger_client::accounts::AccountView,
    },
    AccountUser {
        login: String,
    },
    Profile {
        open: bool,
        nickname: String,
    },
    Contacts {
        contacts: Vec<ContactSummary>,
    },
    History {
        entries: Vec<HistoryItem>,
    },
    Queued {
        id: String,
    },
    Synced {
        sent: usize,
        received: usize,
        duplicates: usize,
        acked: usize,
        profile_changed: bool,
        delivery_changed: bool,
    },
    Invitation {
        contact: String,
        invitation: String,
        fingerprint: String,
    },
    QuickInvitation {
        contact: String,
        link: String,
        expires_at: i64,
    },
    Verification {
        fingerprint: String,
        verified: bool,
    },
    Done,
}

#[derive(Serialize)]
pub struct ContactSummary {
    pub id: String,
    pub stage: String,
    pub can_send: bool,
    /// None means the older manual invitation protocol, whose trust handling
    /// remains unchanged. Quick invitations are explicitly unverified first.
    pub verified: Option<bool>,
    pub quick: bool,
    pub unread: usize,
    pub nickname: String,
    pub alias: String,
}

#[derive(Serialize)]
pub struct HistoryItem {
    pub sequence: i64,
    pub id: String,
    pub direction: &'static str,
    pub text: String,
    pub unread: bool,
    pub delivery: Option<messenger_store::DeliveryStatus>,
}

struct Command {
    request: Request,
    response: oneshot::Sender<Result<Reply, String>>,
    #[cfg(test)]
    pause: Option<TestPause>,
}

#[cfg(test)]
struct TestPause {
    after_process: bool,
    started: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

#[cfg(test)]
impl TestPause {
    async fn wait(self) {
        let _ = self.started.send(());
        let _ = self.release.await;
    }
}

/// No chat data is returned to Android's job scheduler.
pub struct BackgroundResult {
    pub cursor: usize,
    pub retry: bool,
}

/// Clones address the same worker, rather than opening competing databases.
/// Dropping the last handle closes the channel; queued commands finish and the
/// worker then releases its profile lock. Thread shutdown never blocks the UI.
#[derive(Clone)]
pub struct AppHandle {
    sender: mpsc::Sender<Command>,
}

impl AppHandle {
    /// The native wrapper supplies one fixed application-private profile path.
    /// Spawning does not open or create the profile. No insecure key fallback is
    /// available when `OpenProfile` calls the system-protected storage backend.
    pub fn spawn(profile_path: PathBuf, allow_loopback_http: bool) -> Result<Self, String> {
        Self::start(profile_path, allow_loopback_http, None, OPERATION_TIMEOUT)
    }

    /// Native notification observer receives only bounded local contact IDs,
    /// never message content, names, capabilities or queue addresses.
    pub fn spawn_observed(
        profile_path: PathBuf,
        allow_loopback_http: bool,
        observer: impl Fn(Vec<String>) + Send + Sync + 'static,
    ) -> Result<Self, String> {
        Self::start_observed(
            profile_path,
            allow_loopback_http,
            None,
            OPERATION_TIMEOUT,
            Some(std::sync::Arc::new(observer)),
        )
    }

    fn start(
        profile_path: PathBuf,
        allow_loopback_http: bool,
        worker: Option<ClientWorker>,
        operation_timeout: std::time::Duration,
    ) -> Result<Self, String> {
        Self::start_observed(
            profile_path,
            allow_loopback_http,
            worker,
            operation_timeout,
            None,
        )
    }

    fn start_observed(
        profile_path: PathBuf,
        allow_loopback_http: bool,
        mut worker: Option<ClientWorker>,
        operation_timeout: std::time::Duration,
        observer: Option<std::sync::Arc<dyn Fn(Vec<String>) + Send + Sync>>,
    ) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| UNAVAILABLE.to_owned())?;
        let (sender, mut receiver) = mpsc::channel::<Command>(16);
        std::thread::Builder::new()
            .name("messenger-profile".into())
            .spawn(move || {
                runtime.block_on(async move {
                    while let Some(command) = receiver.recv().await {
                        let Command {
                            request,
                            response,
                            #[cfg(test)]
                            pause,
                        } = command;
                        let operation = async {
                            #[cfg(test)]
                            let (before, after) = match pause {
                                Some(pause) if pause.after_process => (None, Some(pause)),
                                pause => (pause, None),
                            };
                            #[cfg(test)]
                            if let Some(pause) = before {
                                pause.wait().await;
                            }
                            let result =
                                process(&mut worker, &profile_path, allow_loopback_http, request)
                                    .await;
                            #[cfg(test)]
                            if let Some(pause) = after {
                                pause.wait().await;
                            }
                            result
                        };
                        // A whole-operation deadline also bounds a long sync
                        // containing many individually bounded HTTP requests.
                        // Cancelling an await never resets committed client
                        // state; its exact envelopes/proposals remain retryable.
                        let result = match tokio::time::timeout(operation_timeout, operation).await
                        {
                            Ok(result) => result,
                            Err(_) => Err(TIMED_OUT),
                        };
                        // Saving precedes ACK, so a failed/timeout/cancelled
                        // request can still have committed new inbox messages.
                        let incoming = worker
                            .as_mut()
                            .map(ClientWorker::take_incoming_contacts)
                            .unwrap_or_default();
                        if !incoming.is_empty() {
                            if let Some(observer) = &observer {
                                observer(incoming);
                            }
                        }
                        // A caller may leave while a durable operation completes.
                        // The worker must still finish rather than roll back only
                        // because the UI stopped waiting for its reply.
                        let _ = response.send(result.map_err(str::to_owned));
                    }
                });
            })
            .map_err(|_| UNAVAILABLE.to_owned())?;
        Ok(Self { sender })
    }

    /// Native-only bounded background pass through the SAME profile actor.
    /// The native caller checks an existing protected profile and explicit opt-in.
    /// Cursor is an integer, never a contact identifier or message payload.
    pub async fn background_sync(
        &self,
        cursor: usize,
        stop: impl Fn() -> bool,
    ) -> BackgroundResult {
        let mut result = BackgroundResult {
            cursor,
            retry: false,
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(75);
        if stop() {
            return result;
        }
        if self.dispatch(Request::OpenProfile).await.is_err() {
            result.retry = true;
            return result;
        }
        if !stop()
            && tokio::time::Instant::now() < deadline
            && self.dispatch(Request::SyncAccount).await.is_err()
        {
            result.retry = true;
        }
        let contacts = match self.dispatch(Request::Contacts).await {
            Ok(Reply::Contacts { contacts }) => contacts,
            _ => {
                result.retry = true;
                return result;
            }
        };
        if contacts.is_empty() {
            result.cursor = 0;
            return result;
        }
        let start = cursor % contacts.len();
        for offset in 0..contacts.len().min(100) {
            if stop() || tokio::time::Instant::now() >= deadline {
                break;
            }
            let index = (start + offset) % contacts.len();
            result.cursor = (index + 1) % contacts.len();
            let contact = &contacts[index];
            if !matches!(
                contact.stage.as_str(),
                "ready" | "legacy" | "waiting_first_message" | "quick_pending" | "quick_waiting"
            ) {
                continue;
            }
            if self
                .dispatch(Request::Sync {
                    contact: contact.id.clone(),
                })
                .await
                .is_err()
            {
                result.retry = true;
            }
        }
        result
    }

    pub async fn dispatch(&self, request: Request) -> Result<Reply, String> {
        // Bound every field before queueing; no oversized secret strings sit in
        // the bounded mailbox while previous network requests are in flight.
        validate(&request).map_err(str::to_owned)?;
        let (response, received) = oneshot::channel();
        self.sender
            .try_send(Command {
                request,
                response,
                #[cfg(test)]
                pause: None,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => BUSY.to_owned(),
                mpsc::error::TrySendError::Closed(_) => UNAVAILABLE.to_owned(),
            })?;
        received.await.map_err(|_| UNAVAILABLE.to_owned())?
    }
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate(request: &Request) -> Result<(), &'static str> {
    let valid_contact = |id: &str| hex(id, 32);
    let valid_invitation = |text: &str| !text.is_empty() && text.len() <= MAX_INVITATION;
    let valid_endpoint = |url: &str| !url.is_empty() && url.len() <= 2048;
    let valid = match request {
        Request::VerifyProfile { password, .. }
        | Request::ExportProfile { password, .. }
        | Request::RestoreProfile { password, .. } => {
            (12..=128).contains(&password.chars().count()) && password.len() <= 512
        }
        Request::Status
        | Request::OpenProfile
        | Request::Contacts
        | Request::CreateAccountLink
        | Request::AccountStatus
        | Request::SyncAccount
        | Request::LogoutAccount => true,
        Request::AuthenticateAccount {
            login, password, ..
        } => {
            messenger_client::accounts::normalize_login(login).is_some()
                && (10..=128).contains(&password.chars().count())
                && password.len() <= 256
        }
        Request::FindAccount { login } | Request::AddAccount { login } => {
            messenger_client::accounts::normalize_login(login).is_some()
        }
        Request::DecideAccount { id, .. } => hex(id, 32),
        Request::SetNickname { nickname } => messenger_store::valid_nickname(nickname),
        Request::SetContactAlias { contact, alias } => {
            valid_contact(contact) && messenger_store::valid_nickname(alias)
        }
        Request::History {
            contact,
            after_sequence,
        } => valid_contact(contact) && *after_sequence >= 0,
        Request::MarkRead { contact, sequences } => {
            valid_contact(contact)
                && !sequences.is_empty()
                && sequences.len() <= 100
                && sequences
                    .iter()
                    .all(|seq| (1..=9_007_199_254_740_991).contains(seq))
        }
        Request::Enqueue { contact, text } => {
            valid_contact(contact) && !text.trim().is_empty() && text.len() <= MAX_TEXT
        }
        Request::Sync { contact }
        | Request::DeleteContact { contact }
        | Request::ExportInvitation { contact }
        | Request::ExportQuick { contact }
        | Request::ConfirmQuick { contact }
        | Request::Verification { contact } => valid_contact(contact),
        Request::CreateInvitation { relay_url, ticket }
        | Request::CreateQuick { relay_url, ticket } => {
            (relay_url.is_empty() || valid_endpoint(relay_url)) && hex(ticket, 64)
        }
        Request::AcceptQuick { link } => !link.is_empty() && link.len() <= MAX_QUICK_LINK,
        Request::MarkVerified {
            contact,
            fingerprint,
        } => valid_contact(contact) && hex(fingerprint, 64),
        Request::AcceptInvitation {
            offer,
            trusted_fingerprint,
            relay_url,
            ticket,
        } => {
            valid_invitation(offer)
                && hex(trusted_fingerprint, 64)
                && valid_endpoint(relay_url)
                && hex(ticket, 64)
        }
        Request::CompleteInvitation {
            contact,
            reply,
            trusted_fingerprint,
        } => valid_contact(contact) && valid_invitation(reply) && hex(trusted_fingerprint, 64),
        Request::ProvisionQueue { contact, ticket }
        | Request::ProvisionQuick { contact, ticket } => {
            valid_contact(contact) && ticket.as_ref().is_none_or(|ticket| hex(ticket, 64))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(INVALID)
    }
}

fn client_error(error: messenger_client::Error) -> &'static str {
    use messenger_client::Error;
    match error {
        Error::AccountClosed => "Сначала войди в аккаунт стаи.",
        Error::AccountIdentityMismatch => "Этот аккаунт привязан к другому локальному профилю. Перенос ключей между устройствами пока недоступен.",
        Error::AccountRejected(401) => "Логин или пароль не подошли, либо сеанс истёк. Войди ещё раз.",
        Error::AccountRejected(409) => "Логин уже занят или привязан к другому профилю. Повтори вход на исходном устройстве.",
        Error::AccountRejected(404) => "Кот с таким логином не найден или сервер ещё не поддерживает это действие. Проверь логин и версию сервера.",
        Error::AccountRejected(429) => "Сервер временно ограничил запросы. Повтори позже.",
        Error::AccountRejected(_) => "Сервер не принял запрос аккаунта. Повтори позже.",
        Error::AlreadyRunning => "Этот профиль уже открыт в другом окне приложения.",
        Error::Platform(messenger_platform::Error::UnsupportedPlatform) => {
            "Защита профиля недоступна на этом устройстве."
        }
        Error::Platform(messenger_platform::Error::MissingKey) => {
            "Ключ существующего профиля отсутствует. Существующие данные сохранены."
        }
        Error::Platform(_) => {
            "Не удалось открыть защищённый ключ профиля. Существующие данные сохранены."
        }
        Error::RequestFailed
        | Error::UnexpectedStatus(_)
        | Error::InvalidResponse
        | Error::ResponseTooLarge => {
            "Не удалось завершить связь с сервером. Сохранённый прогресс доступен; повтори попытку."
        }
        Error::InvitationProvisionRejected(403) => "Сервер отклонил билет: у него нет права приглашать. Получи билет командой issue-ticket.sh --invite и замени его в сохранённой попытке.",
        Error::InvitationProvisionRejected(401) => "Сервер отклонил билет: он истёк или не подходит этому серверу. Получи новый билет для приглашения и замени его в сохранённой попытке.",
        Error::InvitationProvisionRejected(400) => "Сервер отклонил параметры приглашения (HTTP 400). Проверь время на устройстве и получи билет --invite со сроком больше часа.",
        Error::InvitationProvisionRejected(409) => "Сервер отклонил повторное использование билета или очереди (HTTP 409). Повтори сохранённую попытку с прежним билетом; для нового приглашения нужен отдельный билет.",
        Error::InvitationProvisionRejected(404 | 405) => "Сервер не принял запрос приглашения (HTTP 404/405). Проверь обновление relay и срок сохранённой попытки.",
        Error::InvitationProvisionRejected(429) => "Сервер временно ограничил создание приглашений (HTTP 429). Повтори попытку позже.",
        Error::InvitationProvisionRejected(_) => "Сервер отказал в создании приглашения. Сохранённая попытка доступна; повтори позже.",
        Error::InvalidEndpoint => "Проверь адрес сервера и билет создания очереди.",
        Error::Invitation(_) | Error::ReplyMismatch => {
            "Приглашение или проверенный отпечаток не подходят. Сверь их с собеседником."
        }
        Error::QueueProvisionPending => {
            "Очередь ещё не создана на сервере. Возобнови создание очереди для этого контакта."
        }
        Error::InvitationCompleted => "Обмен приглашениями для этого контакта уже завершён.",
        Error::QueueAlreadyUsed => "Эта очередь уже используется. Создай отдельное приглашение.",
        Error::QuickInvitationInvalid => {
            "Не удалось проверить приглашение. Проверь ссылку или попроси новое приглашение."
        }
        Error::QuickInvitationExpired => {
            "Срок приглашения истёк. Попроси собеседника создать новое."
        }
        Error::QuickConfirmationPending => "Сначала подтверди запрос нового собеседника.",
        Error::Store(error) => store_error(error),
        Error::LocalIo => "Не удалось открыть файлы профиля.",
    }
}

fn store_error(error: messenger_store::Error) -> &'static str {
    use messenger_store::Error;
    match error {
        Error::Archived => {
            "Это архив восстановленной беседы. Начни новое знакомство для отправки сообщений."
        }
        Error::NotFound => "Контакт или сообщение не найдено.",
        Error::InvalidId | Error::InvalidRoute | Error::InvalidSetup => INVALID,
        Error::QuotaExceeded => "Достигнут лимит экспериментального профиля.",
        Error::SetupReplay => "Это приглашение уже принято в этом профиле.",
        Error::SetupPending => SETUP_PENDING,
        Error::SetupConflict | Error::RouteAlreadySet => {
            "Состояние контакта изменилось. Обнови список контактов."
        }
        Error::InvalidStore | Error::InvalidRecord | Error::Conflict => {
            "Не удалось проверить данные профиля. Существующие данные сохранены."
        }
        Error::Crypto(_) => "Не удалось выполнить защищённую операцию для этого контакта.",
        Error::Database => "Не удалось прочитать или сохранить профиль.",
    }
}

fn invitation_reply(created: CreatedInvitation) -> Reply {
    Reply::Invitation {
        contact: created.contact,
        invitation: created.invitation,
        fingerprint: created.fingerprint,
    }
}

fn quick_invitation_reply(created: messenger_client::QuickInvitation) -> Reply {
    Reply::QuickInvitation {
        contact: created.contact,
        link: created.link,
        expires_at: created.expires_at,
    }
}

fn contact_summary(
    worker: &mut ClientWorker,
    contact: String,
) -> Result<ContactSummary, &'static str> {
    let unread = worker.store().unread_count(&contact).map_err(store_error)?;
    let names = worker
        .store()
        .contact_names(&contact)
        .map_err(store_error)?;
    if worker.store().is_archived(&contact).map_err(store_error)? {
        return Ok(ContactSummary {
            id: contact,
            stage: "archived".into(),
            can_send: false,
            verified: None,
            quick: false,
            unread,
            nickname: names.nickname,
            alias: names.alias,
        });
    }
    if let Some(status) = worker
        .quick_invitation_status(&contact)
        .map_err(client_error)?
    {
        return Ok(ContactSummary {
            id: contact,
            stage: status.stage.into(),
            can_send: status.stage == "ready",
            verified: Some(status.verified),
            quick: true,
            unread,
            nickname: names.nickname,
            alias: names.alias,
        });
    }
    let (stage, can_send) = match worker.invitation_status(&contact) {
        Ok(status) if status.provisioning => ("queue_pending", false),
        Ok(status) if !status.ready => ("offer_pending", false),
        Ok(status) if status.kind == InvitationKind::Offer => ("ready", true),
        Ok(_) => {
            let history = worker.store().history(&contact, 0).map_err(store_error)?;
            if history
                .iter()
                .any(|entry| entry.direction == Direction::Incoming)
            {
                ("ready", true)
            } else {
                ("waiting_first_message", false)
            }
        }
        Err(messenger_client::Error::Store(messenger_store::Error::NotFound)) => {
            // Earlier low-level profiles do not carry invitation progress. Only
            // an existing route and actual history allow presenting them as
            // sendable; an empty legacy contact is not assumed to have a session.
            let route = worker.store().route(&contact);
            let can_send = match route {
                Ok(_) => !worker
                    .store()
                    .history(&contact, 0)
                    .map_err(store_error)?
                    .is_empty(),
                Err(messenger_store::Error::NotFound | messenger_store::Error::SetupPending) => {
                    false
                }
                Err(error) => return Err(store_error(error)),
            };
            ("legacy", can_send)
        }
        Err(error) => return Err(client_error(error)),
    };
    Ok(ContactSummary {
        id: contact,
        stage: stage.into(),
        can_send,
        verified: None,
        quick: false,
        unread,
        nickname: names.nickname,
        alias: names.alias,
    })
}

async fn process(
    worker: &mut Option<ClientWorker>,
    profile_path: &std::path::Path,
    allow_loopback_http: bool,
    request: Request,
) -> Result<Reply, &'static str> {
    match request {
        Request::RestoreProfile { path, password } => {
            if worker.is_some() || !messenger_client::backup::can_restore(profile_path) {
                return Err("Восстановление доступно только на устройстве без существующего профиля. Текущие данные не заменяются.");
            }
            *worker = Some(ClientWorker::restore_profile(profile_path, &path, password, allow_loopback_http)
                .map_err(|_| "Не удалось восстановить копию. Проверь пароль, файл и свободное место. Существующие данные не заменяются.")?);
            return Ok(Reply::Profile {
                open: true,
                nickname: worker
                    .as_mut()
                    .ok_or(CLOSED)?
                    .store()
                    .profile_name()
                    .map_err(store_error)?
                    .nickname,
            });
        }
        Request::Status => {
            return Ok(Reply::Profile {
                open: worker.is_some(),
                nickname: match worker.as_mut() {
                    Some(w) => w.store().profile_name().map_err(store_error)?.nickname,
                    None => String::new(),
                },
            });
        }
        Request::OpenProfile => {
            if worker.is_none() {
                *worker = Some(
                    ClientWorker::open_system(profile_path, allow_loopback_http)
                        .map_err(client_error)?,
                );
            }
            return Ok(Reply::Profile {
                open: true,
                nickname: worker
                    .as_mut()
                    .ok_or(CLOSED)?
                    .store()
                    .profile_name()
                    .map_err(store_error)?
                    .nickname,
            });
        }
        _ => {}
    }
    let worker = worker.as_mut().ok_or(CLOSED)?;
    match request {
        Request::VerifyProfile { path, password } => {
            messenger_client::backup::verify_profile(&path, password).map_err(|_| {
                "Не удалось проверить копию. Проверь пароль и файл. Текущий профиль не изменён."
            })?;
            Ok(Reply::Done)
        }
        Request::ExportProfile { path, password } => {
            worker.export_profile(&path, password).map_err(|_| {
                "Не удалось сохранить копию. Выбери новое имя файла и проверь свободное место."
            })?;
            Ok(Reply::Done)
        }
        Request::RestoreProfile { .. } => unreachable!("handled before opening profile"),
        Request::AccountStatus => Ok(Reply::Account {
            view: worker.account_view().map_err(client_error)?,
        }),
        Request::SyncAccount => Ok(Reply::Account {
            view: worker.sync_account().await.map_err(client_error)?,
        }),
        Request::LogoutAccount => Ok(Reply::Account {
            view: worker.logout_account().await.map_err(client_error)?,
        }),
        Request::AuthenticateAccount {
            login,
            password,
            register,
        } => Ok(Reply::Account {
            view: worker
                .authenticate_account(DEFAULT_RELAY, &login, password, register)
                .await
                .map_err(client_error)?,
        }),
        Request::FindAccount { login } => Ok(Reply::AccountUser {
            login: worker
                .find_account(&login)
                .await
                .map_err(client_error)?
                .login,
        }),
        Request::AddAccount { login } => Ok(Reply::Account {
            view: worker.add_account(&login).await.map_err(client_error)?,
        }),
        Request::DecideAccount { id, accept } => Ok(Reply::Account {
            view: worker
                .decide_account(&id, accept)
                .await
                .map_err(client_error)?,
        }),

        Request::SetNickname { nickname } => {
            worker
                .store()
                .set_nickname(&nickname)
                .map_err(store_error)?;
            Ok(Reply::Profile {
                open: true,
                nickname,
            })
        }
        Request::SetContactAlias { contact, alias } => {
            worker
                .store()
                .set_contact_alias(&contact, &alias)
                .map_err(store_error)?;
            Ok(Reply::Done)
        }
        Request::Contacts => {
            let ids = worker.store().contact_ids().map_err(store_error)?;
            let contacts = ids
                .into_iter()
                .map(|id| contact_summary(worker, id))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Reply::Contacts { contacts })
        }
        Request::History {
            contact,
            after_sequence,
        } => {
            if !worker
                .store()
                .contact_ids()
                .map_err(store_error)?
                .contains(&contact)
            {
                return Err("Контакт или сообщение не найдено.");
            }
            let entries = worker
                .store()
                .history(&contact, after_sequence)
                .map_err(store_error)?
                .into_iter()
                .map(|entry| HistoryItem {
                    sequence: entry.sequence,
                    id: entry.id,
                    direction: match entry.direction {
                        Direction::Incoming => "incoming",
                        Direction::Outgoing => "outgoing",
                    },
                    text: entry.text,
                    unread: entry.unread,
                    delivery: entry.delivery,
                })
                .collect();
            Ok(Reply::History { entries })
        }
        Request::Enqueue { contact, text } => {
            if !contact_summary(worker, contact.clone())?.can_send {
                return Err(SETUP_PENDING);
            }
            let envelope = worker
                .store()
                .enqueue(&contact, &text)
                .map_err(store_error)?;
            Ok(Reply::Queued { id: envelope.id })
        }
        Request::Sync { contact } => {
            let report = worker.sync(&contact).await.map_err(client_error)?;
            Ok(Reply::Synced {
                sent: report.sent,
                received: report.received,
                duplicates: report.duplicates,
                acked: report.acked,
                profile_changed: report.profile_changed,
                delivery_changed: report.delivery_changed,
            })
        }
        Request::CreateInvitation { relay_url, ticket } => Ok(invitation_reply(
            worker
                .create_invitation_with_ticket(default_relay(&relay_url), &ticket)
                .await
                .map_err(client_error)?,
        )),
        Request::AcceptInvitation {
            offer,
            trusted_fingerprint,
            relay_url,
            ticket,
        } => Ok(invitation_reply(
            worker
                .accept_invitation_with_ticket(&offer, &trusted_fingerprint, &relay_url, &ticket)
                .await
                .map_err(client_error)?,
        )),
        Request::CompleteInvitation {
            contact,
            reply,
            trusted_fingerprint,
        } => {
            worker
                .complete_invitation(&contact, &reply, &trusted_fingerprint)
                .map_err(client_error)?;
            Ok(Reply::Done)
        }
        Request::ExportInvitation { contact } => Ok(invitation_reply(
            worker.export_invitation(&contact).map_err(client_error)?,
        )),
        Request::ProvisionQueue { contact, ticket } => Ok(invitation_reply(
            worker
                .provision_queue(&contact, ticket.as_deref())
                .await
                .map_err(client_error)?,
        )),
        Request::CreateAccountLink => Ok(quick_invitation_reply(
            worker.create_account_link().await.map_err(client_error)?,
        )),
        Request::CreateQuick { relay_url, ticket } => Ok(quick_invitation_reply(
            worker
                .create_quick_invitation(default_relay(&relay_url), &ticket)
                .await
                .map_err(client_error)?,
        )),
        Request::AcceptQuick { link } => Ok(quick_invitation_reply(
            worker
                .accept_quick_invitation(&link)
                .await
                .map_err(client_error)?,
        )),
        Request::ExportQuick { contact } => Ok(quick_invitation_reply(
            worker
                .export_quick_invitation(&contact)
                .map_err(client_error)?,
        )),
        Request::MarkRead { contact, sequences } => {
            worker
                .store()
                .mark_read(&contact, &sequences)
                .map_err(store_error)?;
            Ok(Reply::Done)
        }
        Request::DeleteContact { contact } => {
            worker
                .store()
                .delete_contact(&contact)
                .map_err(store_error)?;
            Ok(Reply::Done)
        }
        Request::ProvisionQuick { contact, ticket } => Ok(quick_invitation_reply(
            worker
                .provision_quick_invitation(&contact, ticket.as_deref())
                .await
                .map_err(client_error)?,
        )),
        Request::ConfirmQuick { contact } => {
            worker
                .confirm_quick_invitation(&contact)
                .await
                .map_err(client_error)?;
            Ok(Reply::Done)
        }
        Request::Verification { contact } => {
            let status = worker.quick_verification(&contact).map_err(client_error)?;
            Ok(Reply::Verification {
                fingerprint: status.fingerprint,
                verified: status.verified,
            })
        }
        Request::MarkVerified {
            contact,
            fingerprint,
        } => {
            worker
                .mark_quick_verified(&contact, &fingerprint)
                .map_err(client_error)?;
            Ok(Reply::Done)
        }
        Request::Status | Request::OpenProfile => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use messenger_client::ReceiveQueue;
    use messenger_core::StorageKey;
    use messenger_store::QueueEndpoint;
    use serde_json::json;

    #[test]
    fn request_schema_rejects_unknown_commands_and_fields() {
        for value in [
            json!({"kind": "open_profile", "path": "private-profile.sqlite"}),
            json!({"kind": "status", "ticket": "secret"}),
            json!({"kind": "enqueue", "contact": "a".repeat(32), "text": "hi", "route": "secret"}),
            json!({"kind": "accept_quick", "link": "opaque", "trusted_fingerprint": "b".repeat(64)}),
            json!({"kind": "create_quick", "relay_url": "https://relay.example/", "ticket": "c".repeat(64), "delegation": "secret"}),
            json!({"kind": "mark_verified", "contact": "a".repeat(32), "fingerprint": "b".repeat(64), "verified": true}),
            json!({"kind": "set_key", "key": "secret"}),
        ] {
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
        assert!(serde_json::from_value::<Request>(json!({"kind": "status"})).is_ok());
    }

    #[test]
    fn requests_are_bounded_before_entering_the_actor() {
        let id = "a".repeat(32);
        for request in [
            Request::History {
                contact: id.clone(),
                after_sequence: -1,
            },
            Request::History {
                contact: "A".repeat(32),
                after_sequence: 0,
            },
            Request::Enqueue {
                contact: id.clone(),
                text: "x".repeat(MAX_TEXT + 1),
            },
            Request::Enqueue {
                contact: id.clone(),
                text: " \n\t".into(),
            },
            Request::AcceptInvitation {
                offer: "x".repeat(MAX_INVITATION + 1),
                trusted_fingerprint: "b".repeat(64),
                relay_url: "https://relay.example/".into(),
                ticket: "c".repeat(64),
            },
            Request::CreateInvitation {
                relay_url: "x".repeat(2049),
                ticket: "c".repeat(64),
            },
            Request::ProvisionQueue {
                contact: id.clone(),
                ticket: Some("invalid".into()),
            },
            Request::AcceptQuick {
                link: "x".repeat(MAX_QUICK_LINK + 1),
            },
            Request::AcceptQuick {
                link: String::new(),
            },
            Request::CreateQuick {
                relay_url: "https://relay.example/".into(),
                ticket: "invalid".into(),
            },
            Request::MarkVerified {
                contact: id.clone(),
                fingerprint: "B".repeat(64),
            },
            Request::ConfirmQuick {
                contact: "invalid".into(),
            },
        ] {
            assert_eq!(validate(&request), Err(INVALID));
        }
        assert!(validate(&Request::Enqueue {
            contact: id,
            text: "x".repeat(MAX_TEXT),
        })
        .is_ok());
    }

    #[test]
    fn display_replies_have_only_the_documented_fields() {
        let contact = serde_json::to_value(Reply::Contacts {
            contacts: vec![ContactSummary {
                id: "a".repeat(32),
                stage: "queue_pending".into(),
                can_send: false,
                verified: None,
                quick: false,
                unread: 2,
                nickname: "Барсик".into(),
                alias: "Друг".into(),
            }],
        })
        .unwrap();
        assert_eq!(
            contact,
            json!({"kind":"contacts", "contacts":[{
                "id":"a".repeat(32), "stage":"queue_pending", "can_send":false, "verified":null, "quick":false, "unread":2, "nickname":"Барсик", "alias":"Друг"
            }]})
        );
        let history = serde_json::to_value(Reply::History {
            entries: vec![HistoryItem {
                sequence: 1,
                id: "b".repeat(32),
                direction: "incoming",
                text: "Мяу".into(),
                unread: true,
                delivery: None,
            }],
        })
        .unwrap();
        assert_eq!(
            history,
            json!({"kind":"history", "entries":[{
                "sequence":1, "id":"b".repeat(32), "direction":"incoming", "text":"Мяу", "unread":true, "delivery":null
            }]})
        );
        let invitation = serde_json::to_value(Reply::Invitation {
            contact: "a".repeat(32),
            invitation: "explicitly exported artifact".into(),
            fingerprint: "b".repeat(64),
        })
        .unwrap();
        assert_eq!(invitation.as_object().unwrap().len(), 4);
    }

    #[tokio::test]
    async fn unopened_actor_status_and_errors_do_not_create_a_profile() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("unopened.sqlite");
        let actor = AppHandle::spawn(path.clone(), false).unwrap();
        assert!(matches!(
            actor.dispatch(Request::Status).await,
            Ok(Reply::Profile { open: false, .. })
        ));
        assert!(matches!(
            actor.dispatch(Request::Contacts).await,
            Err(error) if error == CLOSED
        ));
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[cfg(not(any(windows, target_os = "android")))]
    #[tokio::test]
    async fn unsupported_system_profile_has_no_plaintext_fallback_or_files() {
        let directory = tempfile::tempdir().unwrap();
        let actor = AppHandle::spawn(directory.path().join("unsupported.sqlite"), false).unwrap();
        let error = match actor.dispatch(Request::OpenProfile).await {
            Err(error) => error,
            Ok(_) => panic!("unsupported platform must fail closed"),
        };
        assert_eq!(error, "Защита профиля недоступна на этом устройстве.");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        assert!(matches!(
            actor.dispatch(Request::Status).await,
            Ok(Reply::Profile { open: false, .. })
        ));
    }

    fn queue(number: u8) -> ReceiveQueue {
        let endpoint = |token| QueueEndpoint {
            relay_url: "http://127.0.0.1:1/".into(),
            queue_id: format!("{number:032x}"),
            token: format!("{token:064x}"),
        };
        ReceiveQueue {
            read: endpoint(u64::from(number) + 64),
            write: endpoint(u64::from(number) + 128),
        }
    }

    #[tokio::test]
    async fn actor_serializes_durable_messages_and_releases_profile_lock_on_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alice.sqlite");
        let mut alice = ClientWorker::open(&path, StorageKey::from_bytes([42; 32]), true).unwrap();
        let mut bob = ClientWorker::open(
            directory.path().join("bob.sqlite"),
            StorageKey::generate(),
            true,
        )
        .unwrap();
        let offer = alice.create_invitation(queue(1)).unwrap();
        let reply = bob
            .accept_invitation(&offer.invitation, &offer.fingerprint, queue(2))
            .unwrap();
        // Explicit-key fixture injection exists only inside this test module;
        // the public actor always opens the system-protected backend.
        let actor = AppHandle::start(path.clone(), true, Some(alice), OPERATION_TIMEOUT).unwrap();
        assert!(matches!(
            actor
                .dispatch(Request::Enqueue {
                    contact: offer.contact.clone(),
                    text: "too early".into(),
                })
                .await,
            Err(error) if error == SETUP_PENDING
        ));
        actor
            .dispatch(Request::CompleteInvitation {
                contact: offer.contact.clone(),
                reply: reply.invitation,
                trusted_fingerprint: reply.fingerprint,
            })
            .await
            .unwrap();
        let mut callers = Vec::new();
        for number in 0..8 {
            let handle = actor.clone();
            let contact = offer.contact.clone();
            callers.push(tokio::spawn(async move {
                handle
                    .dispatch(Request::Enqueue {
                        contact,
                        text: format!("message {number}"),
                    })
                    .await
            }));
        }
        for caller in callers {
            assert!(matches!(caller.await.unwrap(), Ok(Reply::Queued { .. })));
        }
        let entries = match actor
            .dispatch(Request::History {
                contact: offer.contact.clone(),
                after_sequence: 0,
            })
            .await
            .unwrap()
        {
            Reply::History { entries } => entries,
            _ => panic!("history command must return display history"),
        };
        assert_eq!(entries.len(), 8);
        assert!(entries
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        assert!(matches!(
            ClientWorker::open(&path, StorageKey::from_bytes([42; 32]), true),
            Err(messenger_client::Error::AlreadyRunning)
        ));
        drop(actor);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                match ClientWorker::open(&path, StorageKey::from_bytes([42; 32]), true) {
                    Ok(mut reopened) => {
                        assert_eq!(
                            reopened.store().history(&offer.contact, 0).unwrap().len(),
                            8
                        );
                        assert_eq!(
                            reopened
                                .store()
                                .pending_outbox(&offer.contact)
                                .unwrap()
                                .len(),
                            8
                        );
                        break;
                    }
                    Err(messenger_client::Error::AlreadyRunning) => {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    Err(_) => panic!("profile must remain valid after actor shutdown"),
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_saturated_mailbox_rejects_new_calls_without_waiting_or_creating_files() {
        let directory = tempfile::tempdir().unwrap();
        let actor = AppHandle::spawn(directory.path().join("busy.sqlite"), false).unwrap();
        let (started, running) = oneshot::channel();
        let (release, paused) = oneshot::channel();
        let (response, first_reply) = oneshot::channel();
        assert!(actor
            .sender
            .try_send(Command {
                request: Request::Status,
                response,
                pause: Some(TestPause {
                    after_process: false,
                    started,
                    release: paused,
                }),
            })
            .is_ok());
        tokio::time::timeout(std::time::Duration::from_secs(2), running)
            .await
            .unwrap()
            .unwrap();
        let mut queued_replies = Vec::new();
        for _ in 0..16 {
            let (response, received) = oneshot::channel();
            assert!(actor
                .sender
                .try_send(Command {
                    request: Request::Status,
                    response,
                    pause: None,
                })
                .is_ok());
            queued_replies.push(received);
        }
        let rejected = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            actor.dispatch(Request::Status),
        )
        .await
        .expect("a full mailbox must reject immediately instead of waiting");
        assert!(matches!(rejected, Err(error) if error == BUSY));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            assert!(matches!(
                first_reply.await.unwrap(),
                Ok(Reply::Profile { open: false, .. })
            ));
            for reply in queued_replies {
                assert!(matches!(
                    reply.await.unwrap(),
                    Ok(Reply::Profile { open: false, .. })
                ));
            }
            assert!(matches!(
                actor.dispatch(Request::Status).await,
                Ok(Reply::Profile { open: false, .. })
            ));
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_deadline_preserves_committed_progress_and_the_actor_remains_usable() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("alice.sqlite");
        let mut alice = ClientWorker::open(&path, StorageKey::generate(), true).unwrap();
        let mut bob = ClientWorker::open(
            directory.path().join("bob.sqlite"),
            StorageKey::generate(),
            true,
        )
        .unwrap();
        let offer = alice.create_invitation(queue(1)).unwrap();
        let reply = bob
            .accept_invitation(&offer.invitation, &offer.fingerprint, queue(2))
            .unwrap();
        alice
            .complete_invitation(&offer.contact, &reply.invitation, &reply.fingerprint)
            .unwrap();
        let actor = AppHandle::start(
            path,
            true,
            Some(alice),
            std::time::Duration::from_millis(250),
        )
        .unwrap();
        let (started, committed) = oneshot::channel();
        let (release, paused) = oneshot::channel();
        let (response, received) = oneshot::channel();
        assert!(actor
            .sender
            .try_send(Command {
                request: Request::Enqueue {
                    contact: offer.contact.clone(),
                    text: "Сохранённое мяу".into(),
                },
                response,
                pause: Some(TestPause {
                    after_process: true,
                    started,
                    release: paused,
                }),
            })
            .is_ok());
        tokio::time::timeout(std::time::Duration::from_secs(2), committed)
            .await
            .unwrap()
            .unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(error) if error == TIMED_OUT));
        assert!(release.send(()).is_err());
        match actor
            .dispatch(Request::History {
                contact: offer.contact.clone(),
                after_sequence: 0,
            })
            .await
            .unwrap()
        {
            Reply::History { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].text, "Сохранённое мяу");
            }
            _ => panic!("a timed-out caller must retain its committed message"),
        }
        assert!(matches!(
            actor
                .dispatch(Request::Enqueue {
                    contact: offer.contact,
                    text: "Следующее мяу".into(),
                })
                .await,
            Ok(Reply::Queued { .. })
        ));
    }
}

#[cfg(test)]
mod deletion_request_tests {
    use super::*;
    #[test]
    fn contact_deletion_and_quick_retry_validate_boundary() {
        let valid: Request = serde_json::from_value(
            serde_json::json!({"kind":"delete_contact","contact":"a".repeat(32)}),
        )
        .unwrap();
        assert!(validate(&valid).is_ok());
        let bad: Request = serde_json::from_value(
            serde_json::json!({"kind":"delete_contact","contact":"../profile"}),
        )
        .unwrap();
        assert!(validate(&bad).is_err());
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"kind":"delete_contact","contact":"a".repeat(32),"all":true})
        )
        .is_err());
        let retry: Request = serde_json::from_value(
            serde_json::json!({"kind":"provision_quick","contact":"a".repeat(32),"ticket":null}),
        )
        .unwrap();
        assert!(validate(&retry).is_ok());
        let bad: Request = serde_json::from_value(serde_json::json!({"kind":"provision_quick","contact":"a".repeat(32),"ticket":"secret"})).unwrap();
        assert!(validate(&bad).is_err());
    }
    #[test]
    fn rejected_invite_ticket_is_not_presented_as_network_outage() {
        assert!(
            client_error(messenger_client::Error::InvitationProvisionRejected(403))
                .contains("--invite")
        );
        assert!(
            client_error(messenger_client::Error::InvitationProvisionRejected(401))
                .contains("истёк")
        );
        assert!(
            client_error(messenger_client::Error::InvitationProvisionRejected(429)).contains("429")
        );
    }
}

#[cfg(test)]
mod unread_request_tests {
    use super::*;
    #[test]
    fn mark_read_only_accepts_bounded_exact_safe_sequence_ids() {
        let id = "a".repeat(32);
        assert!(validate(&Request::MarkRead {
            contact: id.clone(),
            sequences: vec![1, 9_007_199_254_740_991]
        })
        .is_ok());
        for sequences in [
            vec![],
            vec![0],
            vec![-1],
            vec![9_007_199_254_740_992],
            vec![1; 101],
        ] {
            assert!(validate(&Request::MarkRead {
                contact: id.clone(),
                sequences
            })
            .is_err());
        }
        assert!(validate(&Request::MarkRead {
            contact: "../profile".into(),
            sequences: vec![1]
        })
        .is_err());
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"kind":"mark_read","contact":id,"sequences":[1],"all":true})
        )
        .is_err());
    }
}

#[cfg(test)]
mod name_request_tests {
    use super::*;
    #[test]
    fn names_are_bounded_and_default_relay_requires_no_renderer_address() {
        let request: Request = serde_json::from_value(
            serde_json::json!({"kind":"create_quick","ticket":"a".repeat(64)}),
        )
        .unwrap();
        assert!(validate(&request).is_ok());
        match request {
            Request::CreateQuick { relay_url, .. } => {
                assert_eq!(default_relay(&relay_url), DEFAULT_RELAY)
            }
            _ => panic!("wrong request"),
        }
        for nickname in ["Барсик 🐱", "", &"🐱".repeat(48)] {
            assert!(validate(&Request::SetNickname {
                nickname: nickname.into()
            })
            .is_ok());
        }
        for nickname in ["x\ny", "\u{202e}fake", &"🐱".repeat(49), " spaces "] {
            assert!(validate(&Request::SetNickname {
                nickname: nickname.into()
            })
            .is_err());
        }
        assert!(validate(&Request::SetContactAlias {
            contact: "../db".into(),
            alias: "name".into()
        })
        .is_err());
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"kind":"set_nickname","nickname":"Кот","path":"../db"})
        )
        .is_err());
    }
}

#[cfg(test)]
mod incoming_observer_tests {
    use super::*;
    use axum::{
        http::StatusCode,
        routing::{delete, get},
        Json, Router,
    };
    use messenger_core::{Contact, Envelope, StorageKey};
    use messenger_store::{ContactRoute, QueueEndpoint};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tokio::net::TcpListener;

    async fn fixture() -> (
        tempfile::TempDir,
        ClientWorker,
        String,
        tokio::task::JoinHandle<()>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut a = Contact::new();
        let mut b = Contact::new();
        let ak = a.public_bundle();
        let bk = b.public_bundle();
        a.bind_peer(bk.clone(), &bk.fingerprint().unwrap()).unwrap();
        b.bind_peer(ak.clone(), &ak.fingerprint().unwrap()).unwrap();
        a.start_session().unwrap();
        let envelope: Envelope = a.encrypt("private fixture content").unwrap();
        let fault = Arc::new(AtomicBool::new(true));
        let f = fault.clone();
        let router = Router::new()
            .route(
                "/v1/queues/{id}/messages",
                get(move || {
                    let envelope = envelope.clone();
                    async move { Json(serde_json::json!({"messages":[envelope]})) }
                })
                .post(|| async { StatusCode::ACCEPTED }),
            )
            .route(
                "/v1/queues/{queue}/messages/{id}",
                delete(move || {
                    let f = f.clone();
                    async move {
                        if f.swap(false, Ordering::SeqCst) {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::NO_CONTENT
                        }
                    }
                }),
            );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut worker =
            ClientWorker::open(dir.path().join("profile"), StorageKey::generate(), true).unwrap();
        let contact = worker.store().insert_contact(b).unwrap();
        let endpoint = |id: &str| QueueEndpoint {
            relay_url: url.clone(),
            queue_id: id.repeat(32),
            token: "c".repeat(64),
        };
        worker
            .store()
            .set_route(
                &contact,
                &ContactRoute {
                    send: endpoint("a"),
                    receive: endpoint("b"),
                },
            )
            .unwrap();
        (dir, worker, contact, task)
    }
    #[tokio::test]
    async fn background_pass_uses_the_same_actor_and_keeps_inbox_unread_on_ack_failure() {
        let (dir, worker, contact, server) = fixture().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let actor = AppHandle::start_observed(
            dir.path().join("receiver.sqlite"),
            true,
            Some(worker),
            std::time::Duration::from_secs(2),
            Some(Arc::new(move |ids| {
                let _ = tx.send(ids);
            })),
        )
        .unwrap();
        let stopped = actor.background_sync(77, || true).await;
        assert_eq!(stopped.cursor, 77);
        assert!(!stopped.retry);
        assert!(rx.try_recv().is_err());
        let first = actor.background_sync(usize::MAX, || false).await;
        assert!(first.retry);
        assert_eq!(rx.try_recv().unwrap(), vec![contact.clone()]);
        let Reply::History { entries } = actor
            .dispatch(Request::History {
                contact: contact.clone(),
                after_sequence: 0,
            })
            .await
            .unwrap()
        else {
            panic!("history")
        };
        assert_eq!(entries.len(), 1);
        assert!(entries[0].unread);
        // GUI and job clones share one writer and the already-persisted ACK.
        let gui = actor.clone();
        let (background, foreground) = tokio::join!(
            actor.background_sync(first.cursor, || false),
            gui.dispatch(Request::Sync {
                contact: contact.clone()
            })
        );
        assert!(!background.retry);
        assert!(foreground.is_ok());
        assert!(rx.try_recv().is_err());
        let Reply::Contacts { contacts } = actor.dispatch(Request::Contacts).await.unwrap() else {
            panic!("contacts")
        };
        assert_eq!(contacts[0].unread, 1);
        server.abort();
    }

    #[tokio::test]
    async fn saved_inbox_emits_once_before_error_reply_and_not_for_duplicate_retry_or_history() {
        let (dir, worker, contact, server) = fixture().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let actor = AppHandle::start_observed(
            dir.path().join("profile"),
            true,
            Some(worker),
            OPERATION_TIMEOUT,
            Some(Arc::new(move |ids| {
                let _ = tx.send(ids);
            })),
        )
        .unwrap();
        assert!(actor
            .dispatch(Request::Sync {
                contact: contact.clone()
            })
            .await
            .is_err());
        assert_eq!(rx.try_recv().unwrap(), vec![contact.clone()]);
        assert!(actor
            .dispatch(Request::Sync {
                contact: contact.clone()
            })
            .await
            .is_ok());
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        match actor
            .dispatch(Request::History {
                contact,
                after_sequence: 0,
            })
            .await
            .unwrap()
        {
            Reply::History { entries } => assert_eq!(entries.len(), 1),
            _ => panic!("history expected"),
        }
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
        server.abort();
    }
    #[tokio::test]
    async fn cancelled_caller_still_publishes_committed_incoming_progress() {
        let (dir, worker, contact, server) = fixture().await;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let actor = AppHandle::start_observed(
            dir.path().join("profile"),
            true,
            Some(worker),
            std::time::Duration::from_millis(300),
            Some(Arc::new(move |ids| {
                let _ = tx.send(ids);
            })),
        )
        .unwrap();
        let (started, committed) = oneshot::channel();
        let (_release, paused) = oneshot::channel();
        let (response, received) = oneshot::channel();
        actor
            .sender
            .try_send(Command {
                request: Request::Sync {
                    contact: contact.clone(),
                },
                response,
                pause: Some(TestPause {
                    after_process: true,
                    started,
                    release: paused,
                }),
            })
            .unwrap_or_else(|_| panic!("actor mailbox"));
        committed.await.unwrap();
        drop(received);
        let ids = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ids, vec![contact]);
        server.abort();
    }
}

#[cfg(test)]
mod backup_boundary_tests {
    use super::*;
    #[test]
    fn renderer_cannot_construct_native_backup_paths() {
        for kind in ["export_profile", "verify_profile", "restore_profile"] {
            let value = serde_json::json!({"kind":kind,"path":"arbitrary/profile.sqlite","password":"a long enough password"});
            assert!(serde_json::from_value::<Request>(value).is_err());
        }
    }
}

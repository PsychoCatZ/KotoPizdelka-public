//! Local, temporary network exercise, not a user-facing CLI or key vault.
//! Every client operation runs in a fresh process. Demo storage keys live only
//! in the parent process and travel to workers over a bounded stdin pipe.

use messenger_client::ClientWorker;
use messenger_core::{Contact, StorageKey};
use messenger_relay::{router, AppState, Queue, Store};
use messenger_store::{ClientStore, ContactRoute, Direction, QueueEndpoint};
use serde::{Deserialize, Serialize};
use std::{path::Path, path::PathBuf, process::ExitCode, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    sync::oneshot,
    time::timeout,
};
use zeroize::{Zeroize, Zeroizing};

const FIRST_TEXT: &str = "Привет с компьютера: сообщение пережило выход клиента.";
const REPLY_TEXT: &str = "Ответ второго клиента получен через настоящий HTTP-сервер.";
const MAX_INPUT: usize = 16 * 1024;
const MAX_OUTPUT: usize = 16 * 1024;
const CHILD_TIMEOUT: Duration = Duration::from_secs(20);

type DemoResult<T> = Result<T, &'static str>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerConfig {
    database: PathBuf,
    key_hex: String,
    contact: String,
    action: WorkerAction,
}

impl Drop for WorkerConfig {
    fn drop(&mut self) {
        self.key_hex.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerAction {
    Enqueue { text: String },
    Sync,
    History,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerOutput {
    Enqueued {
        pending: usize,
    },
    Synced {
        sent: usize,
        received: usize,
        duplicates: usize,
        acked: usize,
    },
    History {
        entries: Vec<HistoryItem>,
    },
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HistoryItem {
    incoming: bool,
    text: String,
}

fn demo_text(text: &str) -> bool {
    text == FIRST_TEXT || text == REPLY_TEXT
}

async fn worker() -> DemoResult<()> {
    let mut input = Zeroizing::new(Vec::new());
    tokio::io::stdin()
        .take((MAX_INPUT + 1) as u64)
        .read_to_end(&mut input)
        .await
        .map_err(|_| "не удалось прочитать команду клиента")?;
    if input.len() > MAX_INPUT {
        return Err("слишком большая команда клиента");
    }
    let mut config: WorkerConfig =
        serde_json::from_slice(&input).map_err(|_| "неверная команда клиента")?;
    drop(input);
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(&config.key_hex, &mut *key)
        .map_err(|_| "неверный ключ демонстрационного клиента")?;
    config.key_hex.zeroize();
    // Cleartext HTTP is an explicit exception for this loopback-only exercise.
    let mut client = ClientWorker::open(&config.database, StorageKey::from_bytes(*key), true)
        .map_err(|_| "не удалось открыть демонстрационный клиент")?;
    drop(key);
    let output = match &config.action {
        WorkerAction::Enqueue { text } => {
            if !demo_text(text) {
                return Err("команда содержит неизвестный демонстрационный текст");
            }
            client
                .store()
                .enqueue(&config.contact, text)
                .map_err(|_| "не удалось сохранить исходящее сообщение")?;
            let pending = client
                .store()
                .pending_outbox(&config.contact)
                .map_err(|_| "не удалось проверить исходящие сообщения")?
                .len();
            WorkerOutput::Enqueued { pending }
        }
        WorkerAction::Sync => {
            let report = client
                .sync(&config.contact)
                .await
                .map_err(|_| "синхронизация демонстрационного клиента не удалась")?;
            WorkerOutput::Synced {
                sent: report.sent,
                received: report.received,
                duplicates: report.duplicates,
                acked: report.acked,
            }
        }
        WorkerAction::History => {
            let history = client
                .store()
                .history(&config.contact, 0)
                .map_err(|_| "не удалось прочитать демонстрационную историю")?;
            if history.iter().any(|entry| !demo_text(&entry.text)) {
                return Err("история содержит неизвестный демонстрационный текст");
            }
            WorkerOutput::History {
                entries: history
                    .into_iter()
                    .map(|entry| HistoryItem {
                        incoming: entry.direction == Direction::Incoming,
                        text: entry.text,
                    })
                    .collect(),
            }
        }
    };
    // Output has only counters and the two public, fixed demo texts. No keys,
    // queue capabilities, contact bundles, raw network bodies or database paths.
    let output = serde_json::to_vec(&output).map_err(|_| "не удалось подготовить результат")?;
    if output.len() > MAX_OUTPUT {
        return Err("слишком большой результат клиента");
    }
    let mut stdout = tokio::io::stdout();
    stdout
        .write_all(&output)
        .await
        .map_err(|_| "не удалось передать результат клиента")?;
    stdout
        .flush()
        .await
        .map_err(|_| "не удалось передать результат клиента")?;
    Ok(())
}

async fn run_worker(
    database: &Path,
    key: &StorageKey,
    contact: &str,
    action: WorkerAction,
) -> DemoResult<WorkerOutput> {
    let config = WorkerConfig {
        database: database.to_owned(),
        key_hex: hex::encode(key.as_bytes()),
        contact: contact.to_owned(),
        action,
    };
    let input = Zeroizing::new(
        serde_json::to_vec(&config).map_err(|_| "не удалось подготовить команду клиента")?,
    );
    drop(config);
    if input.len() > MAX_INPUT {
        return Err("слишком большая команда клиента");
    }
    let executable = std::env::current_exe().map_err(|_| "не найден исполняемый файл примера")?;
    let mut child = Command::new(executable)
        .arg("--worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "не удалось запустить процесс клиента")?;
    let result = timeout(CHILD_TIMEOUT, async {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("недоступен канал команды клиента")?;
        stdin
            .write_all(&input)
            .await
            .map_err(|_| "не удалось передать команду клиента")?;
        stdin
            .shutdown()
            .await
            .map_err(|_| "не удалось завершить передачу команды клиента")?;
        drop(stdin);
        let stdout = child
            .stdout
            .take()
            .ok_or("недоступен канал результата клиента")?;
        let mut output = Vec::new();
        stdout
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut output)
            .await
            .map_err(|_| "не удалось получить результат клиента")?;
        if output.len() > MAX_OUTPUT {
            return Err("слишком большой результат клиента");
        }
        let status = child
            .wait()
            .await
            .map_err(|_| "не удалось дождаться выхода клиента")?;
        if !status.success() {
            return Err("процесс клиента завершился с ошибкой");
        }
        serde_json::from_slice(&output).map_err(|_| "неверный результат клиента")
    })
    .await;
    drop(input);
    match result {
        Ok(Ok(output)) => Ok(output),
        Ok(Err(reason)) => {
            let _ = child.kill().await;
            Err(reason)
        }
        Err(_) => {
            let _ = child.kill().await;
            Err("превышено время ожидания клиента")
        }
    }
}

async fn create_queue(http: &reqwest::Client, relay_url: &str, admin: &str) -> DemoResult<Queue> {
    let mut response = http
        .post(format!("{relay_url}/v1/queues"))
        .bearer_auth(admin)
        .send()
        .await
        .map_err(|_| "не удалось создать очередь демонстрационного сервера")?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err("демонстрационный сервер отказал в создании очереди");
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "не удалось получить очередь демонстрационного сервера")?
    {
        if body.len().saturating_add(chunk.len()) > 4096 {
            return Err("слишком большой ответ демонстрационного сервера");
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| "неверный ответ демонстрационного сервера")
}

fn endpoint(relay_url: &str, queue: &Queue, read: bool) -> QueueEndpoint {
    QueueEndpoint {
        relay_url: relay_url.to_owned(),
        queue_id: queue.id.clone(),
        token: if read {
            queue.read_token.clone()
        } else {
            queue.write_token.clone()
        },
    }
}

fn bootstrap(
    alice_path: &Path,
    alice_key: &StorageKey,
    bob_path: &Path,
    bob_key: &StorageKey,
    alice_route: &ContactRoute,
    bob_route: &ContactRoute,
) -> DemoResult<(String, String)> {
    let mut alice = ClientStore::open(alice_path, StorageKey::from_bytes(*alice_key.as_bytes()))
        .map_err(|_| "не удалось подготовить первого клиента")?;
    let mut bob = ClientStore::open(bob_path, StorageKey::from_bytes(*bob_key.as_bytes()))
        .map_err(|_| "не удалось подготовить второго клиента")?;
    let alice_id = alice
        .insert_contact(Contact::new())
        .map_err(|_| "не удалось создать первый контакт")?;
    let bob_id = bob
        .insert_contact(Contact::new())
        .map_err(|_| "не удалось создать второй контакт")?;
    let alice_bundle = alice
        .public_bundle(&alice_id)
        .map_err(|_| "не удалось подготовить первый публичный набор")?;
    let bob_bundle = bob
        .public_bundle(&bob_id)
        .map_err(|_| "не удалось подготовить второй публичный набор")?;
    // Bundles are trusted local objects in this exercise. This is deliberately
    // not an invitation protocol or a claim of remote identity verification.
    let alice_fingerprint = alice_bundle
        .fingerprint()
        .map_err(|_| "не удалось проверить первый публичный набор")?;
    let bob_fingerprint = bob_bundle
        .fingerprint()
        .map_err(|_| "не удалось проверить второй публичный набор")?;
    alice
        .bind_peer(&alice_id, bob_bundle, &bob_fingerprint)
        .map_err(|_| "не удалось привязать первый контакт")?;
    bob.bind_peer(&bob_id, alice_bundle, &alice_fingerprint)
        .map_err(|_| "не удалось привязать второй контакт")?;
    alice
        .start_session(&alice_id)
        .map_err(|_| "не удалось начать демонстрационную сессию")?;
    alice
        .set_route(&alice_id, alice_route)
        .map_err(|_| "не удалось сохранить маршрут первого клиента")?;
    bob.set_route(&bob_id, bob_route)
        .map_err(|_| "не удалось сохранить маршрут второго клиента")?;
    Ok((alice_id, bob_id))
}

fn expect(actual: WorkerOutput, expected: WorkerOutput) -> DemoResult<()> {
    if actual == expected {
        Ok(())
    } else {
        Err("результат сетевого диалога не соответствует ожидаемому")
    }
}

fn synced(sent: usize, received: usize, acked: usize) -> WorkerOutput {
    WorkerOutput::Synced {
        sent,
        received,
        duplicates: 0,
        acked,
    }
}

async fn dialog(directory: &Path, relay_url: &str, admin: &str) -> DemoResult<()> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "не удалось создать локальный HTTP-клиент")?;
    let alice_to_bob = create_queue(&http, relay_url, admin).await?;
    let bob_to_alice = create_queue(&http, relay_url, admin).await?;
    let alice_route = ContactRoute {
        send: endpoint(relay_url, &alice_to_bob, false),
        receive: endpoint(relay_url, &bob_to_alice, true),
    };
    let bob_route = ContactRoute {
        send: endpoint(relay_url, &bob_to_alice, false),
        receive: endpoint(relay_url, &alice_to_bob, true),
    };
    let alice_path = directory.join("alice.sqlite");
    let bob_path = directory.join("bob.sqlite");
    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();
    let (alice_id, bob_id) = bootstrap(
        &alice_path,
        &alice_key,
        &bob_path,
        &bob_key,
        &alice_route,
        &bob_route,
    )?;

    // Enqueue performs no HTTP. Alice exits with the encrypted outbox on disk;
    // Bob proves the relay has nothing until a fresh Alice process flushes it.
    expect(
        run_worker(
            &alice_path,
            &alice_key,
            &alice_id,
            WorkerAction::Enqueue {
                text: FIRST_TEXT.to_owned(),
            },
        )
        .await?,
        WorkerOutput::Enqueued { pending: 1 },
    )?;
    expect(
        run_worker(&bob_path, &bob_key, &bob_id, WorkerAction::Sync).await?,
        synced(0, 0, 0),
    )?;
    expect(
        run_worker(&alice_path, &alice_key, &alice_id, WorkerAction::Sync).await?,
        synced(1, 0, 0),
    )?;
    expect(
        run_worker(&bob_path, &bob_key, &bob_id, WorkerAction::Sync).await?,
        synced(0, 1, 1),
    )?;
    expect(
        run_worker(
            &bob_path,
            &bob_key,
            &bob_id,
            WorkerAction::Enqueue {
                text: REPLY_TEXT.to_owned(),
            },
        )
        .await?,
        WorkerOutput::Enqueued { pending: 1 },
    )?;
    expect(
        run_worker(&bob_path, &bob_key, &bob_id, WorkerAction::Sync).await?,
        synced(1, 0, 0),
    )?;
    expect(
        run_worker(&alice_path, &alice_key, &alice_id, WorkerAction::Sync).await?,
        synced(0, 1, 1),
    )?;
    for (path, key, contact) in [
        (&alice_path, &alice_key, &alice_id),
        (&bob_path, &bob_key, &bob_id),
    ] {
        expect(
            run_worker(path, key, contact, WorkerAction::Sync).await?,
            synced(0, 0, 0),
        )?;
    }
    for (path, key, contact, first_incoming) in [
        (&alice_path, &alice_key, &alice_id, false),
        (&bob_path, &bob_key, &bob_id, true),
    ] {
        expect(
            run_worker(path, key, contact, WorkerAction::History).await?,
            WorkerOutput::History {
                entries: vec![
                    HistoryItem {
                        incoming: first_incoming,
                        text: FIRST_TEXT.to_owned(),
                    },
                    HistoryItem {
                        incoming: !first_incoming,
                        text: REPLY_TEXT.to_owned(),
                    },
                ],
            },
        )?;
    }
    Ok(())
}

async fn parent() -> DemoResult<()> {
    let directory = tempfile::tempdir().map_err(|_| "не удалось создать временный каталог")?;
    let relay_path = directory.path().join("relay.sqlite");
    let relay_path = relay_path
        .to_str()
        .ok_or("неверный путь демонстрационного сервера")?;
    let store =
        Store::open(relay_path).map_err(|_| "не удалось открыть демонстрационный сервер")?;
    let admin_key = StorageKey::generate();
    let admin = Zeroizing::new(hex::encode(admin_key.as_bytes()));
    let state = AppState::new(store, &admin);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "не удалось открыть локальный порт")?;
    let address = listener
        .local_addr()
        .map_err(|_| "не удалось определить локальный порт")?;
    let relay_url = format!("http://{address}");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let result = dialog(directory.path(), &relay_url, &admin).await;
    let _ = shutdown_tx.send(());
    let server_result = timeout(Duration::from_secs(3), &mut server).await;
    let server_stopped = match server_result {
        Ok(Ok(Ok(()))) => true,
        Ok(_) => false,
        Err(_) => {
            server.abort();
            let _ = server.await;
            false
        }
    };
    result?;
    if !server_stopped {
        return Err("демонстрационный сервер не завершился корректно");
    }
    // Temporary databases are removed here; keys are intentionally not retained.
    directory
        .close()
        .map_err(|_| "не удалось удалить временные базы")?;
    println!("Сетевой диалог проверен: HTTP, перезапуски клиентов и повторная синхронизация.");
    println!("A → B: {FIRST_TEXT}");
    println!("B → A: {REPLY_TEXT}");
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    let result = if arguments.is_empty() {
        parent().await
    } else if arguments.len() == 1 && arguments[0] == "--worker" {
        worker().await
    } else {
        Err("неверные аргументы демонстрационного примера")
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            // All reasons are fixed strings; never format underlying errors,
            // secret-bearing configs, network response bodies or tokens.
            eprintln!("Демонстрация не завершена: {reason}.");
            ExitCode::FAILURE
        }
    }
}

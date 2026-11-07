//! Temporary invitation and encrypted HTTP dialog exercise.
//! This controlled process trusts both fingerprints as test fixtures. In real
//! use they MUST be verified through an independent trusted channel.
//! Demo storage keys stay in memory; this example is not an OS key vault.

use std::{path::Path, process::ExitCode, time::Duration};

use messenger_client::{ClientWorker, ReceiveQueue, SyncReport};
use messenger_core::StorageKey;
use messenger_relay::{router, AppState, Queue, Store};
use messenger_store::{Direction, QueueEndpoint};
use tokio::{sync::oneshot, time::timeout};
use zeroize::Zeroizing;

const FIRST_TEXT: &str = "Привет! Контакт создан через приглашение.";
const REPLY_TEXT: &str = "Ответ получен после повторного открытия профиля.";
type DemoResult<T> = Result<T, &'static str>;

fn copy_key(key: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*key.as_bytes())
}

fn open(path: &Path, key: &StorageKey) -> DemoResult<ClientWorker> {
    // Direct cleartext HTTP is only allowed to literal loopback addresses.
    ClientWorker::open(path, copy_key(key), true)
        .map_err(|_| "не удалось открыть демонстрационный профиль")
}

async fn provision(http: &reqwest::Client, url: &str, admin: &str) -> DemoResult<ReceiveQueue> {
    let mut response = http
        .post(format!("{url}/v1/queues"))
        .bearer_auth(admin)
        .send()
        .await
        .map_err(|_| "не удалось создать демонстрационную очередь")?;
    if response.status() != reqwest::StatusCode::CREATED {
        return Err("сервер отказал в создании демонстрационной очереди");
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "не удалось получить демонстрационную очередь")?
    {
        if body.len().saturating_add(chunk.len()) > 4096 {
            return Err("слишком большой ответ демонстрационного сервера");
        }
        body.extend_from_slice(&chunk);
    }
    let queue: Queue =
        serde_json::from_slice(&body).map_err(|_| "неверный ответ демонстрационного сервера")?;
    Ok(ReceiveQueue {
        read: QueueEndpoint {
            relay_url: url.to_owned(),
            queue_id: queue.id.clone(),
            token: queue.read_token,
        },
        write: QueueEndpoint {
            relay_url: url.to_owned(),
            queue_id: queue.id,
            token: queue.write_token,
        },
    })
}

fn expect_report(actual: SyncReport, sent: usize, received: usize, acked: usize) -> DemoResult<()> {
    if actual.sent == sent
        && actual.received == received
        && actual.acked == acked
        && actual.duplicates == 0
        && !actual.profile_changed
    {
        Ok(())
    } else {
        Err("счётчики демонстрационного диалога не соответствуют ожидаемым")
    }
}

async fn dialog(directory: &Path, url: &str, admin: &str) -> DemoResult<()> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| "не удалось создать локальный HTTP-клиент")?;
    let alice_queue = provision(&http, url, admin).await?;
    let bob_queue = provision(&http, url, admin).await?;
    let alice_path = directory.join("alice.sqlite");
    let bob_path = directory.join("bob.sqlite");
    let alice_key = StorageKey::generate();
    let bob_key = StorageKey::generate();

    let mut alice = open(&alice_path, &alice_key)?;
    let offer = alice
        .create_invitation(alice_queue)
        .map_err(|_| "не удалось создать приглашение")?;
    drop(alice);
    let mut alice = open(&alice_path, &alice_key)?;
    let exported_offer = alice
        .export_invitation(&offer.contact)
        .map_err(|_| "не удалось восстановить приглашение")?;
    if exported_offer.invitation != offer.invitation
        || exported_offer.fingerprint != offer.fingerprint
    {
        return Err("приглашение изменилось после повторного открытия профиля");
    }
    drop(alice);

    let mut bob = open(&bob_path, &bob_key)?;
    // Both artifacts originate inside this controlled demonstration. Passing
    // their computed fingerprints is NOT a remote identity verification step.
    let reply = bob
        .accept_invitation(
            &exported_offer.invitation,
            &exported_offer.fingerprint,
            bob_queue,
        )
        .map_err(|_| "не удалось принять демонстрационное приглашение")?;
    drop(bob);
    let mut bob = open(&bob_path, &bob_key)?;
    let exported_reply = bob
        .export_invitation(&reply.contact)
        .map_err(|_| "не удалось восстановить ответ на приглашение")?;
    if exported_reply.invitation != reply.invitation
        || exported_reply.fingerprint != reply.fingerprint
    {
        return Err("ответ на приглашение изменился после повторного открытия профиля");
    }
    drop(bob);

    let mut alice = open(&alice_path, &alice_key)?;
    alice
        .complete_invitation(
            &offer.contact,
            &exported_reply.invitation,
            &exported_reply.fingerprint,
        )
        .map_err(|_| "не удалось завершить обмен приглашениями")?;
    alice
        .store()
        .enqueue(&offer.contact, FIRST_TEXT)
        .map_err(|_| "не удалось сохранить первое демонстрационное сообщение")?;
    drop(alice);
    let mut alice = open(&alice_path, &alice_key)?;
    expect_report(
        alice
            .sync(&offer.contact)
            .await
            .map_err(|_| "не удалось отправить первое демонстрационное сообщение")?,
        1,
        0,
        0,
    )?;
    drop(alice);

    let mut bob = open(&bob_path, &bob_key)?;
    expect_report(
        bob.sync(&reply.contact)
            .await
            .map_err(|_| "не удалось принять первое демонстрационное сообщение")?,
        0,
        1,
        1,
    )?;
    bob.store()
        .enqueue(&reply.contact, REPLY_TEXT)
        .map_err(|_| "не удалось сохранить демонстрационный ответ")?;
    drop(bob);
    let mut bob = open(&bob_path, &bob_key)?;
    expect_report(
        bob.sync(&reply.contact)
            .await
            .map_err(|_| "не удалось отправить демонстрационный ответ")?,
        1,
        0,
        0,
    )?;
    drop(bob);
    let mut alice = open(&alice_path, &alice_key)?;
    expect_report(
        alice
            .sync(&offer.contact)
            .await
            .map_err(|_| "не удалось принять демонстрационный ответ")?,
        0,
        1,
        2,
    )?;
    drop(alice);

    for (path, key, contact, first_direction) in [
        (&alice_path, &alice_key, &offer.contact, Direction::Outgoing),
        (&bob_path, &bob_key, &reply.contact, Direction::Incoming),
    ] {
        let mut client = open(path, key)?;
        let history = client
            .store()
            .history(contact, 0)
            .map_err(|_| "не удалось открыть демонстрационную историю")?;
        if history.len() != 2
            || history[0].text != FIRST_TEXT
            || history[0].direction != first_direction
            || history[1].text != REPLY_TEXT
            || history[1].direction == first_direction
        {
            return Err("демонстрационная история не соответствует ожидаемой");
        }
        expect_report(
            client
                .sync(contact)
                .await
                .map_err(|_| "не удалось повторить демонстрационную синхронизацию")?,
            0,
            0,
            if first_direction == Direction::Incoming {
                1
            } else {
                0
            },
        )?;
    }
    Ok(())
}

async fn run() -> DemoResult<()> {
    let directory = tempfile::tempdir().map_err(|_| "не удалось создать временный каталог")?;
    let relay_path = directory.path().join("relay.sqlite");
    let relay_path = relay_path
        .to_str()
        .ok_or("неверный путь демонстрационного сервера")?;
    let relay =
        Store::open(relay_path).map_err(|_| "не удалось открыть демонстрационный сервер")?;
    let admin_key = StorageKey::generate();
    let admin = Zeroizing::new(hex::encode(admin_key.as_bytes()));
    let state = AppState::new(relay, &admin);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|_| "не удалось открыть локальный порт")?;
    let address = listener
        .local_addr()
        .map_err(|_| "не удалось определить локальный порт")?;
    let url = format!("http://{address}");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    let result = dialog(directory.path(), &url, &admin).await;
    let _ = shutdown_tx.send(());
    let stopped = match timeout(Duration::from_secs(3), &mut server).await {
        Ok(Ok(Ok(()))) => true,
        Ok(_) => false,
        Err(_) => {
            server.abort();
            let _ = server.await;
            false
        }
    };
    result?;
    if !stopped {
        return Err("демонстрационный сервер не завершился корректно");
    }
    directory
        .close()
        .map_err(|_| "не удалось удалить временные базы")?;
    // Only public fixed texts and counters appear on stdout, never capabilities,
    // invitation artifacts, fingerprints, URLs or local profile paths.
    println!("Приглашение и ответ восстановлены после повторного открытия профилей.");
    println!("Сообщений доставлено: 2. Повторных сообщений: 0.");
    println!("A → B: {FIRST_TEXT}");
    println!("B → A: {REPLY_TEXT}");
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    let result = if std::env::args_os().len() == 1 {
        run().await
    } else {
        Err("неверные аргументы демонстрационного примера")
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("Демонстрация не завершена: {reason}.");
            ExitCode::FAILURE
        }
    }
}

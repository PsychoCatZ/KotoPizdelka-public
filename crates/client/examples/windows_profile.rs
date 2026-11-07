//! A temporary Windows profile reopened by independent client processes.
//! DPAPI keeps the storage key under the current Windows user; the parent
//! passes only a database path and an action, never a key or contact bundle.

use messenger_client::ClientWorker;
use messenger_core::Contact;
use messenger_store::Direction;
use serde::{Deserialize, Serialize};
use std::{path::Path, path::PathBuf, process::ExitCode, process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, process::Command, time::timeout};

const TEST_TEXT: &str = "Сообщение сохранилось после выхода клиента.";
const MAX_OUTPUT: usize = 16 * 1024;
const CHILD_TIMEOUT: Duration = Duration::from_secs(20);
type DemoResult<T> = Result<T, &'static str>;

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WorkerOutput {
    Seeded {
        pending: usize,
    },
    Inspected {
        contacts: usize,
        messages: usize,
        pending: usize,
    },
}

async fn worker(database: &Path, action: &str) -> DemoResult<()> {
    let mut client = ClientWorker::open_system(database, false)
        .map_err(|_| "не удалось открыть профиль Windows")?;
    let output = match action {
        "seed" => {
            if !client
                .store()
                .contact_ids()
                .map_err(|_| "не удалось проверить контакты")?
                .is_empty()
            {
                return Err("демонстрационный профиль уже содержит контакты");
            }
            let contact = client
                .store()
                .insert_contact(Contact::new())
                .map_err(|_| "не удалось создать демонстрационный контакт")?;
            // This fresh local object is an independently trusted fixture,
            // not an invitation protocol or remote identity verification.
            let peer = Contact::new();
            let bundle = peer.public_bundle();
            let fingerprint = bundle
                .fingerprint()
                .map_err(|_| "не удалось проверить локальный набор ключей")?;
            client
                .store()
                .bind_peer(&contact, bundle, &fingerprint)
                .map_err(|_| "не удалось привязать демонстрационный контакт")?;
            client
                .store()
                .start_session(&contact)
                .map_err(|_| "не удалось начать демонстрационную сессию")?;
            // Enqueue does no HTTP; the encrypted outbox survives process exit.
            client
                .store()
                .enqueue(&contact, TEST_TEXT)
                .map_err(|_| "не удалось сохранить исходящее сообщение")?;
            WorkerOutput::Seeded {
                pending: client
                    .store()
                    .pending_outbox(&contact)
                    .map_err(|_| "не удалось проверить исходящие сообщения")?
                    .len(),
            }
        }
        "inspect" => {
            let contacts = client
                .store()
                .contact_ids()
                .map_err(|_| "не удалось прочитать контакты")?;
            if contacts.len() != 1 {
                return Err("контакты профиля не соответствуют ожидаемым");
            }
            let history = client
                .store()
                .history(&contacts[0], 0)
                .map_err(|_| "не удалось прочитать историю")?;
            if history.len() != 1
                || history[0].text != TEST_TEXT
                || history[0].direction != Direction::Outgoing
            {
                return Err("история профиля не соответствует ожидаемой");
            }
            WorkerOutput::Inspected {
                contacts: contacts.len(),
                messages: history.len(),
                pending: client
                    .store()
                    .pending_outbox(&contacts[0])
                    .map_err(|_| "не удалось прочитать исходящие сообщения")?
                    .len(),
            }
        }
        _ => return Err("неверное действие демонстрационного клиента"),
    };
    // Only success counters cross this pipe, never secrets or raw errors.
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
        .map_err(|_| "не удалось передать результат клиента")
}

async fn run_worker(database: &Path, action: &str) -> DemoResult<WorkerOutput> {
    let executable = std::env::current_exe().map_err(|_| "не найден исполняемый файл примера")?;
    let mut child = Command::new(executable)
        .arg("--worker")
        .arg(database)
        .arg(action)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "не удалось запустить процесс клиента")?;
    let result = timeout(CHILD_TIMEOUT, async {
        let stdout = child.stdout.take().ok_or("недоступен результат клиента")?;
        let mut output = Vec::new();
        stdout
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut output)
            .await
            .map_err(|_| "не удалось прочитать результат клиента")?;
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
    .await
    .unwrap_or(Err("превышено время ожидания клиента"));
    if result.is_err() {
        // Reap every worker before the parent removes its temporary profile.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

async fn profile(directory: &Path) -> DemoResult<()> {
    let database = directory.join("profile.sqlite");
    if run_worker(&database, "seed").await? != (WorkerOutput::Seeded { pending: 1 }) {
        return Err("сохранение сообщения не соответствует ожидаемому");
    }
    if !messenger_platform::key_path(&database).is_file() {
        return Err("защищённый файл ключа не найден");
    }
    if run_worker(&database, "inspect").await?
        != (WorkerOutput::Inspected {
            contacts: 1,
            messages: 1,
            pending: 1,
        })
    {
        return Err("восстановление профиля не соответствует ожидаемому");
    }
    Ok(())
}

async fn parent() -> DemoResult<()> {
    let directory = tempfile::tempdir().map_err(|_| "не удалось создать временный каталог")?;
    let result = profile(directory.path()).await;
    let cleanup = directory
        .close()
        .map_err(|_| "не удалось удалить временный профиль");
    result?;
    cleanup?;
    println!("Windows сохранила ключ профиля через DPAPI без передачи ключа между процессами.");
    println!("Новый процесс восстановил историю и одно ожидающее отправки сообщение.");
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() -> ExitCode {
    let result = if messenger_platform::ensure_supported().is_err() {
        // Check before creating a directory, database, lock or key sidecar.
        Err("системное хранение ключа доступно только в Windows")
    } else {
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        if arguments.is_empty() {
            parent().await
        } else if arguments.len() == 3 && arguments[0] == "--worker" {
            match arguments[2].to_str() {
                Some(action @ ("seed" | "inspect")) => {
                    worker(&PathBuf::from(&arguments[1]), action).await
                }
                _ => Err("неверное действие демонстрационного клиента"),
            }
        } else {
            Err("неверные аргументы демонстрационного примера")
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("Демонстрация не завершена: {reason}.");
            ExitCode::FAILURE
        }
    }
}

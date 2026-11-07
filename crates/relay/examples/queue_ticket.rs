//! Local operator command: only the explicitly selected relay database is used.
//! Successful stdout contains only the new ticket. `--invite` explicitly grants
//! authority for one inviter queue plus one non-delegating recipient ticket.
use messenger_relay::Store;
use std::{env, process::ExitCode};

fn issue() -> Result<String, &'static str> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let invitation = match arguments.as_slice() {
        [] => false,
        [argument] if argument == "--invite" => true,
        _ => return Err("Only --invite is accepted; set RELAY_DATABASE."),
    };
    let path = env::var("RELAY_DATABASE")
        .map_err(|_| "Set RELAY_DATABASE to the relay's persistent SQLite file.")?;
    if path.trim().is_empty() || path == ":memory:" {
        return Err("Set RELAY_DATABASE to the relay's persistent SQLite file.");
    }
    let ttl = match env::var("RELAY_TICKET_TTL") {
        Ok(value) => value
            .parse::<i64>()
            .map_err(|_| "RELAY_TICKET_TTL must be between 1 and 86400 seconds.")?,
        Err(env::VarError::NotPresent) => {
            if invitation {
                86400
            } else {
                3600
            }
        }
        Err(_) => return Err("RELAY_TICKET_TTL must be between 1 and 86400 seconds."),
    };
    if !(1..=86400).contains(&ttl) {
        return Err("RELAY_TICKET_TTL must be between 1 and 86400 seconds.");
    }
    let mut store = Store::open(&path).map_err(|_| "Unable to open the relay database.")?;
    let result = if invitation {
        store.issue_invitation_ticket(ttl)
    } else {
        store.issue_ticket(ttl)
    };
    result.map_err(|_| "Unable to issue a queue ticket.")
}

fn main() -> ExitCode {
    match issue() {
        Ok(ticket) => {
            println!("{ticket}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

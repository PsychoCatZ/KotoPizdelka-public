//! A headless storage worker being open does not unlock the renderer session.
use messenger_app::{Reply, Request};
use std::sync::atomic::{AtomicBool, Ordering};
#[derive(Default)]
pub struct ProfileGate(AtomicBool);
impl ProfileGate {
    pub fn before(&self, request: &Request) -> Result<Option<Reply>, String> {
        if self.0.load(Ordering::Acquire) {
            return Ok(None);
        }
        match request {
            Request::Status => Ok(Some(Reply::Profile {
                open: false,
                nickname: String::new(),
            })),
            Request::OpenProfile | Request::RestoreProfile { .. } => Ok(None),
            _ => Err("Сначала открой профиль.".into()),
        }
    }
    pub fn finish_open(&self, reply: &Reply) {
        if matches!(reply, Reply::Profile { open: true, .. }) {
            self.0.store(true, Ordering::Release);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn background_storage_does_not_expose_profile_until_explicit_successful_gui_open() {
        let gate = ProfileGate::default();
        let Some(Reply::Profile { open, nickname }) = gate.before(&Request::Status).unwrap() else {
            panic!("profile")
        };
        assert!(!open);
        assert!(nickname.is_empty());
        assert!(gate.before(&Request::Contacts).is_err());
        assert!(gate
            .before(&Request::History {
                contact: "a".repeat(32),
                after_sequence: 0
            })
            .is_err());
        assert!(gate.before(&Request::OpenProfile).unwrap().is_none());
        gate.finish_open(&Reply::Profile {
            open: false,
            nickname: String::new(),
        });
        assert!(gate.before(&Request::Contacts).is_err());
        gate.finish_open(&Reply::Profile {
            open: true,
            nickname: "Кот".into(),
        });
        assert!(gate.before(&Request::Contacts).unwrap().is_none());
    }
}

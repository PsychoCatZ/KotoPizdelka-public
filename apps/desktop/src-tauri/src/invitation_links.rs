//! Bounded, in-memory handoff from operating-system links to the local UI.
//! Full invitation authentication stays in the profile worker after acceptance.

use std::sync::Mutex;

pub(crate) const MAX_LINK: usize = 2300;
const PREFIX: &str = "kotopizdelka://invite#";

pub(crate) fn valid_link(link: &str) -> bool {
    link.len() <= MAX_LINK
        && link.strip_prefix(PREFIX).is_some_and(|payload| {
            !payload.is_empty()
                && payload
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

#[derive(Default)]
pub(crate) struct PendingInvitation(Mutex<Option<String>>);

impl PendingInvitation {
    pub(crate) fn put(&self, link: &str) -> bool {
        if !valid_link(link) {
            return false;
        }
        if let Ok(mut pending) = self.0.lock() {
            *pending = Some(link.to_owned());
            true
        } else {
            false
        }
    }

    pub(crate) fn take(&self) -> Option<String> {
        self.0.lock().ok()?.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_bounded_opaque_invitation_links_enter_the_handoff() {
        assert!(valid_link("kotopizdelka://invite#A0_-z"));
        for invalid in [
            "https://example.org/#secret",
            "kotopizdelka://invite#",
            "kotopizdelka://invite/#secret",
            "kotopizdelka://invite?secret#payload",
            "kotopizdelka://other#payload",
            "kotopizdelka://invite#x%0ay",
            "kotopizdelka://invite#x\ny",
            "kotopizdelka://invite#x/y",
            "kotopizdelka://invite#кошки",
        ] {
            assert!(!valid_link(invalid));
        }
        assert!(!valid_link(&format!("{PREFIX}{}", "x".repeat(MAX_LINK))));
    }

    #[test]
    fn pending_handoff_is_single_use_and_rejects_replacement_by_invalid_data() {
        let pending = PendingInvitation::default();
        assert!(pending.put("kotopizdelka://invite#first"));
        assert!(!pending.put("https://invalid.example"));
        assert_eq!(
            pending.take().as_deref(),
            Some("kotopizdelka://invite#first")
        );
        assert!(pending.take().is_none());
        assert!(pending.put("kotopizdelka://invite#first"));
        assert!(pending.put("kotopizdelka://invite#latest"));
        assert_eq!(
            pending.take().as_deref(),
            Some("kotopizdelka://invite#latest")
        );
    }
}

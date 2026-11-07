//! Native, bounded viewing context. No name/text or capability goes to Android.
use std::sync::Mutex;
#[derive(Default)]
pub struct NotificationView(Mutex<Option<String>>);
impl NotificationView {
    pub fn set(&self, contact: Option<String>) -> Result<(), &'static str> {
        if contact.as_ref().is_some_and(|id| {
            id.len() != 32
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err("Некорректный контекст уведомления.");
        }
        *self
            .0
            .lock()
            .map_err(|_| "Контекст уведомления недоступен.")? = contact;
        Ok(())
    }
    #[cfg(any(target_os = "android", test))]
    pub fn all_viewed(&self, contacts: &[String]) -> bool {
        let Ok(current) = self.0.lock() else {
            return false;
        };
        !contacts.is_empty()
            && current
                .as_ref()
                .is_some_and(|id| contacts.iter().all(|c| c == id))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_a_valid_selected_chat_suppresses_its_own_batch() {
        let view = NotificationView::default();
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        assert!(!view.all_viewed(std::slice::from_ref(&a)));
        view.set(Some(a.clone())).unwrap();
        assert!(view.all_viewed(std::slice::from_ref(&a)));
        assert!(!view.all_viewed(&[a.clone(), b]));
        assert!(!view.all_viewed(&[]));
        assert!(view.set(Some("../profile".into())).is_err());
        assert!(view.all_viewed(std::slice::from_ref(&a)));
        view.set(None).unwrap();
        assert!(!view.all_viewed(&[a]));
    }
}

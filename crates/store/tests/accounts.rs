use messenger_core::{accounts::AccountIdentity, StorageKey};
use messenger_store::{AccountState, ClientStore};
use rusqlite::Connection;
fn copy(k: &StorageKey) -> StorageKey {
    StorageKey::from_bytes(*k.as_bytes())
}
#[test]
fn account_sealed_and_v6_upgrade_requires_original_key() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("db");
    let key = StorageKey::generate();
    drop(ClientStore::open(&path, copy(&key)).unwrap());
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch(
        "DROP TABLE account_state; DROP TABLE account_jobs; UPDATE store_meta SET version=6",
    )
    .unwrap();
    assert!(ClientStore::open(&path, StorageKey::generate()).is_err());
    assert_eq!(
        sql.query_row("SELECT version FROM store_meta", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!(
        sql.query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='account_state'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    let mut store = ClientStore::open(&path, copy(&key)).unwrap();
    let a = AccountState {
        login: "my_cat".into(),
        relay_url: "https://relay.example".into(),
        identity: AccountIdentity::default(),
        session: "a".repeat(64),
        registered: true,
        authenticated: true,
        cursor: 0,
    };
    let public = a.identity.public_key();
    store.save_account(&a).unwrap();
    let blob: Vec<u8> = sql
        .query_row("SELECT record FROM account_state", [], |r| r.get(0))
        .unwrap();
    assert!(!blob.windows(64).any(|w| w == a.session.as_bytes()));
    assert!(!blob.windows(6).any(|w| w == b"my_cat"));
    drop(store);
    let store = ClientStore::open(&path, copy(&key)).unwrap();
    assert_eq!(
        store.account().unwrap().unwrap().identity.public_key(),
        public
    );
    drop(store);
    sql.execute_batch("DROP TABLE account_jobs").unwrap();
    assert!(ClientStore::open(&path, copy(&key)).is_err());
}

use messenger_relay::{router, valid_admin_token, AppState, Store};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = std::env::var("RELAY_ADMIN_TOKEN").map_err(|_| "RELAY_ADMIN_TOKEN is required")?;
    if !valid_admin_token(&token) {
        return Err("RELAY_ADMIN_TOKEN must be 64 lowercase hex characters".into());
    }
    let database = std::env::var("RELAY_DATABASE").unwrap_or_else(|_| "relay.sqlite".into());
    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let state = AppState::new(Store::open(&database)?, &token);
    let cleanup = state.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if cleanup.cleanup().await.is_err() {
                eprintln!("relay cleanup failed");
            }
        }
    });
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("relay listening on {}", listener.local_addr()?);
    let result = axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    task.abort();
    result?;
    Ok(())
}

use anyhow::Result;
use clap::{Parser, Subcommand};
use handshacke as hs;
use rand::RngCore;
use std::io::Write;

#[derive(Parser)]
#[command(
    name = "handshacke",
    version,
    about = "Deterministic P2P communication without servers"
)]
struct Args {
    #[arg(long)]
    unsafe_expose_api: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Onionize(hs::cli::onionize::OnionizeArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    if let Some(Commands::Onionize(cmd)) = args.command {
        return hs::cli::onionize::run(cmd).await;
    }

    tracing::info!("🚀 Avvio Handshacke Core...");

    // Load configuration
    let config = hs::config::Config::from_env();
    tracing::info!("📋 Configuration loaded: API bind on {}", config.api_bind);
    if config.api_bind.starts_with("0.0.0.0") && !args.unsafe_expose_api {
        anyhow::bail!("Refusing to bind API to 0.0.0.0 without --unsafe-expose-api");
    }
    let needs_token = args.unsafe_expose_api || !is_localhost_bind(&config.api_bind);
    let api_token = if needs_token {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = hex::encode(bytes);
        tracing::info!("API bearer token: {}", token);
        if let Ok(path) = std::env::var("HANDSHACKE_API_TOKEN_FILE") {
            if let Err(e) = write_token_file(&path, &token) {
                tracing::warn!("Failed to write API token file: {:?}", e);
            } else if cfg!(windows) {
                tracing::info!(
                    "Token file written (Windows: ensure directory ACLs are restricted)"
                );
            }
        }
        Some(token)
    } else {
        None
    };

    let app_state = hs::state::AppState::default();
    let (streams, _rx_out_spawn_discard) = hs::api::Streams::new();

    hs::api::create_api_server(app_state, streams, config.api_bind.clone(), api_token).await?;

    Ok(())
}

fn is_localhost_bind(bind: &str) -> bool {
    if bind.starts_with("127.0.0.1") || bind.starts_with("localhost") {
        return true;
    }
    if bind.starts_with("[::1]") || bind.starts_with("::1") {
        return true;
    }
    if let Ok(addr) = bind.parse::<std::net::SocketAddr>() {
        return addr.ip().is_loopback();
    }
    false
}

fn write_token_file(path: &str, token: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    writeln!(file, "{}", token)?;
    Ok(())
}

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use clap::{Parser, Subcommand};
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};

const DEFAULT_API: &str = "http://127.0.0.1:3000";

#[derive(Parser)]
#[command(name = "hs-cli", version, about = "Handshacke CLI")]
struct Args {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, default_value = DEFAULT_API)]
    api: String,
}

#[derive(Subcommand)]
enum Commands {
    Host {
        #[arg(long)]
        passphrase: Option<String>,
        #[arg(long)]
        include_tor: bool,
        #[arg(long)]
        ttl_s: Option<u64>,
    },
    Join {
        offer: String,
    },
}

#[derive(Serialize)]
struct OfferRequest {
    passphrase: Option<String>,
    ttl_s: Option<u64>,
    role_hint: Option<String>,
    include_tor: Option<bool>,
}

#[derive(Deserialize)]
struct OfferResponse {
    offer: String,
    ver: u8,
    expires_at_ms: u64,
    endpoints: Vec<String>,
}

#[derive(Serialize)]
struct ConnectRequest {
    offer: Option<String>,
    passphrase: Option<String>,
    local_role: Option<String>,
}

#[derive(Deserialize)]
struct ConnectResponse {
    status: String,
    port: Option<u16>,
    mode: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let client = Client::new();

    match args.command {
        Commands::Host {
            passphrase,
            include_tor,
            ttl_s,
        } => {
            let passphrase = passphrase.unwrap_or_else(random_passphrase);

            let connect_req = ConnectRequest {
                offer: None,
                passphrase: Some(passphrase.clone()),
                local_role: Some("host".into()),
            };
            let connect_url = format!("{}/v1/connect", args.api);
            let connect_res = client.post(connect_url).json(&connect_req).send().await?;
            if !connect_res.status().is_success() {
                return Err(anyhow!("Connect failed: {}", connect_res.status()));
            }

            let req = OfferRequest {
                passphrase: Some(passphrase),
                ttl_s,
                role_hint: Some("host".into()),
                include_tor: Some(include_tor),
            };
            let url = format!("{}/v1/offer", args.api);
            let res = client.post(url).json(&req).send().await?;

            if !res.status().is_success() {
                return Err(anyhow!("Offer generation failed: {}", res.status()));
            }
            let body: OfferResponse = res.json().await?;
            println!("Offer v{} (expires at {} ms)", body.ver, body.expires_at_ms);
            println!("Endpoints: {}", body.endpoints.join(", "));
            println!("Offer (QR-friendly):");
            println!("{}", body.offer);
        }
        Commands::Join { offer } => {
            let req = ConnectRequest {
                offer: Some(offer),
                passphrase: None,
                local_role: None,
            };
            let url = format!("{}/v1/connect", args.api);
            let res = client.post(url).json(&req).send().await?;

            let body: ConnectResponse = res.json().await?;
            println!("Status: {}", body.status);
            println!("Mode: {}", body.mode);
            if let Some(port) = body.port {
                println!("Port: {}", port);
            }
        }
    }

    Ok(())
}

fn random_passphrase() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

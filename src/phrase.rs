use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};

const INVITE_PREFIX: &str = "hs1:";

#[derive(Debug, Serialize, Deserialize)]
pub struct PhraseInvite {
    pub ver: u8,
    pub product: String,
    pub policy: String,
    pub onion: String,
    pub virt_port: u16,
}

impl PhraseInvite {
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_vec(self).context("invite json")?;
        let b64 = general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("{}{}", INVITE_PREFIX, b64))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let b64 = s
            .strip_prefix(INVITE_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("invalid invite prefix"))?;
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .context("invite base64")?;
        let invite = serde_json::from_slice(&bytes).context("invite json")?;
        Ok(invite)
    }
}

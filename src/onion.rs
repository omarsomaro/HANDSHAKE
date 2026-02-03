use anyhow::{Result, bail, Context};

const MIN_V3_ONION_LEN: usize = 56;
const MAX_V3_ONION_LEN: usize = 62;
const ONION_SUFFIX: &str = ".onion";

pub fn validate_onion_addr(target: &str) -> Result<()> {
    let _ = parse_onion_addr(target)?;
    Ok(())
}

pub fn parse_onion_addr(target: &str) -> Result<(String, u16)> {
    let parts: Vec<&str> = target.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        bail!("Tor address must include port: address.onion:port");
    }

    let port_str = parts[0];
    let host = parts[1];

    let port: u16 = port_str.parse()
        .context("Invalid port in Tor address")?;
    if port == 0 {
        bail!("Invalid port in Tor address (cannot be 0)");
    }

    if !host.ends_with(ONION_SUFFIX) {
        bail!("Tor address must end with .onion");
    }

    let host_no_suffix = host.trim_end_matches(ONION_SUFFIX);
    if host_no_suffix.len() < MIN_V3_ONION_LEN {
        bail!(
            "Invalid v3 onion length: {} chars (minimum {})",
            host_no_suffix.len(),
            MIN_V3_ONION_LEN
        );
    }
    if host_no_suffix.len() > MAX_V3_ONION_LEN {
        bail!(
            "Invalid v3 onion length: {} chars (maximum {})",
            host_no_suffix.len(),
            MAX_V3_ONION_LEN
        );
    }
    if !host_no_suffix.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')) {
        bail!("Invalid onion address characters (expected base32 lowercase: a-z, 2-7)");
    }

    Ok((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

    prop_compose! {
        fn onion_host()(len in MIN_V3_ONION_LEN..=MAX_V3_ONION_LEN)
            (chars in prop::collection::vec(prop::sample::select(ALPHABET), len)) -> String {
            chars.into_iter().map(|c| c as char).collect()
        }
    }

    proptest! {
        #[test]
        fn parse_roundtrip_onion(host in onion_host(), port in 1u16..=u16::MAX) {
            let target = format!("{}.onion:{}", host, port);
            let (parsed_host, parsed_port) = parse_onion_addr(&target).unwrap();
            prop_assert_eq!(parsed_host, format!("{}.onion", host));
            prop_assert_eq!(parsed_port, port);
        }
    }

    #[test]
    fn parse_rejects_missing_port() {
        let err = parse_onion_addr("abcd.onion").unwrap_err();
        assert!(err.to_string().contains("port"));
    }
}

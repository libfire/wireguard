use std::net::IpAddr;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine};
use boringtun::x25519::{PublicKey, StaticSecret};

pub(crate) fn decode_private_key(private_key: &str) -> Result<StaticSecret> {
    let decoded = general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| anyhow!("Private key base64 decode failed: {}", e))?;

    if decoded.len() != 32 {
        return Err(anyhow!("Invalid private key len: {}", decoded.len()));
    }

    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("Private key try_into failed"))?;

    Ok(StaticSecret::from(key))
}

pub(crate) fn decode_public_key(public_key: &str) -> Result<PublicKey> {
    let decoded = general_purpose::STANDARD
        .decode(public_key)
        .map_err(|e| anyhow!("Public key base64 decode failed: {}", e))?;

    if decoded.len() != 32 {
        return Err(anyhow!("Invalid public key len: {}", decoded.len()));
    }

    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("Public Key try_into failed"))?;

    PublicKey::try_from(key).map_err(|e| anyhow!("Curve check failed: {:?}", e))
}

pub(crate) fn parse_address(address: &str) -> Result<(IpAddr, u8)> {
    let address = parse_cidr(address).ok_or(anyhow!("Parse address failed: {address}"))?;
    Ok(address)
}

pub(crate) fn parse_dns(dns: &str) -> Result<IpAddr> {
    let dns = dns.parse().map_err(|e| anyhow!("Parse dns failed: {e}"))?;
    Ok(dns)
}

pub(crate) fn parse_allowed_ips(cidrs: &[&str]) -> Result<Vec<(IpAddr, u8)>> {
    let mut allowed_ips = Vec::new();
    for cidr in cidrs {
        let (ip, mask) =
            parse_cidr(cidr).ok_or(anyhow!("Parse allowed_ips: {}", (*cidr).to_string()))?;
        allowed_ips.push((ip, mask));
    }
    Ok(allowed_ips)
}

pub(crate) fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let mut parts = s.split('/');
    let ip = parts.next()?.parse().ok()?;
    let mask = parts.next()?.parse().ok()?;
    Some((ip, mask))
}

pub(crate) fn if_index_to_addr(index: u32) -> Result<IpAddr> {
    let addr = getifaddrs::getifaddrs()?
        .find(|v| v.index == Some(index) && v.address.is_ipv4())
        .map(|i| i.address)
        .ok_or(anyhow!("Interface address not found"))?;
    Ok(addr)
}

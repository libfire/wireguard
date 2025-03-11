use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use anyhow::{anyhow, Ok, Result};
use boringtun::x25519::PublicKey;

use crate::utils::{decode_public_key, parse_allowed_ips};

pub(crate) struct Peer {
    pub public_key: Option<PublicKey>,
    pub allowed_ips: Option<Vec<(IpAddr, u8)>>,
    pub persistent_keepalive: Option<u16>,
    pub endpoint: Option<SocketAddr>,
}

impl Peer {
    pub fn new() -> Result<Self> {
        let peer = Self {
            public_key: None,
            allowed_ips: None,
            persistent_keepalive: None,
            endpoint: None,
        };
        Ok(peer)
    }

    pub fn set_public_key(&mut self, public_key: &str) -> Result<()> {
        self.public_key = Some(decode_public_key(public_key)?);
        Ok(())
    }

    pub fn set_allowed_ips(&mut self, allowed_ips: &[&str]) -> Result<()> {
        self.allowed_ips = Some(parse_allowed_ips(allowed_ips)?);
        Ok(())
    }

    pub fn set_persistent_keepalive(&mut self, persistent_keepalive: u16) -> Result<()> {
        self.persistent_keepalive = Some(persistent_keepalive);
        Ok(())
    }

    pub fn set_endpoint(&mut self, endpoint: &str) -> Result<()> {
        self.endpoint = Some(endpoint_socket_addr(endpoint)?);
        Ok(())
    }

    pub fn check(&self) -> Result<bool> {
        if self.public_key.is_none() {
            Err(anyhow!("missing public_key"))?
        }
        if self.allowed_ips.is_none() {
            Err(anyhow!("missing allowed_ips"))?
        }
        // FIXME: Update unconfigured endpoint based on handshake packet
        if self.endpoint.is_none() {
            Err(anyhow!("missing endpoint"))?
        }
        Ok(true)
    }
}

fn endpoint_socket_addr(endpoint: &str) -> Result<SocketAddr> {
    let socket_addr = endpoint
        .to_socket_addrs()
        .map_err(|e| anyhow!("Parse socket address failed: {}", e))?
        .next()
        .ok_or(anyhow!("No addresses found"))?;
    Ok(socket_addr)
}

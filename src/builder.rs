use std::net::IpAddr;

use anyhow::anyhow;

#[derive(Debug, Clone)]
pub struct WireGuardConfig {
    pub(crate) interface: InterfaceConfig,
    pub(crate) peer: PeerConfig,
}

#[derive(Debug, Clone)]
pub(crate) struct InterfaceConfig {
    pub private_key: String,
    pub address: (IpAddr, u8),
    pub listen_port: u16,
    pub _dns: Option<IpAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerConfig {
    pub public_key: String,
    pub endpoint: (String, u16),
    pub _allowed_ips: Vec<(IpAddr, u8)>,
    pub persistent_keepalive: Option<u16>,
}

pub struct WireGuardConfigBuilder {
    interface_private_key: Option<String>,
    interface_address: Option<(IpAddr, u8)>,
    interface_dns: Option<IpAddr>,
    interface_listen_port: Option<u16>,

    peer_public_key: Option<String>,
    peer_endpoint: Option<(String, u16)>,
    peer_allowed_ips: Option<Vec<(IpAddr, u8)>>,
    peer_persistent_keepalive: Option<u16>,
}

impl WireGuardConfigBuilder {
    pub fn new() -> Self {
        Self {
            interface_private_key: None,
            interface_address: None,
            interface_listen_port: None,
            interface_dns: None,
            peer_public_key: None,
            peer_endpoint: None,
            peer_allowed_ips: None,
            peer_persistent_keepalive: None,
        }
    }

    pub fn private_key(mut self, key: impl Into<String>) -> Self {
        self.interface_private_key = Some(key.into());
        self
    }

    pub fn address(mut self, cidr: &str) -> anyhow::Result<Self> {
        let (ip, mask) =
            parse_cidr(cidr).ok_or(anyhow!("invalid address: {}", cidr.to_string()))?;
        self.interface_address = Some((ip, mask));
        Ok(self)
    }

    #[allow(dead_code)]
    pub fn listen_port(mut self, port: u16) -> Self {
        self.interface_listen_port = Some(port);
        self
    }

    pub fn dns(mut self, ip: &str) -> anyhow::Result<Self> {
        let ip = ip
            .parse()
            .map_err(|_| anyhow!("invalid dns: {}", ip.to_string()))?;
        self.interface_dns = Some(ip);
        Ok(self)
    }

    pub fn public_key(mut self, key: impl Into<String>) -> Self {
        self.peer_public_key = Some(key.into());
        self
    }

    pub fn endpoint(mut self, addr: &str) -> anyhow::Result<Self> {
        let (host, port) =
            parse_endpoint(addr).ok_or(anyhow!("invalid endpoint: {}", addr.to_string()))?;
        self.peer_endpoint = Some((host, port));
        Ok(self)
    }

    pub fn allowed_ips(mut self, cidrs: &[&str]) -> anyhow::Result<Self> {
        let mut ips = Vec::new();
        for cidr in cidrs {
            let (ip, mask) =
                parse_cidr(cidr).ok_or(anyhow!("invalid allowed ips: {}", (*cidr).to_string()))?;
            ips.push((ip, mask));
        }
        self.peer_allowed_ips = Some(ips);
        Ok(self)
    }

    pub fn persistent_keepalive(mut self, seconds: u16) -> Self {
        self.peer_persistent_keepalive = Some(seconds);
        self
    }

    pub fn build(self) -> anyhow::Result<WireGuardConfig> {
        Ok(WireGuardConfig {
            interface: InterfaceConfig {
                private_key: self
                    .interface_private_key
                    .ok_or(anyhow!("missing private key"))?,
                address: self.interface_address.ok_or(anyhow!("missing address"))?,
                listen_port: self.interface_listen_port.unwrap_or(0),
                _dns: self.interface_dns,
            },
            peer: PeerConfig {
                public_key: self.peer_public_key.ok_or(anyhow!("missing public key"))?,
                endpoint: self.peer_endpoint.ok_or(anyhow!("missing endpoint"))?,
                _allowed_ips: self.peer_allowed_ips.ok_or(anyhow!("missing allowedips"))?,
                persistent_keepalive: self.peer_persistent_keepalive,
            },
        })
    }
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let mut parts = s.split('/');
    let ip = parts.next()?.parse().ok()?;
    let mask = parts.next()?.parse().ok()?;
    Some((ip, mask))
}

fn parse_endpoint(s: &str) -> Option<(String, u16)> {
    let mut parts = s.rsplitn(2, ':');
    let port = parts.next()?.parse().ok()?;
    let host = parts.next()?.to_string();
    Some((host, port))
}

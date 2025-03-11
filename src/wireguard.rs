use std::{net::SocketAddr, sync::{Arc, Weak}};

use anyhow::{anyhow, Ok, Result};
use dashmap::DashMap;
use lazy_static::lazy_static;

use crate::{interface::Interface, peer::Peer};

lazy_static! {
    static ref PEER_MAP: DashMap<SocketAddr, Weak<Peer>> =DashMap::new();
}

pub(crate) struct WireGuard {
    pub interface: Option<Interface>,
    pub peers: Vec<Arc<Peer>>,
}

impl WireGuard {
    pub fn new() -> Result<Self> {
        let wg = Self {
            interface: None,
            peers: vec![],
        };
        Ok(wg)
    }

    pub fn from_content(content: &str) -> Result<Self> {
        let mut wg = Self::new()?;
        let mut interface = Interface::new()?;
        let mut current_peer = None;
        let mut current_section = Section::None;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(section) = parse_section_header(line) {
                match section {
                    Section::Interface => {
                        if Section::None != current_section {
                            Err(anyhow!("The First Section must be [Interface]"))?
                        }
                        current_section = Section::Interface;
                    }
                    Section::Peer => {
                        if Section::None == current_section {
                            Err(anyhow!("Setup [Interface] before [Peer]"))?
                        }
                        if let Some(peer) = current_peer.take() {
                            wg.add_peer(peer)?;
                        }
                        current_peer = Some(Peer::new()?);
                        current_section = Section::Peer;
                    }
                    _ => Err(anyhow!("Unexpected session"))?,
                }
                continue;
            }

            if let Some((key, values)) = parse_key_value(line) {
                match current_section {
                    Section::Interface => match key.as_str() {
                        "PrivateKey" => {
                            if let Some(private_key) = values.first() {
                                interface.set_private_key(&private_key)?;
                            }
                        }
                        "Address" => {
                            if let Some(address) = values.first() {
                                interface.set_address(&address)?;
                            }
                        }
                        "ListenPort" => {
                            if let Some(listen_port) = values.first() {
                                interface.set_listen_port(listen_port.parse::<u16>()?)?;
                            }
                        }
                        "DNS" => {
                            let dns: Vec<&str> = values.iter().map(|i| i.as_str()).collect();
                            interface.set_dns(&dns)?;
                        }
                        other => {
                            Err(anyhow!("Unexpected Interface Key: {other}"))?;
                        }
                    },
                    Section::Peer => match key.as_str() {
                        "PublicKey" => {
                            if let Some(public_key) = values.first() {
                                current_peer.as_mut().unwrap().set_public_key(public_key)?;
                            }
                        }
                        "AllowedIPs" => {
                            let allowed_ips: Vec<&str> =
                                values.iter().map(|i| i.as_str()).collect();
                            current_peer
                                .as_mut()
                                .unwrap()
                                .set_allowed_ips(&allowed_ips)?;
                        }
                        "Endpoint" => {
                            if let Some(endpoint) = values.first() {
                                current_peer.as_mut().unwrap().set_endpoint(endpoint)?;
                            }
                        }
                        "PersistentKeepalive" => {
                            if let Some(persistent_keepalive) = values.first() {
                                current_peer.as_mut().unwrap().set_persistent_keepalive(
                                    persistent_keepalive.parse::<u16>()?,
                                )?;
                            }
                        }
                        other => {
                            Err(anyhow!("Unexpected Peer Key: {other}"))?;
                        }
                    },
                    _ => Err(anyhow!("Unexpected session"))?,
                }
            }
        }

        if let Some(peer) = current_peer.take() {
            wg.add_peer(peer)?;
        }

        wg.set_interface(interface)?;

        wg.check()?;

        Ok(wg)
    }

    pub fn set_interface(&mut self, interface: Interface) -> Result<()> {
        interface.check()?;
        self.interface = Some(interface);
        Ok(())
    }

    pub fn add_peer(&mut self, peer: Peer) -> Result<()> {
        peer.check()?;
        self.peers.push(Arc::new(peer));
        Ok(())
    }

    pub fn check(&self) -> Result<bool> {
        if self.interface.is_none() {
            Err(anyhow!("missing interface"))?
        }
        if self.peers.len() < 1 {
            Err(anyhow!("missing peer"))?
        }
        Ok(true)
    }

    pub async fn _run(&self) -> Result<()> {
        self.check()?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
enum Section {
    Interface,
    Peer,
    None,
}

fn parse_section_header(line: &str) -> Option<Section> {
    if line.starts_with('[') && line.ends_with(']') {
        let section = &line[1..line.len() - 1].trim().to_lowercase();
        match section.as_str() {
            "interface" => Some(Section::Interface),
            "peer" => Some(Section::Peer),
            _ => Some(Section::None),
        }
    } else {
        None
    }
}

fn parse_key_value(line: &str) -> Option<(String, Vec<String>)> {
    let mut parts = line.splitn(2, '=');
    let key = parts.next()?.trim().to_string();
    let values = parts
        .next()?
        .split(',')
        .map(|v| v.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    Some((key, values))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn create_by_parmars() -> Result<()> {
        let mut interface = Interface::new()?;
        interface.set_private_key("KDm3jxEeAlrQZUL83/FJY9NKalRFXJ+57Qz9xlR6FW0=")?;
        interface.set_address("10.0.0.2/24")?;
        interface.set_dns(&["8.8.8.8", "114.114.114.114"])?;

        let mut peer = Peer::new()?;
        peer.set_public_key("1zXLl+YK10igioXEjq6XlVqUUZLLDZ6Myi4q0zrJ8Fo=")?;
        peer.set_allowed_ips(&["0.0.0.0/0"])?;
        peer.set_persistent_keepalive(25)?;
        peer.set_endpoint("10.209.197.73:51820")?;

        let mut wg = WireGuard::new()?;
        wg.set_interface(interface)?;
        wg.add_peer(peer)?;
        Ok(())
    }

    #[test]
    fn create_from_content() -> Result<()> {
        let content = r#"[Interface]
PrivateKey = KDm3jxEeAlrQZUL83/FJY9NKalRFXJ+57Qz9xlR6FW0=
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = 1zXLl+YK10igioXEjq6XlVqUUZLLDZ6Myi4q0zrJ8Fo=
Endpoint = 10.209.197.73:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;
        WireGuard::from_content(content)?;

        Ok(())
    }

    #[test]
    fn parse_section_header_test() -> Result<()> {
        assert_eq!(
            parse_section_header("[Interface]").unwrap(),
            Section::Interface
        );
        assert_eq!(parse_section_header("[Peer]").unwrap(), Section::Peer);
        assert_eq!(parse_section_header("[Test]").unwrap(), Section::None);
        assert!(parse_section_header("Test").is_none());
        Ok(())
    }
}

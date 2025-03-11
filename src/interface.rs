use std::net::IpAddr;

use anyhow::Result;
use boringtun::x25519::StaticSecret;

use crate::utils::{decode_private_key, parse_address, parse_dns};

pub(crate) struct Interface {
    pub private_key: Option<StaticSecret>,
    pub address: Option<(IpAddr, u8)>,
    pub dns: Option<Vec<IpAddr>>,
    pub listen_port: Option<u16>,
}

impl Interface {
    pub fn new() -> Result<Self> {
        let interface = Self {
            private_key: None,
            address: None,
            dns: None,
            listen_port: None,
        };
        Ok(interface)
    }

    pub fn set_private_key(&mut self, private_key: &str) -> Result<()> {
        self.private_key = Some(decode_private_key(private_key)?);
        Ok(())
    }

    pub fn set_address(&mut self, address: &str) -> Result<()> {
        self.address = Some(parse_address(address)?);
        Ok(())
    }

    pub fn set_dns(&mut self, dns: &[&str]) -> Result<()> {
        self.dns = Some(
            dns.iter()
                .map(|item| parse_dns(&item))
                .collect::<Result<Vec<IpAddr>, anyhow::Error>>()?,
        );
        Ok(())
    }

    pub fn set_listen_port(&mut self, listen_port: u16) -> Result<()> {
        self.listen_port = Some(listen_port);
        Ok(())
    }
}

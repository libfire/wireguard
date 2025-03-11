use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
};

use anyhow::{anyhow, Ok, Result};
use async_recursion::async_recursion;
use boringtun::{
    noise::{errors::WireGuardError, Tunn, TunnResult},
    x25519::PublicKey,
};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::utils::{decode_public_key, parse_allowed_ips};

pub(crate) struct Peer {
    pub public_key: Option<PublicKey>,
    pub allowed_ips: Option<Vec<(IpAddr, u8)>>,
    pub persistent_keepalive: Option<u16>,
    pub endpoint: Option<SocketAddr>,

    send_socket: Option<Arc<UdpSocket>>,
    send_tun: Option<Arc<tun_rs::AsyncDevice>>,
    tunn: Option<Mutex<Tunn>>,
}

impl Peer {
    pub fn new() -> Result<Self> {
        let peer = Self {
            public_key: None,
            allowed_ips: None,
            persistent_keepalive: None,
            endpoint: None,
            send_socket: None,
            send_tun: None,
            tunn: None,
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

    pub fn set_send_socket(&mut self, send_socket: Arc<UdpSocket>) -> Result<()> {
        self.send_socket = Some(send_socket);
        Ok(())
    }

    pub fn set_send_tun(&mut self, send_tun: Arc<tun_rs::AsyncDevice>) -> Result<()> {
        self.send_tun = Some(send_tun);
        Ok(())
    }

    pub fn set_tunn(&mut self, tunn: Tunn) -> Result<()> {
        self.tunn = Some(Mutex::new(tunn));
        Ok(())
    }

    pub async fn handle_socket_packet(&self, src: &mut [u8]) -> Result<()> {
        let mut dst = vec![0u8; 2048];
        if let Some(tunn) = &self.tunn {
            let result = tunn.lock().await.decapsulate(None, src, &mut dst);
            match result {
                TunnResult::WriteToNetwork(packet) => {
                    let send_socket = self
                        .send_socket
                        .clone()
                        .ok_or(anyhow!("Missing send socket"))?;
                    let endpoint = self.endpoint.ok_or(anyhow!("Missing endpoint"))?;

                    send_socket.send_to(packet, &endpoint).await.map_err(|e| {
                        anyhow!("Send to network failed in handle socket packet: {e}")
                    })?;

                    while let TunnResult::WriteToNetwork(packet) =
                        tunn.lock().await.decapsulate(None, &[], &mut dst)
                    {
                        send_socket.send_to(packet, &endpoint).await.map_err(|e| {
                            anyhow!("Send to network in loop failed: {e}")
                        })?;
                    }
                }
                TunnResult::WriteToTunnelV4(packet, _) => {
                    self.send_tun
                        .clone()
                        .ok_or(anyhow!("Tun device not found"))?
                        .send(&packet)
                        .await
                        .map_err(|e| anyhow!("Send to tun dev failed: {e}"))?;
                }
                TunnResult::Done | TunnResult::WriteToTunnelV6(_, _) => {
                    // Ignored
                }
                other => {
                    Err(anyhow!("Unexpect wireguard result: {:?}", other))?;
                }
            }
        }
        Ok(())
    }

    pub async fn handle_tun_packet(&self, src: &mut [u8]) -> Result<()> {
        let mut dst = vec![0u8; 2048];
        if let Some(tunn) = &self.tunn {
            let result = tunn.lock().await.encapsulate(src, &mut dst);
            match result {
                TunnResult::WriteToNetwork(packet) => {
                    let send_socket = self
                        .send_socket
                        .clone()
                        .ok_or(anyhow!("Udp socket not found"))?;
                    let endpoint = self.endpoint.ok_or(anyhow!("Missing endpoint"))?;

                    send_socket
                        .send_to(packet, &endpoint)
                        .await
                        .map_err(|e| anyhow!("Send to network failed: {e}"))?;

                    while let TunnResult::WriteToNetwork(packet) =
                        tunn.lock().await.decapsulate(None, &[], &mut dst)
                    {
                        send_socket
                            .send_to(packet, &endpoint)
                            .await
                            .map_err(|e| anyhow!("Send to network in loop failed: {:?}", e))?;
                    }
                }
                TunnResult::Done => {
                    // Ignored
                }
                other => {
                    Err(anyhow!("Unexpect wireguard result: {:?}", other))?;
                }
            }
        }
        Ok(())
    }

    pub async fn handle_routine_task(&self) -> Result<()> {
        let mut dst = vec![0u8; 2048];
        if let Some(tunn) = &self.tunn {
            let result = tunn.lock().await.update_timers(&mut dst);
            self.handle_routine_task_result(tunn, result).await?;
        }
        Ok(())
    }

    #[async_recursion]
    async fn handle_routine_task_result<'a: 'async_recursion>(
        &self,
        tunn: &Mutex<Tunn>,
        result: TunnResult<'a>,
    ) -> Result<()> {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                let send_socket = self
                    .send_socket
                    .clone()
                    .ok_or(anyhow!("Udp socket not found"))?;
                let endpoint = self.endpoint.ok_or(anyhow!("Missing endpoint"))?;

                send_socket
                    .send_to(packet, endpoint)
                    .await
                    .map_err(|e| anyhow!("Send to network failed: {e}"))?;
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                let mut buf = vec![0u8; 2048];
                let result = tunn
                    .lock()
                    .await
                    .format_handshake_initiation(&mut buf[..], false);

                self.handle_routine_task_result(tunn, result).await?;
            }
            TunnResult::Err(e) => {
                Err(anyhow!("Handle failed: {:?}", e))?;
            }
            TunnResult::Done => {}
            other => {
                Err(anyhow!(
                    "handle_routine_task unexpected result: {:?}",
                    other
                ))?;
            }
        }
        Ok(())
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

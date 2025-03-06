use std::net::ToSocketAddrs;

use anyhow::{anyhow, Result};
use async_recursion::async_recursion;
use base64::engine::general_purpose;
use base64::Engine;
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::RngCore;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tun_rs::AsyncDevice;

use crate::builder::WireGuardConfig;

pub(crate) struct WireGuard {
    tun: AsyncDevice,
    socket: UdpSocket,

    wg: Mutex<Tunn>,
    endpoint: SocketAddr,
}

const MAX_PACKET: usize = 2048;

impl WireGuard {
    pub async fn new(cfg: WireGuardConfig) -> anyhow::Result<Self> {
        let tun = {
            let (ip, mask) = cfg.interface.address;

            tun_rs::DeviceBuilder::new()
                .ipv4(ip, mask, None)
                .build_async()
                .map_err(|e| anyhow!("Create tun device failed: {}", e))?
        };

        let wg = Mutex::new({
            let private_key = base64_to_static_secret(&cfg.interface.private_key)?;
            let peer_public_key = base64_to_public_key(&cfg.peer.public_key)?;
            Tunn::new(
                private_key,
                peer_public_key,
                None,
                cfg.peer.persistent_keepalive,
                rand::rng().next_u32(),
                None,
            )
            .map_err(|e| anyhow!("Create new Tunn failed: {}", e))?
        });

        let endpoint = {
            let (ip, port) = cfg.peer.endpoint;
            let addr_string = format!("{}:{}", ip, port);
            addr_string
                .to_socket_addrs()
                .map_err(|e| anyhow!("Parse socket address failed: {}", e))?
                .next()
                .ok_or(anyhow!("No addresses found"))?
        };

        let socket = UdpSocket::bind(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            cfg.interface.listen_port,
        )))
        .await?;

        Ok(Self {
            tun,
            socket,
            wg,
            endpoint,
        })
    }

    async fn create_handshake_init(&self) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];

        let handshake_init = self
            .wg
            .lock()
            .await
            .format_handshake_initiation(&mut dst, false);

        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    #[async_recursion]
    async fn handle_routine_task_result<'a: 'async_recursion>(
        &self,
        result: TunnResult<'a>,
    ) -> anyhow::Result<()> {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                self.socket
                    .send_to(packet, self.endpoint)
                    .await
                    .map_err(|e| anyhow!("Send socket failed: {e}"))?;
            }
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                let mut buf = vec![0u8; MAX_PACKET];
                let result = self
                    .wg
                    .lock()
                    .await
                    .format_handshake_initiation(&mut buf[..], false);

                self.handle_routine_task_result(result).await?;
            }
            TunnResult::Err(e) => {
                Err(anyhow!("handle_routine_task failed: {:?}", e))?;
            }
            TunnResult::Done => {}
            other => {
                Err(anyhow!(
                    "handle_routine_task unexpected result: {:?}",
                    other
                ))?;
            }
        };
        Ok(())
    }

    pub async fn handle_routine_task(&self) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET];
        let result = { self.wg.lock().await.update_timers(&mut buf) };
        self.handle_routine_task_result(result).await
    }

    pub async fn handle_socket_buf(
        &self,
        socket_buf: &mut [u8],
        len: usize,
        socket_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET];
        let tunn_result = {
            let mut peer = self.wg.lock().await;
            peer.decapsulate(Some(socket_addr.ip()), &socket_buf[..len], &mut buf)
        };

        match tunn_result {
            TunnResult::WriteToNetwork(packet) => {
                self.socket
                    .send_to(packet, self.endpoint)
                    .await
                    .map_err(|e| anyhow!("Send to socket failed: {:?}", e))?;

                let mut peer = self.wg.lock().await;
                let mut buf = vec![0u8; MAX_PACKET];
                while let TunnResult::WriteToNetwork(packet) = peer.decapsulate(None, &[], &mut buf)
                {
                    self.socket
                        .send_to(packet, self.endpoint)
                        .await
                        .map_err(|e| anyhow!("Send to socket failed: {:?}", e))?;
                }
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                self.tun
                    .send(&packet)
                    .await
                    .map_err(|e| anyhow!("Send to tun dev failed: {e}"))?;
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                Err(anyhow!(
                    "Unexpected WireGuard state during decapsulation: {:?}",
                    other
                ))?;
            }
        }
        Ok(())
    }

    pub async fn handle_tun_buf(&self, tun_buf: &mut [u8], len: usize) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET];
        let tunn_result = {
            let mut peer = self.wg.lock().await;
            peer.encapsulate(&tun_buf[..len], &mut buf)
        };

        match tunn_result {
            TunnResult::WriteToNetwork(packet) => {
                self.socket
                    .send_to(packet, self.endpoint)
                    .await
                    .map_err(|e| anyhow!("udp socket failed: {e}"))?;
            }
            TunnResult::Err(e) => {
                Err(anyhow!("wireguard error: {:?}", e))?;
            }
            TunnResult::Done => {
                // Ignored
            }
            other => {
                Err(anyhow!("unexpect wireguard result: {:?}", other))?;
            }
        };

        Ok(())
    }

    pub async fn run(&self) -> Result<()> {
        let handshake = self.create_handshake_init().await;
        self.socket.send_to(&handshake, self.endpoint).await?;

        let mut socket_buf = vec![0; MAX_PACKET];
        let mut tun_buf = vec![0; self.tun.mtu()? as usize];

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("Quit...");
                    break;
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(250)) => {
                    self.handle_routine_task().await?;
                }
                res = self.socket.recv_from(&mut socket_buf) => {
                    let (len, socket_addr) = res?;
                    self.handle_socket_buf(&mut socket_buf, len, socket_addr).await?;
                }
                res = self.tun.recv(&mut tun_buf)=>{
                    let len = res?;
                    self.handle_tun_buf(&mut tun_buf,len).await?
                }
            };
        }

        Ok(())
    }
}

fn base64_to_static_secret(base64_str: &str) -> anyhow::Result<StaticSecret> {
    let decoded = general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| anyhow!("Private key base64 decode failed: {}", e))?;

    if decoded.len() != 32 {
        return Err(anyhow!("Invalid private key len: {}", decoded.len()));
    }

    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("Private key try_into failed"))?;

    Ok(StaticSecret::from(key))
}

fn base64_to_public_key(base64_str: &str) -> anyhow::Result<PublicKey> {
    let decoded = general_purpose::STANDARD
        .decode(base64_str)
        .map_err(|e| anyhow!("Public key base64 decode failed: {}", e))?;

    if decoded.len() != 32 {
        return Err(anyhow!("Invalid public key len: {}", decoded.len()));
    }

    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("Public Key try_into failed"))?;

    PublicKey::try_from(key).map_err(|e| anyhow!("Curve check failed: {:?}", e))
}

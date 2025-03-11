use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Result};
use boringtun::noise::Tunn;
use dashmap::DashMap;
use rand::RngCore;
use route_manager::{Route, RouteManager};
use tokio::net::UdpSocket;

use crate::{interface::Interface, peer::Peer, utils::if_index_to_addr};

pub(crate) struct WireGuard {
    pub interface: Option<Interface>,
    pub peers: Option<Vec<Peer>>,
    route_stack: Vec<Route>,
}

impl WireGuard {
    pub fn new() -> Result<Self> {
        let wg = Self {
            interface: None,
            peers: Some(vec![]),
            route_stack: vec![],
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

        Ok(wg)
    }

    pub fn set_interface(&mut self, interface: Interface) -> Result<()> {
        self.interface = Some(interface);
        Ok(())
    }

    pub fn add_peer(&mut self, peer: Peer) -> Result<()> {
        self.peers = Some({
            if let Some(mut peers) = self.peers.take() {
                peers.push(peer);
                peers
            } else {
                vec![peer]
            }
        });
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let interface = self
            .interface
            .as_ref()
            .ok_or(anyhow!("Missing interface"))?;

        let mut route_manager =
            RouteManager::new().map_err(|e| anyhow!("Create route manager failed: {e}"))?;

        let udp_socket = {
            let bind_addr = {
                let ip = "0.0.0.0"
                    .parse()
                    .map_err(|e| anyhow!("Parse 0.0.0.0 failed: {e}"))?;

                let if_index = route_manager
                    .find_route(&ip)
                    .map_err(|e| anyhow!("Find default route failed: {e}"))?
                    .ok_or(anyhow!("Default route not found"))?
                    .if_index()
                    .ok_or(anyhow!("Get bind ip failed"))?;

                let addr = if_index_to_addr(if_index)?;
                println!("Bind address: {addr}");
                addr
            };
            Arc::new(
                UdpSocket::bind(SocketAddr::from((
                    bind_addr,
                    interface.listen_port.unwrap_or(51820),
                )))
                .await
                .map_err(|e| anyhow!("UdpSocket bind failed: {e}"))?,
            )
        };

        let (interface_address, interface_mask) = interface
            .address
            .ok_or(anyhow!("Interface missing address"))?;

        let tun_dev = Arc::new({
            tun_rs::DeviceBuilder::new()
                .ipv4(interface_address, interface_mask, None)
                .mtu(1500)
                .build_async()
                .map_err(|e| anyhow!("Create tun device failed: {}", e))?
        });

        let endpoint_peer_map = DashMap::new();
        let mut allowed_ips_peer_map = vec![];
        let mut routine_peers = vec![];

        for mut peer in self.peers.take().unwrap() {
            peer.set_send_socket(udp_socket.clone())?;
            peer.set_send_tun(tun_dev.clone())?;

            let tunn = Tunn::new(
                interface
                    .private_key
                    .clone()
                    .ok_or(anyhow!("Missing interface private key"))?,
                peer.public_key.ok_or(anyhow!("Missing peer public key"))?,
                None,
                peer.persistent_keepalive,
                rand::rng().next_u32(),
                None,
            )
            .map_err(|e| anyhow!("Create tunn failed: {e}"))?;
            peer.set_tunn(tunn)?;

            let allowed_ips = peer.allowed_ips.take().unwrap();

            let peer = Arc::new(peer);
            if let Some(endpoint) = peer.endpoint {
                endpoint_peer_map.insert(endpoint, peer.clone());
            }
            let if_index = tun_dev
                .if_index()
                .map_err(|e| anyhow!("Get tun dev interface index failed: {e}"))?;
            let name = tun_dev
                .name()
                .map_err(|e| anyhow!("Get tun dev interface name failed: {e}"))?;

            for allowed_ip in allowed_ips {
                let (destination, prefix) = allowed_ip;
                let route = Route::new(destination, prefix)
                    .with_if_index(if_index)
                    .with_if_name(name.clone())
                    .with_gateway(interface_address)
                    .with_metric(0);
                route_manager
                    .add(&route)
                    .map_err(|e| anyhow!("Add route failed: {route}: {e}"))?;
                self.route_stack.push(route);
                allowed_ips_peer_map.push((allowed_ip, peer.clone()));
            }
            routine_peers.push(peer.clone());
        }

        let mut tasks = vec![];

        tasks.push(tokio::spawn(async {
            let _ = tokio::signal::ctrl_c().await;
        }));

        let recv_socket = udp_socket.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0; 2048];
            while let Ok((len, endpoint)) = recv_socket.recv_from(&mut buf).await {
                if let Some(peer) = endpoint_peer_map.get(&endpoint) {
                    if let Err(e) = peer.handle_socket_packet(&mut buf[..len]).await {
                        println!("Handle socket packet failed: {e}")
                    }
                }
            }
        }));

        let recv_tun = tun_dev.clone();
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0; 2048];
            while let Ok(len) = recv_tun.recv(&mut buf).await {
                // TODO: get peer by route, now we just fetch the first peer
                if let Some(peer) = allowed_ips_peer_map.first() {
                    let (_, peer) = &peer;
                    if let Err(e) = peer.handle_tun_packet(&mut buf[..len]).await {
                        println!("Handle tun packet failed: {e}")
                    }
                }
            }
        }));

        tasks.push(tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                for peer in &routine_peers {
                    if let Err(e) = peer.handle_routine_task().await {
                        println!("Handle routine task failed: {e}")
                    }
                }
            }
        }));

        let _ = futures::future::select_all(tasks).await;

        while let Some(route) = self.route_stack.pop() {
            if let Err(e) = route_manager.delete(&route) {
                println!("Delete route failed: {e}");
            }
        }

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

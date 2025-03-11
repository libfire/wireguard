use anyhow::{Ok, Result};
use wireguard::WireGuard;

mod interface;
mod peer;
mod utils;
mod wireguard;

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let content = r#"[Interface]
PrivateKey = KDm3jxEeAlrQZUL83/FJY9NKalRFXJ+57Qz9xlR6FW0=
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = 1zXLl+YK10igioXEjq6XlVqUUZLLDZ6Myi4q0zrJ8Fo=
AllowedIPs = 0.0.0.0/0
Endpoint = 10.209.197.73:51820
PersistentKeepalive = 25
"#;
    WireGuard::from_content(content)?;
    Ok(())
}

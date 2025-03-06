use anyhow::Result;
use builder::WireGuardConfigBuilder;
use wireguard::WireGuard;

mod builder;
mod wireguard;

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = WireGuardConfigBuilder::new()
        .private_key("KDm3jxEeAlrQZUL83/FJY9NKalRFXJ+57Qz9xlR6FW0=")
        .address("10.0.0.2/24")?
        .dns("8.8.8.8")?
        .public_key("1zXLl+YK10igioXEjq6XlVqUUZLLDZ6Myi4q0zrJ8Fo=")
        .endpoint("10.209.197.73:51820")?
        .allowed_ips(&["10.0.0.0/24"])?
        .persistent_keepalive(25)
        .build()?;

    let wg = WireGuard::new(cfg).await?;
    wg.run().await?;
    Ok(())
}

use std::fs;

use anyhow::{anyhow, Result};
use wireguard::WireGuard;

mod interface;
mod peer;
mod utils;
mod wireguard;

use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(name = "wireguard", about = "A user-space implementation of WireGuard")]
struct Opt {
    #[structopt(short = "c", long = "config")]
    config_file: String,
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    let content = fs::read_to_string(opt.config_file)
        .map_err(|e| anyhow!("Read config file content failed: {e}"))?;
    let mut wg =
        WireGuard::from_content(&content).map_err(|e| anyhow!("Create wireguard failed: {e}"))?;
    wg.run()
        .await
        .map_err(|e| anyhow!("WireGuard run failed: {e}"))?;
    Ok(())
}

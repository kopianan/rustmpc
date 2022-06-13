use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use gg20_mpc::*;
use round_based::async_runtime::AsyncProtocol;

#[tokio::main]
async fn main() -> Result<()> {
    let result = gg20_mpc::keygen_run(3).await;
    println!("{:?}", result);
    Ok(())
}

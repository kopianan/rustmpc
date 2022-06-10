use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use std::path::PathBuf;
use structopt::StructOpt;

use gg20_mpc::*;
use round_based::async_runtime::AsyncProtocol;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    room: String,
    #[structopt(short, long, default_value = "default-signing")]
    local_share: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    //let args: Cli = Cli::from_args();
    let local_share = tokio::fs::read("local-key2.json")
        .await
        .context("cannot read local share")?;
        println!("{:?}",local_share);
    let result = gg20_mpc::presign_run(2,local_share,2).await;
    println!("{:?}",result);
    Ok(())

}
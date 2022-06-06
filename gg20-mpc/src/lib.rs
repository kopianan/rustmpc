use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::{SinkExt, StreamExt, TryStreamExt};
use rand::rngs::OsRng;

use round_based::Msg;
use round_based::async_runtime::AsyncProtocol;

use curv::arithmetic::Converter;
use curv::BigInt;

mod common;
mod dkg;
mod presigning;
mod utilities;

use dkg::keygen::Keygen;
use presigning::presign::{
    OfflineStage, SignManual,
};

mod gg20_sm_client;
use gg20_sm_client::join_computation;
mod gg20_sm_manager;

#[derive(Debug, StructOpt)]
struct Cli {
    #[structopt(short, long, default_value = "http://localhost:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long, default_value = "1")]
    index: u16,
    #[structopt(short, long, default_value = "1")]
    threshold: u16,
    #[structopt(short, long, default_value = "3")]
    number_of_parties: u16,
}

//MPC CONSTANTS
const THRESHOLD:u16 = 1;
const PARTIES:u16 = 3;

pub async fn http_local_run()
{
    gg20_sm_manager::run_http();
}

pub async fn keygen_run(index:u16, port_: i64) -> Result<String> {
    
    let args: Cli = Cli::from_args();

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(index, THRESHOLD, PARTIES, port_)?;
    let output = round_based::AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;
    let output = serde_json::to_string(&output).unwrap();

    Ok(output)
    
}

/*
#[allow(clippy::too_many_arguments)]
async fn keygen_run(
    signal_client: SignalClient,
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    i: u16,
    t: u16,
    n: u16,
    output: impl AsRef<Path>,
) -> Result<()> {
    device_secrets
        .write()
        .await
        .trust_to(&group)
        .context("adding trust to the group")?;

    let mut signal_client = signal_client
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .await
        .context("cannot create output file")?;

    let (incoming, outgoing) = signal_client
        .join_computation(me.addr, group)
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();

    let initial = Keygen::new(i, t, n).context("create initial state")?;
    let local_key = round_based::AsyncProtocol::new(initial, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("execute keygen protocol: {}", e))?;

    // save local key shares into json file
    let ser_output = serde_json::to_vec_pretty(&local_key).context("serialize output")?;
    tokio::io::copy(&mut ser_output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;
    
    Ok(())
}

async fn presign(args: cli::PresignArgs) -> Result<()> {
    //establish the signal client
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;
    //read the MPC device id, address, public key
    let mut device_secrets = DeviceStore::from_file(&args.secrets.path)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();
    //read the group.json file and ensure this device is included
    let group = read_group(args.group).await.context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };
    
    presign_run(
        signal_client,
        device_secrets.clone(),
        group,
        me,
        my_ind,
        args.local_key,
        args.output,
    )
    .await;

    if let Err(err) = device_secrets.save(args.secrets.path).await {
        tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
    }

    Ok(())
}

async fn presign_run(
    signal_client: SignalClient,
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    my_ind: u16,
    local_key_path: std::path::PathBuf,
    output: impl AsRef<Path>,
) -> Result<()> {
    //Note: supposed to be an argument parsed in terminal, hardcoded for now
    let args_parties = vec![1,2];
    //read the local key shares stored in json file
    let local_key = tokio::fs::read(local_key_path)
    .await
    .context("cannot read local share")?;
    let local_key = serde_json::from_slice(&local_key).context("parse local share")?;

    let number_of_parties = args_parties.len();
    
    let mut signal_client = signal_client
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    let (incoming, outgoing) = signal_client
        .join_computation(me.addr.clone(), group.clone())
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();

    let signing = OfflineStage::new(my_ind, args_parties, local_key)?;
    let completed_offline_stage = round_based::AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    // save the presign signature into json file
    let mut output_file = tokio::fs::OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(output)
    .await
    .context("cannot create output file")?;

    let ser_output = serde_json::to_vec_pretty(&completed_offline_stage).context("serialize output")?;
    tokio::io::copy(&mut ser_output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;

    Ok(())
}
async fn sign(args: cli::SignArgs) -> Result<()> {
    //establish the signal client
    let signal_client = signal_client(args.server)
    .await
    .context("constructing signal client")?;
    //read the MPC device id, address, public key
    let mut device_secrets = DeviceStore::from_file(&args.secrets.path)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();
    //read the group.json file and ensure this device is included
    let group = read_group(args.group).await.context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };
    
    sign_run(
        signal_client,
        device_secrets.clone(),
        group,
        me,
        my_ind,
        args.presign_share,
        args.digits,
    )
    .await;

    if let Err(err) = device_secrets.save(args.secrets.path).await {
        tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
    }

    Ok(())
}
async fn sign_run (
    signal_client: SignalClient,
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    my_ind: u16,
    presign_share_path: std::path::PathBuf,
    message: String,
) -> Result<()> {
    //MPC Signing Stage starts here
    //Note: supposed to be an argument parsed in terminal, hardcoded for now
    let args_parties = vec![1,2];
    //read the local presign shares stored in json file
    let presign_share = tokio::fs::read(presign_share_path).await.context("cannot read presign share")?;
    let completed_offline_stage = serde_json::from_slice(&presign_share).context("parse local presign share")?;
    let number_of_parties = args_parties.len();
    
    let mut signal_client = signal_client
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    let (incoming, mut outgoing) = signal_client
        .join_computation(me.addr.clone(), group.clone())
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();

    let (signing, partial_signature) = SignManual::new(
        BigInt::from_bytes(message.as_bytes()),
        completed_offline_stage,
    )?;
    
    outgoing
        .send(Msg {
            sender: my_ind,
            receiver: None,
            body: partial_signature,
        })
        .await?;
    
    let partial_signatures: Vec<_> = incoming
        .take(number_of_parties - 1)
        .map_ok(|msg| msg.body)
        .try_collect()
        .await?;
    
    let signature = signing
        .complete(&partial_signatures)
        .context("online stage failed")?;
    
    let signature = serde_json::to_string(&signature).context("serialize signature")?;
    println!("{}", signature); 
    
    Ok(())
}

async fn save_local_key(local_key: &LocalKey, output_file: File) -> Result<()> {
    let ser_output = serde_json::to_vec_pretty(&local_key).context("serialize output")?;
    tokio::io::copy(&mut ser_output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;
}

async fn read_local_key(path: impl AsRef<Path>) -> Result<LocalKey> {
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
}
*/


use allo_isolate::Isolate;
use std::path::Path;
use std::time::Duration;
use std::str;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::{SinkExt, StreamExt, TryStreamExt};
use rand::rngs::OsRng;

use round_based::async_runtime::AsyncProtocol;
use round_based::Msg;

use core::slice;
use curv::arithmetic::Converter;
use curv::BigInt;
use std::os::raw::{c_char, c_uchar};
use std::path::PathBuf;
mod common;
mod dkg;
mod presigning;
mod utilities;

use dkg::keygen::Keygen;
use presigning::presign::{OfflineStage, SignManual};

mod gg20_sm_client;
use gg20_sm_client::join_computation;
mod gg20_sm_manager;

//MPC CONSTANTS
const THRESHOLD:u16 = 1;
const PARTIES:u16 = 3;

#[derive(Debug, StructOpt)]
struct DkgCli {
    #[structopt(short, long, default_value = "http://10.0.2.2:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-keygen")]
    room: String,
    #[structopt(short, long, default_value = "1")]
    index: u16,
    #[structopt(short, long, default_value = "1")]
    threshold: u16,
    #[structopt(short, long, default_value = "3")]
    number_of_parties: u16,
    /*
    #[structopt(short, long)]
    output: PathBuf,
    */
}

#[derive(Debug, StructOpt)]
struct OfflineSignCli {
    #[structopt(short, long, default_value = "http://10.0.2.2:8000/")]
    address: surf::Url,
    #[structopt(short, long, default_value = "default-signing")]
    room: String,
}

pub async fn http_local_run()
{
    gg20_sm_manager::run_http();
}

pub async fn keygen_run(index: u16, port_: i64) -> Result<Vec<u8>> {
    let args: DkgCli = DkgCli::from_args();

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("dkg:failed join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(index, THRESHOLD, PARTIES)?;
    let output = round_based::AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("dkg: protocol execution terminated with error: {}", e))?;
<<<<<<< HEAD
    // let output = serde_json::to_string(&output).unwrap();
    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    // let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    // let s = match str::from_utf8(&mut output.as_slice()) {
    //     Ok(v) => v,
    //     Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    // };
    // Ok(s.to_owned())
    Ok(output)
}
pub async fn keygen_run_string(index: u16) -> Result<String> {
    let args: DkgCli = DkgCli::from_args();

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("dkg:failed join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(index, THRESHOLD, PARTIES)?;
    let output = round_based::AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("dkg: protocol execution terminated with error: {}", e))?;
    let output = serde_json::to_string(&output).unwrap();
    // let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    Ok(output)
=======

    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    /*
    let mut output_file = tokio::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(args.output)
        .await
        .context("cannot create output file")?;

    tokio::io::copy(&mut output.as_slice(), &mut output_file)
            .await
            .context("save output to file")?;
    */
    let s = match str::from_utf8(&mut output.as_slice()) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    Ok(s.to_owned())
    
>>>>>>> 1e39f9c0bb5fdd691b115fdcb917a1c531b164e5
}
pub async fn keygen_run_vector(index: u16) -> Result<Vec<u8>> {
    let args: DkgCli = DkgCli::from_args();

    let (_i, incoming, outgoing) = join_computation(args.address, &args.room)
        .await
        .context("dkg:failed join computation")?;

    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let keygen = Keygen::new(index, THRESHOLD, PARTIES)?;
    let output = round_based::AsyncProtocol::new(keygen, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("dkg: protocol execution terminated with error: {}", e))?;
    // let output = serde_json::to_string(&output).unwrap();
    let output = serde_json::to_vec_pretty(&output).context("serialize output")?;
    Ok(output)
}

pub async fn presign_run(index: u16, local_key: Vec<u8>) -> Result<String> {
    let args: OfflineSignCli = OfflineSignCli::from_args();
    //Note: supposed to be an argument parsed in terminal, hardcoded for now
    let args_parties = vec![1, 2];
    let local_key = serde_json::from_slice(&local_key).context("offline_sign: failed to parse local share")?;
    
    let (_, incoming, outgoing) =
        join_computation(args.address.clone(), &format!("{}-offline", args.room))
            .await
            .context("offline_sign: failed join computation")?;
    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

    let signing = OfflineStage::new(index, args_parties, local_key)?;
    let completed_offline_stage = round_based::AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("offline_sign:  with error: {}", e))?;

    let completed_offline_stage = serde_json::to_string(&completed_offline_stage).unwrap();

    Ok(completed_offline_stage)
}

pub async fn sign_run(my_ind: u16, presign_share: Vec<u8>, message: &str) -> Result<String> {
    //MPC Signing Stage starts here
    let args: OfflineSignCli = OfflineSignCli::from_args();
    //Note: supposed to be an argument parsed in terminal, hardcoded for now
    let args_parties = vec![1, 2];
    let completed_offline_stage =
        serde_json::from_slice(&presign_share).context("parse local presign share")?;
    let number_of_parties = args_parties.len();
    let (_, incoming, outgoing) = join_computation(args.address, &format!("{}-online", args.room))
        .await
        .context("join online computation")?;
    let incoming = incoming.fuse();
    tokio::pin!(incoming);
    tokio::pin!(outgoing);

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
    Ok(signature)
}

/*
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

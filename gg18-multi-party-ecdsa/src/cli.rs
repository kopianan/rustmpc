
use structopt::StructOpt;

use std::time::Duration;

use anyhow::{anyhow, Context, Result};


use futures::{StreamExt};

use std::{fs, vec::Vec};
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};

use crate::dkg::keygen::Keygen;
use curv::{
    BigInt,
};
use crate::common::party_i::{LocalKeyShare, Params};
use crate::signing::sign::OfflineStage;

#[derive(StructOpt, Debug)]
/// Demo CLI
pub struct App {
    #[structopt(long)]
    pub debug: bool,
    #[structopt(subcommand)]
    pub command: Cmd,
}

#[derive(StructOpt, Debug)]
pub enum Cmd {
    #[structopt(display_order = 1)]
    Login(LoginArgs),
    #[structopt(display_order = 2)]
    Me(MeArgs),
    #[structopt(display_order = 3)]
    Keygen(KeygenArgs),
    #[structopt(display_order = 4)]
    Sign(SignArgs),
    //#[structopt(display_order = 5)]
    //Verify(VerifyArgs),
}

#[derive(StructOpt, Debug)]
pub struct SignalServer {
    /// Signal Server URL
    ///
    /// Allows overriding Signal Server URL in case if you're using own-hosted Signal Server
    #[structopt(
        long = "signal-host",
        default_value = "https://textsecure-service.whispersystems.org/",
        display_order = 21
    )]
    pub host: String,
    /// Path to PEM-encoded certificate
    ///
    /// Sets root of trust in establishing secure connection to server. By default, original
    /// Signal Server certificate is used.
    #[structopt(long = "signal-cert", display_order = 22)]
    pub certificate: Option<String>,
}

#[derive(StructOpt, Debug)]
pub struct SecretsFile {
    /// Path to file containing sensitive information like secrets keys and tokens
    ///
    /// Keep it in secret! Information in this file can be used to perform actions on behalf of
    /// your account: send, receive messages, edit profile info, etc.
    #[structopt(
        long = "secrets-file",
        default_value = "secrets.json",
        display_order = 20
    )]
    pub path: String,
}

#[derive(StructOpt, Debug)]
/// Pairs your Signal app account with MPC device that will be used to send and receive MPC messages
///
/// You will be prompted to scan QR code that allow us linking with your Signal account. New device
/// will be displayed in "Linked Devices" in Signal app on your phone and you'll be able to unlink
/// it at any moment.
///
/// Not that after logging in, this app will receive your private identity and profile keys and
/// will save them in `secrets-file` (see `--secrets-file` option).
pub struct LoginArgs {
    /// Device name that will be associated with a new device
    ///
    /// It will be displayed in "Linked Devices" in Signal app on your phone.
    #[structopt(long, default_value = "MPC-over-Signal device", display_order = 1)]
    pub device_name: String,
}

#[derive(StructOpt, Debug)]
/// Prints information about MPC device: account name, device id, public key
pub struct MeArgs {
    /// Prints your visit card in json format
    #[structopt(long)]
    pub json: bool,
}

#[derive(StructOpt, Debug)]
/// Distributed key generation
pub struct KeygenArgs {
    /// Threshold value `t`.
    ///
    /// `t`+1 parties will be required to perform signing
    #[structopt(short = "t", long, display_order = 1)]
    pub threshold: u16,
    /// Number of parties involved in keygen
    #[structopt(short = "n", long, display_order = 1)]
    pub parties: u16,
    /// Path to file containing addresses and public keys of every party of the protocol
    #[structopt(long, display_order = 2)]
    pub group: String,
    /// Path to file where to save resulting local party key
    ///
    /// If file already exist, it will be overwritten
    #[structopt(short, long, display_order = 3)]
    pub output: String,
}

#[derive(StructOpt, Debug)]
/// Threshold signing
pub struct SignArgs {
    /// Path to local secret key file obtained after keygen
    #[structopt(long, display_order = 1)]
    pub local_key: String,

    /// Path to file containing addresses and public keys of every party of the signing protocol
    #[structopt(long, display_order = 2)]
    pub group: String,

    /// Message to sign
    #[structopt(long, parse(from_str), display_order = 3)]
    pub digits: String,
}

type Bytes = Vec<u8>;

#[derive(StructOpt, Debug)]
/// Locally verifies that message matches signature
pub struct VerifyArgs {
    /// Public key which was used to sign message
    #[structopt(long)]
    pub public_key: String,
    /// Signature
    #[structopt(long)]
    pub signature: String,
    /// Being verified message
    #[structopt(long, parse(from_str))]
    pub digits: Bytes,
}

#[allow(clippy::too_many_arguments)]
pub async fn keygen_run(
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    i: u16,
    t: u16,
    n: u16,
) -> Result<String> {
    device_secrets
        .write()
        .await
        .trust_to(&group)
        .context("adding trust to the group")?;
    
    let mut signal_client = signal_client()
        .unwrap()
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    
    let (incoming, outgoing) = signal_client
        .join_computation(me.addr, group)
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();
    let initial = Keygen::new(i, t, n).context("create initial state")?;
    let output = round_based::AsyncProtocol::new(initial, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("execute keygen protocol: {}", e))?;
    // save local key shares into json file
    let keygen_json = serde_json::to_string(&(
        output.keys,
        output.shared_keys,
        output.party_num_int,
        output.vss_vec,
        output.pail_key_vec,
        output.y_sum_s,
        ))
        .unwrap();
    
    Ok(keygen_json)
}

pub async fn sign_run(
    signal_client: SignalClient,
    device_secrets: DeviceStore,
    group: Group,
    me: ParticipantIdentity,
    my_ind: u16,
    key_share: LocalKeyShare,
    message_bn: BigInt,
) -> Result<()> {

    //read parameters:
    let data = fs::read_to_string("params.json")
        .expect("Unable to read params, make sure config file is present in the same folder ");
    let params: Params = serde_json::from_str(&data).unwrap();
    let t = params.threshold.parse::<u16>().unwrap();

    let mut signal_client = signal_client
        .start_listening_for_incoming_messages(device_secrets)
        .await
        .context("connecting to signal api")?;
    let (incoming, outgoing) = signal_client
        .join_computation(me.addr, group)
        .await
        .context("join computation")?;
    let incoming = incoming.fuse();

    let signing = OfflineStage::new(my_ind, t, key_share, message_bn)?;
    let completed_offline_stage = round_based::AsyncProtocol::new(signing, incoming, outgoing)
        .run()
        .await
        .map_err(|e| anyhow!("protocol execution terminated with error: {}", e))?;

    
    /*outgoing
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
    println!("{}", signature);*/
    

    Ok(())
}
/*
pub async fn verify(args: cli::VerifyArgs) -> Result<()> {
    let public_key =
        hex::decode(args.public_key).context("public key is not valid hex encoded string")?;
    let signature =
        hex::decode(args.signature).context("signature key is not valid hex encoded string")?;

    let signature = GE1::from_bytes(&signature)
        .map_err(|e| anyhow!("signature is not valid g1 point: {:?}", e))?;
    let public_key = GE2::from_bytes(&public_key)
        .map_err(|e| anyhow!("public key is not valid g2 point: {:?}", e))?;

    let valid = BLSSignature { sigma: signature }.verify(&args.digits, &public_key);
    if valid {
        println!("Signature is valid");
    } else {
        bail!("Signature is not valid");
    }

    Ok(())
}
*/
pub fn signal_client() -> Result<SignalClient> {
    let server = SignalServer::from_args();
    let mut builder = SignalClient::builder()?;
    builder.set_server_host(server.host)?;
    Ok(builder.finish())
}

pub fn read_group(file_content:Vec<u8>) -> Result<Group> {
    let parties_raw =
        serde_json::Deserializer::from_slice(&file_content).into_iter::<ParticipantIdentity>();
    let mut parties = vec![];
    for (i, party) in parties_raw.enumerate() {
        parties.push(party.context(format!("parse {} party", i))?)
    }
    Ok(Group::new(parties))
}

/*
pub async fn save_local_key(local_key: &LocalKey, output_file: File) -> Result<()> {
    let ser_output = serde_json::to_vec_pretty(&local_key).context("serialize output")?;
    tokio::io::copy(&mut ser_output.as_slice(), &mut output_file)
        .await
        .context("save output to file")?;
}

pub async fn read_local_key(path: impl AsRef<Path>) -> Result<LocalKey> {
    let local_share = tokio::fs::read(args.local_share)
        .await
        .context("cannot read local share")?;
    let local_share = serde_json::from_slice(&local_share).context("parse local share")?;
}
*/
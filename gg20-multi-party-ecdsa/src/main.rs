use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::{SinkExt, StreamExt, TryStreamExt};
use rand::rngs::OsRng;

use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};
use round_based::Msg;

use curv::arithmetic::Converter;
use curv::BigInt;

mod cli;
use cli::Cmd;

mod common;
mod dkg;
mod presigning;
mod utilities;

use dkg::keygen::Keygen;
use presigning::presign::{
    OfflineStage, SignManual,
};

#[actix::main]
async fn main() -> Result<()> {
    let args: cli::App = StructOpt::from_args();
    if args.debug {
        tracing_subscriber::fmt::init();
    }
    match args.command {
        Cmd::Login(args) => login(args).await,
        Cmd::Me(args) => me(args).await,
        Cmd::Keygen(args) => keygen(args).await,
        Cmd::Presign(args) => presign(args).await,
        Cmd::Sign(args) => sign(args).await,
    }
}

async fn login(args: cli::LoginArgs) -> Result<()> {
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;

    let (provision_url_tx, provision_url) = oneshot::channel();
    let (device_tx, device) = oneshot::channel();
    let device_name = args.device_name;
    actix::spawn(async move {
        let device = signal_client
            .login(&mut OsRng, provision_url_tx, device_name)
            .await
            .context("login failed");
        let _ = device_tx.send(device);
    });

    match provision_url.await {
        Ok(url) => {
            println!();
            println!("To continue, scan following QR code using Signal app on your phone.");
            println!("On Android: Signal Settings → Linked Devices → '+' Button");
            println!("On iOS:     Signal Settings → Linked Devices → Link New Device");
            println!();
            qr2term::print_qr(url.to_string()).context("printing QR code")?
        }
        Err(_e) => {
            // real error will be discovered below
        }
    }

    let device = device.await.context("retrieving device")??;
    DeviceStore::new(device)
        .save_no_overwrite(args.secrets.path)
        .await
        .context("save secrets")?;

    println!();
    println!("MPC device successfully created");

    Ok(())
}

async fn me(args: cli::MeArgs) -> Result<()> {
    let device = DeviceStore::from_file(args.secrets.path)
        .await
        .context("read device from file")?;
    let device = device.read().await;
    let me = device.me();
    if args.json {
        let json = serde_json::to_string(&me).context("serialize")?;
        println!("{}", json);
    } else {
        println!("Name:       {}", me.addr.name());
        println!("Device ID:  {}", me.addr.device_id());
        println!("Public key: {}", base64::encode(me.public_key.serialize()));
    }
    Ok(())
}

async fn keygen(args: cli::KeygenArgs) -> Result<()> {
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;
    let mut device_secrets = DeviceStore::from_file(&args.secrets.path)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();

    let group = read_group(args.group).await.context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };

    ensure!(
        group.parties_count() == args.parties,
        "protocol expected to have {} parties (from `-n` option), but group file contains {} parties",
        args.parties, group.parties_count()
    );
    ensure!(args.parties > 1, "at least two parties required");
    ensure!(
        args.parties >= args.threshold,
        "threshold value is more than number of parties"
    );

    keygen_run(
        signal_client,
        device_secrets.clone(),
        group,
        me,
        my_ind,
        args.threshold,
        args.parties,
        args.output,
    )
    .await;

    if let Err(err) = device_secrets.save(args.secrets.path).await {
        tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
    }

    Ok(())
}

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
/*
async fn verify(args: cli::VerifyArgs) -> Result<()> {
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
async fn signal_client(server: cli::SignalServer) -> Result<SignalClient> {
    let mut builder = SignalClient::builder()?;
    builder.set_server_host(server.host)?;

    if let Some(cert) = server.certificate {
        let cert = tokio::fs::read(cert).await.context("read certificate")?;

        let mut root_certs = rustls::RootCertStore::empty();
        root_certs
            .add_pem_file(&mut cert.as_slice())
            .map_err(|()| anyhow!("parse certificate"))?;

        let mut tls_config = rustls::ClientConfig::new();
        tls_config.root_store = root_certs;

        let client = awc::Client::builder()
            .connector(
                awc::Connector::new()
                    .rustls(tls_config.into())
                    .timeout(Duration::from_secs(30))
                    .finish(),
            )
            .disable_timeout()
            .finish();

        builder.set_http_client(client);
    }

    Ok(builder.finish())
}

async fn read_group(path: impl AsRef<Path>) -> Result<Group> {
    let file_content = tokio::fs::read(path).await.context("read group file")?;
    let parties_raw =
        serde_json::Deserializer::from_slice(&file_content).into_iter::<ParticipantIdentity>();
    let mut parties = vec![];
    for (i, party) in parties_raw.enumerate() {
        parties.push(party.context(format!("parse {} party", i))?)
    }
    Ok(Group::new(parties))
}

/*
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

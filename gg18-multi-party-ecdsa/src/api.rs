use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::{StreamExt};
use rand::rngs::OsRng;

use std::{env, fs};
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};

use crate::cli as cli;
use cli::Cmd;

use crate::dkg::keygen::Keygen;
use curv::{
    cryptographic_primitives::{
        secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point},
    arithmetic::Converter, BigInt,
};
use paillier::EncryptionKey;
use crate::common::party_i::{Keys, SharedKeys, LocalKeyShare, Params};
use crate::signing::sign::OfflineStage;

pub async fn login(args: cli::LoginArgs) -> Result<()> {
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

pub async fn me(args: cli::MeArgs) -> Result<()> {
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

pub async fn keygen(args: cli::KeygenArgs) -> Result<()> {
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
    
    let output_file = tokio::fs::OpenOptions::new()
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

    fs::write(env::args().nth(9).unwrap(), keygen_json).expect("Unable to save !");
    
    Ok(())
}

pub async fn sign(args: cli::SignArgs) -> Result<()> {
    //1) establish the signal client
    let signal_client = signal_client(args.server)
        .await
        .context("constructing signal client")?;
    //2) read the MPC device id, address, public key
    let mut device_secrets = DeviceStore::from_file(&args.secrets.path)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();
    //3) read the group.json file and ensure this device is included
    let group = read_group(args.group).await.context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };
    //4) read the local shares from file
    let data = fs::read_to_string(args.local_key)
        .expect("Unable to load keys, did you run keygen first? ");
        
    let (party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum): (
        Keys,
        SharedKeys,
        u16,
        Vec<VerifiableSS<Secp256k1>>,
        Vec<EncryptionKey>,
        Point<Secp256k1>,
    ) = serde_json::from_str(&data).unwrap();

    let key_share = LocalKeyShare {
        party_keys, shared_keys, party_id, vss_scheme_vec, paillier_key_vector, y_sum
    };
    //5) read the message string to be signed
    let message_str = args.digits;
    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];
    // we assume the message is already hashed (by the signer).
    let message_bn = BigInt::from_bytes(message);

    sign_run(
        signal_client,
        device_secrets.clone(),
        group,
        me,
        my_ind,
        key_share,
        message_bn,
    )
    .await;

    if let Err(err) = device_secrets.save(args.secrets.path).await {
        tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
    }

    Ok(())
}

async fn sign_run(
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


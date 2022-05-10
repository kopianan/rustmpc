use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::{StreamExt};
use rand::rngs::OsRng;

use std::{env, fs};
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};
use tokio::runtime::Runtime;
use crate::cli as cli;
use cli::{Cmd, keygen_run, signal_client, read_group, sign_run};

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



pub fn login(args: cli::LoginArgs) -> Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let signal_client = signal_client()
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
            .save_no_overwrite("secrets.json")
            .await
            .context("save secrets")?;

        println!();
        println!("MPC device successfully created");

        Ok(())
    })
}


pub fn me(args: cli::MeArgs) -> Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let device = DeviceStore::from_file("secrets.json")
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
    })
}

pub fn keygen(args: cli::KeygenArgs) -> Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        let signal_client = signal_client()
            .await
            .context("constructing signal client")?;
        let mut device_secrets = DeviceStore::from_file("secrets.json")
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

        if let Err(err) = device_secrets.save("secrets.json").await {
            tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
        }

        Ok(())
    })
}

pub fn sign(args: cli::SignArgs) -> Result<()> {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        //1) establish the signal client
        let signal_client = signal_client()
            .await
            .context("constructing signal client")?;
        //2) read the MPC device id, address, public key
        let mut device_secrets = DeviceStore::from_file("secrets.json")
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

        if let Err(err) = device_secrets.save("secrets.json").await {
            tracing::event!(tracing::Level::ERROR, %err, "Failed to save secrets to file");
        }

        Ok(())
    })
}


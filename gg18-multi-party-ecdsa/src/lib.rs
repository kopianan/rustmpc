pub mod common;
pub mod dkg;
pub mod signing;
pub mod utilities;
pub mod cli;

use anyhow::{ anyhow, bail, ensure, Context, Result};
use cli::{keygen_run, signal_client, read_group};
use structopt::StructOpt;
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

//MPC CONSTANTS
const THRESHOLD:u16 = 1;
const PARTIES:u16 = 3;

pub async fn keygen(secrets_byte_vec: Vec<u8>, group_byte_vec: Vec<u8>) -> Result<String> {
    
    let device_secrets = DeviceStore::from_byte_vec(secrets_byte_vec)
        .await
        .context("read device from file")?;
    let me = device_secrets.read().await.me();

    let group = read_group(group_byte_vec).context("read group")?;
    let my_ind = match group.party_index(&me.addr) {
        Some(i) => i,
        None => bail!("group must contain this party too"),
    };
    
    ensure!(
        group.parties_count() == PARTIES,
        "protocol expected to have {} parties (from `-n` option), but group file contains {} parties",
        PARTIES, group.parties_count()
    );
    ensure!(PARTIES > 1, "at least two parties required");
    ensure!(
        PARTIES >= THRESHOLD,
        "threshold value is more than number of parties"
    );
    
    let keygen_json = keygen_run(
        device_secrets.clone(),
        group,
        me,
        my_ind,
        THRESHOLD,
        PARTIES,
    )
    .await;
    keygen_json
}
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

pub async fn getSignalServerCert() -> Result<Vec<u8>> {
    let server = SignalServer::from_args();
    let mut builder = SignalClient::builder()?;
    builder.set_server_host(server.host)?;

    if let Some(cert) = server.certificate {
        Ok(tokio::fs::read(cert).await.context("read certificate")?)
    }
    else {
        Err(anyhow!("Missing signal certificate"))
    }
    
}
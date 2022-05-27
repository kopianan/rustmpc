#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use allo_isolate::Isolate;
use async_ffi::{FfiFuture, FutureExt};
use std::os::raw::{c_char, c_uchar};
use core::slice;

//use gg18_multi_party_ecdsa::common::*;
//use gg18_multi_party_ecdsa::dkg::*;
//use gg18_multi_party_ecdsa::signing::*;
//use gg18_multi_party_ecdsa::utilities::*;
use gg18_multi_party_ecdsa::cli::*;

use anyhow::{ anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;
use std::{fs, vec::Vec};
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};

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

#[no_mangle]
pub extern "C" fn wire_keygen(
    port_: i64,
    secrets_byte_vec: *const c_uchar,
    secrets_byte_len: usize,
    group_byte_vec: *const c_uchar,
    group_byte_len: usize,
) {
    let secrets_byte_vec = unsafe {slice::from_raw_parts(secrets_byte_vec, secrets_byte_len)};
    let mut api_secrets_byte_vec: Vec<u8> = Vec::from(secrets_byte_vec);
    
    let group_byte_vec = unsafe {slice::from_raw_parts(group_byte_vec, group_byte_len)};
    let mut api_group_byte_vec: Vec<u8> = Vec::from(group_byte_vec);

    async move {
        /*
        let result = gg18_multi_party_ecdsa::keygen(api_secrets_byte_vec, api_group_byte_vec).await;
        // make a ref to an isolate using it's port
        let isolate = Isolate::new(port_);
        // and sent it the `Rust's` result
        // no need to convert anything :)

        
        isolate.post(result);
        */
        let isolate = Isolate::new(port_);
        isolate.post("Reading device_secrets . . .");
        // let device_secrets = DeviceStore::from_byte_vec(api_secrets_byte_vec)
        //     .await
        //     .context("read device from file")?;
        // isolate.post("device_secrets read completed. start reading my public key . .");
        // let me = device_secrets.read().await.me();
        // let group = read_group(api_group_byte_vec).context("read group")?;
        // let result: String;
        // let my_ind = match group.party_index(&me.addr) {
        //     Some(i) => {isolate.post("my index is found")},
        //     None => {isolate.post("group must contain this party too")},
        // };

        // if group.parties_count() != PARTIES 
        // {
        //     isolate.post("group.parties_count() != PARTIES");
        // }
        // isolate.post("keygen_run ..");

        // let my_ind = match group.party_index(&me.addr) {
        //     Some(i) => i,
        //     None => bail!("group must contain this party too"),
        // };
        // let keygen_json = keygen_run(
        //     device_secrets.clone(),
        //     group,
        //     me,
        //     my_ind,
        //     THRESHOLD,
        //     PARTIES,
        // )
        // .await;
        // isolate.post(keygen_json);
        // Ok(())
    }.into_local_ffi();
}

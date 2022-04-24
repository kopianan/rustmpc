use gg18_mpc_ecdsa::api::{login, me, keygen, sign};

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context, Result};
use structopt::StructOpt;

use futures::channel::oneshot;
use futures::{StreamExt};
use rand::rngs::OsRng;

use std::{env, fs};
use mpc_over_signal::{DeviceStore, Group, ParticipantIdentity, SignalClient};

use gg18_mpc_ecdsa::cli as cli;
use cli::Cmd;

use gg18_mpc_ecdsa::dkg::keygen::Keygen;
use curv::{
    cryptographic_primitives::{
        secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{secp256_k1::Secp256k1, Point},
    arithmetic::Converter, BigInt,
};
use paillier::EncryptionKey;
use gg18_mpc_ecdsa::common::party_i::{Keys, SharedKeys, LocalKeyShare, Params};
use gg18_mpc_ecdsa::signing::sign::OfflineStage;

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
        Cmd::Sign(args) => sign(args).await,
        //Cmd::Verify(args) => verify(args).await,
    }
}
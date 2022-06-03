#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use allo_isolate::Isolate;
use async_ffi::{FfiFuture, FutureExt};
use core::slice;
use std::os::raw::{c_char, c_uchar};

use gg20_mpc::*;

use anyhow::{anyhow, bail, ensure, Context, Result};
use std::{fs, vec::Vec};
use structopt::StructOpt;

use lazy_static::lazy_static;
use std::{ffi::CStr, io, os::raw};
use tokio::runtime::{Builder, Runtime};

lazy_static! {
    static ref RUNTIME: io::Result<Runtime> = Builder::new()
        .threaded_scheduler()
        .enable_all()
        .core_threads(4)
        .thread_name("flutterust")
        .build();
}

macro_rules! runtime {
    () => {
        match RUNTIME.as_ref() {
            Ok(rt) => rt,
            Err(_) => {
                return ();
            }
        }
    };
}

//MPC CONSTANTS
const THRESHOLD: u16 = 1;
const PARTIES: u16 = 3;

#[no_mangle]
pub extern "C" fn http_local_run(port_: i64) {
    let rt = runtime!();
    let http_task = async move {
        let isolate = Isolate::new(port_);
        isolate.post("start");
        let result = gg20_mpc::http_local_run().await;
        isolate.post("completed");
    }
    .into_ffi();
    rt.spawn(http_task);
}

#[no_mangle]
pub extern "C" fn wire_keygen(port_: i64, index: u16) {
    let rt = runtime!();
    let keygen_task = async move {
        let isolate = Isolate::new(port_);
        isolate.post("test");
        let result = gg20_mpc::keygen_run(index).await;
        isolate.post("test");
        // isolate.post(result);
    }
    .into_ffi();

    rt.spawn(keygen_task);
}

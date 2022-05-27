#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use allo_isolate::Isolate;
use async_ffi::{FfiFuture, FutureExt};
use std::os::raw::{c_char, c_uchar};
use core::slice;

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
        let result = gg18_multi_party_ecdsa::keygen(api_secrets_byte_vec, api_group_byte_vec).await;
        // make a ref to an isolate using it's port
        let isolate = Isolate::new(port_);
        // and sent it the `Rust's` result
        // no need to convert anything :)

        
        isolate.post(result);
    }.into_local_ffi();
}

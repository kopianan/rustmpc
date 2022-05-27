#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use allo_isolate::Isolate;
use flutter_rust_bridge::*;
use async_ffi::{FfiFuture, FutureExt};

#[no_mangle]
pub extern "C" fn wire_keygen(
    port_: i64,
    secrets_byte_vec: *mut wire_uint_8_list,
    group_byte_vec: *mut wire_uint_8_list,
) {
    let api_secrets_byte_vec = secrets_byte_vec.wire2api();
    let api_group_byte_vec = group_byte_vec.wire2api();
    async move {
        let result = gg18_multi_party_ecdsa::keygen(api_secrets_byte_vec, api_group_byte_vec).await;
        // make a ref to an isolate using it's port
        let isolate = Isolate::new(port_);
        // and sent it the `Rust's` result
        // no need to convert anything :)
        isolate.post(result);
    }.into_local_ffi();
}

// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_uint_8_list {
    ptr: *mut u8,
    len: i32,
}


// Section: wrapper structs

// Section: static checks

// Section: allocate functions
 

// Section: impl Wire2Api

pub trait Wire2Api<T> {
    fn wire2api(self) -> T;
}

impl<T, S> Wire2Api<Option<T>> for *mut S
where
    *mut S: Wire2Api<T>,
{
    fn wire2api(self) -> Option<T> {
        if self.is_null() {
            None
        } else {
            Some(self.wire2api())
        }
    }
}

impl Wire2Api<u8> for u8 {
    fn wire2api(self) -> u8 {
        self
    }
}

impl Wire2Api<Vec<u8>> for *mut wire_uint_8_list {
    fn wire2api(self) -> Vec<u8> {
        unsafe {
            let wrap = support::box_from_leak_ptr(self);
            support::vec_from_leak_ptr(wrap.ptr, wrap.len)
        }
    }
}


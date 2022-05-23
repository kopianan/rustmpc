#![allow(clippy::missing_safety_doc, clippy::not_unsafe_ptr_arg_deref)]

use allo_isolate::Isolate;
use lazy_static::lazy_static;
use std::{io, os::raw};
use tokio::runtime::{Builder, Runtime};
use std::thread;

use flutter_rust_bridge::*;

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
                return ;
            }
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn last_error_length() -> i32 {
    ffi_helpers::error_handling::last_error_length()
}

#[no_mangle]
pub unsafe extern "C" fn error_message_utf8(buf: *mut raw::c_char, length: i32) -> i32 {
    ffi_helpers::error_handling::error_message_utf8(buf, length)
}

#[no_mangle]
pub extern "C" fn getSignalServerCert(port: i64) {
    let rt = runtime!();
    rt.spawn(async move {  
        let result = gg18_multi_party_ecdsa::getSignalServerCert().await;
        let isolate = Isolate::new(port);
        isolate.post(result);
    });
}
/*
#[no_mangle]
pub extern "C" fn wire_keygen(
    port_: i64,
    secrets_byte_vec: *mut wire_uint_8_list,
    group_byte_vec: *mut wire_uint_8_list,
) {
    // get a ref to the runtime
    let rt = runtime!();
    let api_secrets_byte_vec = secrets_byte_vec.wire2api();
    let api_group_byte_vec = group_byte_vec.wire2api();
        
    rt.spawn(async move {  
        let result = gg18_multi_party_ecdsa::keygen(api_secrets_byte_vec, api_group_byte_vec).await;
        // make a ref to an isolate using it's port
        let isolate = Isolate::new(port_);
        // and sent it the `Rust's` result
        // no need to convert anything :)
        isolate.post(result);
    });
}
*/

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

#[no_mangle]
pub extern "C" fn new_uint_8_list(len: i32) -> *mut wire_uint_8_list {
    let ans = wire_uint_8_list {
        ptr: support::new_leak_vec_ptr(Default::default(), len),
        len,
    };
    support::new_leak_box_ptr(ans)
}

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

// Section: impl NewWithNullPtr

pub trait NewWithNullPtr {
    fn new_with_null_ptr() -> Self;
}

impl<T> NewWithNullPtr for *mut T {
    fn new_with_null_ptr() -> Self {
        std::ptr::null_mut()
    }
}

// Section: impl IntoDart

// Section: executor

// Section: sync execution mode utility

#[no_mangle]
pub extern "C" fn free_WireSyncReturnStruct(val: support::WireSyncReturnStruct) {
    unsafe {
        let _ = support::vec_from_leak_ptr(val.ptr, val.len);
    }
}

    // ----------- DUMMY CODE FOR BINDGEN ----------

    // copied from: allo-isolate
    pub type DartPort = i64;
    pub type DartPostCObjectFnType = unsafe extern "C" fn(port_id: DartPort, message: *mut std::ffi::c_void) -> bool;
    #[no_mangle] pub unsafe extern "C" fn store_dart_post_cobject(ptr: DartPostCObjectFnType) { panic!("dummy code") }

    // copied from: frb_rust::support.rs
    #[repr(C)]
    pub struct WireSyncReturnStruct {
        pub ptr: *mut u8,
        pub len: i32,
        pub success: bool,
    }

    // ---------------------------------------------

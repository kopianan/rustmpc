#![allow(
    non_camel_case_types,
    unused,
    clippy::redundant_closure,
    clippy::useless_conversion,
    clippy::unit_arg,
    clippy::double_parens,
    non_snake_case
)]
// AUTO GENERATED FILE, DO NOT EDIT.
// Generated by `flutter_rust_bridge`.

use crate::api::*;
use flutter_rust_bridge::*;

// Section: imports

use crate::cli::KeygenArgs;
use crate::cli::LoginArgs;
use crate::cli::MeArgs;
use crate::cli::SignArgs;

// Section: wire functions

#[no_mangle]
pub extern "C" fn wire_login(port_: i64, args: *mut wire_LoginArgs) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "login",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_args = args.wire2api();
            move |task_callback| login(api_args)
        },
    )
}

#[no_mangle]
pub extern "C" fn wire_me(port_: i64, args: *mut wire_MeArgs) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "me",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_args = args.wire2api();
            move |task_callback| me(api_args)
        },
    )
}

#[no_mangle]
pub extern "C" fn wire_keygen(port_: i64, args: *mut wire_KeygenArgs) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "keygen",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_args = args.wire2api();
            move |task_callback| keygen(api_args)
        },
    )
}

#[no_mangle]
pub extern "C" fn wire_sign(port_: i64, args: *mut wire_SignArgs) {
    FLUTTER_RUST_BRIDGE_HANDLER.wrap(
        WrapInfo {
            debug_name: "sign",
            port: Some(port_),
            mode: FfiCallMode::Normal,
        },
        move || {
            let api_args = args.wire2api();
            move |task_callback| sign(api_args)
        },
    )
}

// Section: wire structs

#[repr(C)]
#[derive(Clone)]
pub struct wire_KeygenArgs {
    threshold: u16,
    parties: u16,
    group: *mut wire_uint_8_list,
    output: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_LoginArgs {
    device_name: *mut wire_uint_8_list,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_MeArgs {
    json: bool,
}

#[repr(C)]
#[derive(Clone)]
pub struct wire_SignArgs {
    local_key: *mut wire_uint_8_list,
    group: *mut wire_uint_8_list,
    digits: *mut wire_uint_8_list,
}

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
pub extern "C" fn new_box_autoadd_keygen_args() -> *mut wire_KeygenArgs {
    support::new_leak_box_ptr(wire_KeygenArgs::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_login_args() -> *mut wire_LoginArgs {
    support::new_leak_box_ptr(wire_LoginArgs::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_me_args() -> *mut wire_MeArgs {
    support::new_leak_box_ptr(wire_MeArgs::new_with_null_ptr())
}

#[no_mangle]
pub extern "C" fn new_box_autoadd_sign_args() -> *mut wire_SignArgs {
    support::new_leak_box_ptr(wire_SignArgs::new_with_null_ptr())
}

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

impl Wire2Api<String> for *mut wire_uint_8_list {
    fn wire2api(self) -> String {
        let vec: Vec<u8> = self.wire2api();
        String::from_utf8_lossy(&vec).into_owned()
    }
}

impl Wire2Api<bool> for bool {
    fn wire2api(self) -> bool {
        self
    }
}

impl Wire2Api<KeygenArgs> for *mut wire_KeygenArgs {
    fn wire2api(self) -> KeygenArgs {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        (*wrap).wire2api().into()
    }
}

impl Wire2Api<LoginArgs> for *mut wire_LoginArgs {
    fn wire2api(self) -> LoginArgs {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        (*wrap).wire2api().into()
    }
}

impl Wire2Api<MeArgs> for *mut wire_MeArgs {
    fn wire2api(self) -> MeArgs {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        (*wrap).wire2api().into()
    }
}

impl Wire2Api<SignArgs> for *mut wire_SignArgs {
    fn wire2api(self) -> SignArgs {
        let wrap = unsafe { support::box_from_leak_ptr(self) };
        (*wrap).wire2api().into()
    }
}

impl Wire2Api<KeygenArgs> for wire_KeygenArgs {
    fn wire2api(self) -> KeygenArgs {
        KeygenArgs {
            threshold: self.threshold.wire2api(),
            parties: self.parties.wire2api(),
            group: self.group.wire2api(),
            output: self.output.wire2api(),
        }
    }
}

impl Wire2Api<LoginArgs> for wire_LoginArgs {
    fn wire2api(self) -> LoginArgs {
        LoginArgs {
            device_name: self.device_name.wire2api(),
        }
    }
}

impl Wire2Api<MeArgs> for wire_MeArgs {
    fn wire2api(self) -> MeArgs {
        MeArgs {
            json: self.json.wire2api(),
        }
    }
}

impl Wire2Api<SignArgs> for wire_SignArgs {
    fn wire2api(self) -> SignArgs {
        SignArgs {
            local_key: self.local_key.wire2api(),
            group: self.group.wire2api(),
            digits: self.digits.wire2api(),
        }
    }
}

impl Wire2Api<u16> for u16 {
    fn wire2api(self) -> u16 {
        self
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

impl NewWithNullPtr for wire_KeygenArgs {
    fn new_with_null_ptr() -> Self {
        Self {
            threshold: Default::default(),
            parties: Default::default(),
            group: core::ptr::null_mut(),
            output: core::ptr::null_mut(),
        }
    }
}

impl NewWithNullPtr for wire_LoginArgs {
    fn new_with_null_ptr() -> Self {
        Self {
            device_name: core::ptr::null_mut(),
        }
    }
}

impl NewWithNullPtr for wire_MeArgs {
    fn new_with_null_ptr() -> Self {
        Self {
            json: Default::default(),
        }
    }
}

impl NewWithNullPtr for wire_SignArgs {
    fn new_with_null_ptr() -> Self {
        Self {
            local_key: core::ptr::null_mut(),
            group: core::ptr::null_mut(),
            digits: core::ptr::null_mut(),
        }
    }
}

// Section: impl IntoDart

// Section: executor

support::lazy_static! {
    pub static ref FLUTTER_RUST_BRIDGE_HANDLER: support::DefaultHandler = Default::default();
}

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
    
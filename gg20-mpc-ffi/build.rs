use dart_bindgen::{config::*, Codegen};

fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut config = cbindgen::Config {
        language: cbindgen::Language::C,
        ..Default::default()
    };
    config.braces = cbindgen::Braces::SameLine;
    config.cpp_compat = true;
    config.style = cbindgen::Style::Both;
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("binding.h");
        
    let config = DynamicLibraryConfig {
        ios: DynamicLibraryCreationMode::Executable.into(),
        android: DynamicLibraryCreationMode::open("libgg20_mpc_ffi.so").into(),
        ..Default::default()
    };
    // load the c header file, with config and lib name
    let codegen = Codegen::builder()
        .with_src_header("binding.h")
        .with_lib_name("libgg20_mpc_ffi")
        .with_config(config)
        .with_allo_isolate()
        .build()
        .unwrap();
    // generate the dart code and get the bindings back
    let bindings = codegen.generate().unwrap();
    // write the bindings to your dart package
    // and start using it to write your own high level abstraction.
    bindings
        .write_to_file("/Users/anan/Documents/CoinBit/FlutterRustMpc/rust_mpc_ffi/lib/ffi.dart")
        .unwrap();
}   



// cargo ndk -t armeabi-v7a -t arm64-v8a -o /Users/anan/Documents/CoinBit/FlutterRustMpc/rust_mpc_ffi/example/android/app/src/main/jniLibs build --release 
// ln -s /Users/anan/Documents/CoinBit/FlutterRustMpc/rustmpc/target/universal/release/libgg20_mpc_ffi.a
// cat /Users/anan/Documents/CoinBit/FlutterRustMpc/rustmpc/gg20-mpc-ffi/binding.h >> Classes/RustMpcFfiPlugin.h
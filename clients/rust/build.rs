//! Links the NativeAOT library. CMake passes its folder in VAULT_NATIVE_DIR.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=VAULT_NATIVE_DIR");
    let dir = PathBuf::from(
        env::var("VAULT_NATIVE_DIR")
            .expect("set VAULT_NATIVE_DIR to the folder holding vault_native"),
    );

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match target_os.as_str() {
        // Windows links through the import library, vault_native.lib.
        "windows" => {
            println!(
                "cargo:rerun-if-changed={}",
                dir.join("vault_native.lib").display()
            );
            println!("cargo:rustc-link-search=native={}", dir.display());
            println!("cargo:rustc-link-lib=dylib=vault_native");
        }
        // NativeAOT names the library without a "lib" prefix, so `-lvault_native`
        // would not find it. Link it by path, and look for it next to the
        // executable at run time.
        os => {
            let (file, origin) = if os == "macos" {
                ("vault_native.dylib", "@loader_path")
            } else {
                ("vault_native.so", "$ORIGIN")
            };
            let library = dir.join(file);
            println!("cargo:rerun-if-changed={}", library.display());
            println!("cargo:rustc-link-arg={}", library.display());
            println!("cargo:rustc-link-arg=-Wl,-rpath,{origin}");
        }
    }
}

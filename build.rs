use std::env;
use std::path::PathBuf;

const TINY_ECDH_HEADER: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tiny-ECDH-c/ecdh.h");
const TINY_ECDH_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tiny-ECDH-c/ecdh.c");

fn main() {
    let src = [TINY_ECDH_SRC];

    let mut builder = cc::Build::new();
    let build = builder
        .files(src.iter())
        .include(TINY_ECDH_HEADER)
        .define("USE_ZLIB", None);
    build.compile("tiny-ecdh");

    println!("cargo:rustc-link-lib=tiny-ecdh");
    let bindings = bindgen::Builder::default()
        .header(TINY_ECDH_HEADER)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("tiny-ecdh.rs"))
        .expect("Couldn't write bindings!");
}

//! Build script for `xmlsec-mini-sys`.
//!
//! Dynamically links the *system* libxmlsec1 (OpenSSL backend) + libxml2 via
//! pkg-config (`libxmlsec1-dev` + `libxml2-dev`), and runs bindgen over
//! `wrapper.h` restricted to the handful of symbols the XML-DSig sign/verify
//! path actually calls.

use std::env;
use std::path::PathBuf;
use std::process::Command;

// Only these symbols cross the FFI boundary — the "bind only what we use" goal.
const FUNCTIONS: &[&str] = &[
    // libxml2: parse, serialize, free, root, ID registration.
    "xmlInitParser",
    "xmlReadMemory",
    "xmlDocDumpMemory",
    "xmlFreeDoc",
    "xmlDocGetRootElement",
    // xmlsec: library + OpenSSL crypto lifecycle.
    "xmlSecInit",
    "xmlSecShutdown",
    "xmlSecErrorsSetCallback",
    "xmlSecOpenSSLAppInit",
    "xmlSecOpenSSLAppShutdown",
    "xmlSecOpenSSLInit",
    "xmlSecOpenSSLShutdown",
    // xmlsec: node lookup + SAML ID-attribute registration.
    "xmlSecFindNode",
    "xmlSecAddIDs",
    // xmlsec: load a key (private key to sign, or a cert's public key to verify).
    "xmlSecOpenSSLAppKeyLoadMemory",
    // xmlsec: the DSig context.
    "xmlSecDSigCtxCreate",
    "xmlSecDSigCtxDestroy",
    "xmlSecDSigCtxSign",
    "xmlSecDSigCtxVerify",
];

const TYPES: &[&str] = &["xmlSecDSigCtx", "xmlSecDSigStatus", "xmlSecKeyDataFormat"];

// `const xmlChar[]` globals and the xmlFree function-pointer global.
const VARS: &[&str] = &["xmlSecNodeSignature", "xmlSecDSigNs", "xmlFree"];

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=build.rs");

    // Probe pkg-config: emits the dynamic link directives and gives the include
    // paths bindgen needs (the cflags below carry the -I paths and -D defines).
    let lib = pkg_config::Config::new()
        .probe("xmlsec1-openssl")
        .expect("pkg-config could not find `xmlsec1-openssl` — install libxmlsec1-dev + libxml2-dev");

    // Feed the exact compiler flags xmlsec needs (esp. -DXMLSEC_CRYPTO_OPENSSL and
    // the -I paths) to clang so bindgen parses the headers the same way the C
    // library is built.
    let cflags = Command::new("pkg-config")
        .args(["--cflags", "xmlsec1-openssl"])
        .output()
        .expect("run pkg-config --cflags");
    let clang_args: Vec<String> = String::from_utf8_lossy(&cflags.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect();

    let mut builder = bindgen::Builder::default()
        .header("wrapper.h")
        .clang_args(&clang_args)
        // Also cover include paths the pkg-config crate resolved, for safety.
        .clang_args(
            lib.include_paths
                .iter()
                .map(|p| format!("-I{}", p.display())),
        )
        .allowlist_recursively(true)
        .use_core()
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    for f in FUNCTIONS {
        builder = builder.allowlist_function(f);
    }
    for t in TYPES {
        builder = builder.allowlist_type(t);
    }
    for v in VARS {
        builder = builder.allowlist_var(v);
    }

    let bindings = builder.generate().expect("bindgen failed to generate bindings");
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("write bindings.rs");
}

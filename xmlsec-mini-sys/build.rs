//! Build script for `xmlsec-mini-sys`.
//!
//! Locates libxmlsec1 (OpenSSL backend) + libxml2 via pkg-config, emits the
//! cargo link directives, and runs bindgen over `wrapper.h` restricted to the
//! handful of symbols the XML-DSig sign/verify path actually calls.
//!
//! Today this links a *system* libxmlsec1 (`libxmlsec1-dev` + `libxml2-dev`).
//! The intended end state is a vendored static build so the library ships inside
//! the binary; see PHASE_C_BUNDLING.md. That is a build.rs change only — the
//! bindings and the Rust API above it stay identical.

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

    // Static linking spike: with XMLSEC_MINI_SYS_STATIC=1, link libxmlsec1 +
    // libxml2 + OpenSSL from their `.a` archives so they are baked into the
    // binary (nothing xmlsec/xml2-related loaded at runtime) — the "shipped in
    // the binary" goal. `pkg-config --static` refuses to static-link libraries
    // in system dirs, so the archive chain is emitted explicitly. See
    // PHASE_C_BUNDLING.md.
    let static_link = env::var_os("XMLSEC_MINI_SYS_STATIC").is_some();
    println!("cargo:rerun-if-env-changed=XMLSEC_MINI_SYS_STATIC");

    // Always probe with pkg-config for the include paths bindgen needs (cflags
    // below). When linking dynamically this also emits the link directives; when
    // static, we emit the archive chain ourselves and only use it for -I paths.
    let mut cfg = pkg_config::Config::new();
    if static_link {
        cfg.cargo_metadata(false);
    }
    let lib = cfg
        .probe("xmlsec1-openssl")
        .expect("pkg-config could not find `xmlsec1-openssl` — install libxmlsec1-dev + libxml2-dev");

    if static_link {
        emit_static_link_chain(&lib);
    }

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

/// Emit the static-archive link chain for libxmlsec1 + libxml2 + OpenSSL.
///
/// Order is dependents-before-dependencies for the GNU linker. The xmlsec /
/// xml2 / openssl layers are linked from their `.a` archives (baked into the
/// binary); base system libs (z, lzma, m, dl, pthread) stay dynamic — the same
/// division `openssl-src`-style vendoring uses.
fn emit_static_link_chain(lib: &pkg_config::Library) {
    for p in &lib.link_paths {
        println!("cargo:rustc-link-search=native={}", p.display());
    }
    // Default multiarch archive dir, in case pkg-config reported none.
    println!("cargo:rustc-link-search=native=/usr/lib/x86_64-linux-gnu");

    for archive in ["xmlsec1-openssl", "xmlsec1", "xml2", "ssl", "crypto"] {
        println!("cargo:rustc-link-lib=static={archive}");
    }
    // Transitive private deps left dynamic for the spike. `libxslt` has no `.a`
    // in the distro packages at all; the ICU libs (pulled by an ICU-enabled
    // libxml2.a) and z/lzma/m/dl/pthread are base/system libs. A vendored source
    // build of libxml2 (`--without-icu`) and xmlsec (`--without-libxslt`) — eID
    // uses neither — removes xslt and ICU entirely and makes a fully static
    // bundle achievable.
    for dynamic in [
        "xslt", "icui18n", "icuuc", "icudata", "z", "lzma", "m", "dl", "pthread",
    ] {
        println!("cargo:rustc-link-lib=dylib={dynamic}");
    }
}

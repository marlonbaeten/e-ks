//! XML-DSig / XML-Enc backend adapter.
//!
//! `sign` and `verify_signature` are backed by a *selectable* XML-DSig backend,
//! chosen at compile time by a cargo feature:
//!
//! * `backend-bergshamra` (default) — the pure-Rust `bergshamra-dsig`, shipped
//!   in the binary with no system dependency.
//! * `backend-xmlsec` — libxmlsec1 (the reference C implementation) via the
//!   minimal `xmlsec-mini-sys` FFI. Useful to cross-check the pure-Rust backend
//!   against the canonical implementation.
//!
//! `decrypt` (XML-Enc) always uses `bergshamra-enc` regardless of the DSig
//! backend: libxmlsec1 as bound here does not do XML encryption, and the eID
//! `EncryptedID` path needs it. `bergshamra-enc`/`bergshamra-keys` are therefore
//! unconditional dependencies; only the DSig half is swapped.
//!
//! Whichever backend is selected must satisfy the same contract, including the
//! signature-layer XML Signature Wrapping (XSW) defenses exercised by
//! `tests/backend_conformance.rs`. bergshamra enforces those internally; the
//! xmlsec backend re-asserts them in Rust (see `xmlsec.rs`).

use crate::error::{AuthError, Result};
use bergshamra_enc::{EncContext, decrypt::decrypt as backend_decrypt};
use bergshamra_keys::{KeysManager, loader};
use tracing::warn;

// Exactly one DSig backend must be active.
#[cfg(all(feature = "backend-bergshamra", feature = "backend-xmlsec"))]
compile_error!(
    "features `backend-bergshamra` and `backend-xmlsec` are mutually exclusive; \
     build the xmlsec backend with `--no-default-features --features backend-xmlsec`"
);
#[cfg(not(any(feature = "backend-bergshamra", feature = "backend-xmlsec")))]
compile_error!(
    "no XML-DSig backend selected: enable `backend-bergshamra` (default) or `backend-xmlsec`"
);

#[cfg(feature = "backend-bergshamra")]
mod bergshamra;
#[cfg(feature = "backend-bergshamra")]
pub use bergshamra::{sign, verify_signature};

#[cfg(feature = "backend-xmlsec")]
mod xmlsec;
#[cfg(feature = "backend-xmlsec")]
pub use xmlsec::{sign, verify_signature};

/// Outcome of verifying an XML signature against a certificate.
pub enum SignatureVerification {
    Valid,
    /// The signature did not validate; carries the backend's reason.
    Invalid(String),
}

/// Decrypt an XML-Enc fragment, trying each `(private_key_pem, key_name)` pair
/// and returning the first success.
///
/// Key transport is crypto-bound to the keypair (the backend unwraps the
/// `EncryptedKey` with the RSA private key, not by matching `<KeyName>`), so
/// trying each key in turn decrypts a blob wrapped to any configured key and
/// keeps cert rollover working regardless of list order. `key_name` is for
/// diagnostics only; keys that fail to load are skipped.
///
/// Always backed by `bergshamra-enc` — the DSig backend feature does not affect
/// decryption.
pub fn decrypt(encrypted_xml: &str, keys: &[(&str, &str)]) -> Result<String> {
    let mut last_err: Option<String> = None;
    for (key_pem, key_name) in keys {
        // SECURITY: never log key_pem; key_name is a thumbprint of the public cert.
        let bkey = match loader::load_rsa_private_pem(key_pem.as_bytes()) {
            Ok(bkey) => bkey.with_name(*key_name),
            Err(e) => {
                warn!("[crypto] failed to load decryption key {key_name}: {e}");
                continue;
            }
        };
        let mut mgr = KeysManager::new();
        mgr.add_key(bkey);
        let ctx = EncContext::new(mgr);
        match backend_decrypt(&ctx, encrypted_xml) {
            Ok(xml) => return Ok(xml),
            Err(e) => last_err = Some(e.to_string()),
        }
    }
    Err(AuthError::Crypto(format!(
        "decryption failed: {}",
        last_err.unwrap_or_else(|| "no usable decryption key".to_string())
    )))
}

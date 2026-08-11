//! Default XML-DSig backend: the pure-Rust `bergshamra-dsig`.
//!
//! Selected by the `backend-bergshamra` feature (on by default). The strict
//! verification flags below are the backend-level XSW / trusted-key floor; they
//! are already `DsigContext::new` defaults but are pinned so the floor survives
//! a backend default change (as with `min_tls_version` in `bindings::soap`).

use super::SignatureVerification;
use crate::error::{AuthError, Result};
use bergshamra_dsig::DsigContext;
use bergshamra_keys::{KeysManager, loader};

/// Sign `xml` in place with the RSA private key (`private_key_pem`).
///
/// `xml` must already contain an inline, unfilled `ds:Signature` template; the
/// backend computes and fills its `DigestValue` and `SignatureValue`.
pub fn sign(xml: &str, private_key_pem: &str) -> Result<String> {
    let key = loader::load_rsa_private_pem(private_key_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("Failed to load signing key: {e}")))?;
    let mut mgr = KeysManager::new();
    mgr.add_key(key);
    let ctx = DsigContext::new(mgr);
    bergshamra_dsig::sign::sign(&ctx, xml)
        .map_err(|e| AuthError::Crypto(format!("XML signing failed: {e}")))
}

/// Verify the signature anchored by `xml` against `cert_pem`, which is used as
/// the sole trusted key. `Err` indicates a cert-load or backend error; a failed
/// signature match is `Ok(Invalid)`.
pub fn verify_signature(xml: &str, cert_pem: &str) -> Result<SignatureVerification> {
    let key = loader::load_x509_cert_pem(cert_pem.as_bytes())
        .map_err(|e| AuthError::Crypto(format!("Failed to load verification cert: {e}")))?;
    let mut mgr = KeysManager::new();
    mgr.add_key(key);
    // Only `cert_pem` may verify, reference targets must sit in an expected
    // position relative to the `<Signature>` (a second XSW check beside
    // `signature_covers_root`), and every Reference digest must be verified
    // locally.
    let ctx = DsigContext::new(mgr)
        .with_trusted_keys_only(true)
        .with_strict_verification(true)
        .with_require_reference_digests(true);
    match bergshamra_dsig::verify::verify(&ctx, xml) {
        Ok(bergshamra_dsig::VerifyResult::Valid { .. }) => Ok(SignatureVerification::Valid),
        Ok(bergshamra_dsig::VerifyResult::Invalid { reason }) => {
            Ok(SignatureVerification::Invalid(reason))
        }
        Err(e) => Err(AuthError::Crypto(format!(
            "Signature verification error: {e}"
        ))),
    }
}

//! Backend-agnostic conformance contract for the XML-DSig signing backend.
//!
//! `saml::crypto::{sign, verify_signature}` is a swappable seam: today it is
//! backed by `bergshamra-dsig`, and a `backend-xmlsec` build swaps it for
//! libxmlsec1 FFI. Both backends MUST satisfy the same contract, and in
//! particular both must reject the signature-layer XML Signature Wrapping (XSW)
//! manipulations below — libxmlsec1 does not do this on its own, so the xmlsec
//! backend has to re-assert the floor that `crypto::verify_signature` pins on
//! bergshamra (`with_trusted_keys_only` / `with_strict_verification` /
//! `with_require_reference_digests`).
//!
//! These tests exercise the adapter directly (not the full receive chain) so a
//! backend swap is validated against one shared contract. Run under either
//! backend:
//!   cargo test -p auth-service --test backend_conformance
//!   cargo test -p auth-service --test backend_conformance \
//!       --no-default-features --features backend-xmlsec

mod common;
use common::{RD, SAML, SAMLP, inline_signature, load_key};

use auth_service::saml::crypto::{SignatureVerification, sign, verify_signature};
use secrecy::ExposeSecret;

/// Assert a `SignatureVerification` is `Valid`, printing the reason otherwise.
fn assert_valid(v: SignatureVerification) {
    match v {
        SignatureVerification::Valid => {}
        SignatureVerification::Invalid(reason) => panic!("expected Valid, got Invalid: {reason}"),
    }
}

/// Assert a verify outcome is NOT `Valid` (either `Ok(Invalid)` or a backend
/// `Err`) — a forgery must never be accepted.
fn assert_not_valid(v: Result<SignatureVerification, impl std::fmt::Debug>) {
    match v {
        Ok(SignatureVerification::Valid) => panic!("SECURITY: forged/invalid signature accepted"),
        Ok(SignatureVerification::Invalid(_)) | Err(_) => {}
    }
}

/// A minimal enveloped-signature document whose root carries `ID=ref_id`; the
/// inline template references `#ref_id` and covers the whole root.
fn signed_doc(ref_id: &str, cert_b64: &str, payload: &str) -> String {
    let sig = inline_signature(ref_id, cert_b64);
    format!(
        r#"<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="{ref_id}" Version="2.0"><saml:Issuer>{RD}</saml:Issuer>{sig}<saml:Payload>{payload}</saml:Payload></samlp:Response>"#
    )
}

/// A genuine sign -> verify round-trip against the signer's own cert is `Valid`.
#[test]
fn genuine_roundtrip_is_valid() {
    let key = load_key("rd-signing-1");
    let doc = signed_doc("_r1", &key.cert_base64, "genuine");
    let signed = sign(&doc, key.key_pem.expose_secret()).expect("sign");
    assert_valid(verify_signature(&signed, &key.cert_pem).expect("verify"));
}

/// Trusted-keys-only: a signature made by a different keypair must not verify
/// against our pinned cert, even though its own cert is embedded in KeyInfo.
#[test]
fn signature_from_untrusted_key_is_rejected() {
    let signer = load_key("rd-signing-1");
    let trusted = load_key("dv-signing-1"); // a different keypair
    // Sign with the signer key, but embed/verify against the trusted cert.
    let doc = signed_doc("_r1", &signer.cert_base64, "genuine");
    let signed = sign(&doc, signer.key_pem.expose_secret()).expect("sign");
    assert_not_valid(verify_signature(&signed, &trusted.cert_pem));
}

/// Any post-signature mutation of the signed content breaks the reference
/// digest, so verification must fail.
#[test]
fn tampered_signed_content_is_rejected() {
    let key = load_key("rd-signing-1");
    let doc = signed_doc("_r1", &key.cert_base64, "genuine");
    let signed = sign(&doc, key.key_pem.expose_secret()).expect("sign");
    let tampered = signed.replace("genuine", "hijacked");
    assert_ne!(tampered, signed, "tamper must have landed");
    assert_not_valid(verify_signature(&tampered, &key.cert_pem));
}

/// XSW: after signing, an attacker injects a second element carrying the SAME
/// `ID` as the signed one, inside the signed root. This both breaks the
/// enveloped-signature digest over the root and makes the reference `#_r1`
/// ambiguous; either way the backend must not report `Valid`.
#[test]
fn duplicate_signed_id_is_rejected() {
    let key = load_key("rd-signing-1");
    let doc = signed_doc("_r1", &key.cert_base64, "genuine");
    let signed = sign(&doc, key.key_pem.expose_secret()).expect("sign");

    // Inject a forged element re-using ID `_r1` right after the opening root tag,
    // ahead of the genuine referenced element.
    let open = r#"Version="2.0">"#;
    let forged = r#"<saml:Forged ID="_r1">attacker</saml:Forged>"#;
    let wrapped = signed.replacen(open, &format!("{open}{forged}"), 1);
    assert_ne!(wrapped, signed, "duplicate-ID injection must have landed");
    assert_not_valid(verify_signature(&wrapped, &key.cert_pem));
}

/// XSW: the genuine signed element is relocated into a wrapper and a forged
/// element with the original `ID` is placed where the app would read it. The
/// captured signature is byte-identical, so a position-blind verifier would
/// still report `Valid`; the backend must not.
#[test]
fn wrapped_signed_element_is_rejected() {
    let key = load_key("rd-signing-1");
    let inner = signed_doc("_r1", &key.cert_base64, "genuine");
    let signed = sign(&inner, key.key_pem.expose_secret()).expect("sign");

    // Wrap the whole signed Response inside an outer envelope, then add a forged
    // sibling carrying the same ID `_r1` as a wrapping target.
    let forged = r#"<saml:Forged ID="_r1">attacker</saml:Forged>"#;
    let wrapped = format!(
        r#"<samlp:Wrapper xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}"><samlp:Stash>{signed}</samlp:Stash>{forged}</samlp:Wrapper>"#
    );
    assert_not_valid(verify_signature(&wrapped, &key.cert_pem));
}

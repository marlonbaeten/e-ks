//! Alternative XML-DSig backend: libxmlsec1 (the reference C implementation) via
//! the minimal `xmlsec-mini-sys` FFI. Selected by the `backend-xmlsec` feature.
//!
//! libxmlsec1 does the cryptography (canonicalization, digesting, RSA verify)
//! and trusted-cert chaining, but it does NOT defend against XML Signature
//! Wrapping on its own: given two elements sharing the referenced `ID`, it
//! resolves `#id` to one and reports success. bergshamra's `verify_signature`
//! rejects that via `with_strict_verification`; to keep the two backends
//! interchangeable (and to satisfy `tests/backend_conformance.rs`), this module
//! re-asserts the same floor in Rust before trusting a positive verify:
//!
//! * duplicate-ID rejection (an ID-carrying attribute value must be unique), and
//! * trusted-keys-only, via a keys manager seeded with only the pinned cert.
//!
//! In production this is defense-in-depth: `saml::verification` already enforces
//! the enveloping-signature / covers-root / unique-ID structure around the
//! backend independent of which backend is compiled in.

use super::SignatureVerification;
use crate::error::{AuthError, Result};
use crate::saml::xml_parser::{all_elements, parse};
use std::ffi::{CString, c_void};
use std::ptr;
use std::sync::OnceLock;

use xmlsec_mini_sys as sys;

/// Attribute names that carry an `#id` reference target. Must stay aligned with
/// `saml::verification::ID_ATTRIBUTES` and the pure-Rust backend's ID map so all
/// three resolve a reference the same way.
const ID_ATTRIBUTES: &[&str] = &["ID", "Id", "id", "AssertionID"];

/// libxmlsec1 attribute-name list (NUL-terminated C strings) for `xmlSecAddIDs`,
/// so `URI="#x"` references resolve. Mirrors [`ID_ATTRIBUTES`].
const ID_ATTRIBUTES_C: &[&[u8]] = &[b"ID\0", b"Id\0", b"id\0", b"AssertionID\0"];

// ---------------------------------------------------------------------------
// One-time global initialization (libxml2 + xmlsec + OpenSSL backend).
// ---------------------------------------------------------------------------

/// Initialize libxml2, xmlsec, and the xmlsec OpenSSL backend exactly once.
/// libxmlsec1 requires initialization to happen once, single-threaded; per-call
/// operations on independent contexts are then safe to run concurrently.
fn ensure_init() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    INIT.get_or_init(|| {
        // SAFETY: FFI init sequence, run once under the OnceLock.
        unsafe {
            sys::xmlInitParser();
            if sys::xmlSecInit() < 0 {
                return Err("xmlSecInit failed".to_string());
            }
            if sys::xmlSecOpenSSLAppInit(ptr::null()) < 0 {
                return Err("xmlSecOpenSSLAppInit failed".to_string());
            }
            if sys::xmlSecOpenSSLInit() < 0 {
                return Err("xmlSecOpenSSLInit failed".to_string());
            }
        }
        Ok(())
    })
    .clone()
    .map_err(AuthError::Crypto)
}

// ---------------------------------------------------------------------------
// RAII guards so every early return frees the C objects it owns.
// ---------------------------------------------------------------------------

struct Doc(sys::xmlDocPtr);
impl Drop for Doc {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::xmlFreeDoc(self.0) };
        }
    }
}

struct DsigCtx(sys::xmlSecDSigCtxPtr);
impl Drop for DsigCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { sys::xmlSecDSigCtxDestroy(self.0) };
        }
    }
}

/// Parse `xml` into a libxml2 document and register SAML ID attributes so
/// `URI="#id"` references resolve.
fn parse_and_register_ids(xml: &str) -> Result<Doc> {
    let c_xml = CString::new(xml).map_err(|_| AuthError::Crypto("XML contains NUL".into()))?;
    // SAFETY: buffer/len are consistent; URL/encoding null; options 0.
    let doc = unsafe {
        sys::xmlReadMemory(
            c_xml.as_ptr(),
            xml.len() as i32,
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    if doc.is_null() {
        return Err(AuthError::Crypto("libxml2 failed to parse XML".into()));
    }
    let doc = Doc(doc);
    // SAFETY: doc is valid; root may be null for an empty doc, handled by callers.
    let root = unsafe { sys::xmlDocGetRootElement(doc.0) };
    if root.is_null() {
        return Err(AuthError::Crypto("XML has no root element".into()));
    }
    let mut ids: Vec<*const sys::xmlChar> = ID_ATTRIBUTES_C
        .iter()
        .map(|n| n.as_ptr() as *const sys::xmlChar)
        .collect();
    ids.push(ptr::null()); // NUL-terminate the list.
    // SAFETY: xmlSecAddIDs reads the NUL-terminated `ids` list; does not retain it.
    unsafe { sys::xmlSecAddIDs(doc.0, root, ids.as_ptr() as *mut *const sys::xmlChar) };
    Ok(doc)
}

/// Locate the (first) enveloping `<ds:Signature>` in `doc`.
fn find_signature(doc: &Doc) -> Result<sys::xmlNodePtr> {
    // SAFETY: doc is valid; the constants are NUL-terminated `xmlChar` arrays.
    let node = unsafe {
        let root = sys::xmlDocGetRootElement(doc.0);
        sys::xmlSecFindNode(
            root,
            sys::xmlSecNodeSignature.as_ptr(),
            sys::xmlSecDSigNs.as_ptr(),
        )
    };
    if node.is_null() {
        return Err(AuthError::Crypto("no ds:Signature element found".into()));
    }
    Ok(node)
}

/// Reject a document in which any ID-carrying attribute value repeats. This is
/// the XSW floor libxmlsec1 does not enforce: with a duplicate signed `ID`, a
/// forged element can share the referenced ID and the raw verify would still
/// resolve `#id` to the genuine element and report success.
fn reject_duplicate_ids(xml: &str) -> Result<()> {
    let doc = parse(xml).map_err(|e| AuthError::Crypto(format!("XML parse error: {e}")))?;
    let mut seen: Vec<&str> = Vec::new();
    for node in all_elements(&doc) {
        for attr in ID_ATTRIBUTES {
            if let Some(value) = doc.get_attribute(node, attr) {
                if seen.contains(&value) {
                    return Err(AuthError::Crypto(format!(
                        "duplicate ID {value:?} (possible XML signature wrapping)"
                    )));
                }
                seen.push(value);
            }
        }
    }
    Ok(())
}

/// Drop a leading `<?xml …?>` declaration (and the whitespace up to the first
/// element), returning the document body. Input without a declaration is
/// returned unchanged.
fn strip_xml_declaration(s: &str) -> &str {
    let trimmed = s.trim_start();
    if let Some(rest) = trimmed.strip_prefix("<?xml")
        && let Some(end) = rest.find("?>")
    {
        return rest[end + 2..].trim_start();
    }
    trimmed
}

/// Serialize a libxml2 document back to a `String`.
fn dump_doc(doc: &Doc) -> Result<String> {
    let mut out: *mut sys::xmlChar = ptr::null_mut();
    let mut len: i32 = 0;
    // SAFETY: out/len are written by libxml2; buffer is owned by libxml2 (freed below).
    unsafe { sys::xmlDocDumpMemory(doc.0, &mut out, &mut len) };
    if out.is_null() || len < 0 {
        return Err(AuthError::Crypto("failed to serialize signed XML".into()));
    }
    // SAFETY: out points to len bytes of libxml2-owned memory.
    let bytes = unsafe { std::slice::from_raw_parts(out as *const u8, len as usize) };
    let dumped = String::from_utf8_lossy(bytes).into_owned();
    // SAFETY: free the libxml2 buffer with libxml2's allocator.
    unsafe {
        if let Some(free) = sys::xmlFree {
            free(out as *mut c_void);
        }
    }
    // `xmlDocDumpMemory` prepends an `<?xml …?>` declaration; the pure-Rust
    // backend returns the signed fragment without one. Strip it so the result is
    // an embeddable fragment (a mid-document declaration is a parse error) and
    // the two backends produce interchangeable output.
    Ok(strip_xml_declaration(&dumped).to_string())
}

// ---------------------------------------------------------------------------
// Public backend surface (mirrors `bergshamra.rs`).
// ---------------------------------------------------------------------------

/// Sign `xml` in place with the RSA private key (`private_key_pem`); the inline
/// `ds:Signature` template's `DigestValue`/`SignatureValue` are filled.
pub fn sign(xml: &str, private_key_pem: &str) -> Result<String> {
    ensure_init()?;
    let doc = parse_and_register_ids(xml)?;
    let sig_node = find_signature(&doc)?;

    // Load the private key.
    // SAFETY: PEM bytes + length are consistent; no password.
    let key = unsafe {
        sys::xmlSecOpenSSLAppKeyLoadMemory(
            private_key_pem.as_ptr(),
            private_key_pem.len() as u32,
            sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if key.is_null() {
        return Err(AuthError::Crypto("failed to load signing key".into()));
    }

    // SAFETY: DSigCtxCreate(null) makes a context with no keys manager.
    let ctx = DsigCtx(unsafe { sys::xmlSecDSigCtxCreate(ptr::null_mut()) });
    if ctx.0.is_null() {
        return Err(AuthError::Crypto("xmlSecDSigCtxCreate failed".into()));
    }
    // The context adopts `signKey` and frees it on destroy.
    // SAFETY: ctx.0 is a valid, freshly created context.
    unsafe { (*ctx.0).signKey = key };

    // SAFETY: ctx and sig_node belong to the same live doc.
    let rc = unsafe { sys::xmlSecDSigCtxSign(ctx.0, sig_node) };
    if rc < 0 {
        return Err(AuthError::Crypto("XML signing failed".into()));
    }
    dump_doc(&doc)
}

/// Verify the signature anchored by `xml` against `cert_pem` (the sole trusted
/// key). `Err` is a load/backend error; a failed match is `Ok(Invalid)`.
pub fn verify_signature(xml: &str, cert_pem: &str) -> Result<SignatureVerification> {
    ensure_init()?;

    // XSW floor libxmlsec1 does not enforce: a duplicated signed ID must fail.
    if let Err(e) = reject_duplicate_ids(xml) {
        return Ok(SignatureVerification::Invalid(e.to_string()));
    }

    let doc = parse_and_register_ids(xml)?;
    let sig_node = find_signature(&doc)?;

    // Trusted-keys-only: pin the public key of `cert_pem` as the sole
    // verification key. Setting `signKey` makes xmlsec use exactly this key and
    // skip KeyInfo key discovery, so the signature's embedded X509Certificate
    // cannot introduce a different key, and no CA/chain is consulted. This
    // mirrors bergshamra pinning the leaf cert rather than building a chain.
    let key = unsafe {
        sys::xmlSecOpenSSLAppKeyLoadMemory(
            cert_pem.as_ptr(),
            cert_pem.len() as u32,
            sys::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem,
            ptr::null(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if key.is_null() {
        return Err(AuthError::Crypto("failed to load verification cert".into()));
    }

    // SAFETY: DSigCtxCreate(null) makes a context with no keys manager.
    let ctx = DsigCtx(unsafe { sys::xmlSecDSigCtxCreate(ptr::null_mut()) });
    if ctx.0.is_null() {
        return Err(AuthError::Crypto("xmlSecDSigCtxCreate failed".into()));
    }
    // The context adopts `signKey` and frees it on destroy.
    // SAFETY: ctx.0 is a valid, freshly created context.
    unsafe { (*ctx.0).signKey = key };

    // SAFETY: ctx and sig_node belong to the same live doc.
    let rc = unsafe { sys::xmlSecDSigCtxVerify(ctx.0, sig_node) };
    if rc < 0 {
        return Err(AuthError::Crypto("signature verification error".into()));
    }
    // SAFETY: reading the status field of a live, just-verified context.
    let status = unsafe { (*ctx.0).status };
    if status == sys::xmlSecDSigStatus_xmlSecDSigStatusSucceeded {
        Ok(SignatureVerification::Valid)
    } else {
        Ok(SignatureVerification::Invalid(
            "signature did not verify against the trusted certificate".into(),
        ))
    }
}

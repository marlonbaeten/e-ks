//! Fetch and validate real TVS (Toegang Verlening Service) metadata from DICTU.
//!
//! These tests hit external URLs and require network access.
//! Run with: cargo test --test tvs_metadata -- --ignored

use auth_service::saml::{
    constants::NS_MD,
    idp_metadata::{IdpKeys, extract_idp_keys},
    model::{EntityDescriptor, IdpSsoDescriptor, Signed},
    verification::{ExpectedRoot, verify_xml_signature},
    xml::Document,
};

/// The root of any SAML metadata document; the `@ID` is the RD's own and is not
/// asserted here.
fn entity_descriptor_root() -> ExpectedRoot<'static> {
    ExpectedRoot {
        namespace: NS_MD,
        local_name: "EntityDescriptor",
        id: None,
    }
}

const TVS_PP_METADATA_URL: &str = "https://pp2.toegang.overheid.nl/kvs/rd/metadata";
const TVS_PROD_METADATA_URL: &str = "https://rd2.toegang.overheid.nl/kvs/rd/metadata";

async fn fetch_metadata(url: &str) -> String {
    reqwest::get(url)
        .await
        .unwrap_or_else(|e| panic!("Failed to fetch {url}: {e}"))
        .text()
        .await
        .unwrap_or_else(|e| panic!("Failed to read response from {url}: {e}"))
}

fn validate_metadata(xml: &str, url: &str) {
    let doc = Document::parse(xml).unwrap_or_else(|e| panic!("{url}: XML parse error: {e}"));
    assert!(
        doc.root().is(NS_MD, "EntityDescriptor"),
        "{url}: root element is not md:EntityDescriptor"
    );
    let ed: EntityDescriptor = doc
        .deserialize()
        .unwrap_or_else(|e| panic!("{url}: not an EntityDescriptor: {e}"));

    let idp = validate_structure(&ed, url);
    let keys = validate_key_descriptors(idp, url);
    validate_signature(xml, &doc, url, &keys);
}

/// The document shape eID §8.4 requires of RD metadata: an `EntityDescriptor`
/// root with an `entityID`, an `IDPSSODescriptor`, and the SSO and artifact
/// resolution endpoints inside that role descriptor.
fn validate_structure<'e>(ed: &'e EntityDescriptor, url: &str) -> &'e IdpSsoDescriptor {
    assert!(ed.entity_id.is_some(), "{url}: missing entityID attribute");

    let idp = ed
        .idp_sso_descriptor
        .as_ref()
        .unwrap_or_else(|| panic!("{url}: missing IDPSSODescriptor"));
    assert!(
        !idp.single_sign_on_services.is_empty(),
        "{url}: missing SingleSignOnService"
    );
    assert!(
        !idp.artifact_resolution_services.is_empty(),
        "{url}: missing ArtifactResolutionService"
    );
    idp
}

/// The published key material: the expected counts per use, and an explicit
/// `use` attribute on every `KeyDescriptor` (a bare one, usable for both, would
/// be a TVS misconfiguration).
fn validate_key_descriptors(idp: &IdpSsoDescriptor, url: &str) -> IdpKeys {
    let keys = extract_idp_keys(idp);

    assert!(
        keys.signing.len() == 1 || keys.signing.len() == 2,
        "{url}: expected 1 or 2 signing keys, got {}",
        keys.signing.len()
    );
    // IdP metadata may have 0-2 encryption keys (typically 0: only SPs publish
    // encryption keys so the IdP can encrypt assertions for them).
    assert!(
        keys.encryption.len() <= 2,
        "{url}: expected at most 2 encryption keys, got {}",
        keys.encryption.len()
    );

    for kd in &idp.key_descriptors {
        let use_attr = kd.key_use.as_deref();
        assert!(
            use_attr == Some("signing") || use_attr == Some("encryption"),
            "{url}: KeyDescriptor has unexpected use attribute: {use_attr:?}"
        );
    }
    keys
}

/// The metadata signature: present, referencing one of the published signing
/// certs by `KeyName`, verifying against the signing keys, and **not** verifying
/// against an encryption-only key.
fn validate_signature(xml: &str, doc: &Document, url: &str, keys: &IdpKeys) {
    let signed: Signed = doc
        .deserialize()
        .unwrap_or_else(|e| panic!("{url}: malformed signature: {e}"));
    let sig = signed
        .signatures
        .first()
        .unwrap_or_else(|| panic!("{url}: metadata is not signed"));

    // TVS metadata signatures use KeyName: the thumbprint we derive from a
    // published cert must match the KeyName in the Signature's KeyInfo.
    if let Some(sig_key_name) = sig.key_info.as_ref().and_then(|k| k.key_names.first()) {
        let sig_key_name = sig_key_name.trim();
        assert!(
            keys.signing
                .iter()
                .any(|k| k.matches_key_name(sig_key_name)),
            "{url}: Signature KeyName '{sig_key_name}' not found in signing KeyDescriptors"
        );
    }

    let result = verify_xml_signature(xml, &keys.signing, &entity_descriptor_root());
    assert!(
        result.is_valid(),
        "{url}: signature verification with signing keys failed: {:?}",
        result.errors
    );

    // An encryption-only key must never verify the signature (eID §9.2).
    let signing_thumbprints: Vec<&str> = keys.signing.iter().map(|k| k.key_name.as_str()).collect();
    let encryption_only: Vec<_> = keys
        .encryption
        .iter()
        .filter(|k| !signing_thumbprints.contains(&k.key_name.as_str()))
        .cloned()
        .collect();
    if !encryption_only.is_empty() {
        let result = verify_xml_signature(xml, &encryption_only, &entity_descriptor_root());
        assert!(
            !result.is_valid(),
            "{url}: signature verification should fail with encryption-only keys"
        );
    }
}

#[tokio::test]
#[ignore] // requires network access; run with: cargo test --test tvs_metadata -- --ignored
async fn validate_preproduction_metadata() {
    let xml = fetch_metadata(TVS_PP_METADATA_URL).await;
    validate_metadata(&xml, TVS_PP_METADATA_URL);
}

#[tokio::test]
#[ignore] // requires network access; run with: cargo test --test tvs_metadata -- --ignored
async fn validate_production_metadata() {
    let xml = fetch_metadata(TVS_PROD_METADATA_URL).await;
    validate_metadata(&xml, TVS_PROD_METADATA_URL);
}

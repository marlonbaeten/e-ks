//! The validators, run against `ArtifactResponse` messages the real TVS
//! *Routeringsdienst* emitted.
//!
//! Every other suite in `tests/` feeds the validators XML this repository
//! composed. That proves the rules are implemented, but not that they are
//! implemented against the wire format the RD actually produces: real messages
//! differ in namespace prefixes, attribute order, element indentation, and the
//! whitespace inside element text. This suite closes that gap with samples
//! captured from TVS (see `fixtures/tvs/README.md` for provenance and licence).
//!
//! # What these samples cannot exercise
//!
//! - **Signatures.** Each sample's `KeyInfo` names its key by fingerprint only,
//!   and eID §9.2 forbids trusting a key that did not come from verified
//!   metadata — of which we hold none for the environment they were captured
//!   from. The suite therefore drives the Response (§7.6.2) and Assertion
//!   (§7.6.3) validators directly; the signature layer keeps its own tests in
//!   `xsw_*.rs`.
//! - **The decrypted identity.** The `EncryptedID` payloads are wrapped to a DV
//!   key we do not hold, so `Claims::acting_subject_id` is always `None` here.
//!
//! # Timestamps
//!
//! The samples are from 2021-2023 and their `Conditions` windows are two minutes
//! wide, so [`shift_timestamps`] rewrites every instant into the current window,
//! preserving the offsets between them. Nothing else about the bytes changes.
//! [`success_sample_unshifted_fails_only_the_time_checks`] pins that: on the
//! pristine bytes, the *only* errors are time-dependent ones.

use auth_service::{
    bindings::soap::unwrap_soap,
    saml::{
        constants::{NS_SAMLP, STATUS_SUCCESS},
        loa::MINIMUM_LOA,
        validation::{
            Claims, ValidateArtifactResponseOpts, ValidateAssertionOpts, ValidateResponseOpts,
            validate_artifact_response_at, validate_assertion_at, validate_response_at,
        },
        xml_parser::{Document, NodeId, find_child, parse},
    },
    types::{EndpointUrl, EntityId, MessageId, ServiceUuid},
};
use chrono::{DateTime, Utc};

// ---------------------------------------------------------------------------
// Fixture values. Each is the literal value in the captured message, so a test
// configures the DV the RD actually addressed rather than a stand-in.
// ---------------------------------------------------------------------------

const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";

/// `artifact_response_success.xml`: the LoA-substantial happy path.
mod success {
    pub const FILE: &str = "artifact_response_success.xml";
    pub const ACS: &str = "https://poc-1.uzi.bavod.nl/acs";
    pub const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000002006756402002:entities:9999";
    pub const SERVICE_UUID: &str = "464f504d-5857-5946-304f-494449414a4d";
    pub const LOA: &str = "http://eidas.europa.eu/LoA/substantial";
    pub const AD: &str = "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:9002";
    /// The Subject NameID of the *outer* assertion: a bare hex string carrying
    /// no `@Format` at all.
    pub const NAME_ID: &str = "64b0d194095940008ffa142b12444c01";
    pub const IN_RESPONSE_TO: &str =
        "_837f3790c95cd6ca4cb815edd30f583d0fe6313a2ab0b53ccc65f972b571fabcf70924f49e4d8deb0e";

    /// Values that exist only inside the `<saml:Advice>` AD assertion. Claim
    /// extraction must never surface one of these.
    pub mod advice {
        pub const NAME_ID: &str = "2cbd6231-4257-44ae-aa87-b4bfc25e232f";
        pub const IN_RESPONSE_TO: &str = "_a7efd80d17a4f064dde50b9cd78aca7b";
        pub const RECIPIENT: &str = "https://pp2.toegang.overheid.nl/foam/saml/acs";
    }
}

/// `artifact_response_cluster.xml`: the §6.3 cluster-connection variant.
mod cluster {
    pub const FILE: &str = "artifact_response_cluster.xml";
    pub const ACS: &str = "https://endpoint.example/acs";
    pub const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000002003182447001:entities:9888";
    pub const SERVICE_UUID: &str = "c57ec6e6-baba-472d-9db4-5ef8cf5e29c8";
    pub const LOA: &str = "http://eidas.europa.eu/LoA/high";
    pub const NAME_ID: &str = "3efa072a56034ebe939516e30a979a00";
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

fn load(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tvs")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Every timestamp in `xml`, moved into the current validity window.
///
/// The first instant encountered becomes "now" and every other one keeps its
/// offset from it, so the two-minute `Conditions` and `SubjectConfirmationData`
/// windows the RD issued still bracket the present. Only attribute values that
/// parse as a timestamp are touched; the rest of the document, including the
/// signatures (which we do not verify), is byte-identical.
fn shift_timestamps(xml: &str) -> String {
    let now = Utc::now();
    let mut anchor: Option<DateTime<Utc>> = None;
    let mut out = String::with_capacity(xml.len());

    for (i, part) in xml.split('"').enumerate() {
        if i > 0 {
            out.push('"');
        }
        match part.parse::<DateTime<Utc>>() {
            Ok(instant) => {
                let base = *anchor.get_or_insert(instant);
                let shifted = now + (instant - base);
                // Keep the sub-second precision the RD used: the outer messages
                // are whole seconds, the AD assertion in <Advice> is not.
                let format = if part.contains('.') {
                    "%Y-%m-%dT%H:%M:%S%.3fZ"
                } else {
                    "%Y-%m-%dT%H:%M:%SZ"
                };
                out.push_str(&shifted.format(format).to_string());
            }
            Err(_) => out.push_str(part),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Running the validators
// ---------------------------------------------------------------------------

/// The `samlp:ArtifactResponse` inside the sample's SOAP envelope.
fn artifact_response(doc: &Document) -> NodeId {
    unwrap_soap(doc, doc.document_element()).expect("sample has a SOAP Body with one child")
}

/// The `samlp:Response` inside an ArtifactResponse, reached without going
/// through [`validate_artifact_response_at`] (which would first fail on the
/// signature we cannot verify).
fn inner_response(doc: &Document, art: NodeId) -> NodeId {
    find_child(doc, art, NS_SAMLP, "Response").expect("sample carries an inner Response")
}

/// Run the Response (§7.6.2) and Assertion (§7.6.3) validators over a sample,
/// configured for the DV that message was actually addressed to.
fn validate_sample(
    doc: &Document,
    acs: &str,
    dv: &str,
    service_uuid: &str,
) -> (Option<Claims>, Vec<String>) {
    let mut errors = Vec::new();

    let acs = EndpointUrl::from_metadata(acs, "ACS").expect("fixture ACS URL");
    let dv = EntityId::parse(dv).expect("fixture DV EntityID");
    let rd = EntityId::parse(RD).expect("fixture RD EntityID");
    let service_uuid = ServiceUuid::parse(service_uuid).expect("fixture ServiceUUID");

    let art = artifact_response(doc);
    let response = inner_response(doc, art);

    let assertion = validate_response_at(
        doc,
        response,
        &ValidateResponseOpts {
            expected_destination: Some(&acs),
            expected_issuer: Some(&rd),
        },
        &mut errors,
    );

    let claims = assertion.and_then(|a| {
        validate_assertion_at(
            doc,
            a,
            &ValidateAssertionOpts {
                dv_entity_id: &dv,
                expected_recipient: Some(&acs),
                expected_issuer: Some(&rd),
                // The EncryptedID is wrapped to a DV key we do not hold.
                private_keys: &[],
                minimum_loa: Some(MINIMUM_LOA),
                expected_service_uuid: Some(&service_uuid),
            },
            &mut errors,
        )
    });

    (claims, errors)
}

/// [`validate_sample`] on a sample whose timestamps have been moved into the
/// current window, asserting the validators recorded nothing at all.
fn validate_shifted(name: &str, acs: &str, dv: &str, service_uuid: &str) -> Claims {
    let xml = shift_timestamps(&load(name));
    let doc = parse(&xml).expect("real TVS ArtifactResponse parses");
    let (claims, errors) = validate_sample(&doc, acs, dv, service_uuid);
    assert!(
        errors.is_empty(),
        "{name}: a real TVS message was rejected: {errors:#?}"
    );
    claims.expect("a run with no errors yields claims")
}

// ---------------------------------------------------------------------------
// The successful 4.4 authentication
// ---------------------------------------------------------------------------

#[test]
fn success_sample_validates_and_yields_the_expected_claims() {
    let claims = validate_shifted(
        success::FILE,
        success::ACS,
        success::DV,
        success::SERVICE_UUID,
    );

    assert_eq!(claims.name_id.as_str(), success::NAME_ID);
    assert_eq!(claims.service_uuid.as_deref(), Some(success::SERVICE_UUID));
    assert_eq!(
        claims.in_response_to.as_ref().map(MessageId::as_str),
        Some(success::IN_RESPONSE_TO)
    );
    // No DV decryption key, so the encrypted identity cannot be recovered here.
    assert!(claims.acting_subject_id.is_none());
    assert!(claims.legal_subject_id.is_none());
}

#[test]
fn success_sample_claims_come_from_the_outer_assertion_not_from_advice() {
    // The `<saml:Advice>` subtree holds a complete, separately signed AD
    // assertion with its own Subject, Recipient, InResponseTo, ServiceUUID and
    // ActingSubjectID. eID §9.1 makes it evidence only, so every claim must be
    // read from the outer assertion. The values differ between the two, which is
    // what makes the pruning observable rather than merely asserted.
    let xml = load(success::FILE);
    for value in [
        success::advice::NAME_ID,
        success::advice::IN_RESPONSE_TO,
        success::advice::RECIPIENT,
    ] {
        assert!(
            xml.contains(value),
            "fixture no longer carries the Advice assertion this test relies on ({value})"
        );
    }

    let claims = validate_shifted(
        success::FILE,
        success::ACS,
        success::DV,
        success::SERVICE_UUID,
    );

    assert_ne!(claims.name_id.as_str(), success::advice::NAME_ID);
    assert_ne!(
        claims.in_response_to.as_ref().map(MessageId::as_str),
        Some(success::advice::IN_RESPONSE_TO)
    );
    // The Recipient check passed against the outer ACS, not the AD's own — a
    // mismatch would already have failed `validate_shifted`.
}

#[test]
fn success_sample_matches_the_loa_despite_whitespace_around_the_uri() {
    // The RD pretty-prints, so `AuthnContextClassRef` text is the URI followed
    // by a newline and the closing tag's indentation. The §10.3 lookup is an
    // exact match, so without normalising that away a conformant authentication
    // is rejected as an unrecognised LoA. Same for `AuthenticatingAuthority`.
    let raw = load(success::FILE);
    assert!(
        raw.contains(&format!("{}\n", success::LOA)),
        "fixture no longer carries the trailing whitespace this test relies on"
    );

    let claims = validate_shifted(
        success::FILE,
        success::ACS,
        success::DV,
        success::SERVICE_UUID,
    );

    assert_eq!(
        claims.authn_context_class_ref.as_deref(),
        Some(success::LOA)
    );
    assert_eq!(
        claims.authenticating_authority.as_deref(),
        Some(success::AD)
    );
}

#[test]
fn success_sample_unshifted_fails_only_the_time_checks() {
    // Guards [`shift_timestamps`]: on the pristine 2022 bytes every
    // time-bounded check must fail and nothing else may, so the shift cannot be
    // hiding a structural failure in the tests above.
    const TIME_ERROR_MARKERS: &[&str] = &[
        "is stale",
        "is in the future",
        "expired",
        "not yet valid",
        "outside the usable range",
    ];

    let xml = load(success::FILE);
    let doc = parse(&xml).expect("real TVS ArtifactResponse parses");
    let (_, errors) = validate_sample(&doc, success::ACS, success::DV, success::SERVICE_UUID);

    let structural: Vec<&String> = errors
        .iter()
        .filter(|e| !TIME_ERROR_MARKERS.iter().any(|m| e.contains(m)))
        .collect();
    assert!(
        structural.is_empty(),
        "expected only time-dependent errors on the unshifted sample, got: {structural:#?}"
    );
    assert!(
        !errors.is_empty(),
        "the unshifted sample is years old and must fail its time checks"
    );
}

// ---------------------------------------------------------------------------
// The cluster-connection variant (§6.3)
// ---------------------------------------------------------------------------

#[test]
fn cluster_sample_validates_with_two_audiences() {
    // A cluster message names both the LC and the DV in one
    // `AudienceRestriction`; §7.6.3.5 rule 5 only requires ours to be among
    // them. The LC entry comes first and is the one carrying leading whitespace
    // from the pretty-printing.
    let claims = validate_shifted(
        cluster::FILE,
        cluster::ACS,
        cluster::DV,
        cluster::SERVICE_UUID,
    );

    assert_eq!(claims.name_id.as_str(), cluster::NAME_ID);
    assert_eq!(
        claims.authn_context_class_ref.as_deref(),
        Some(cluster::LOA)
    );
}

// ---------------------------------------------------------------------------
// The §7.8 error paths
// ---------------------------------------------------------------------------

#[test]
fn login_cancelled_sample_is_rejected_by_the_response_status_check() {
    // The artifact layer reports Success; the failure is the inner Response's
    // nested `Responder` / `AuthnFailed`. `handle_acs` maps exactly this to
    // `AuthFailure::Cancelled`, so the status check has to see both levels and
    // the StatusMessage.
    let xml = load("artifact_response_login_cancelled.xml");
    let doc = parse(&xml).expect("real TVS login-cancelled message parses");
    let art = artifact_response(&doc);
    let response = inner_response(&doc, art);

    let mut errors = Vec::new();
    let assertion = validate_response_at(
        &doc,
        response,
        &ValidateResponseOpts {
            expected_destination: None,
            expected_issuer: None,
        },
        &mut errors,
    );

    assert!(
        assertion.is_none(),
        "a cancelled login carries no Assertion"
    );
    let status_error = errors
        .iter()
        .find(|e| e.starts_with("Response status:"))
        .unwrap_or_else(|| panic!("no Response status error recorded: {errors:#?}"));
    assert!(
        status_error.contains("status:Responder")
            && status_error.contains("status:AuthnFailed")
            && status_error.contains("Authentication cancelled"),
        "the status error must carry both StatusCode levels and the StatusMessage, \
         got: {status_error}"
    );
}

#[test]
fn request_denied_sample_is_rejected_at_the_artifact_layer() {
    // `Requester` / `RequestDenied` is reported on the ArtifactResponse itself,
    // and the message carries no inner Response at all (§7.6.1).
    let xml = load("artifact_response_request_denied.xml");
    let doc = parse(&xml).expect("real TVS request-denied message parses");
    let art = artifact_response(&doc);

    assert!(
        find_child(&doc, art, NS_SAMLP, "Response").is_none(),
        "a denied request carries no inner Response"
    );

    let mut errors = Vec::new();
    let response = validate_artifact_response_at(
        &doc,
        art,
        &ValidateArtifactResponseOpts {
            // eID §9.2 keys come from verified metadata and we hold none for this
            // environment, so the signature check fails too. This test is about
            // the status check running and reporting both levels.
            trusted_keys: &[],
            expected_in_response_to: None,
            expected_issuer: None,
        },
        &mut errors,
    );

    assert!(response.is_none());
    assert!(
        errors.iter().any(|e| {
            e.starts_with("ArtifactResponse status:")
                && e.contains("status:Requester")
                && e.contains("status:RequestDenied")
        }),
        "expected an ArtifactResponse status error naming both levels: {errors:#?}"
    );
}

// ---------------------------------------------------------------------------
// The pre-4.4 shape
// ---------------------------------------------------------------------------

#[test]
fn pre_44_digid_sample_is_rejected_for_carrying_no_eid_identity() {
    // The older direct-DigiD koppelvlak put a sector-coded plaintext BSN in the
    // Subject NameID (`s00000000:<bsn>`) and carried no eID attributes at all.
    // This crate only speaks 4.4, where the identity arrives as an encrypted
    // ActingSubjectID and the assertion must name our ServiceUUID. Accepting one
    // of these would mean taking an identity from a profile we do not validate,
    // so the checks that make 4.4 mandatory have to fire — nothing about the
    // message's *status* betrays it, since it is a successful login.
    let xml = load("artifact_response_digid_pre44.xml");
    assert!(xml.contains(STATUS_SUCCESS));
    assert!(xml.contains("s00000000:900029365"));

    let xml = shift_timestamps(&xml);
    let doc = parse(&xml).expect("pre-4.4 DigiD message parses");
    let art = artifact_response(&doc);
    let response = inner_response(&doc, art);

    let idp = EntityId::parse("https://was-preprod1.digid.nl/saml/idp/metadata").expect("issuer");
    let dv = EntityId::parse("https://siam1.test.anoigo.nl/aselectserver/server").expect("DV");
    let acs = EndpointUrl::from_metadata(
        "https://siam1.test.anoigo.nl/aselectserver/server/saml20_assertion_digid",
        "ACS",
    )
    .expect("fixture ACS URL");
    let service_uuid = ServiceUuid::parse(success::SERVICE_UUID).expect("ServiceUUID");

    let mut errors = Vec::new();
    let assertion = validate_response_at(
        &doc,
        response,
        &ValidateResponseOpts {
            expected_destination: None,
            expected_issuer: Some(&idp),
        },
        &mut errors,
    )
    .expect("the pre-4.4 message still has an Assertion element");

    let claims = validate_assertion_at(
        &doc,
        assertion,
        &ValidateAssertionOpts {
            dv_entity_id: &dv,
            expected_recipient: Some(&acs),
            expected_issuer: Some(&idp),
            private_keys: &[],
            minimum_loa: Some(MINIMUM_LOA),
            expected_service_uuid: Some(&service_uuid),
        },
        &mut errors,
    );

    assert!(
        claims.is_none(),
        "a pre-4.4 assertion must not yield claims"
    );
    assert!(
        errors.iter().any(|e| e.contains("ServiceUUID")),
        "a pre-4.4 message carries no ServiceUUID and must be rejected for it: {errors:#?}"
    );
}

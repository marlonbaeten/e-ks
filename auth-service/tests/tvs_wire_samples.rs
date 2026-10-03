//! gamlastan's eID processing, run against real TVS `ArtifactResponse`
//! messages (see `fixtures/tvs/README.md`) rather than XML this repository
//! composed, so the RD's actual namespace prefixes, attribute order, element
//! whitespace, `Advice` evidence and `EncryptedKey` layout are covered.
//!
//! Two layers are exercised:
//!
//! - the full back-channel path, `process_artifact_response`, which on these
//!   samples must get through SOAP unwrapping, parsing and the §9 algorithm
//!   allow-list (including the SHA-1 OAEP digest the RD uses for key transport)
//!   and fail only at trust: the samples name RD keys by fingerprint, and eID
//!   §9.2 allows only keys from verified metadata, of which we hold none for
//!   their environment;
//! - the typed `validate_response` rules (§7.6.2, §7.6.3) on the inner
//!   `Response`, read from the sample as the DV would have it once the
//!   signatures verified, so the status handling, the LoA table, the two-audience
//!   cluster shape and the pre-4.4 rejection run on the real wire format.
//!
//! Not exercised: the decrypted identity (`EncryptedID` is wrapped to a DV key
//! we do not hold).

use auth_service::config::MINIMUM_LOA;
use chrono::{DateTime, Utc};
use gamlastan::{
    bindings::soap::soap_envelope_unwrap,
    core::protocol::{ArtifactResponseRef, Response, ResponseRef},
    profiles::nl_eid::{
        ArtifactResponseParams, DvDecryptionKeys, LevelOfAssurance, NlEidConfig, NlEidError,
        RdMetadata, ResponseVerdict, check_artifact_response,
        constants::{
            NS_SAML_PROTOCOL, STATUS_AUTHN_FAILED, STATUS_REQUEST_DENIED, STATUS_REQUESTER,
            STATUS_RESPONDER,
        },
        process_artifact_response, validate_response,
    },
    security::replay::InMemoryReplayCache,
    xml::{SamlDeserialize, deserialize::parse_saml, parse_secure},
};

// Literal values from the captured messages, so each test configures the DV the
// RD actually addressed.

const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";

mod success {
    pub const FILE: &str = "artifact_response_success.xml";
    pub const ACS: &str = "https://poc-1.uzi.bavod.nl/acs";
    pub const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000002006756402002:entities:9999";
    pub const SERVICE_UUID: &str = "464f504d-5857-5946-304f-494449414a4d";
    pub const AD: &str = "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:9002";
    /// Outer Subject NameID: a bare hex string with no `@Format`.
    pub const NAME_ID: &str = "64b0d194095940008ffa142b12444c01";
    pub const IN_RESPONSE_TO: &str =
        "_837f3790c95cd6ca4cb815edd30f583d0fe6313a2ab0b53ccc65f972b571fabcf70924f49e4d8deb0e";
    pub const ASSERTION_ID: &str = "_3afef2d16b05473e954786992f82fcf8";
    /// The `KeyName` the RD signs with in this environment.
    pub const RD_KEY_NAME: &str = "458d39f98d53307ec0987f2d8db1e0fad7d77aa2";

    /// Values only inside the `<saml:Advice>` AD assertion; the outcome must
    /// never surface one.
    pub mod advice {
        pub const NAME_ID: &str = "2cbd6231-4257-44ae-aa87-b4bfc25e232f";
        pub const ASSERTION_ID: &str = "_ede93752cb4b366c96c90780fa126fdb";
    }
}

mod denied {
    pub const FILE: &str = "artifact_response_request_denied.xml";
    /// The anonymised sample carries a placeholder issuer, not an RD EntityID.
    pub const ISSUER: &str = "https://issuer-endpoint.example/saml/idp/metadata";
}

mod cluster {
    pub const FILE: &str = "artifact_response_cluster.xml";
    pub const ACS: &str = "https://endpoint.example/acs";
    pub const DV: &str = "urn:nl-eid-gdi:1.0:DV:00000002003182447001:entities:9888";
    pub const SERVICE_UUID: &str = "c57ec6e6-baba-472d-9db4-5ef8cf5e29c8";
    pub const NAME_ID: &str = "3efa072a56034ebe939516e30a979a00";
    pub const IN_RESPONSE_TO: &str =
        "_500a8ad60d5c241e2753ee56e5ae871b01bea7a72aebbfdb564b9982423375330762b76ad4f29c6c03";
}

fn load(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tvs")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The `samlp:ArtifactResponse` of a sample, out of its SOAP envelope, as the
/// DV has it once the back-channel answered.
fn artifact_response_xml(name: &str) -> String {
    soap_envelope_unwrap(load(name).as_bytes())
        .expect("real TVS message is a SOAP envelope")
        .body_xml
}

/// A DV configured as the sample's addressee.
fn cfg(acs: &str, dv: &str, service_uuid: &str) -> NlEidConfig {
    cfg_for_rd(acs, dv, service_uuid, RD)
}

/// As [`cfg`], expecting `rd` as the issuer.
fn cfg_for_rd(acs: &str, dv: &str, service_uuid: &str, rd: &str) -> NlEidConfig {
    NlEidConfig::service_provider(dv, service_uuid, acs, rd, MINIMUM_LOA)
}

/// RD metadata trusting one of this repository's own test certificates under
/// a `KeyName` the samples never use, so the samples' signatures are refused
/// as *unknown keys* rather than as cryptographic failures.
fn rd_metadata_without_the_samples_keys() -> RdMetadata {
    let cert_pem = include_str!("../fixtures/rd-signing-1.pem");
    let published = gamlastan::profiles::nl_eid::PublishedCertificate::from_pem(cert_pem)
        .expect("fixture certificate");
    let key_info = published.key_info_xml();
    let xml = format!(
        r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{RD}" cacheDuration="PT24H"><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing">{key_info}</md:KeyDescriptor><md:ArtifactResolutionService Binding="urn:oasis:names:tc:SAML:2.0:bindings:SOAP" Location="https://rd.test/ars" index="0"/><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://rd.test/sso"/><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://rd.test/slo"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
    );
    gamlastan::profiles::nl_eid::parse_rd_metadata(&xml).expect("test RD metadata")
}

fn params<'a>(
    cache: &'a InMemoryReplayCache,
    in_response_to: &'a str,
    now: DateTime<Utc>,
) -> ArtifactResponseParams<'a> {
    ArtifactResponseParams {
        expected_artifact_resolve_id: "_resolve",
        expected_authn_request_id: in_response_to,
        replay_cache: cache,
        relay_state: None,
        now,
    }
}

/// The full back-channel path on a sample: the first thing that can fail on a
/// real TVS message from an environment whose keys we do not hold is the key
/// lookup, so everything before it (SOAP, parsing, §9 algorithms) passed.
fn process_sample(name: &str, acs: &str, dv: &str, service_uuid: &str) -> NlEidError {
    let cache = InMemoryReplayCache::new();
    let rd = rd_metadata_without_the_samples_keys();
    let keys = DvDecryptionKeys::new();
    process_artifact_response(
        &cfg(acs, dv, service_uuid),
        &load(name),
        &rd.verifier().expect("verifier"),
        &keys,
        &params(&cache, "_any", Utc::now()),
    )
    .expect_err("a sample signed by a key outside our metadata must not authenticate")
}

#[test]
fn every_sample_parses_and_passes_the_algorithm_allow_list_up_to_the_key_lookup() {
    for (name, acs, dv, service_uuid) in [
        (
            success::FILE,
            success::ACS,
            success::DV,
            success::SERVICE_UUID,
        ),
        (
            cluster::FILE,
            cluster::ACS,
            cluster::DV,
            cluster::SERVICE_UUID,
        ),
        (
            "artifact_response_login_cancelled.xml",
            success::ACS,
            success::DV,
            success::SERVICE_UUID,
        ),
        (
            denied::FILE,
            success::ACS,
            success::DV,
            success::SERVICE_UUID,
        ),
        (
            "artifact_response_digid_pre44.xml",
            success::ACS,
            success::DV,
            success::SERVICE_UUID,
        ),
    ] {
        let err = process_sample(name, acs, dv, service_uuid);
        assert!(
            matches!(err, NlEidError::UnknownSigningKey(_)),
            "{name}: expected the RD key to be the first failure, got {err}"
        );
    }
}

#[test]
fn the_success_sample_names_the_rd_key_by_fingerprint() {
    let err = process_sample(
        success::FILE,
        success::ACS,
        success::DV,
        success::SERVICE_UUID,
    );
    match err {
        NlEidError::UnknownSigningKey(detail) => assert!(
            detail.contains(success::RD_KEY_NAME),
            "the unknown key is named by its fingerprint: {detail}"
        ),
        other => panic!("{other}"),
    }
}

/// The inner `Response` of a sample, typed, with the IDs its signatures cover
/// (the RD signs the ArtifactResponse and the Assertion, so after a successful
/// verification the assertion's ID is among the verified references).
fn inner_response(name: &str) -> (Response, Vec<String>) {
    let xml = artifact_response_xml(name);
    let doc = parse_secure(&xml).expect("real TVS message parses");
    let root = doc.document_element().expect("root");
    let body = doc
        .descendants(root)
        .into_iter()
        .find(|n| {
            doc.element(*n)
                .is_some_and(|e| e.matches_name_ns(NS_SAML_PROTOCOL, "Response"))
        })
        .expect("sample carries an inner Response");
    let response = ResponseRef::from_xml(&doc, body)
        .expect("the Response deserializes")
        .to_owned();
    let signed_ids = response.assertions.iter().map(|a| a.id.clone()).collect();
    (response, signed_ids)
}

/// Run the §7.6.2 / §7.6.3 rules over a sample's inner Response at the time
/// the RD issued it.
fn validate_sample(
    name: &str,
    acs: &str,
    dv: &str,
    service_uuid: &str,
    in_response_to: &str,
) -> Result<ResponseVerdict, NlEidError> {
    let (response, signed_ids) = inner_response(name);
    let cache = InMemoryReplayCache::new();
    let ids: Vec<&str> = signed_ids.iter().map(String::as_str).collect();
    validate_response(
        &cfg(acs, dv, service_uuid),
        &response,
        &ids,
        None,
        &params(&cache, in_response_to, response.base.issue_instant),
    )
}

#[test]
fn success_sample_validates_and_yields_the_outer_assertions_facts() {
    let verdict = validate_sample(
        success::FILE,
        success::ACS,
        success::DV,
        success::SERVICE_UUID,
        success::IN_RESPONSE_TO,
    )
    .expect("a real TVS success message validates");
    let ResponseVerdict::Valid(validated) = verdict else {
        panic!("expected a valid verdict, got {verdict:?}");
    };

    // The facts come from the outer assertion, not from the `<saml:Advice>`
    // evidence (eID §9.1), whose Subject and InResponseTo differ.
    assert_eq!(validated.transient_name_id, success::NAME_ID);
    assert_ne!(validated.transient_name_id, success::advice::NAME_ID);
    assert_eq!(validated.authn.assertion_id, success::ASSERTION_ID);
    assert_ne!(validated.authn.assertion_id, success::advice::ASSERTION_ID);
    assert_eq!(validated.authn.idp_entity_id, RD);
    // The RD pretty-prints, so the LoA URI carries surrounding whitespace on
    // the wire; the §10.3 lookup still resolves it.
    assert_eq!(validated.level_of_assurance, LevelOfAssurance::Substantial);
    assert_eq!(
        validated.authenticating_authorities,
        vec![success::AD.to_string()]
    );
}

#[test]
fn success_sample_is_rejected_when_it_answers_another_request() {
    let err = validate_sample(
        success::FILE,
        success::ACS,
        success::DV,
        success::SERVICE_UUID,
        "_someone-elses-request",
    )
    .expect_err("a Response for another AuthnRequest must not validate");
    assert!(
        matches!(
            err,
            NlEidError::InResponseToMismatch {
                element: "Response",
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn success_sample_is_rejected_for_another_dv() {
    // The same message read by a DV it was not minted for: audience and
    // Destination no longer match.
    let err = validate_sample(
        success::FILE,
        cluster::ACS,
        cluster::DV,
        cluster::SERVICE_UUID,
        success::IN_RESPONSE_TO,
    )
    .expect_err("an assertion for another DV must not validate");
    assert!(
        matches!(err, NlEidError::DestinationMismatch { .. }),
        "{err}"
    );
}

#[test]
fn success_sample_at_the_present_time_fails_only_the_time_checks() {
    // Guards the use of the issue instant as "now" above: on the 2022 message
    // at today's clock the only failure is staleness, so the fixed clock
    // cannot be hiding a structural failure.
    let (response, signed_ids) = inner_response(success::FILE);
    let cache = InMemoryReplayCache::new();
    let ids: Vec<&str> = signed_ids.iter().map(String::as_str).collect();
    let err = validate_response(
        &cfg(success::ACS, success::DV, success::SERVICE_UUID),
        &response,
        &ids,
        None,
        &params(&cache, success::IN_RESPONSE_TO, Utc::now()),
    )
    .expect_err("the sample is years old and must fail its time checks");
    assert!(matches!(err, NlEidError::StaleMessage { .. }), "{err}");
}

#[test]
fn cluster_sample_validates_with_two_audiences_at_loa_high() {
    // A cluster message names the LC and the DV in one `AudienceRestriction`;
    // §7.6.3.5 rule 5 only requires ours to be among them. The LC entry comes
    // first and carries the pretty-printing's leading whitespace.
    let verdict = validate_sample(
        cluster::FILE,
        cluster::ACS,
        cluster::DV,
        cluster::SERVICE_UUID,
        cluster::IN_RESPONSE_TO,
    )
    .expect("a real TVS cluster message validates");
    let ResponseVerdict::Valid(validated) = verdict else {
        panic!("expected a valid verdict, got {verdict:?}");
    };
    assert_eq!(validated.transient_name_id, cluster::NAME_ID);
    assert_eq!(validated.level_of_assurance, LevelOfAssurance::High);
}

#[test]
fn login_cancelled_sample_is_a_cancelled_outcome() {
    // The artifact layer reports Success; the inner Response carries the
    // nested `Responder` / `AuthnFailed` with "Authentication cancelled",
    // which the ACS handler maps to `AuthFailure::Cancelled` (TVS T3).
    // The sample was captured for the cluster DV's endpoint.
    let (response, _) = inner_response("artifact_response_login_cancelled.xml");
    let in_response_to = response
        .base
        .in_response_to
        .clone()
        .expect("the cancelled Response names its request");
    let cache = InMemoryReplayCache::new();
    let verdict = validate_response(
        &cfg(cluster::ACS, cluster::DV, cluster::SERVICE_UUID),
        &response,
        &[],
        None,
        &params(&cache, &in_response_to, response.base.issue_instant),
    );
    match verdict {
        Ok(ResponseVerdict::Cancelled { status }) => {
            assert_eq!(status.status_code.value, STATUS_RESPONDER);
            assert_eq!(
                status
                    .status_code
                    .sub_status
                    .as_ref()
                    .map(|s| s.value.as_str()),
                Some(STATUS_AUTHN_FAILED)
            );
            assert!(
                status
                    .status_message
                    .as_deref()
                    .is_some_and(|m| m.contains("Authentication cancelled")),
                "{status:?}"
            );
        }
        other => panic!("expected a cancelled verdict, got {other:?}"),
    }
}

#[test]
fn request_denied_sample_fails_at_the_artifact_layer() {
    // §7.6.1: the status is on the ArtifactResponse and there is no inner
    // Response at all.
    // The sample's issuer is anonymised, so the DV here expects that
    // placeholder as its RD.
    let xml = artifact_response_xml(denied::FILE);
    let doc = parse_secure(&xml).expect("real TVS request-denied message parses");
    let art = parse_saml::<ArtifactResponseRef<'_>>(&doc)
        .expect("an ArtifactResponse")
        .to_owned();
    let in_response_to = art
        .in_response_to
        .clone()
        .expect("the ArtifactResponse names its ArtifactResolve");
    let cache = InMemoryReplayCache::new();
    let params = ArtifactResponseParams {
        expected_artifact_resolve_id: &in_response_to,
        expected_authn_request_id: "_any",
        replay_cache: &cache,
        relay_state: None,
        now: art.issue_instant,
    };
    let err = check_artifact_response(
        &cfg_for_rd(
            success::ACS,
            success::DV,
            success::SERVICE_UUID,
            denied::ISSUER,
        ),
        &art,
        &params,
    )
    .expect_err("a denied artifact resolution is an error");
    match err {
        NlEidError::ArtifactResolutionFailed(status) => {
            assert_eq!(status.status_code.value, STATUS_REQUESTER);
            assert_eq!(
                status
                    .status_code
                    .sub_status
                    .as_ref()
                    .map(|s| s.value.as_str()),
                Some(STATUS_REQUEST_DENIED)
            );
        }
        other => panic!("expected ArtifactResolutionFailed, got {other}"),
    }
}

#[test]
fn pre44_digid_sample_is_rejected() {
    // A pre-4.4 DigiD message: sector-coded plaintext NameID, no eID
    // attributes. Whatever rule trips first, it must not validate.
    let (response, signed_ids) = inner_response("artifact_response_digid_pre44.xml");
    let in_response_to = response
        .base
        .in_response_to
        .clone()
        .expect("the Response names its request");
    let cache = InMemoryReplayCache::new();
    let ids: Vec<&str> = signed_ids.iter().map(String::as_str).collect();
    let err = validate_response(
        &cfg(success::ACS, success::DV, success::SERVICE_UUID),
        &response,
        &ids,
        None,
        &params(&cache, &in_response_to, response.base.issue_instant),
    )
    .expect_err("a pre-4.4 message must be rejected");
    assert!(
        !matches!(err, NlEidError::StaleMessage { .. }),
        "the rejection must be structural, not the clock: {err}"
    );
}

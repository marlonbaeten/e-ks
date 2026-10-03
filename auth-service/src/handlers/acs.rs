//! ACS: resolve the SAML artifact into a validated authentication and hand off
//! to the embedding application.
//!
//! The SAML work (the signed `ArtifactResolve`, the SOAP envelope, and the
//! verification of the RD-signed `ArtifactResponse` → `Response` → `Assertion`
//! chain down to the decrypted `SubjectID`) is gamlastan's
//! [`process_artifact_response`]. This handler adds what is the deployment's:
//! the flow cookie that binds the callback to the browser that started the
//! flow, the mTLS back-channel, the consume-once pending-request store, and
//! the mapping of every outcome to the embedding application's pages.
//!
//! Every failure maps to a small `AuthFailure`, and the embedding application
//! renders the user-facing page (TVS T3/L10) directly on the ACS response. The
//! technical detail is logged at the failure site. The response is marked
//! `no-store` and `no-referrer`, so the one-time `SAMLart` in the ACS query is
//! neither cached nor leaked via `Referer`. What remains in the address bar is
//! useless on its own: an artifact is consumed at the RD the first time it is
//! resolved, and one that never was can only be accepted together with the flow
//! cookie bound to its AuthnRequest, whose ID only ever travelled in the signed
//! POST body.
//!
//! Whether a failure also ends the local session (TVS L10) depends on how far
//! the callback got, see [`Rejection`].
use crate::{
    SamlAcsPath,
    bindings::soap::send_soap_request,
    config::AuthConfig,
    keys::KeySet,
    rd_metadata::IdpMetadata,
    state::{AuthFailure, AuthServiceState, AuthState},
    types::{Artifact, MessageId, NameId, SubjectId},
};
use axum::{
    extract::{FromRef, Query, State},
    http::{HeaderMap, HeaderValue, header},
    response::Response,
};
use axum_extra::extract::CookieJar;
use gamlastan::{
    bindings::soap::soap_envelope_wrap,
    core::protocol::status::Status,
    profiles::nl_eid::{
        ArtifactResponseParams, AuthnOutcome, NlEidAuthnResult, NlEidError,
        process_artifact_response, signed_artifact_resolve,
    },
};
use std::{collections::HashMap, sync::Arc};
use tracing::{debug, error, info, warn};

/// Why the callback produced no session, split on whether the RD had by then
/// answered this browser's own AuthnRequest.
///
/// Only an answered flow ends the local session (TVS L10). Everything before
/// that point can be provoked cross-site: the flow cookie is `Lax`, so a
/// top-level GET to the ACS from any site carries it, and a garbage `SAMLart`
/// gets past the cookie gate. Ending the session there would let a link log a
/// user out. An RD-signed Response naming the flow cookie's AuthnRequest cannot
/// be provoked that way: the ID never left the signed POST body.
#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    /// No RD-signed Response for the flow cookie's AuthnRequest was seen: bad
    /// or missing input, transport, or a Response to some other request.
    Unanswered(AuthFailure),
    /// An RD-signed Response whose `InResponseTo` is the flow cookie's
    /// AuthnRequest ID, that then failed: a DigiD status (T3/L10) or an
    /// assertion that did not validate.
    Answered(AuthFailure),
}

/// Assertion Consumer Service (eID §7.1 steps 4-8 / §3.1.1).
///
/// Receives the artifact via HTTP-Artifact binding (eID §7.4). Requires the
/// browser's flow cookie *before* touching the artifact, then resolves it over
/// the mTLS back-channel (eID §7.5, §9.4) and has gamlastan validate the
/// ArtifactResponse (§7.6.1), Response (§7.6.2), and Assertion (§7.6.3,
/// §7.6.3.5). On success, delegates to the embedding application via
/// `AuthState::on_authenticated` so it can create its own session and set the
/// appropriate cookie.
pub async fn handle_acs<S>(
    _: SamlAcsPath,
    State(state): State<S>,
    State(auth_state): State<AuthServiceState>,
    jar: CookieJar,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response
where
    S: AuthState,
    AuthServiceState: FromRef<S>,
{
    debug!("[ACS] Handler entered, query params: {}", params.len());

    // Cheapest gate first: a callback with no flow cookie can never be accepted,
    // so refuse it before resolving. Resolving costs an mTLS SOAP round-trip to
    // the RD, which an unauthenticated caller must not be able to trigger.
    let (bound_authn_id, jar) = crate::handlers::flow::take_bound_authn_id(
        jar,
        &auth_state.auth_config().dv.acs_url,
        &headers,
    );
    let Some(bound_authn_id) = bound_authn_id else {
        warn!(
            "[ACS] SSO flow cookie missing, malformed, or not bound to this User-Agent: \
             rejecting before resolving the artifact (possible login CSRF / forced login)"
        );
        let rejection = Rejection::Unanswered(AuthFailure::Error);
        return fail(&state, rejection, jar).await;
    };

    let authenticated = match resolve_and_validate(&auth_state, &params, &bound_authn_id).await {
        Ok(a) => a,
        Err(rejection) => return fail(&state, rejection, jar).await,
    };

    if !confirm_pending_request(&state, &bound_authn_id).await {
        let rejection = Rejection::Answered(AuthFailure::Error);
        return fail(&state, rejection, jar).await;
    }

    // SECURITY: never log decrypted SubjectID values; they are PII (BSN /
    // pseudonym per eID §7.6.3.4). Log only non-PII metadata for tracing.
    info!(
        "[ACS] Authentication successful. acting_subject_type={:?}, \
         legal_subject_present={}, loa={:?}, authenticating_authorities={:?}, \
         rd_signing_key={}",
        authenticated.acting_subject.identifier_type(),
        authenticated.legal_subject.is_some(),
        authenticated.level_of_assurance,
        authenticated.authenticating_authorities,
        authenticated.rd_signing_key_name,
    );

    // Hand off to the embedding application to create its session. gamlastan
    // guarantees an acting SubjectID on every `Authenticated` outcome (an
    // assertion without one is an error, TVS L10), and a Subject NameID on
    // every validated RD assertion (§7.6.3, cardinality 1).
    let subject_id = SubjectId::from_eid(&authenticated.acting_subject);
    let name_id = match NameId::parse(&authenticated.transient_name_id) {
        Ok(name_id) => name_id,
        Err(e) => {
            warn!("[ACS] Subject NameID unusable: {e}; treating as auth failure");
            let rejection = Rejection::Answered(AuthFailure::Error);
            return fail(&state, rejection, jar).await;
        }
    };
    debug!("[ACS] Handing off to AuthState::on_authenticated");
    state
        .on_authenticated(subject_id, name_id, jar, &headers)
        .await
}

/// Consume the AuthnRequest this DV issued to this browser from the
/// pending-request store. `false` means reject with `AuthFailure::Error` (TVS L10).
///
/// eID §7.6.3.5 rule 4 / §9.7: gamlastan has already required the Response's
/// `InResponseTo` and the assertion's bearer `InResponseTo` to equal
/// `bound_authn_id`, the ID the (verified and cleared) flow cookie carries, so
/// an assertion for a flow this browser did not start was refused there
/// (login-CSRF / forced-login defense). What remains is proving the DV actually
/// issued that request and consuming it in the same atomic step, so a replay
/// can never be accepted (the store is the application's, so this holds even
/// when /login and the ACS callback hit different instances). Fails closed: an
/// unknown, expired, or already-consumed ID is rejected.
async fn confirm_pending_request<S: AuthState>(state: &S, bound_authn_id: &MessageId) -> bool {
    if !state.consume_if_pending(bound_authn_id.clone()).await {
        warn!(
            "[ACS] InResponseTo did not match an outstanding AuthnRequest \
             (unknown, expired, or replayed): rejecting"
        );
        return false;
    }
    true
}

/// Render the failure page for a rejected callback. The embedding application
/// draws the page and, for an answered flow, ends its local session (TVS L10).
/// Cookie changes staged on `jar` (the one-shot flow-cookie clearing) ride along.
async fn fail<S: AuthState>(state: &S, rejection: Rejection, jar: CookieJar) -> Response {
    let (failure, end_session) = match rejection {
        Rejection::Unanswered(failure) => (failure, false),
        Rejection::Answered(failure) => (failure, true),
    };
    let mut response = state
        .on_authentication_failed(failure, jar, end_session)
        .await;
    harden_headers(response.headers_mut());
    response
}

/// Defense-in-depth headers for the failure page, served on the URL that
/// carried the artifact: never cache it, and never leak it via `Referer`.
fn harden_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// Pull the one-time-use artifact out of the ACS query string (eID §7.4).
///
/// The artifact is an opaque reference, so a short prefix is safe to log for
/// correlation and is not itself sensitive PII.
fn artifact_from_params(params: &HashMap<String, String>) -> Result<Artifact, AuthFailure> {
    let Some(artifact) = params.get("SAMLart") else {
        warn!("[ACS] Missing SAMLart query parameter");
        return Err(AuthFailure::Error);
    };
    // Parsed, not just read: the value is signed into an ArtifactResolve and
    // sent to the RD, so an unbounded or non-base64 query parameter is refused
    // here rather than forwarded.
    let artifact = Artifact::parse(artifact).map_err(|e| {
        warn!("[ACS] Malformed SAMLart query parameter: {e}");
        AuthFailure::Error
    })?;

    info!("[ACS] Artifact received: {}...", artifact.log_prefix());

    Ok(artifact)
}

/// Resolve the artifact into a validated authentication, or a [`Rejection`]
/// the caller turns into a user-facing page. `bound_authn_id` is the
/// AuthnRequest the flow cookie binds this browser to.
async fn resolve_and_validate(
    auth_state: &AuthServiceState,
    params: &HashMap<String, String>,
    bound_authn_id: &MessageId,
) -> Result<Box<NlEidAuthnResult>, Rejection> {
    let resolved = resolve_artifact(auth_state, params)
        .await
        .map_err(Rejection::Unanswered)?;
    validate_resolved(auth_state, &resolved, bound_authn_id)
}

/// The RD's SOAP ArtifactResponse, the `@ID` of the ArtifactResolve it must
/// answer, and the RD descriptor it was resolved against.
struct ResolvedArtifact {
    body: String,
    resolve_id: MessageId,
    rd: Arc<IdpMetadata>,
}

/// Steps 1-2: turn the `SAMLart` query parameter into the RD's ArtifactResponse.
async fn resolve_artifact(
    auth_state: &AuthServiceState,
    params: &HashMap<String, String>,
) -> Result<ResolvedArtifact, AuthFailure> {
    let artifact = artifact_from_params(params)?;

    let cfg = auth_state.auth_config();
    let dv_keys = auth_state.dv_keys();
    // Without the RD descriptor we have neither the ARS endpoint to resolve the
    // artifact against nor the RD signing keys to verify the response (eID §9.2),
    // so the flow cannot proceed. Transient: the RD metadata is not loaded yet.
    let Some(rd) = auth_state.rd_metadata() else {
        warn!("[ACS] RD metadata not loaded: cannot resolve or validate the artifact");
        return Err(AuthFailure::Unavailable);
    };

    debug!(
        "[ACS] Using DV entity_id={}, ARS url={}, signing_keys={}, encryption_keys={}",
        cfg.dv.entity_id,
        rd.ars_url,
        dv_keys.signing.len(),
        dv_keys.encryption.len()
    );

    // 1. Create signed ArtifactResolve (eID §7.5)
    let resolve = build_artifact_resolve(&artifact, cfg, dv_keys, &rd)?;

    // 2. Wrap in SOAP and send to ARS over mTLS (eID §9.4)
    let body = send_artifact_resolve(&resolve.xml, &rd, cfg).await?;
    Ok(ResolvedArtifact {
        body,
        resolve_id: resolve.id,
        rd,
    })
}

/// A signed outgoing message and the `@ID` it carries.
struct SignedResolve {
    id: MessageId,
    xml: String,
}

fn build_artifact_resolve(
    artifact: &Artifact,
    cfg: &AuthConfig,
    keys: &KeySet,
    rd: &IdpMetadata,
) -> Result<SignedResolve, AuthFailure> {
    debug!("[ACS] Step 1: building signed ArtifactResolve");
    let signing_key = keys.primary_signing().map_err(|e| {
        error!("[ACS] Cannot sign the ArtifactResolve: {e}");
        AuthFailure::from(&e)
    })?;
    let signer = signing_key.signer().map_err(|e| {
        error!("[ACS] Cannot load the signing key: {e}");
        AuthFailure::from(&e)
    })?;
    let signed = signed_artifact_resolve(
        &cfg.nl_eid(),
        artifact.as_str(),
        rd.ars_url.as_str(),
        &signer,
        signing_key.cert_base64.as_str(),
    )
    .map_err(|e| {
        error!("[ACS] Failed to create ArtifactResolve: {e}");
        AuthFailure::Error
    })?;
    let id = MessageId::parse(signed.id).map_err(|e| {
        error!("[ACS] ArtifactResolve ID unusable: {e}");
        AuthFailure::Error
    })?;
    debug!(
        "[ACS] ArtifactResolve built: id={}, xml_len={}",
        id.log_prefix(),
        signed.xml.len()
    );
    Ok(SignedResolve {
        id,
        xml: signed.xml,
    })
}

async fn send_artifact_resolve(
    resolve_xml: &str,
    rd: &IdpMetadata,
    cfg: &AuthConfig,
) -> Result<String, AuthFailure> {
    debug!("[ACS] Step 2: sending ArtifactResolve over mTLS SOAP back-channel");
    let soap_xml = soap_envelope_wrap(resolve_xml, None);
    match send_soap_request(&rd.ars_url, &soap_xml, &cfg.tls).await {
        Ok(r) => {
            debug!(
                "[ACS] SOAP back-channel returned response (len={})",
                r.len()
            );
            Ok(r)
        }
        Err(e) => {
            error!("[ACS] SOAP back-channel failed: {e}");
            Err(AuthFailure::Error)
        }
    }
}

/// Steps 3-5: have gamlastan validate the ArtifactResponse -> Response ->
/// Assertion chain (eID §7.6) against the RD signing keys from verified
/// metadata and decrypt the identifiers with the DV keys, and map the outcome.
fn validate_resolved(
    auth_state: &AuthServiceState,
    resolved: &ResolvedArtifact,
    bound_authn_id: &MessageId,
) -> Result<Box<NlEidAuthnResult>, Rejection> {
    debug!(
        "[ACS] Step 3: validating ArtifactResponse against {} RD signing key(s), \
         expected InResponseTo={}",
        resolved.rd.signing_key_names.len(),
        resolved.resolve_id.log_prefix()
    );
    let cfg = auth_state.auth_config();
    let decryption_keys = auth_state.dv_keys().decryption_keys().map_err(|e| {
        error!("[ACS] Cannot load the DV decryption keys: {e}");
        Rejection::Unanswered(AuthFailure::from(&e))
    })?;
    let params = ArtifactResponseParams {
        expected_artifact_resolve_id: resolved.resolve_id.as_str(),
        // Login-CSRF / forced-login defense: the Response and the assertion
        // must answer the AuthnRequest this browser's flow cookie is bound to.
        expected_authn_request_id: bound_authn_id.as_str(),
        replay_cache: auth_state.replay_cache(),
        relay_state: None,
        now: chrono::Utc::now(),
    };

    match process_artifact_response(
        &cfg.nl_eid(),
        &resolved.body,
        resolved.rd.verifier(),
        &decryption_keys,
        &params,
    ) {
        Ok(AuthnOutcome::Authenticated(result)) => {
            debug!("[ACS] ArtifactResponse, Response and Assertion OK");
            Ok(result)
        }
        // TVS "Checklist Testen" v2.1 T3: the user cancelled.
        Ok(AuthnOutcome::Cancelled { status }) => {
            warn!(
                "[ACS] Authentication cancelled by user ({})",
                status_summary(&status)
            );
            Err(Rejection::Answered(AuthFailure::Cancelled))
        }
        // TVS "Checklist Testen" v2.1 L10: RD/DigiD error status.
        Ok(AuthnOutcome::Failed { status }) => {
            warn!(
                "[ACS] Authentication failed at the RD ({})",
                status_summary(&status)
            );
            Err(Rejection::Answered(AuthFailure::Error))
        }
        Err(e) => {
            let rejection = rejection_for(&e);
            error!("[ACS] ArtifactResponse rejected ({rejection:?}): {e}");
            Err(rejection)
        }
    }
}

/// Which [`Rejection`] a gamlastan error is.
///
/// gamlastan verifies every signature and the ArtifactResponse envelope before
/// it looks at the Response, and requires the Response's `InResponseTo` to be
/// this browser's AuthnRequest before it applies the Response and Assertion
/// rules. So a failure is *answered* (ends the session, TVS L10) only once
/// those gates are passed: an RD-signed Response for this flow that then fails
/// a rule, or an assertion that does not validate. Anything an attacker could
/// provoke cross-site stays unanswered: not SAML at all, a signature that is
/// missing, unknown or does not verify, an artifact the RD refused, or an
/// RD-signed Response for *another* flow (forced login).
fn rejection_for(err: &NlEidError) -> Rejection {
    use NlEidError as E;
    let answered = match err {
        // Not usable at all: transport, format, algorithms, configuration.
        E::MalformedMessage(_)
        | E::DisallowedAlgorithm { .. }
        | E::Config(_)
        | E::ClockSkewTooLarge(_)
        | E::InvalidRequestOptions(_)
        | E::Metadata(_)
        | E::Crypto(_)
        | E::Xml(_) => false,
        // No valid RD signature over the consumed element: nothing in the
        // message is the RD's word.
        E::MissingSignature(_)
        | E::AmbiguousSignature(_)
        | E::UnknownSigningKey(_)
        | E::InvalidSignature { .. }
        | E::SignatureNotBoundToElement(_) => false,
        // The artifact was not resolved into a Response: no flow was answered.
        E::ArtifactResolutionFailed(_) | E::ResponseCount(_) => false,
        // The ArtifactResponse is not the answer to our resolve, or the RD
        // answered a flow this browser did not start.
        E::InResponseToMismatch { .. } => false,
        // The ArtifactResponse envelope itself is off.
        E::IssuerMismatch { element, .. } | E::StaleMessage { element, .. } => {
            !element.starts_with("ArtifactResponse")
        }
        E::MissingIssuer(element) => *element != "ArtifactResponse",
        // Everything else is a rule the RD-signed Response or Assertion for
        // this flow failed.
        _ => true,
    };
    if answered {
        Rejection::Answered(AuthFailure::Error)
    } else {
        Rejection::Unanswered(AuthFailure::Error)
    }
}

/// The status codes (and message) of a non-success Status, for the log.
fn status_summary(status: &Status) -> String {
    let mut summary = status.status_code.value.clone();
    if let Some(sub) = &status.status_code.sub_status {
        summary.push_str(" / ");
        summary.push_str(&sub.value);
    }
    if let Some(message) = &status.status_message {
        summary.push_str(": ");
        summary.push_str(message.trim());
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AuthConfig,
        handlers::test_support::MockAuthState,
        keys::{CertificatePem, KeyPair, PrivateKeyPem, key_pair_paths},
        types::{EndpointUrl, EntityId, ServiceUuid},
    };
    use chrono::Utc;
    use gamlastan::{
        core::assertion::name_id::NameId as SamlNameId,
        profiles::nl_eid::{
            LevelOfAssurance,
            constants::{ID_TYPE_LEGACY_BSN, NAMEID_PERSISTENT},
            rd::{
                RdResponseOptions, RdSubject, cancel_status, create_artifact_response,
                create_artifact_response_error, create_error_response, create_response,
                encrypt_subject_id, request_denied_status, request_unsupported_status,
                signed_artifact_response_xml,
            },
        },
        profiles::sso::web_browser::ResponseTimes,
    };
    use secrecy::ExposeSecret;
    use std::path::PathBuf;

    /// The DV this test suite configures.
    const DV: &str = "urn:test:dv";
    const ACS: &str = "https://dv.example.com/saml/sp/acs";
    const SERVICE_UUID: &str = "f847dc11-ac24-47b2-84a8-a057440ce56d";
    /// The DigiD AD the RD reports as authenticating authority.
    const AD: &str = "urn:nl-eid-gdi:1.0:AD:00000004166909913000:entities:9002";
    /// The `@ID` of the ArtifactResolve the RD's ArtifactResponse answers.
    const RESOLVE_ID: &str = "_resolve1";
    /// The AuthnRequest this browser's flow cookie is bound to.
    const BOUND_ID: &str = "_bound1";
    /// The BSN the RD encrypts into the assertion's ActingSubjectID.
    const BSN: &str = "900070341";
    const TRANSIENT_ID: &str = "64b0d194095940008ffa142b12444c01";
    const ASSERTION_ID: &str = "_assertion1";

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    /// A keypair from the committed fixtures, read synchronously (the library's
    /// loaders are async).
    fn load_key(name: &str) -> KeyPair {
        let paths = key_pair_paths(&fixtures_dir(), name);
        let read = |path: &std::path::Path| {
            std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
        };
        let cert = CertificatePem::parse(read(&paths.cert)).expect("fixture cert parses");
        KeyPair::from_pem(cert, PrivateKeyPem::new(read(&paths.key)))
    }

    /// The RD of these tests: the Test environment's RD identity, signing with
    /// the `rd-signing-1` fixture.
    fn rd_entity_id() -> String {
        IdpMetadata::for_tests().entity_id.as_str().to_owned()
    }

    fn rd_key() -> KeyPair {
        load_key("rd-signing-1")
    }

    /// A configured DV that trusts the `rd-signing-1` fixture as the RD's
    /// signing key, so an RD-signed ArtifactResponse validates against it.
    async fn state_with_rd() -> AuthServiceState {
        let mut cfg = AuthConfig::default().with_certs_dir(fixtures_dir());
        cfg.dv.entity_id = EntityId::from_static(DV);
        cfg.dv.service_uuid = ServiceUuid::from_static(SERVICE_UUID);
        cfg.dv.acs_url = EndpointUrl::from_base_url(ACS, "ACS").expect("test ACS URL");
        let keys = crate::keys::load_key_set(&cfg.dv.signing, &cfg.dv.encryption)
            .await
            .expect("load fixtures");
        let rd = IdpMetadata::for_tests_trusting(&[&rd_key().cert_pem]);
        AuthServiceState::new(cfg, keys, None, Some(rd))
    }

    /// A jar carrying the flow cookie `/login` would have set, so a test gets
    /// past the gate to the artifact-resolving part of the handler.
    fn jar_with_flow_cookie(
        auth: &AuthServiceState,
        authn_id: &str,
        headers: &HeaderMap,
    ) -> CookieJar {
        let acs_url = &auth.auth_config().dv.acs_url;
        let id = MessageId::parse(authn_id).expect("test message id");
        CookieJar::new().add(crate::handlers::flow::flow_cookie(acs_url, &id, headers))
    }

    /// Whether the embedder was told to end its session, as `MockAuthState`
    /// records it. Also asserts the failure page is rendered in place (no
    /// redirect) with the artifact-hardening headers.
    fn failure_ends_session(resp: &Response) -> bool {
        assert!(
            resp.headers().get(axum::http::header::LOCATION).is_none(),
            "the failure page is rendered directly on the ACS response"
        );
        assert_eq!(
            resp.headers().get(axum::http::header::CACHE_CONTROL),
            Some(&axum::http::HeaderValue::from_static("no-store")),
            "failure responses must not be cached"
        );
        assert_eq!(
            resp.headers().get(axum::http::header::REFERRER_POLICY),
            Some(&axum::http::HeaderValue::from_static("no-referrer")),
            "failure responses must not leak the artifact via Referer"
        );
        resp.headers()
            .get("x-test-end-session")
            .and_then(|v| v.to_str().ok())
            .expect("MockAuthState records end_session")
            == "true"
    }

    fn artifact_params() -> HashMap<String, String> {
        HashMap::from([(
            "SAMLart".to_string(),
            "AAQAAsomeOpaqueArtifact==".to_string(),
        )])
    }

    #[tokio::test]
    async fn missing_saml_artifact_renders_error_without_ending_session() {
        // No `SAMLart` query parameter, with a flow cookie: the callback fails
        // closed with Error. Nothing RD-signed answered this browser's flow (a
        // cross-site GET carries the Lax cookie), so the session is kept.
        let mock = MockAuthState::empty();
        let headers = HeaderMap::new();
        let resp = handle_acs(
            SamlAcsPath,
            State(mock.clone()),
            State(mock.auth.clone()),
            jar_with_flow_cookie(&mock.auth, "_pending", &headers),
            headers.clone(),
            Query(HashMap::new()),
        )
        .await;
        // MockAuthState renders Error as 401.
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(!failure_ends_session(&resp));
    }

    #[tokio::test]
    async fn artifact_without_rd_metadata_renders_unavailable() {
        // An artifact is present but no RD descriptor is loaded, so the flow
        // cannot be resolved or validated: the Unavailable page, session kept.
        let mock = MockAuthState::empty();
        let headers = HeaderMap::new();
        let resp = handle_acs(
            SamlAcsPath,
            State(mock.clone()),
            State(mock.auth.clone()),
            jar_with_flow_cookie(&mock.auth, "_pending", &headers),
            headers.clone(),
            Query(artifact_params()),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        assert!(!failure_ends_session(&resp));
    }

    #[tokio::test]
    async fn callback_without_flow_cookie_is_rejected_before_resolving() {
        // The page proves the ordering: this mock has no RD metadata, so
        // resolving first would have rendered Unavailable rather than Error.
        let mock = MockAuthState::empty();
        let resp = handle_acs(
            SamlAcsPath,
            State(mock.clone()),
            State(mock.auth.clone()),
            axum_extra::extract::CookieJar::new(),
            HeaderMap::new(),
            Query(artifact_params()),
        )
        .await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::UNAUTHORIZED,
            "the flow-cookie gate must reject before the artifact is resolved"
        );
        // no flow to end: a cross-site link must not log anyone out
        assert!(!failure_ends_session(&resp));
    }

    #[tokio::test]
    async fn answered_flow_ends_the_session() {
        let mock = MockAuthState::empty();
        let resp = fail(
            &mock,
            Rejection::Answered(AuthFailure::Cancelled),
            CookieJar::new(),
        )
        .await;
        // MockAuthState renders Cancelled as 403.
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(failure_ends_session(&resp));
    }

    #[tokio::test]
    async fn unanswered_flow_does_not_end_the_session() {
        let mock = MockAuthState::empty();
        let resp = fail(
            &mock,
            Rejection::Unanswered(AuthFailure::Cancelled),
            CookieJar::new(),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        assert!(!failure_ends_session(&resp));
    }

    #[tokio::test]
    async fn build_artifact_resolve_produces_a_signed_message() {
        let auth = state_with_rd().await;
        let rd = auth.rd_metadata().unwrap();
        let artifact = Artifact::parse("AAQAAartifact").expect("test artifact");
        let msg = build_artifact_resolve(&artifact, auth.auth_config(), auth.dv_keys(), &rd)
            .expect("ArtifactResolve must build and sign");
        assert!(msg.id.as_str().starts_with('_'), "message id: {}", msg.id);
        assert!(msg.xml.contains("ArtifactResolve"), "{}", msg.xml);
        // The artifact and the destination ARS endpoint are carried in the XML,
        // and the DV's primary signing key signed it.
        assert!(msg.xml.contains("AAQAAartifact"));
        assert!(msg.xml.contains("https://rd.example.com/ars"));
        let primary = auth.dv_keys().primary_signing().unwrap();
        let verifier = IdpMetadata::for_tests_trusting(&[&primary.cert_pem]);
        assert!(
            verifier
                .verifier()
                .verify_enveloped(&msg.xml)
                .unwrap()
                .is_valid()
        );
    }

    #[tokio::test]
    async fn malformed_saml_artifact_renders_error_without_ending_session() {
        // Refused where it is read, before it can be signed into an
        // ArtifactResolve and sent to the RD.
        let mock = MockAuthState::new(state_with_rd().await);
        let headers = HeaderMap::new();
        let resp = handle_acs(
            SamlAcsPath,
            State(mock.clone()),
            State(mock.auth.clone()),
            jar_with_flow_cookie(&mock.auth, BOUND_ID, &headers),
            headers.clone(),
            Query(HashMap::from([(
                "SAMLart".to_string(),
                "not base64!".to_string(),
            )])),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(!failure_ends_session(&resp));
    }

    #[tokio::test]
    async fn a_failing_back_channel_renders_error_without_ending_session() {
        // The artifact is well-formed and gets signed into an ArtifactResolve,
        // but the ARS is unreachable: nothing RD-signed ever answered this
        // browser's flow, so the session survives the transport failure.
        let mut auth_cfg = AuthConfig::default().with_certs_dir(fixtures_dir());
        auth_cfg.dv.entity_id = EntityId::from_static(DV);
        auth_cfg.dv.service_uuid = ServiceUuid::from_static(SERVICE_UUID);
        auth_cfg.dv.acs_url = EndpointUrl::from_base_url(ACS, "ACS").expect("test ACS URL");
        let keys = crate::keys::load_key_set(&auth_cfg.dv.signing, &auth_cfg.dv.encryption)
            .await
            .expect("load fixtures");
        let rd = IdpMetadata {
            // A closed port on loopback: connection refused, no DNS, no waiting.
            ars_url: EndpointUrl::from_metadata("https://127.0.0.1:1/ars", "ARS")
                .expect("test ARS URL"),
            ..IdpMetadata::for_tests()
        };
        let mock = MockAuthState::new(AuthServiceState::new(auth_cfg, keys, None, Some(rd)));

        let headers = HeaderMap::new();
        let resp = handle_acs(
            SamlAcsPath,
            State(mock.clone()),
            State(mock.auth.clone()),
            jar_with_flow_cookie(&mock.auth, BOUND_ID, &headers),
            headers.clone(),
            Query(artifact_params()),
        )
        .await;
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert!(!failure_ends_session(&resp));
    }

    // -----------------------------------------------------------------------
    // The validation step, driven over real RD-signed ArtifactResponses built
    // with gamlastan's RD-side builders and the `rd-signing-1` fixture, so the
    // wiring the handler performs (trusted RD keys from the descriptor, the DV
    // decryption keys, the flow-cookie correlation, the outcome mapping) is
    // exercised rather than stubbed. Only the mTLS back-channel that would
    // deliver these bytes is left out; the protocol rules themselves are
    // gamlastan's and covered by its own suite.
    // -----------------------------------------------------------------------

    /// How the RD answered: the Response Status, and with it whether the
    /// Response carries an Assertion at all (eID §7.6.2).
    enum Outcome {
        Success,
        /// The user pressed cancel at DigiD (TVS T3).
        Cancelled,
        /// Any other RD/DigiD error status (TVS L10).
        Failed,
    }

    /// The parts of the RD's ArtifactResponse a test varies; [`Default`] is the
    /// message a successful login against this DV produces.
    struct Wire {
        /// The ArtifactResolve `@ID` the ArtifactResponse answers.
        resolve_id: &'static str,
        /// The AuthnRequest the RD is answering.
        in_response_to: &'static str,
        outcome: Outcome,
        /// Whether the RD resolved the artifact at all (eID §7.6.1).
        artifact_resolved: bool,
        /// The key the RD messages are signed with.
        signing_key: &'static str,
        /// The assertion's `<saml:Audience>`: the DV it was minted for.
        audience: &'static str,
        /// The RD's own key as published, or a cert the DV does not trust.
        encrypt_to: &'static str,
    }

    impl Default for Wire {
        fn default() -> Self {
            Self {
                resolve_id: RESOLVE_ID,
                in_response_to: BOUND_ID,
                outcome: Outcome::Success,
                artifact_resolved: true,
                signing_key: "rd-signing-1",
                audience: DV,
                encrypt_to: "dv-encryption-1",
            }
        }
    }

    /// An `<saml:EncryptedID>` carrying the acting subject's BSN, wrapped to
    /// `cert` the way the RD does it (eID §7.6.3.4, §9.3: AES-256-CBC data,
    /// RSA-OAEP key wrap, addressed to the DV by `@Recipient`).
    fn encrypted_acting_subject(cert: &KeyPair) -> String {
        let name_id = SamlNameId {
            value: BSN.to_string(),
            format: Some(NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some(ID_TYPE_LEGACY_BSN.to_string()),
            sp_name_qualifier: None,
            sp_provided_id: None,
        };
        encrypt_subject_id(
            &name_id,
            DV,
            &cert.cert_pem.to_der(),
            cert.key_name.as_str(),
        )
        .expect("encrypt the NameID")
    }

    /// The RD's SOAP ArtifactResponse for `wire`, signed as the RD signs it:
    /// the Assertion and the enveloping ArtifactResponse (eID §7.6.1, §7.6.3).
    fn soap_artifact_response(wire: &Wire) -> String {
        let rd = rd_entity_id();
        let now = Utc::now();
        let mut artifact_response = if wire.artifact_resolved {
            let response = match wire.outcome {
                Outcome::Success => {
                    let opts = RdResponseOptions::new(
                        rd.clone(),
                        wire.audience,
                        ACS,
                        wire.in_response_to,
                        SERVICE_UUID,
                        LevelOfAssurance::Substantial,
                        RdSubject::new(
                            TRANSIENT_ID,
                            encrypted_acting_subject(&load_key(wire.encrypt_to)),
                        ),
                    );
                    let mut opts = opts;
                    opts.authenticating_authorities = vec![AD.to_string()];
                    let mut response = create_response(&opts, ResponseTimes::at(now));
                    response.assertions.first_mut().expect("one assertion").id =
                        ASSERTION_ID.to_string();
                    response
                }
                Outcome::Cancelled => {
                    create_error_response(&rd, wire.in_response_to, ACS, cancel_status(), now)
                }
                Outcome::Failed => create_error_response(
                    &rd,
                    wire.in_response_to,
                    ACS,
                    request_unsupported_status("Er is een fout opgetreden"),
                    now,
                ),
            };
            create_artifact_response(&rd, wire.resolve_id, &response).expect("wrap")
        } else {
            create_artifact_response_error(&rd, wire.resolve_id, request_denied_status())
        };
        artifact_response.issue_instant = now;

        let assertion_id = (wire.artifact_resolved && matches!(wire.outcome, Outcome::Success))
            .then_some(ASSERTION_ID);
        let signing_key = load_key(wire.signing_key);
        let signed = signed_artifact_response_xml(
            &artifact_response,
            assertion_id,
            &signing_key.signer().expect("RD signer"),
            signing_key.key_name.as_str(),
        )
        .expect("sign as the RD");
        soap_envelope_wrap(&signed, None)
    }

    /// Run the handler's validation step over `body`, exactly as
    /// `resolve_and_validate` does once the back-channel has answered.
    fn validate_body(
        auth: &AuthServiceState,
        body: String,
    ) -> Result<Box<NlEidAuthnResult>, Rejection> {
        let resolved = ResolvedArtifact {
            body,
            resolve_id: MessageId::parse(RESOLVE_ID).expect("test resolve id"),
            rd: auth.rd_metadata().expect("test RD metadata"),
        };
        validate_resolved(
            auth,
            &resolved,
            &MessageId::parse(BOUND_ID).expect("test bound id"),
        )
    }

    /// Build the RD's answer for `wire` and validate it.
    async fn run_wire(wire: Wire) -> Result<Box<NlEidAuthnResult>, Rejection> {
        let auth = state_with_rd().await;
        validate_body(&auth, soap_artifact_response(&wire))
    }

    #[tokio::test]
    async fn a_valid_artifact_response_authenticates_the_subject() {
        let result = run_wire(Wire::default()).await.expect("the chain accepts");

        assert_eq!(result.acting_subject.expose_value(), BSN);
        assert_eq!(result.transient_name_id, TRANSIENT_ID);
        assert_eq!(result.level_of_assurance, LevelOfAssurance::Substantial);
        assert_eq!(result.authenticating_authorities, vec![AD.to_string()]);
        assert_eq!(result.service_uuid, SERVICE_UUID);
        assert_eq!(result.rd_signing_key_name, rd_key().key_name.as_str());
        assert_eq!(result.authn.idp_entity_id, rd_entity_id());

        // What the embedding application receives: the BSN behind a
        // SecretString, with its identifier type, and the TransientID.
        let subject = SubjectId::from_eid(&result.acting_subject);
        assert_eq!(subject.value.expose_secret(), BSN);
        assert_eq!(subject.name_qualifier, ID_TYPE_LEGACY_BSN);
        assert!(!format!("{subject:?}").contains(BSN));
        assert!(NameId::parse(&result.transient_name_id).is_ok());
    }

    #[tokio::test]
    async fn a_cancelled_login_is_an_answered_failure() {
        // The RD answered this browser's own flow, so the session ends (TVS T3).
        assert_eq!(
            run_wire(Wire {
                outcome: Outcome::Cancelled,
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Answered(AuthFailure::Cancelled))
        );
    }

    #[tokio::test]
    async fn an_rd_error_status_is_an_answered_failure() {
        // Same flow, but not a cancellation: the generic error page (TVS L10).
        assert_eq!(
            run_wire(Wire {
                outcome: Outcome::Failed,
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Answered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn a_response_to_another_flow_never_ends_this_session() {
        // A forced-login attempt: an RD-signed Response for someone else's
        // AuthnRequest, handed to this browser. Rejected *before* the failure
        // counts as answered, so a link cannot log the user out.
        assert_eq!(
            run_wire(Wire {
                in_response_to: "_theirs",
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Unanswered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn an_artifact_response_answering_another_resolve_is_rejected() {
        // eID §7.6.1: the ArtifactResponse must answer the ArtifactResolve we
        // just sent, so a replayed one for an earlier resolve gets no further.
        assert_eq!(
            run_wire(Wire {
                resolve_id: "_someotherresolve",
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Unanswered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn a_denied_artifact_resolution_is_an_unanswered_failure() {
        // eID §7.6.1: the RD refused the artifact (unknown, expired, spent):
        // no Response, so no flow of this browser was answered.
        assert_eq!(
            run_wire(Wire {
                artifact_resolved: false,
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Unanswered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn an_assertion_minted_for_another_dv_is_an_answered_failure() {
        // eID §7.6.3.5 rule 5: the assertion must name this DV in its
        // AudienceRestriction. The Response was RD-signed and answers this
        // browser's own flow, so the failed login does end the session (L10).
        assert_eq!(
            run_wire(Wire {
                audience: "urn:test:another-dv",
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Answered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn an_identifier_the_dv_cannot_decrypt_is_an_answered_failure() {
        // Wrapped to a certificate the DV does not hold the key of: the RD
        // answered this flow, but no identity can be established (TVS L10).
        assert_eq!(
            run_wire(Wire {
                encrypt_to: "rd-signing-1",
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Answered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn a_response_signed_by_anyone_but_the_rd_is_rejected() {
        // Signed with a well-formed key that is simply not in the RD metadata
        // (eID §9.2: verification keys come from verified metadata only).
        assert_eq!(
            run_wire(Wire {
                signing_key: "dv-signing-1",
                ..Wire::default()
            })
            .await
            .err(),
            Some(Rejection::Unanswered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn a_replayed_artifact_response_is_rejected() {
        let auth = state_with_rd().await;
        let body = soap_artifact_response(&Wire::default());
        assert!(validate_body(&auth, body.clone()).is_ok());
        // The same assertion again: gamlastan's replay cache refuses it.
        assert_eq!(
            validate_body(&auth, body).err(),
            Some(Rejection::Answered(AuthFailure::Error))
        );
    }

    #[tokio::test]
    async fn a_back_channel_body_that_is_not_a_soap_artifact_response_is_rejected() {
        let auth = state_with_rd().await;
        for body in ["<html><body>proxy error</body></html>", "502 Bad Gateway"] {
            assert_eq!(
                validate_body(&auth, body.to_string()).err(),
                Some(Rejection::Unanswered(AuthFailure::Error)),
                "{body}"
            );
        }
    }

    #[test]
    fn rejection_classification_keeps_cross_site_provocable_failures_unanswered() {
        use gamlastan::profiles::nl_eid::NlEidError as E;
        let unanswered = [
            E::MalformedMessage("x".into()),
            E::UnknownSigningKey("k".into()),
            E::InvalidSignature {
                element: "Assertion",
                reason: "bad".into(),
            },
            E::ArtifactResolutionFailed(request_denied_status()),
            E::ResponseCount(0),
            E::InResponseToMismatch {
                element: "Response",
                received: Some("_theirs".into()),
                expected: BOUND_ID.into(),
            },
            E::StaleMessage {
                element: "ArtifactResponse @IssueInstant",
                detail: "old".into(),
            },
            E::Config("unset".into()),
        ];
        for err in &unanswered {
            assert_eq!(
                rejection_for(err),
                Rejection::Unanswered(AuthFailure::Error),
                "{err}"
            );
        }
        let answered = [
            E::EncryptedAssertionForbidden,
            E::ServiceUuidMismatch {
                received: Some("x".into()),
                expected: SERVICE_UUID.into(),
            },
            E::MissingActingSubjectId,
            E::LevelOfAssuranceTooLow {
                received: LevelOfAssurance::Basic.as_request_uri().to_string(),
                minimum: LevelOfAssurance::Low.as_request_uri(),
            },
            E::DestinationMismatch {
                received: None,
                expected: ACS.into(),
            },
            E::StaleMessage {
                element: "Assertion @IssueInstant",
                detail: "old".into(),
            },
        ];
        for err in &answered {
            assert_eq!(
                rejection_for(err),
                Rejection::Answered(AuthFailure::Error),
                "{err}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // eID §7.6.3.5 rule 4 / §9.7: consume against the application's
    // pending-request store.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn an_outstanding_authn_request_is_confirmed_once_and_then_consumed() {
        let mock = MockAuthState::empty().with_pending(BOUND_ID);
        let bound = MessageId::parse(BOUND_ID).expect("test message id");

        assert!(confirm_pending_request(&mock, &bound).await);
        // Consumed in the same step, so replaying the assertion finds nothing.
        assert!(
            !confirm_pending_request(&mock, &bound).await,
            "a replayed assertion must not be accepted a second time"
        );
        // And an ID the store never held is refused.
        let unknown = MessageId::parse("_unknown").expect("test message id");
        assert!(!confirm_pending_request(&mock, &unknown).await);
    }
}

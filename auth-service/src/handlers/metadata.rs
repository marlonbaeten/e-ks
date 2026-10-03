use crate::{
    error::Result,
    keys::{KeyPair, KeySet},
    state::AuthServiceState,
};
use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use gamlastan::profiles::nl_eid::{DvMetadataOptions, PublishedCertificate, build_dv_metadata};
use tracing::{debug, error};

/// GET /saml/sp/metadata: serve the DV's signed SAML metadata (eID §8.3),
/// from cache when available.
pub async fn handle_metadata(
    _: crate::SamlMetadataPath,
    State(auth_state): State<AuthServiceState>,
) -> Response {
    debug!("[metadata] Handler entered");
    if let Some(xml) = auth_state.cached_metadata() {
        debug!("[metadata] Cache hit (xml_len={})", xml.len());
        return xml_response(xml);
    }
    debug!("[metadata] Cache miss; building signed metadata");

    match build_metadata(&auth_state) {
        Ok(xml) => {
            debug!(
                "[metadata] Built signed metadata (xml_len={}); caching",
                xml.len()
            );
            auth_state.set_cached_metadata(xml.clone());
            xml_response(xml)
        }
        Err(e) => {
            error!("Failed to build metadata: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to build metadata",
            )
                .into_response()
        }
    }
}

/// Assemble the SP identity, endpoints and key material from the state and
/// have gamlastan build and sign the DV metadata (eID §8.3). The document is
/// signed with the primary signing key, whose certificate is also carried in
/// the Signature `KeyInfo`.
fn build_metadata(auth_state: &AuthServiceState) -> Result<String> {
    let cfg = auth_state.auth_config();
    let keys = auth_state.dv_keys();

    debug!(
        "[metadata] entity_id={}, acs_url={}, slo_url={}, service_name={}, \
         service_uuid={}, signing_keys={}, encryption_keys={}, tls_signing_cert={}",
        cfg.dv.entity_id,
        cfg.dv.acs_url,
        cfg.dv.slo_url,
        cfg.dv.service_name,
        cfg.dv.service_uuid,
        keys.signing.len(),
        keys.encryption.len(),
        auth_state.metadata_tls_cert().is_some(),
    );

    let signing_key = keys.primary_signing()?;
    let mut opts = DvMetadataOptions::from_config(&cfg.nl_eid(), cfg.dv.service_name.clone());
    opts.signing_certificates =
        published_signing_certificates(keys, auth_state.metadata_tls_cert());
    opts.encryption_certificates = keys.encryption.iter().map(KeyPair::published).collect();

    Ok(build_dv_metadata(
        &opts,
        &signing_key.signer()?,
        signing_key.cert_base64.as_str(),
    )?)
}

/// The `use="signing"` certificates to publish: every SAML signing key plus the
/// mTLS client cert (eID §8.3), dropping the TLS cert when it is already one of
/// the signing certs (a combined signing+TLS certificate) so the metadata never
/// carries a duplicate KeyDescriptor.
fn published_signing_certificates(
    keys: &KeySet,
    tls_signing_cert: Option<&KeyPair>,
) -> Vec<PublishedCertificate> {
    let tls_extra =
        tls_signing_cert.filter(|tls| keys.signing.iter().all(|k| k.key_name != tls.key_name));
    keys.signing
        .iter()
        .chain(tls_extra)
        .map(KeyPair::published)
        .collect()
}

fn xml_response(xml: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/xml"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        xml,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::AuthConfig,
        types::{EndpointUrl, EntityId, ServiceUuid},
    };
    use axum::body::to_bytes;

    fn dv_url(url: &str) -> EndpointUrl {
        EndpointUrl::from_base_url(url, "DV endpoint").expect("test DV endpoint")
    }

    fn fixtures_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
    }

    /// A state backed by the committed DV fixtures, enough to build real signed
    /// metadata without any env/network access.
    async fn fixture_state(with_tls_cert: bool) -> AuthServiceState {
        let mut cfg = AuthConfig::default().with_certs_dir(fixtures_dir());
        cfg.dv.entity_id = EntityId::from_static("urn:test:dv");
        cfg.dv.acs_url = dv_url("https://dv.example.com/saml/sp/acs");
        cfg.dv.slo_url = dv_url("https://dv.example.com/saml/sp/logout");
        cfg.dv.service_name = "Kiesraad Test".to_string();
        cfg.dv.service_uuid = ServiceUuid::from_static("f847dc11-ac24-47b2-84a8-a057440ce56d");
        let keys = crate::keys::load_key_set(&cfg.dv.signing, &cfg.dv.encryption)
            .await
            .expect("load fixtures");
        let tls_cert = if with_tls_cert {
            crate::keys::load_metadata_tls_cert(&cfg.tls.client_cert).await
        } else {
            None
        };
        AuthServiceState::new(cfg, keys, tls_cert, None)
    }

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn builds_signs_and_caches_metadata_on_first_request() {
        let state = fixture_state(true).await;
        assert!(
            state.cached_metadata().is_none(),
            "nothing cached before the first request"
        );

        let resp = handle_metadata(crate::SamlMetadataPath, State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/xml"
        );
        assert_eq!(
            resp.headers().get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );

        let body = body_string(resp).await;
        assert!(body.contains("EntityDescriptor"), "{body}");
        assert!(body.contains("urn:test:dv"));
        assert!(body.contains("Kiesraad Test"));
        assert!(body.contains("https://dv.example.com/saml/sp/logout"));
        // The built metadata is now cached for subsequent requests.
        assert_eq!(state.cached_metadata().as_deref(), Some(body.as_str()));
    }

    #[tokio::test]
    async fn the_signed_metadata_verifies_with_the_primary_signing_key() {
        let state = fixture_state(true).await;
        let xml = build_metadata(&state).expect("metadata builds");
        let primary = state.dv_keys().primary_signing().unwrap();
        let verifier = crate::rd_metadata::IdpMetadata::for_tests_trusting(&[&primary.cert_pem]);
        let result = verifier
            .verifier()
            .verify_enveloped(&xml)
            .expect("verifier runs");
        assert!(result.is_valid(), "{result:?}");
    }

    #[tokio::test]
    async fn tls_cert_published_as_extra_signing_key_descriptor() {
        let state = fixture_state(true).await;
        let xml = build_metadata(&state).expect("metadata builds");
        let tls = state.metadata_tls_cert().expect("fixture TLS cert");
        // Two SAML signing certs (rollover) + the TLS cert; two encryption certs.
        assert_eq!(xml.matches(r#"use="signing""#).count(), 3, "{xml}");
        assert_eq!(xml.matches(r#"use="encryption""#).count(), 2);
        assert!(
            xml.contains(tls.key_name.as_str()),
            "TLS cert KeyName must appear in the metadata"
        );
        for key in &state.dv_keys().signing {
            assert!(xml.contains(key.key_name.as_str()));
        }
    }

    #[tokio::test]
    async fn tls_cert_equal_to_signing_cert_is_not_duplicated() {
        let state = fixture_state(false).await;
        let keys = state.dv_keys();
        // A combined signing+TLS certificate: the cert handed in as the TLS
        // cert is the same one already listed as the SAML signing key.
        let published = published_signing_certificates(keys, keys.signing.first());
        assert_eq!(published.len(), keys.signing.len());
        let published = published_signing_certificates(keys, None);
        assert_eq!(published.len(), keys.signing.len());
    }

    #[tokio::test]
    async fn serves_cached_metadata_without_rebuilding() {
        // A state with no keys cannot build metadata, so a served response proves
        // it came from the cache rather than the build path.
        let state = AuthServiceState::new_empty();
        state.set_cached_metadata("<md:EntityDescriptor/>".to_string());

        let resp = handle_metadata(crate::SamlMetadataPath, State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_string(resp).await, "<md:EntityDescriptor/>");
    }

    #[tokio::test]
    async fn build_failure_without_signing_keys_is_a_500() {
        // No signing keys and no cache: building signed metadata fails and the
        // handler surfaces a 500 rather than panicking.
        let resp = handle_metadata(
            crate::SamlMetadataPath,
            State(AuthServiceState::new_empty()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}

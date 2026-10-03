//! Trust in the RD (IdP) metadata: fetch it, pin the RD identity, filter its
//! signing certificates by PKIoverheid chain and OIN, verify its signature,
//! pin the endpoint domain, and cache it on disk.
//!
//! eID §9.2: signature verification keys MUST come from verified metadata.
//! Reading the document is gamlastan's job
//! ([`gamlastan::profiles::nl_eid::parse_rd_metadata`]); *trusting* it is this
//! deployment's, because the anchor is external to SAML: the RD `entityID` is a
//! configured constant, and only certificates that carry the RD OIN and chain
//! to the pinned PKIoverheid root may verify anything.
use crate::{
    error::{AuthError, Result},
    keys::CertificatePem,
    pki::subject_oin,
    types::{EndpointUrl, EntityId},
};
use chrono::{DateTime, Utc};
use gamlastan::{
    crypto::SamlVerifier,
    profiles::nl_eid::{RdMetadata, RdSigningKey, constants::DEFAULT_CLOCK_SKEW_SECONDS},
};
use rustls_pki_types::{CertificateDer, UnixTime};
use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};
use tracing::{debug, info, warn};

/// The RD descriptor the handlers work with: identity, endpoints, and a
/// verifier over exactly the trusted RD signing certificates.
#[derive(Clone)]
pub struct IdpMetadata {
    pub entity_id: EntityId,
    /// SSO endpoint with HTTP-POST binding (eID §3.1.1).
    pub sso_url: EndpointUrl,
    /// Artifact Resolution endpoint with SOAP binding (eID §7.5).
    pub ars_url: EndpointUrl,
    /// Single Logout endpoint with HTTP-POST binding (eID §7.7.1).
    pub slo_url: EndpointUrl,
    /// The `<ds:KeyName>`s of the trusted RD signing certificates: what an RD
    /// signature's `KeyInfo` must name (eID §9.2). Diagnostics only; the keys
    /// themselves live in [`verifier`](Self::verifier).
    pub signing_key_names: Vec<String>,
    /// Parsed `cacheDuration` (eID §8.5), the RD's hint for how long the
    /// descriptor may be cached. The background refresh task uses it, capped at
    /// 24h, to schedule the next fetch. `None` when absent or unparseable.
    pub cache_duration: Option<Duration>,
    /// Verifier holding exactly the trusted RD signing certificates, keyed by
    /// `KeyName`, with the §9.1 algorithm policy.
    pub(crate) verifier: SamlVerifier,
}

impl IdpMetadata {
    /// The verifier for RD signatures: `ArtifactResponse`, `Assertion` (§7.6)
    /// and `LogoutResponse` (§7.7.2).
    pub fn verifier(&self) -> &SamlVerifier {
        &self.verifier
    }
}

impl fmt::Debug for IdpMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdpMetadata")
            .field("entity_id", &self.entity_id)
            .field("sso_url", &self.sso_url)
            .field("ars_url", &self.ars_url)
            .field("slo_url", &self.slo_url)
            .field("signing_key_names", &self.signing_key_names)
            .field("cache_duration", &self.cache_duration)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl IdpMetadata {
    /// A descriptor for tests: the Test environment's RD identity and three
    /// endpoints, trusting no signing key. Callers override individual fields
    /// with `..IdpMetadata::for_tests()`.
    pub(crate) fn for_tests() -> Self {
        Self::for_tests_trusting(&[])
    }

    /// As [`for_tests`](Self::for_tests), trusting `certs` as the RD's signing
    /// certificates (named by their SHA-1 thumbprint, as the TVS does).
    pub(crate) fn for_tests_trusting(certs: &[&CertificatePem]) -> Self {
        use gamlastan::crypto::{KeyUsage, KeysManager, keys::loader};

        let endpoint = |path: &str| {
            EndpointUrl::from_metadata(&format!("https://rd.example.com/{path}"), path)
                .expect("test RD endpoint")
        };
        let mut km = KeysManager::new();
        let mut signing_key_names = Vec::new();
        for cert in certs {
            let key_name = cert.key_name();
            let mut key = loader::load_x509_cert_pem(cert.as_str().as_bytes())
                .expect("test RD certificate")
                .with_name(key_name.as_str());
            key.usage = KeyUsage::Verify;
            km.add_key(key);
            signing_key_names.push(key_name.as_str().to_owned());
        }
        Self {
            entity_id: crate::config::Environment::Test.rd_entity_id(),
            sso_url: endpoint("sso"),
            ars_url: endpoint("ars"),
            slo_url: endpoint("slo"),
            signing_key_names,
            cache_duration: None,
            verifier: SamlVerifier::new(km)
                .with_algorithm_policy(gamlastan::profiles::nl_eid::constants::algorithm_policy()),
        }
    }
}

/// Pinned trust material for validating the RD metadata signing certificate
/// (eID §9.1/§9.2): the expected RD identity plus the embedded root/intermediate
/// CAs the signing cert must chain to. Every field is a compile-time constant, so
/// this is cheap to build and copy.
#[derive(Clone)]
pub struct RdTrust {
    /// Expected RD `entityID`; loaded metadata must match it exactly.
    pub expected_entity_id: EntityId,
    /// Expected RD OIN, required in the signing cert's `Subject.serialNumber`.
    pub expected_oin: &'static str,
    /// Domain the SSO/ARS/SLO endpoint hosts must be (sub)domains of
    /// ([`crate::config::RD_ENDPOINT_DOMAIN`]).
    pub endpoint_domain: &'static str,
    /// Trust-anchor root CA(s), PEM-encoded
    /// ([`crate::pki::RD_METADATA_TRUST_ROOTS`]).
    pub roots: &'static [&'static [u8]],
    /// Path-building intermediate CA(s), PEM-encoded
    /// ([`crate::pki::RD_METADATA_INTERMEDIATES`]).
    pub intermediates: &'static [&'static [u8]],
}

impl RdTrust {
    /// The pinned RD trust for `environment`: the RD EntityID and OIN from
    /// [`crate::config`] and the root/intermediate CAs from [`crate::pki`].
    pub fn for_environment(environment: crate::config::Environment) -> Self {
        Self {
            expected_entity_id: environment.rd_entity_id(),
            expected_oin: crate::config::RD_OIN,
            endpoint_domain: environment.rd_endpoint_domain(),
            roots: crate::pki::RD_METADATA_TRUST_ROOTS,
            intermediates: crate::pki::RD_METADATA_INTERMEDIATES,
        }
    }
}

fn pem_bytes_to_der(pem: &[u8]) -> Result<Vec<u8>> {
    let pem = std::str::from_utf8(pem)
        .map_err(|e| AuthError::Crypto(format!("non-UTF-8 certificate PEM: {e}")))?;
    Ok(CertificatePem::parse(pem)?.to_der())
}

/// Whether `leaf_der` is a trusted RD signing certificate (eID §9.1/§9.2): it
/// MUST carry the expected RD OIN in its subject AND chain to one of the pinned
/// roots via the supplied intermediates. The signing keys themselves are
/// intentionally NOT pinned (they rotate); trust derives from the chain + OIN.
fn cert_is_trusted(leaf_der: &[u8], trust: &RdTrust) -> Result<()> {
    check_rd_oin(leaf_der, trust)?;
    check_chains_to_pinned_root(leaf_der, trust)
}

/// eID §9.1: the certificate MUST contain the participant (RD) OIN, so a
/// different PKIoverheid participant's cert cannot impersonate the RD.
fn check_rd_oin(leaf_der: &[u8], trust: &RdTrust) -> Result<()> {
    match subject_oin(leaf_der) {
        Some(oin) if oin == trust.expected_oin => Ok(()),
        Some(oin) => Err(AuthError::Crypto(format!(
            "RD signing cert OIN {oin} does not match expected {}",
            trust.expected_oin
        ))),
        None => Err(AuthError::Crypto(
            "RD signing cert has no subject serialNumber (OIN)".into(),
        )),
    }
}

/// eID §9.2: the certificate MUST chain to a pinned PKIoverheid root. The RD
/// metadata ships only the leaf, so the intermediates are supplied from pki.
fn check_chains_to_pinned_root(leaf_der: &[u8], trust: &RdTrust) -> Result<()> {
    let root_ders = pem_list_to_der(trust.roots)?;
    let intermediate_ders = pem_list_to_der(trust.intermediates)?;

    let root_certs = certificates(&root_ders);
    let anchors: Vec<rustls_pki_types::TrustAnchor> = root_certs
        .iter()
        .map(webpki::anchor_from_trusted_cert)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| AuthError::Crypto(format!("invalid pinned PKIoverheid root: {e}")))?;
    let intermediates = certificates(&intermediate_ders);

    verify_cert_chain(leaf_der, &anchors, &intermediates)
}

/// Run the webpki path validation of `leaf_der` against the pinned anchors.
fn verify_cert_chain(
    leaf_der: &[u8],
    anchors: &[rustls_pki_types::TrustAnchor],
    intermediates: &[CertificateDer],
) -> Result<()> {
    let leaf = CertificateDer::from(leaf_der);
    let end_entity = webpki::EndEntityCert::try_from(&leaf)
        .map_err(|e| AuthError::Crypto(format!("invalid RD signing cert: {e}")))?;
    end_entity
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            anchors,
            intermediates,
            UnixTime::now(),
            // `server_auth()` is `required_if_present(serverAuth)`: it accepts the
            // production leaf (which carries serverAuth) and the mock leaf (no EKU).
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| {
            AuthError::Crypto(format!(
                "RD signing cert does not chain to the pinned PKIoverheid root: {e}"
            ))
        })?;
    Ok(())
}

fn pem_list_to_der(pems: &[&[u8]]) -> Result<Vec<Vec<u8>>> {
    pems.iter().map(|pem| pem_bytes_to_der(pem)).collect()
}

fn certificates(ders: &[Vec<u8>]) -> Vec<CertificateDer<'_>> {
    ders.iter()
        .map(|d| CertificateDer::from(d.as_slice()))
        .collect()
}

/// Parse metadata XML into the RD descriptor, after pinning the RD identity
/// and establishing trust (eID §9.1/§9.2).
///
/// gamlastan reads the document (§8.5 structure, endpoints, certificates,
/// `validUntil`/`cacheDuration`); the trust is anchored here, not
/// self-referential:
///  1. the metadata `entityID` MUST equal the configured `trust.expected_entity_id`;
///  2. a `validUntil` in the past (beyond the clock skew) is refused (§8.2/§8.5);
///  3. only signing certs that carry the RD OIN AND chain to the embedded
///     PKIoverheid root (`trust.roots`/`trust.intermediates`) are kept;
///  4. the enveloped XML signature is then verified against exactly those certs;
///  5. every endpoint must be a clean https URL under the pinned RD domain.
///
/// So a spoofed metadata document re-signed with an attacker's own key is
/// rejected even if the HTTPS metadata fetch is subverted. The RD signing keys
/// are not pinned individually (they rotate); trust comes from the chain + OIN.
pub fn parse_idp_metadata(xml: &str, trust: &RdTrust) -> Result<IdpMetadata> {
    debug!("[metadata] Parsing IdP metadata (xml_len={})", xml.len());
    let mut rd = gamlastan::profiles::nl_eid::parse_rd_metadata(xml)?;

    let entity_id = pinned_entity_id(&rd, trust)?;
    check_metadata_expiry(&rd, Utc::now())?;
    rd.retain_signing_keys(|key| trusted_signing_key(key, trust))
        .map_err(|e| AuthError::Crypto(format!(
            "no RD metadata signing certificate chains to the pinned PKIoverheid root with the expected OIN: {e}"
        )))?;
    debug!("[metadata] Trusted signing keys: {}", rd.signing_keys.len());
    let signed_by = rd
        .verify_signature(xml)
        .map_err(|e| AuthError::Crypto(format!("metadata signature verification failed: {e}")))?;
    debug!("[metadata] Metadata signature verified against pinned RD signing cert {signed_by}");

    let (sso_url, ars_url, slo_url) = resolve_endpoints(&rd, trust)?;
    debug!("[metadata] Endpoints resolved: sso={sso_url}, ars={ars_url}, slo={slo_url}");

    let cache_duration = rd.cache_duration_std();
    debug!("[metadata] cacheDuration parsed as {cache_duration:?}");

    let verifier = rd.verifier()?;
    Ok(IdpMetadata {
        entity_id,
        sso_url,
        ars_url,
        slo_url,
        signing_key_names: rd.signing_keys.iter().map(|k| k.key_name.clone()).collect(),
        cache_duration,
        verifier,
    })
}

/// eID §9.2 / §10.2: pin the RD identity. The expected EntityID is a configured
/// constant, not a value taken from this (only self-signature-checked) document.
fn pinned_entity_id(rd: &RdMetadata, trust: &RdTrust) -> Result<EntityId> {
    debug!("[metadata] entityID={}", rd.entity_id);
    let entity_id = EntityId::parse(rd.entity_id.as_str())?;
    if entity_id != trust.expected_entity_id {
        return Err(AuthError::Crypto(format!(
            "metadata entityID {entity_id} does not match the pinned RD EntityID {}",
            trust.expected_entity_id
        )));
    }
    Ok(entity_id)
}

/// eID §8.2/§8.5: do not use metadata past its hard expiry. If `validUntil` is
/// present and has passed (subject to clock skew), reject the document so an
/// expired descriptor, including a stale on-disk cache, is never trusted.
/// (gamlastan already refuses a document with neither `validUntil` nor
/// `cacheDuration`, eID §8.4.)
fn check_metadata_expiry(rd: &RdMetadata, now: DateTime<Utc>) -> Result<()> {
    // `checked_sub_signed`, not `-`: this runs before the signature is verified,
    // so `validUntil` is attacker-influenced, and chrono panics on a shift past
    // the edge of its range.
    let skew = chrono::Duration::seconds(DEFAULT_CLOCK_SKEW_SECONDS as i64);
    let reference = now
        .checked_sub_signed(skew)
        .ok_or_else(|| AuthError::Config("clock out of range".to_string()))?;
    if !rd.is_valid_at(reference) {
        return Err(AuthError::Config(format!(
            "metadata has expired: validUntil {:?} is in the past",
            rd.valid_until
        )));
    }
    Ok(())
}

/// eID §9.1/§9.2: a signing cert is kept only when it carries the RD OIN and
/// chains to the embedded PKIoverheid root; a rejected one is logged.
fn trusted_signing_key(key: &RdSigningKey, trust: &RdTrust) -> bool {
    match cert_is_trusted(&key.cert_der, trust) {
        Ok(()) => true,
        Err(e) => {
            warn!(
                "[metadata] Rejecting RD signing certificate {}: {e}",
                key.key_name
            );
            false
        }
    }
}

/// Resolve the three required endpoints (eID §3.1.1/§7.5/§7.7.1) and validate
/// each as a clean absolute https URL (eID §9.4) under the pinned RD domain. The
/// validation also keeps the values safe to interpolate downstream (HTML
/// attribute, CSP, HTTP target).
fn resolve_endpoints(
    rd: &RdMetadata,
    trust: &RdTrust,
) -> Result<(EndpointUrl, EndpointUrl, EndpointUrl)> {
    let endpoint = |location: &str, what: &str| -> Result<EndpointUrl> {
        let url = EndpointUrl::from_metadata(location, what)?;
        // The document is signed, but its endpoints still may not send the
        // browser or the back-channel outside the pinned RD domain.
        url.require_domain(trust.endpoint_domain, what)?;
        Ok(url)
    };
    Ok((
        endpoint(&rd.sso_url, "SingleSignOnService")?,
        endpoint(&rd.artifact_resolution_url, "ArtifactResolutionService")?,
        endpoint(&rd.single_logout_url, "SingleLogoutService")?,
    ))
}

/// On-disk cache file name for the RD (Routeringsdienst) metadata.
const RD_METADATA_CACHE_FILE: &str = "rd-metadata.xml";

/// Path of the on-disk RD metadata cache under `certs_dir`.
pub fn metadata_cache_path(certs_dir: &Path) -> PathBuf {
    certs_dir.join(RD_METADATA_CACHE_FILE)
}

/// Fetch metadata from `url` (HTTP GET), parse it, and on success persist the
/// raw document to the on-disk cache. Used at startup and by the background
/// refresh task that keeps the descriptor within its `cacheDuration`/`validUntil`
/// (eID §8.5).
///
/// The cached file is the signed document verbatim, so reloading it via
/// [`load_cached_idp_metadata`] re-runs the same signature verification. A
/// failure to write the cache is logged but does not fail the fetch.
pub async fn fetch_and_cache_idp_metadata(
    url: &str,
    certs_dir: &Path,
    trust: &RdTrust,
) -> Result<IdpMetadata> {
    info!("[metadata] Fetching IdP metadata from {url}");
    let response = reqwest::get(url).await?.error_for_status()?;
    // Cap the buffered body (see bindings::soap::read_body_capped).
    let xml = crate::bindings::soap::read_body_capped(
        response,
        crate::bindings::soap::MAX_HTTP_BODY_BYTES,
    )
    .await?;
    debug!("[metadata] Fetched metadata XML (len={})", xml.len());
    let metadata = parse_idp_metadata(&xml, trust)?;
    info!(
        "[metadata] IdP metadata loaded: entity_id={}, signing_keys={}",
        metadata.entity_id,
        metadata.signing_key_names.len(),
    );

    let path = metadata_cache_path(certs_dir);
    match write_cache(certs_dir, &path, &xml).await {
        Ok(()) => debug!("[metadata] Wrote metadata cache to {}", path.display()),
        Err(e) => warn!(
            "[metadata] Failed to write metadata cache {}: {e}",
            path.display()
        ),
    }

    Ok(metadata)
}

async fn write_cache(certs_dir: &Path, path: &Path, xml: &str) -> std::io::Result<()> {
    tokio::fs::create_dir_all(certs_dir).await?;
    tokio::fs::write(path, xml).await
}

/// Load and parse IdP metadata from the on-disk cache written by an earlier
/// [`fetch_and_cache_idp_metadata`] call. Used as a startup fallback when the
/// IdP is unreachable. Returns `None` when no cache file exists or the cached
/// document fails to parse or verify; callers treat that as "no fallback".
pub async fn load_cached_idp_metadata(certs_dir: &Path, trust: &RdTrust) -> Option<IdpMetadata> {
    let path = metadata_cache_path(certs_dir);
    let xml = tokio::fs::read_to_string(&path).await.ok()?;
    let metadata = match parse_idp_metadata(&xml, trust) {
        Ok(metadata) => metadata,
        Err(e) => {
            warn!(
                "[metadata] Ignoring invalid cached metadata at {}: {e}",
                path.display()
            );
            return None;
        }
    };

    // eID §8.5: not past cacheDuration, and never past the ceiling
    let Some(age) = cache_age(&path).await else {
        warn!(
            "[metadata] Ignoring cached metadata at {}: its age cannot be determined",
            path.display()
        );
        return None;
    };
    let max_age = metadata
        .cache_duration
        .unwrap_or(DEFAULT_CACHE_AGE)
        .min(MAX_CACHE_AGE);
    if age > max_age {
        warn!(
            "[metadata] Ignoring cached metadata at {}: written {}s ago, older than its cacheDuration of {}s",
            path.display(),
            age.as_secs(),
            max_age.as_secs()
        );
        return None;
    }

    info!(
        "[metadata] Loaded IdP metadata from disk cache {} (entity_id={}, age={}s)",
        path.display(),
        metadata.entity_id,
        age.as_secs()
    );
    Some(metadata)
}

/// Age limit for a cached descriptor without a usable `cacheDuration`.
const DEFAULT_CACHE_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// Age limit for a cached descriptor whatever its `cacheDuration` says.
const MAX_CACHE_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How long ago the cache file was written, from its modification time.
async fn cache_age(path: &Path) -> Option<Duration> {
    let written = tokio::fs::metadata(path).await.ok()?.modified().ok()?;
    Some(
        std::time::SystemTime::now()
            .duration_since(written)
            .unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{KeyPair, PrivateKeyPem};
    use gamlastan::profiles::nl_eid::{
        constants::{BINDING_HTTP_POST, BINDING_SOAP},
        rd::sign_rd_metadata_xml,
    };

    // The fixture CA directly issues the fixture rd-signing-1 cert, so it is the
    // trust anchor for the test chain (no intermediates), mirroring `tvs-mock`.
    const TEST_CA_PEM: &[u8] =
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/ca.pem"));
    const TEST_ROOTS: &[&[u8]] = &[TEST_CA_PEM];
    const NO_INTERMEDIATES: &[&[u8]] = &[];
    const FIXTURE_OIN: &str = "00000004000000149000";
    const RD: &str = "urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:9002";

    fn test_trust(entity_id: &'static str) -> RdTrust {
        RdTrust {
            expected_entity_id: EntityId::from_static(entity_id),
            expected_oin: FIXTURE_OIN,
            endpoint_domain: "rd.test",
            roots: TEST_ROOTS,
            intermediates: NO_INTERMEDIATES,
        }
    }

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures")
                .join(name),
        )
        .unwrap()
    }

    fn rd_key() -> KeyPair {
        KeyPair::from_pem(
            CertificatePem::parse(fixture("rd-signing-1.pem")).unwrap(),
            PrivateKeyPem::new(fixture("rd-signing-1-key.pem")),
        )
    }

    /// Unsigned RD metadata (eID §8.5) publishing `cert` as its signing key,
    /// with extra attributes (e.g. `validUntil` / `cacheDuration`) on the root.
    fn rd_metadata_xml(entity_id: &str, cert: &KeyPair, root_attrs: &str) -> String {
        let key_info = cert.published().key_info_xml();
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" ID="_rdmeta1" entityID="{entity_id}"{root_attrs}><md:IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:KeyDescriptor use="signing">{key_info}</md:KeyDescriptor><md:ArtifactResolutionService Binding="{BINDING_SOAP}" Location="https://rd.test/ars" index="0"/><md:SingleSignOnService Binding="{BINDING_HTTP_POST}" Location="https://rd.test/sso"/><md:SingleLogoutService Binding="{BINDING_HTTP_POST}" Location="https://rd.test/slo"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        )
    }

    /// RD metadata signed by the fixture `rd-signing-1` key, as TVS signs it
    /// (`KeyName`-only `KeyInfo`, signature first).
    fn signed_rd_metadata(entity_id: &str, root_attrs: &str) -> String {
        let key = rd_key();
        sign_rd_metadata_xml(
            &rd_metadata_xml(entity_id, &key, root_attrs),
            "_rdmeta1",
            &key.signer().expect("fixture signer"),
            key.key_name.as_str(),
        )
        .expect("sign metadata")
    }

    // -- RD signing-cert trust (eID §9.1/§9.2) --

    #[test]
    fn cert_is_trusted_accepts_fixture_rd_signing() {
        // rd-signing-1 carries the RD OIN and chains to the fixture CA.
        assert!(cert_is_trusted(&rd_key().cert_pem.to_der(), &test_trust("urn:any")).is_ok());
    }

    #[test]
    fn cert_is_trusted_rejects_wrong_oin() {
        let trust = RdTrust {
            expected_oin: "99999999999999999999",
            ..test_trust("urn:any")
        };
        assert!(cert_is_trusted(&rd_key().cert_pem.to_der(), &trust).is_err());
    }

    #[test]
    fn cert_is_trusted_rejects_cert_not_chaining_to_pinned_root() {
        // Right OIN, but no trust anchor to chain to -> rejected.
        let trust = RdTrust {
            roots: &[],
            ..test_trust("urn:any")
        };
        assert!(cert_is_trusted(&rd_key().cert_pem.to_der(), &trust).is_err());
    }

    #[test]
    fn parse_idp_metadata_accepts_pinned_fixture_signed_metadata() {
        let signed = signed_rd_metadata(RD, r#" cacheDuration="PT24H""#);
        let md = parse_idp_metadata(&signed, &test_trust(RD)).expect("must parse");
        assert_eq!(md.entity_id.as_str(), RD);
        assert_eq!(md.sso_url.as_str(), "https://rd.test/sso");
        assert_eq!(md.ars_url.as_str(), "https://rd.test/ars");
        assert_eq!(md.slo_url.as_str(), "https://rd.test/slo");
        assert_eq!(
            md.signing_key_names,
            vec![rd_key().key_name.as_str().to_owned()]
        );
        // eID §8.5: cacheDuration is parsed for the refresh-cadence hint.
        assert_eq!(md.cache_duration, Some(Duration::from_secs(24 * 3600)));
        // The verifier knows the RD key by its KeyName and nothing else.
        assert!(
            md.verifier()
                .keys_manager()
                .find_by_name(rd_key().key_name.as_str())
                .is_some()
        );
        // The debug form never prints the verifier's key material.
        assert!(format!("{md:?}").contains("signing_key_names"));
    }

    #[test]
    fn parse_idp_metadata_rejects_a_document_signed_by_an_untrusted_key() {
        // Published and signed consistently, but by a key that neither carries
        // the RD OIN nor chains to the pinned root: the trust filter leaves no
        // key, so the document is refused before its signature is even checked.
        let key = KeyPair::from_pem(
            CertificatePem::parse(fixture("dv-signing-1.pem")).unwrap(),
            PrivateKeyPem::new(fixture("dv-signing-1-key.pem")),
        );
        let signed = sign_rd_metadata_xml(
            &rd_metadata_xml(RD, &key, r#" cacheDuration="PT24H""#),
            "_rdmeta1",
            &key.signer().unwrap(),
            key.key_name.as_str(),
        )
        .unwrap();
        let err = parse_idp_metadata(&signed, &test_trust(RD)).unwrap_err();
        assert!(
            matches!(&err, AuthError::Crypto(m) if m.contains("pinned PKIoverheid root")),
            "{err:?}"
        );
    }

    #[test]
    fn parse_idp_metadata_rejects_unsigned_and_tampered_documents() {
        let unsigned = rd_metadata_xml(RD, &rd_key(), r#" cacheDuration="PT24H""#);
        let err = parse_idp_metadata(&unsigned, &test_trust(RD)).unwrap_err();
        assert!(
            matches!(&err, AuthError::Crypto(m) if m.contains("signature verification failed")),
            "{err:?}"
        );
        let tampered = signed_rd_metadata(RD, r#" cacheDuration="PT24H""#).replacen(
            "https://rd.test/ars",
            "https://evil.rd.test/ars",
            1,
        );
        let err = parse_idp_metadata(&tampered, &test_trust(RD)).unwrap_err();
        assert!(
            matches!(&err, AuthError::Crypto(m) if m.contains("signature verification failed")),
            "{err:?}"
        );
    }

    #[test]
    fn parse_idp_metadata_rejects_endpoints_outside_the_pinned_domain() {
        // A correctly signed document whose endpoints point elsewhere is
        // refused: the signature authenticates the endpoints, the pin bounds them.
        let signed = signed_rd_metadata(RD, r#" cacheDuration="PT24H""#);
        assert!(parse_idp_metadata(&signed, &test_trust(RD)).is_ok());
        let trust = RdTrust {
            endpoint_domain: "toegang.overheid.nl",
            ..test_trust(RD)
        };
        let err = parse_idp_metadata(&signed, &trust).unwrap_err();
        assert!(
            err.to_string().contains("not under the pinned RD domain"),
            "{err}"
        );
    }

    #[test]
    fn parse_idp_metadata_rejects_expired_metadata() {
        // eID §8.2/§8.5: a past validUntil must be rejected (stale metadata).
        let signed = signed_rd_metadata(RD, r#" validUntil="2000-01-01T00:00:00Z""#);
        let err = parse_idp_metadata(&signed, &test_trust(RD)).unwrap_err();
        assert!(
            matches!(&err, AuthError::Config(m) if m.contains("expired")),
            "{err:?}"
        );
    }

    #[test]
    fn parse_idp_metadata_accepts_unexpired_metadata() {
        let signed = signed_rd_metadata(RD, r#" validUntil="2999-01-01T00:00:00Z""#);
        assert!(parse_idp_metadata(&signed, &test_trust(RD)).is_ok());
    }

    #[test]
    fn parse_idp_metadata_requires_valid_until_or_cache_duration() {
        // eID §8.4: "Either validUntil or cacheDuration MUST be present". With
        // neither, the descriptor has no expiry and no refresh hint, so it would
        // pin the RD's keys indefinitely.
        let err = parse_idp_metadata(&signed_rd_metadata(RD, ""), &test_trust(RD)).unwrap_err();
        assert!(matches!(err, AuthError::Saml(_)), "{err:?}");

        // Either one alone is enough, and so is both together.
        for attrs in [
            r#" cacheDuration="PT24H""#,
            r#" validUntil="2999-01-01T00:00:00Z""#,
            r#" validUntil="2999-01-01T00:00:00Z" cacheDuration="PT24H""#,
        ] {
            assert!(
                parse_idp_metadata(&signed_rd_metadata(RD, attrs), &test_trust(RD)).is_ok(),
                "{attrs} must be accepted"
            );
        }

        // An expired validUntil is still fatal even when a cacheDuration is
        // present, so a long refresh hint cannot keep a dead descriptor alive.
        assert!(
            parse_idp_metadata(
                &signed_rd_metadata(
                    RD,
                    r#" validUntil="2000-01-01T00:00:00Z" cacheDuration="PT24H""#
                ),
                &test_trust(RD)
            )
            .is_err()
        );
    }

    #[test]
    fn parse_idp_metadata_rejects_entity_id_mismatch() {
        let signed = signed_rd_metadata(RD, r#" cacheDuration="PT24H""#);
        let err = parse_idp_metadata(
            &signed,
            &test_trust("urn:nl-eid-gdi:1.0:RD:00000004000000149000:entities:0001"),
        )
        .unwrap_err();
        assert!(matches!(err, AuthError::Crypto(_)), "{err:?}");
    }

    #[test]
    fn parse_idp_metadata_rejects_a_document_that_is_not_rd_metadata() {
        let err = parse_idp_metadata("<not-metadata/>", &test_trust(RD)).unwrap_err();
        assert!(matches!(err, AuthError::Saml(_)), "{err:?}");
        let err = parse_idp_metadata("502 Bad Gateway", &test_trust(RD)).unwrap_err();
        assert!(matches!(err, AuthError::Saml(_)), "{err:?}");
    }

    #[test]
    fn metadata_cache_path_appends_filename() {
        let path = metadata_cache_path(Path::new("/tmp/certs"));
        assert_eq!(path, Path::new("/tmp/certs/rd-metadata.xml"));
    }

    fn unique_temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("idp-meta-test-{}", uuid::Uuid::new_v4()))
    }

    #[tokio::test]
    async fn load_cached_returns_none_when_absent() {
        // No cache file written, so no fallback available.
        assert!(
            load_cached_idp_metadata(&unique_temp_dir(), &test_trust(RD))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn load_cached_returns_none_past_cache_duration() {
        let dir = unique_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = metadata_cache_path(&dir);
        std::fs::write(&path, signed_rd_metadata(RD, r#" cacheDuration="PT1H""#)).unwrap();
        let trust = test_trust(RD);

        assert!(
            load_cached_idp_metadata(&dir, &trust).await.is_some(),
            "a fresh cache is used"
        );

        let two_hours_ago = std::time::SystemTime::now() - Duration::from_secs(2 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(two_hours_ago)
            .unwrap();
        assert!(
            load_cached_idp_metadata(&dir, &trust).await.is_none(),
            "a cache past its cacheDuration is not trusted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn load_cached_returns_none_for_invalid_document() {
        // A cache file that fails to parse/verify is ignored, not surfaced.
        let dir = unique_temp_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(metadata_cache_path(&dir), "<not-metadata/>").unwrap();
        assert!(
            load_cached_idp_metadata(&dir, &test_trust(RD))
                .await
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

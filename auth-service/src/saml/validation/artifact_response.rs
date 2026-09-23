//! SOAP-wrapped ArtifactResponse validation (eID §7.6.1).

use super::helpers::Validator;
use crate::{
    keys::KeyPair,
    saml::{
        constants::{NS_SAMLP, STATUS_SUCCESS},
        model::{ArtifactResponse, Response},
        verification::{ExpectedRoot, verify_xml_signature},
        xml::Document,
    },
    types::{EntityId, MessageId},
};
use tracing::debug;

/// Expectations for [`validate_artifact_response_at`]: the RD signing certs from
/// verified metadata (eID §9.2), the `@ID` of the ArtifactResolve this response
/// must answer, and the pinned RD EntityID its Issuer must carry.
///
/// `None` skips a check; only tests pass it, and the production caller
/// ([`crate::handlers::acs`]) supplies every one.
pub struct ValidateArtifactResponseOpts<'a> {
    pub trusted_keys: &'a [KeyPair],
    pub expected_in_response_to: Option<&'a MessageId>,
    pub expected_issuer: Option<&'a EntityId>,
}

/// Validate `art`, read from the already-parsed document `doc` (eID §7.6.1),
/// and return its inner Response.
///
/// Checks (all §7.6.1): `@Version`, signature, Issuer, InResponseTo, status code
/// and `@IssueInstant` staleness.
/// eID §9.2: the signature verification key MUST come from verified RD metadata.
/// The signature is verified over the source bytes of the very element `art`
/// was read from, so what is verified is what the caller consumes.
pub fn validate_artifact_response_at<'r>(
    doc: &Document,
    art: &'r ArtifactResponse,
    opts: &ValidateArtifactResponseOpts<'_>,
    errors: &mut Vec<String>,
) -> Option<&'r Response> {
    let mut v = Validator::new(doc, errors);
    v.check_version(art.version.as_deref(), "ArtifactResponse");
    v.check_signature(art, opts.trusted_keys);
    // eID §7.6.1: the Issuer MUST be the RD EntityID. The signature is already
    // verified against an RD signing cert from metadata, but binding the Issuer
    // element mirrors the Response/Assertion checks and rejects a signed-by-RD
    // envelope whose Issuer nonetheless names a different entity.
    v.check_issuer(
        art.issuer.as_deref(),
        opts.expected_issuer,
        "ArtifactResponse",
    );
    v.check_in_response_to(art.in_response_to.as_deref(), opts.expected_in_response_to);
    // eID §7.6.1: require Success; the second-level StatusCode and StatusMessage
    // carry the actual reason and are composed into the error (§7.8).
    let status_code = v.check_status_success(art.status.as_ref(), "ArtifactResponse");

    // Bound how stale the ArtifactResponse envelope may be (it carries no Conditions).
    v.check_freshness(
        art.issue_instant.as_deref(),
        "ArtifactResponse @IssueInstant",
    );

    let response = v.extract_response(&art.responses, status_code.as_deref());
    debug!(
        "[validate] ArtifactResponse done: valid={}, errors={}",
        errors.is_empty(),
        errors.len()
    );
    response
}

/// The ArtifactResponse-level checks (eID §7.6.1), as methods on the shared
/// [`Validator`].
impl Validator<'_, '_> {
    fn check_signature(&mut self, art: &ArtifactResponse, trusted_keys: &[KeyPair]) {
        debug!("[validate] Verifying ArtifactResponse XML signature");
        let Some(xml) = self.signed_element_source(art) else {
            return;
        };
        // SECURITY (XSW): these bytes get re-parsed twice more while the claims are
        // read from *this* parse. Naming the element we consume makes "the
        // signature covered what I read" a check, not an inference.
        let expected_root = ExpectedRoot {
            namespace: NS_SAMLP,
            local_name: "ArtifactResponse",
            id: art.id.as_deref(),
        };
        let sig_result = verify_xml_signature(&xml, trusted_keys, &expected_root);
        if !sig_result.is_valid() {
            self.errors.extend(
                sig_result
                    .errors
                    .iter()
                    .map(|e| format!("ArtifactResponse sig: {e}")),
            );
        } else {
            debug!("[validate] ArtifactResponse signature OK");
        }
    }

    /// The signed ArtifactResponse element as a standalone document.
    ///
    /// The RD normally declares the SAML/dsig namespaces on the ArtifactResponse
    /// itself, so its raw bytes are used verbatim. When they are declared on an
    /// ancestor instead the inherited declarations are restored
    /// (digest-preserving under exclusive c14n, see
    /// [`Document::standalone_source`]). The `ExpectedRoot` binding in
    /// `check_signature` is what keeps that reconstruction honest.
    fn signed_element_source(&mut self, art: &ArtifactResponse) -> Option<String> {
        let source = self.doc.standalone_source(art.element);
        if source.is_none() {
            // Not a forgery signal but an RD serialization we cannot make
            // self-contained. Say so, or it surfaces as an opaque parse error.
            self.error(
                "ArtifactResponse sig: the signed element does not parse standalone even with \
                 its inherited namespace declarations restored (unexpected RD serialization)"
                    .to_string(),
            );
        }
        source
    }

    fn check_in_response_to(&mut self, in_response_to: Option<&str>, expected: Option<&MessageId>) {
        let Some(expected) = expected else {
            return;
        };
        let in_response_to = in_response_to.unwrap_or("");
        debug!(
            "[validate] ArtifactResponse InResponseTo='{in_response_to}' (expected='{expected}')"
        );
        if in_response_to != expected.as_str() {
            self.error(format!(
                "ArtifactResponse InResponseTo mismatch: expected {expected}, got {in_response_to}"
            ));
        }
    }

    // eID §7.6.1 (and SAML-bindings §3.6.6, quoted in §7.6.1): `Response` is
    // conditional, and a `Success` status does NOT guarantee it is present (the
    // requester may be unauthorized or the artifact already spent). The missing
    // Response is reported on the success path regardless of other errors, so the
    // caller never treats "signature fine, status Success" as a usable response;
    // more than one Response is ambiguous and rejected rather than picking one.
    fn extract_response<'r>(
        &mut self,
        responses: &'r [Response],
        status_code: Option<&str>,
    ) -> Option<&'r Response> {
        let response = responses.first();
        debug!(
            "[validate] Extracted inner Response: present={}",
            response.is_some()
        );
        if response.is_none() && status_code == Some(STATUS_SUCCESS) {
            self.error(
                "ArtifactResponse reports Success but carries no Response (artifact expired, \
                 already resolved, or requester not authorized)"
                    .to_string(),
            );
        }
        if responses.len() > 1 {
            self.error(format!(
                "ArtifactResponse carries {} Response elements (at most one is allowed)",
                responses.len()
            ));
        }
        response
    }
}

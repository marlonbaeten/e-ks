//! Assertion validation and claim extraction (eID §7.6.3, processing rules §7.6.3.5).

use super::helpers::Validator;
use crate::{
    keys::DecryptionKey,
    saml::{
        constants::{
            EID_ACTING_SUBJECT_ID, EID_ID_TYPES, EID_LEGAL_SUBJECT_ID, EID_SERVICE_UUID,
            NAMEID_PERSISTENT, NAMEID_TRANSIENT, SUBJECT_CONFIRMATION_BEARER,
        },
        decryption::{DecryptedNameId, decrypt_encrypted_id},
        loa::LevelOfAssurance,
        model::{self, Assertion, Attribute, SubjectConfirmation, SubjectConfirmationData},
        subject::SubjectId,
        xml::Document,
    },
    types::{EndpointUrl, EntityId, MessageId, NameId, ServiceUuid},
};
use secrecy::ExposeSecret;
use tracing::debug;

/// Claims extracted from a validated Assertion.
pub struct Claims {
    /// The Subject TransientID NameID. eID §7.6.3 mandates it (cardinality 1),
    /// so a successfully validated assertion always carries one; the caller
    /// persists it to build the later `LogoutRequest` (§7.7.1 / §7.6.3.5).
    pub name_id: NameId,
    pub authn_context_class_ref: Option<String>,
    pub authenticating_authority: Option<String>,
    pub acting_subject_id: Option<SubjectId>,
    pub legal_subject_id: Option<SubjectId>,
    pub service_uuid: Option<String>,
    /// The `InResponseTo` from SubjectConfirmationData, for the caller's replay
    /// check (eID §7.6.3.5 rule 4 / §9.7): the caller verifies it against the
    /// outstanding AuthnRequest IDs and atomically consumes the match. `None` if
    /// the assertion carried no `InResponseTo`.
    pub in_response_to: Option<MessageId>,
}

/// Inputs to [`validate_assertion_at`].
pub struct ValidateAssertionOpts<'a> {
    pub dv_entity_id: &'a EntityId,
    /// The DV ACS the assertion's `Recipient` MUST name (eID §7.6.3.5 rule 2).
    /// `None` skips the check (tests).
    pub expected_recipient: Option<&'a EndpointUrl>,
    /// Expected Assertion `Issuer`: the RD (TVS) EntityID. The Assertion is not
    /// signed independently; its authenticity comes from the RD-signed
    /// ArtifactResponse envelope, and signatures inside an Assertion/Advice are
    /// evidence-only (eID §9.1). Binding the Issuer to the RD EntityID matches the
    /// TVS reference impl (`minvws/nl-rdo-max`). `None` skips the check (tests).
    pub expected_issuer: Option<&'a EntityId>,
    /// DV private keys tried for EncryptedID decryption.
    pub private_keys: &'a [DecryptionKey<'a>],
    /// Minimum required LoA. `None` skips the check (used by tests that
    /// exercise non-LoA validation paths). Production callers pass
    /// `Some(MINIMUM_LOA)`.
    pub minimum_loa: Option<LevelOfAssurance>,
    /// Expected DV `ServiceUUID` (eID §7.6.3.4): the assertion's ServiceUUID
    /// attribute MUST equal this. `None` skips the check (tests).
    pub expected_service_uuid: Option<&'a ServiceUuid>,
}

/// Validate `assertion`, read from the already-parsed document `doc`, per eID
/// §7.6.3 and processing rules §7.6.3.5, and extract [`Claims`].
///
/// Mirrors the envelope validators: failures are pushed onto `errors` and the
/// extracted value is returned, `Some` only when no error was recorded.
///
/// Authenticity comes from the enveloping RD signature on the ArtifactResponse
/// (verified in [`validate_artifact_response_at`]); per eID §9.1, signatures inside
/// an Assertion/Advice are evidence-only and not separately validated (matching
/// the TVS reference impl `minvws/nl-rdo-max`). The `<saml:Advice>` evidence
/// subtree is not part of the [`Assertion`] model at all, so claims come only
/// from the outer RD Assertion.
///
/// Processing rules implemented (eID §7.6.3.5):
///  1. Issuer is the expected RD EntityID (rule 1, binding)
///  2. Recipient in SubjectConfirmationData (rule 2)
///  3. NotOnOrAfter has not passed (rule 3)
///  4. InResponseTo matches the original AuthnRequest ID (rule 4): extracted into
///     `Claims::in_response_to`; the match-and-consume is done by the caller (see
///     `handle_acs`), which atomically consumes the pending ID against the
///     application's store to prevent replay
///  5. DV EntityID is in AudienceRestriction (rule 5)
///  6. General validity: conditions, timing (rule 6)
///  7. Invalid assertions are discarded (rule 7)
///
/// [`validate_artifact_response_at`]: super::validate_artifact_response_at
pub fn validate_assertion_at(
    doc: &Document,
    assertion: &Assertion,
    opts: &ValidateAssertionOpts<'_>,
    errors: &mut Vec<String>,
) -> Option<Claims> {
    let base_error_count = errors.len();
    let mut v = Validator::new(doc, errors);

    v.check_version(assertion.version.as_deref(), "Assertion");
    // §7.6.3.5 rule 1 (binding): the Assertion Issuer MUST be the RD (TVS)
    // EntityID, ensuring the RD-signed payload originates from the RD.
    v.check_issuer(
        assertion.issuer.as_deref(),
        opts.expected_issuer,
        "Assertion",
    );
    v.check_subject_confirmation(assertion, opts);
    v.check_conditions(assertion);
    v.check_audience_restriction(assertion, opts.dv_entity_id);
    v.check_assertion_instants(assertion);

    // Extraction records its own errors (NameID format, LoA, ServiceUUID,
    // decrypted-ID shape), so it runs before the validity verdict.
    let claims = v.extract_claims(assertion, opts);

    let valid = errors.len() == base_error_count;
    debug!(
        "[validate] Assertion done: valid={valid}, errors={}",
        errors.len()
    );
    if !valid {
        return None;
    }
    // A clean run implies the mandatory Subject NameID (eID §7.6.3) was found, so
    // this is `Some`; returning the `Option` as-is rather than unwrapping keeps
    // the failure closed if that invariant ever stops holding.
    claims
}

fn subject_confirmation(assertion: &Assertion) -> Option<&SubjectConfirmation> {
    assertion.subject.as_ref()?.subject_confirmation.as_ref()
}

/// The `<saml:Attribute>`s of the Assertion's `<AttributeStatement>`s (eID
/// §7.6.3.4), in document order. An `<Attribute>` anywhere else (say an
/// extension point of `<Conditions>`) is not in the model, so never a claim.
fn attributes(assertion: &Assertion) -> impl Iterator<Item = &Attribute> {
    assertion
        .attribute_statements
        .iter()
        .flat_map(|s| &s.attributes)
}

/// The assertion-level checks and claim extraction (eID §7.6.3), as methods on
/// the shared [`Validator`] context.
impl Validator<'_, '_> {
    /// Extract the [`Claims`], recording any extraction-level errors (NameID
    /// format, LoA, ServiceUUID, decrypted-ID shape). Returns `None` only when
    /// the mandatory Subject NameID is absent, which
    /// `check_subject_name_id_format` has then already recorded as an error.
    fn extract_claims(
        &mut self,
        assertion: &Assertion,
        opts: &ValidateAssertionOpts<'_>,
    ) -> Option<Claims> {
        let name_id = self.checked_subject_name_id(assertion);

        let (authn_context_class_ref, authenticating_authority) =
            self.check_authn_context(assertion, opts.minimum_loa);

        let (acting_subject_id, legal_subject_id) =
            self.extract_encrypted_subject_ids(assertion, opts);

        // Extract InResponseTo from SubjectConfirmationData for replay protection
        // (eID §9.7). A value that is not a well-formed message ID names no
        // AuthnRequest this DV could have issued, so it is dropped here and the
        // caller's rule-4 check then fails closed on the absent value.
        let in_response_to = subject_confirmation(assertion)
            .and_then(|sc| sc.data.as_ref()?.in_response_to.as_deref())
            .and_then(|id| MessageId::parse(id).ok());

        let service_uuid = self.check_service_uuid(assertion, opts.expected_service_uuid);
        debug!(
            "[validate] in_response_to_present={}, service_uuid_present={}, \
             acting_subject_present={}, legal_subject_present={}",
            in_response_to.is_some(),
            service_uuid.is_some(),
            acting_subject_id.is_some(),
            legal_subject_id.is_some(),
        );

        Some(Claims {
            name_id: name_id?,
            authn_context_class_ref,
            authenticating_authority,
            acting_subject_id,
            legal_subject_id,
            service_uuid,
            in_response_to,
        })
    }

    /// The Subject NameID text, with its presence and Format checked.
    ///
    /// eID §7.6.3: the Subject NameID (a TransientID) is read from the outer
    /// assertion's `<Subject>`, not from a SubjectConfirmation or the Advice
    /// subtree.
    fn checked_subject_name_id(&mut self, assertion: &Assertion) -> Option<NameId> {
        let name_id = assertion.subject.as_ref().and_then(|s| s.name_id.as_ref());
        self.check_subject_name_id_format(name_id);
        // The NameID is echoed back to the RD in the later LogoutRequest, so an
        // empty or otherwise unusable one is rejected here rather than carried.
        let name_id = match name_id.map(|n| NameId::parse(&n.value)) {
            Some(Ok(name_id)) => Some(name_id),
            Some(Err(e)) => {
                self.error(format!("Subject NameID is not usable: {e}"));
                None
            }
            None => None,
        };
        debug!("[validate] NameID present={}", name_id.is_some());
        name_id
    }

    // Bound how stale this Assertion and its authentication act may be. Both
    // instants are mandatory (eID §7.6.3, cardinality 1), so absence is an error.
    fn check_assertion_instants(&mut self, assertion: &Assertion) {
        self.check_freshness(
            assertion.issue_instant.as_deref(),
            "Assertion @IssueInstant",
        );
        // eID §7.6.3 (cardinality 1): the AuthnStatement itself is mandatory; a
        // missing one is reported as such rather than only via its @AuthnInstant.
        match &assertion.authn_statement {
            Some(stmt) => self.check_freshness(
                stmt.authn_instant.as_deref(),
                "AuthnStatement @AuthnInstant",
            ),
            None => self.error("Assertion is missing the required AuthnStatement".to_string()),
        }
    }

    // eID §7.6.3.4: extract the ServiceUUID attribute (unencrypted, always
    // present) and require it to equal the DV's registered one, so an assertion
    // minted for another service is rejected. `expected` of `None` skips the
    // check (tests).
    fn check_service_uuid(
        &mut self,
        assertion: &Assertion,
        expected: Option<&ServiceUuid>,
    ) -> Option<String> {
        // Trimmed at extraction so the returned claim matches what we compare.
        let service_uuid = attributes(assertion)
            .find(|a| a.name.as_deref() == Some(EID_SERVICE_UUID))
            .and_then(|a| a.values.first()?.text.as_deref())
            .map(|u| u.trim().to_string());

        if let Some(expected) = expected {
            match service_uuid.as_deref() {
                Some(u) if u == expected.as_str() => {}
                Some(u) => self.error(format!(
                    "ServiceUUID mismatch: expected {expected}, got {u}"
                )),
                None => self.error("Assertion is missing the required ServiceUUID".to_string()),
            }
        }
        service_uuid
    }

    // eID §7.6.3: the Subject <NameID> MUST be present and be a TransientID.
    fn check_subject_name_id_format(&mut self, name_id: Option<&model::NameId>) {
        let Some(name_id) = name_id else {
            // eID §7.6.3 (cardinality 1): the Subject NameID is mandatory. Fail
            // closed so `Claims.name_id` is guaranteed present on success.
            self.error("Assertion is missing the required Subject NameID".to_string());
            return;
        };
        // SAML 2.0 core §2.2.2: an omitted Format defaults to "unspecified". The
        // TVS preprod IdP omits it on the Subject NameID; tolerate absence (the
        // acting identity comes from the decrypted EncryptedID, not this NameID)
        // but still reject a present-but-non-transient Format.
        match name_id.format.as_deref() {
            None | Some(NAMEID_TRANSIENT) => {}
            Some(format) => self.error(format!(
                "Subject NameID Format must be {NAMEID_TRANSIENT} (a TransientID), got '{format}'"
            )),
        }
    }

    // eID §7.6.3.3: SubjectConfirmation validation (method, recipient, expiry).
    fn check_subject_confirmation(
        &mut self,
        assertion: &Assertion,
        opts: &ValidateAssertionOpts<'_>,
    ) {
        let Some(sc) = subject_confirmation(assertion) else {
            // eID §7.6.3 (cardinality 1) / §7.6.3.5 rules 2-3: SubjectConfirmation
            // is mandatory and carries the Recipient/expiry/InResponseTo bindings,
            // so its absence fails closed rather than skipping those checks.
            debug!("[validate] No SubjectConfirmation element found");
            self.error("Assertion is missing the required SubjectConfirmation".to_string());
            return;
        };
        // §7.6.3.3: Method MUST be bearer.
        let method = sc.method.as_deref().unwrap_or("");
        debug!("[validate] SubjectConfirmation Method='{method}'");
        if method != SUBJECT_CONFIRMATION_BEARER {
            self.error(format!("Expected bearer SubjectConfirmation, got {method}"));
        }

        let Some(scd) = &sc.data else {
            // eID §7.6.3.3 (cardinality 1): mandatory; without it there is no
            // Recipient / NotOnOrAfter / InResponseTo to validate, so fail closed.
            self.error(
                "SubjectConfirmation is missing the required SubjectConfirmationData".to_string(),
            );
            return;
        };
        self.check_subject_confirmation_data(scd, opts.expected_recipient);

        // §7.6.3.5 rule 4 (InResponseTo matches one of our AuthnRequest IDs) is
        // enforced by the caller, not here: matching must atomically *consume* the
        // pending ID to prevent replay (eID §9.7), and the pending-ID store lives
        // in the embedding application (so the IDs can be shared across
        // instances). The raw value is extracted into `Claims::in_response_to`
        // for that check; see `handle_acs`.
    }

    // eID §7.6.3.3 / §7.6.3.5 rules 2-3: the SubjectConfirmationData expiry and
    // Recipient bindings.
    fn check_subject_confirmation_data(
        &mut self,
        scd: &SubjectConfirmationData,
        expected_recipient: Option<&EndpointUrl>,
    ) {
        // §7.6.3.5 rule 3: Verify NotOnOrAfter has not passed.
        // §7.6.3.3: Initially set to +2 minutes; @NotBefore MUST NOT be used.
        debug!(
            "[validate] Rule 3: SubjectConfirmation NotOnOrAfter={:?}",
            scd.not_on_or_after
        );
        self.check_not_on_or_after(scd.not_on_or_after.as_deref(), "SubjectConfirmation");

        // eID §7.6.3.3 (and SAML core §2.4.1.2 for bearer): @NotBefore MUST NOT
        // be used on SubjectConfirmationData. Its presence means the sender is
        // not following the profile we validate against, so fail closed rather
        // than ignore an attribute that would widen the bearer window.
        if let Some(nb) = &scd.not_before {
            self.error(format!(
                "SubjectConfirmationData carries @NotBefore ({nb}), which eID §7.6.3.3 forbids"
            ));
        }

        // §7.6.3.5 rule 2: Verify Recipient matches ACS URL.
        let Some(expected_recipient) = expected_recipient else {
            return;
        };
        let recipient = scd.recipient.as_deref().unwrap_or("");
        debug!("[validate] Rule 2: Recipient='{recipient}' (expected='{expected_recipient}')");
        if recipient != expected_recipient.as_str() {
            self.error(format!(
                "Recipient mismatch: expected {expected_recipient}, got {recipient}"
            ));
        }
    }

    // eID §7.6.3 / §9.5: Conditions NotBefore and NotOnOrAfter window.
    fn check_conditions(&mut self, assertion: &Assertion) {
        let Some(cond) = &assertion.conditions else {
            // eID §7.6.3 (cardinality 1) / §9.5: Conditions with its NotBefore /
            // NotOnOrAfter validity window is mandatory; fail closed on its
            // absence rather than treating the assertion as unconditionally
            // time-valid.
            debug!("[validate] No Conditions element found");
            self.error("Assertion is missing the required Conditions".to_string());
            return;
        };
        debug!(
            "[validate] Rule 6: Conditions NotBefore={:?}, NotOnOrAfter={:?}",
            cond.not_before, cond.not_on_or_after,
        );
        self.check_not_before(cond.not_before.as_deref(), "Assertion Conditions");
        self.check_not_on_or_after(cond.not_on_or_after.as_deref(), "Assertion");
    }

    // §7.6.3.5 rule 5: Verify DV EntityID is in AudienceRestriction.
    // eID §7.6.3.1: Assertion may only be processed if AudienceRestriction
    // contains the DV EntityID.
    fn check_audience_restriction(&mut self, assertion: &Assertion, dv_entity_id: &EntityId) {
        // Trimmed because an <Audience> holds one EntityID token and the RD
        // pretty-prints around it.
        let audiences: Vec<&str> = assertion
            .conditions
            .iter()
            .flat_map(|c| &c.audience_restrictions)
            .flat_map(|r| &r.audiences)
            .map(|a| a.trim())
            .collect();
        debug!(
            "[validate] Rule 5: AudienceRestriction has {} audience(s); expected '{}'",
            audiences.len(),
            dv_entity_id
        );
        if !audiences.contains(&dv_entity_id.as_str()) {
            self.error(format!(
                "DV entityId {} not in AudienceRestriction: [{}]",
                dv_entity_id,
                audiences.join(", ")
            ));
        }
    }

    // eID §7.6.3: AuthnStatement with AuthnContextClassRef and AuthenticatingAuthority.
    // eID §7.6.3.2: DV MUST accept LoA equal to or higher than minimum registered level.
    // TVS "Checklist Testen" v2.1 T6: accept equal or higher, reject lower.
    // https://tvs.dictu.nl/sites/default/files/documents/Checklist-Testen-TVS-2.1.pdf
    fn check_authn_context(
        &mut self,
        assertion: &Assertion,
        minimum_loa: Option<LevelOfAssurance>,
    ) -> (Option<String>, Option<String>) {
        // Both are a single URI token and the RD pretty-prints around them; the
        // §10.3 lookup below is an exact match, so an untrimmed value reads as an
        // unrecognised LoA.
        let authn_context = assertion
            .authn_statement
            .as_ref()
            .and_then(|s| s.authn_context.as_ref());
        let authn_context_class_ref = authn_context
            .and_then(|c| c.class_ref.as_deref())
            .map(|t| t.trim().to_string());
        let authenticating_authority = authn_context
            .and_then(|c| c.authenticating_authorities.first())
            .map(|t| t.trim().to_string());
        debug!(
            "[validate] AuthnContextClassRef={:?}, AuthenticatingAuthority={:?}",
            authn_context_class_ref.as_deref(),
            authenticating_authority.as_deref()
        );

        if let Some(min) = minimum_loa {
            match &authn_context_class_ref {
                Some(loa) => match LevelOfAssurance::from_uri(loa) {
                    Some(level) if level >= min => {
                        debug!("[validate] LoA OK: {level:?} >= minimum {min:?}");
                    }
                    Some(level) => self.error(format!(
                        "LoA too low: got {loa} ({level:?}), minimum required is {min:?}"
                    )),
                    None => self.error(format!(
                        "Unrecognized LoA URI: {loa}, minimum required is {min:?}"
                    )),
                },
                None => {
                    self.error(
                        "Assertion is missing the required AuthnContextClassRef".to_string(),
                    );
                }
            }
        }

        (authn_context_class_ref, authenticating_authority)
    }

    // eID §7.6.3.4: Decrypt EncryptedID attributes (ActingSubjectID, LegalSubjectID).
    // eID §7.6.3.4.4: Identifiers in EncryptedID, decrypted with DV's private key.
    fn extract_encrypted_subject_ids(
        &mut self,
        assertion: &Assertion,
        opts: &ValidateAssertionOpts<'_>,
    ) -> (Option<SubjectId>, Option<SubjectId>) {
        let mut acting_subject_id: Option<SubjectId> = None;
        let mut legal_subject_id: Option<SubjectId> = None;
        debug!(
            "[validate] AttributeStatement contains {} Attribute element(s)",
            attributes(assertion).count()
        );

        for attr in attributes(assertion) {
            let name = attr.name.as_deref().unwrap_or("");
            // Only the encrypted subject-ID attributes carry an EncryptedID we decrypt.
            let is_acting = match name {
                // eID §7.6.3.4: ActingSubjectID MUST be present.
                EID_ACTING_SUBJECT_ID => true,
                // eID §7.6.3.4: LegalSubjectID present when representation is used.
                EID_LEGAL_SUBJECT_ID => false,
                _ => continue,
            };
            let Some(enc_id) = attr.values.iter().find_map(|v| v.encrypted_id.as_ref()) else {
                continue;
            };

            // eID §7.6.3.4: bind decryption to the EncryptedKey addressed to us.
            let Some(d) = decrypt_encrypted_id(
                self.doc,
                enc_id,
                opts.private_keys,
                Some(opts.dv_entity_id.as_str()),
            ) else {
                debug!(
                    "[validate] EncryptedID present on attribute '{name}' but decryption returned None"
                );
                continue;
            };

            // SECURITY: only log presence + name_qualifier (an entity URN, not PII).
            debug!(
                "[validate] Decrypted EncryptedID for attribute '{name}' (name_qualifier='{}')",
                d.name_qualifier
            );
            self.check_decrypted_name_id(name, &d);
            let subject = Some(SubjectId {
                value: d.value,
                name_qualifier: d.name_qualifier,
            });
            if is_acting {
                acting_subject_id = subject;
            } else {
                legal_subject_id = subject;
            }
        }

        (acting_subject_id, legal_subject_id)
    }
    // eID §7.6.3.4.4: a decrypted EncryptedID NameID MUST use the persistent
    // Format, MUST carry a NameQualifier identifying the attribute type, and
    // MUST NOT use SPNameQualifier or SPProvidedID.
    fn check_decrypted_name_id(&mut self, attr_name: &str, d: &DecryptedNameId) {
        // An empty NameID value is not a usable identity; fail closed.
        if d.value.expose_secret().trim().is_empty() {
            self.error(format!("{attr_name} NameID has an empty value"));
        }
        if d.format != NAMEID_PERSISTENT {
            self.error(format!(
                "{attr_name} NameID Format must be {NAMEID_PERSISTENT}, got '{}'",
                d.format
            ));
        }
        // eID §7.6.3.4.4 requires the NameQualifier, and §10.1 enumerates the
        // identifier types it may name. An unknown type is rejected rather than
        // carried into the session as an identity of unknown meaning.
        let name_qualifier = d.name_qualifier.trim();
        if name_qualifier.is_empty() {
            self.error(format!(
                "{attr_name} NameID is missing the required NameQualifier"
            ));
        } else if !EID_ID_TYPES.contains(&name_qualifier) {
            self.error(format!(
                "{attr_name} NameID NameQualifier '{name_qualifier}' is not an eID §10.1 \
                 identifier type (expected one of {EID_ID_TYPES:?})"
            ));
        }
        if d.sp_name_qualifier.is_some() {
            self.error(format!("{attr_name} NameID must not carry SPNameQualifier"));
        }
        if d.sp_provided_id.is_some() {
            self.error(format!("{attr_name} NameID must not carry SPProvidedID"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::saml::constants::NS_SAML;

    fn parse_assertion(xml: &str) -> (Document<'_>, Assertion) {
        let doc = Document::parse(xml).expect("test Assertion parses");
        let assertion = doc.deserialize().expect("test Assertion deserializes");
        (doc, assertion)
    }

    // -- Advice --

    #[test]
    fn claims_are_read_from_outer_assertion_not_advice() {
        // The outer RD Assertion carries the real Issuer; the <Advice> evidence
        // subtree holds the AD's own assertion with a different Issuer and LoA.
        // Claims must come from the outer Assertion only.
        let xml = format!(
            r#"<saml:Assertion xmlns:saml="{NS_SAML}"><saml:Issuer>OUTER_RD</saml:Issuer><saml:Advice><saml:Assertion><saml:Issuer>INNER_AD</saml:Issuer><saml:AuthnStatement><saml:AuthnContext><saml:AuthnContextClassRef>INNER_LOA</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></saml:Advice></saml:Assertion>"#
        );
        let (doc, assertion) = parse_assertion(&xml);
        assert_eq!(assertion.issuer.as_deref(), Some("OUTER_RD"));
        // The AD's AuthnContextClassRef inside <Advice> is invisible.
        let mut errors = Vec::new();
        let (class_ref, _) =
            Validator::new(&doc, &mut errors).check_authn_context(&assertion, None);
        assert!(class_ref.is_none());
    }

    // -- check_decrypted_name_id (eID §7.6.3.4.4) --

    fn name_id(format: &str, nq: &str) -> DecryptedNameId {
        DecryptedNameId {
            value: "BSN".into(),
            format: format.into(),
            name_qualifier: nq.into(),
            sp_name_qualifier: None,
            sp_provided_id: None,
        }
    }

    /// Run `check_decrypted_name_id` over a dummy document (it never reads the
    /// tree) and return the recorded errors.
    fn decrypted_name_id_errors(d: &DecryptedNameId) -> Vec<String> {
        let doc = Document::parse(r#"<x xmlns="urn:x"/>"#).unwrap();
        let mut errors = Vec::new();
        Validator::new(&doc, &mut errors).check_decrypted_name_id(EID_ACTING_SUBJECT_ID, d);
        errors
    }

    #[test]
    fn decrypted_name_id_persistent_with_qualifier_is_accepted() {
        let errors = decrypted_name_id_errors(&name_id(
            NAMEID_PERSISTENT,
            "urn:nl-eid-gdi:1.0:id:legacy-BSN",
        ));
        assert!(errors.is_empty(), "errors: {errors:?}");
    }

    #[test]
    fn decrypted_name_id_rejects_wrong_format_missing_qualifier_and_sp_attrs() {
        let errors = decrypted_name_id_errors(&name_id(NAMEID_TRANSIENT, ""));
        assert!(errors.iter().any(|e| e.contains("Format must be")));
        assert!(errors.iter().any(|e| e.contains("NameQualifier")));

        let mut d = name_id(NAMEID_PERSISTENT, "urn:nl-eid-gdi:1.0:id:legacy-BSN");
        d.sp_name_qualifier = Some("x".into());
        d.sp_provided_id = Some("y".into());
        let errors = decrypted_name_id_errors(&d);
        assert!(errors.iter().any(|e| e.contains("SPNameQualifier")));
        assert!(errors.iter().any(|e| e.contains("SPProvidedID")));
    }

    #[test]
    fn decrypted_name_id_rejects_unknown_identifier_type() {
        // eID §10.1 enumerates the identifier types; a NameQualifier outside
        // that set names an identity of unknown meaning and must be rejected.
        let errors = decrypted_name_id_errors(&name_id(
            NAMEID_PERSISTENT,
            "urn:nl-eid-gdi:1.0:id:SomethingElse",
        ));
        assert!(
            errors.iter().any(|e| e.contains("not an eID §10.1")),
            "{errors:?}"
        );
    }

    #[test]
    fn decrypted_name_id_accepts_every_documented_identifier_type() {
        for nq in EID_ID_TYPES {
            let errors = decrypted_name_id_errors(&name_id(NAMEID_PERSISTENT, nq));
            assert!(errors.is_empty(), "{nq} rejected: {errors:?}");
        }
    }

    #[test]
    fn attributes_are_read_only_from_attribute_statement() {
        // An <Attribute> outside an <AttributeStatement> is not a claim: the
        // ServiceUUID here sits directly under the Assertion, so the binding must
        // report it missing rather than accept the planted value.
        let xml = format!(
            r#"<saml:Assertion xmlns:saml="{NS_SAML}"><saml:Attribute Name="{EID_SERVICE_UUID}"><saml:AttributeValue>planted</saml:AttributeValue></saml:Attribute></saml:Assertion>"#
        );
        let (doc, assertion) = parse_assertion(&xml);
        assert_eq!(attributes(&assertion).count(), 0);
        let mut errors = Vec::new();
        let mut v = Validator::new(&doc, &mut errors);
        let planted = ServiceUuid::from_static("planted");
        assert_eq!(v.check_service_uuid(&assertion, Some(&planted)), None);
        assert!(
            errors.iter().any(|e| e.contains("missing the required")),
            "{errors:?}"
        );
    }

    #[test]
    fn decrypted_name_id_rejects_empty_value() {
        // A persistent NameID with empty text content must be rejected: an empty
        // identifier is not a usable identity.
        let mut d = name_id(NAMEID_PERSISTENT, "urn:nl-eid-gdi:1.0:id:legacy-BSN");
        d.value = "   ".into();
        let errors = decrypted_name_id_errors(&d);
        assert!(
            errors.iter().any(|e| e.contains("empty value")),
            "{errors:?}"
        );
    }

    // -- ServiceUUID binding (eID §7.6.3.4) --

    #[test]
    fn service_uuid_mismatch_is_rejected() {
        // An assertion carrying a ServiceUUID different from the DV's registered
        // one must be rejected (the assertion is for another service).
        let xml = format!(
            r#"<saml:Assertion xmlns:saml="{NS_SAML}"><saml:AttributeStatement><saml:Attribute Name="{EID_SERVICE_UUID}"><saml:AttributeValue>actual-service</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"#
        );
        let (doc, assertion) = parse_assertion(&xml);
        let mut errors = Vec::new();
        let claims = validate_assertion_at(
            &doc,
            &assertion,
            &ValidateAssertionOpts {
                dv_entity_id: &EntityId::from_static("urn:dv"),
                expected_recipient: None,
                expected_issuer: None,
                private_keys: &[],
                minimum_loa: None,
                expected_service_uuid: Some(&ServiceUuid::from_static("expected-service")),
            },
            &mut errors,
        );
        assert!(claims.is_none());
        assert!(
            errors.iter().any(|e| e.contains("ServiceUUID mismatch")),
            "{errors:?}"
        );
    }
}

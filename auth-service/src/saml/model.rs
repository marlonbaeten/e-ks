//! Serde models of the SAML, SOAP, metadata, XML-DSig and XML-Enc elements the
//! DV reads, deserialized from a [`Document`](crate::saml::xml::Document).
//!
//! Element fields are named `alias.Local` (see [`xml`](crate::saml::xml)), so
//! each one matches by `(namespace-URI, local-name)`; attribute fields are `@Name`.
//!
//! The models only declare where the SAML schemas put an element, so a lookup
//! never wanders: the Assertion's `AuthnContextClassRef` is read from
//! `AuthnStatement/AuthnContext`, never from an element planted in `<Advice>` (the
//! AD's evidence assertions, which are not modelled at all) or any other
//! extension point. Undeclared elements and attributes are ignored.
//!
//! Cardinality falls out of the field types and fails closed:
//! - `Option<T>`: 0..1. A second occurrence is a parse error ("duplicate field"),
//!   so an attacker cannot append a competing `Subject` or `Conditions`.
//! - `Vec<T>`: 0..n, for the validators to count where the eID profile is
//!   stricter than the schema (one Assertion per Response, ...).
//! - `String`: an element's text, unescaped. An element with element children
//!   is a parse error, so `<saml:Issuer><x>urn:rd</x></saml:Issuer>` never reads
//!   as `urn:rd`. `$text` fields likewise read only an element's own text.

use crate::saml::xml::ElementRef;
use serde::Deserialize;

// -- SOAP (eID §7.5) --

/// `soap:Envelope` carrying the RD's ArtifactResponse.
#[derive(Debug, Deserialize)]
pub struct Envelope {
    #[serde(rename = "soap.Body")]
    pub body: Option<Body>,
}

#[derive(Debug, Deserialize)]
pub struct Body {
    #[serde(rename = "samlp.ArtifactResponse")]
    pub artifact_response: Option<ArtifactResponse>,
}

// -- Protocol messages (eID §7.6.1, §7.6.2, §7.7.2) --

/// `samlp:ArtifactResponse` (eID §7.6.1).
#[derive(Debug, Deserialize)]
pub struct ArtifactResponse {
    #[serde(rename = "@src.index")]
    pub element: ElementRef,
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: Option<String>,
    #[serde(rename = "@InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "saml.Issuer")]
    pub issuer: Option<String>,
    #[serde(rename = "samlp.Status")]
    pub status: Option<Status>,
    #[serde(rename = "samlp.Response", default)]
    pub responses: Vec<Response>,
}

/// `samlp:Response` (eID §7.6.2).
#[derive(Debug, Deserialize)]
pub struct Response {
    #[serde(rename = "@src.index")]
    pub element: ElementRef,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: Option<String>,
    #[serde(rename = "@Destination")]
    pub destination: Option<String>,
    #[serde(rename = "@InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "saml.Issuer")]
    pub issuer: Option<String>,
    #[serde(rename = "samlp.Status")]
    pub status: Option<Status>,
    #[serde(rename = "saml.Assertion", default)]
    pub assertions: Vec<Assertion>,
}

/// `samlp:LogoutResponse` (eID §7.7.2).
#[derive(Debug, Deserialize)]
pub struct LogoutResponse {
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: Option<String>,
    #[serde(rename = "@Destination")]
    pub destination: Option<String>,
    #[serde(rename = "@InResponseTo")]
    pub in_response_to: Option<String>,
    #[serde(rename = "saml.Issuer")]
    pub issuer: Option<String>,
    #[serde(rename = "samlp.Status")]
    pub status: Option<Status>,
}

/// `samlp:Status` (SAML core §3.2.2.1).
#[derive(Debug, Deserialize)]
pub struct Status {
    #[serde(rename = "samlp.StatusCode")]
    pub status_code: Option<StatusCode>,
    #[serde(rename = "samlp.StatusMessage")]
    pub status_message: Option<String>,
}

/// `samlp:StatusCode`, with the optional second-level code nested in it (§7.8).
#[derive(Debug, Deserialize)]
pub struct StatusCode {
    #[serde(rename = "@Value")]
    pub value: Option<String>,
    #[serde(rename = "samlp.StatusCode")]
    pub status_code: Option<Box<StatusCode>>,
}

impl Status {
    /// The top-level status code `@Value`.
    pub fn code(&self) -> Option<&str> {
        self.status_code.as_ref()?.value.as_deref()
    }

    /// The second-level status code `@Value` (eID §7.8).
    pub fn second_level_code(&self) -> Option<&str> {
        self.status_code
            .as_ref()?
            .status_code
            .as_ref()?
            .value
            .as_deref()
    }
}

// -- Assertion (eID §7.6.3) --

/// `saml:Assertion`.
#[derive(Debug, Deserialize)]
pub struct Assertion {
    #[serde(rename = "@src.index")]
    pub element: ElementRef,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: Option<String>,
    #[serde(rename = "saml.Issuer")]
    pub issuer: Option<String>,
    #[serde(rename = "saml.Subject")]
    pub subject: Option<Subject>,
    #[serde(rename = "saml.Conditions")]
    pub conditions: Option<Conditions>,
    #[serde(rename = "saml.AuthnStatement")]
    pub authn_statement: Option<AuthnStatement>,
    #[serde(rename = "saml.AttributeStatement", default)]
    pub attribute_statements: Vec<AttributeStatement>,
}

#[derive(Debug, Deserialize)]
pub struct Subject {
    #[serde(rename = "saml.NameID")]
    pub name_id: Option<NameId>,
    #[serde(rename = "saml.SubjectConfirmation")]
    pub subject_confirmation: Option<SubjectConfirmation>,
}

/// `saml:NameID`: the Subject's TransientID, or the plaintext of a decrypted
/// `EncryptedID` (eID §7.6.3.4.4).
#[derive(Debug, Deserialize)]
pub struct NameId {
    #[serde(rename = "@Format")]
    pub format: Option<String>,
    #[serde(rename = "@NameQualifier")]
    pub name_qualifier: Option<String>,
    #[serde(rename = "@SPNameQualifier")]
    pub sp_name_qualifier: Option<String>,
    #[serde(rename = "@SPProvidedID")]
    pub sp_provided_id: Option<String>,
    #[serde(rename = "$text", default)]
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct SubjectConfirmation {
    #[serde(rename = "@Method")]
    pub method: Option<String>,
    #[serde(rename = "saml.SubjectConfirmationData")]
    pub data: Option<SubjectConfirmationData>,
}

#[derive(Debug, Deserialize)]
pub struct SubjectConfirmationData {
    #[serde(rename = "@NotBefore")]
    pub not_before: Option<String>,
    #[serde(rename = "@NotOnOrAfter")]
    pub not_on_or_after: Option<String>,
    #[serde(rename = "@Recipient")]
    pub recipient: Option<String>,
    #[serde(rename = "@InResponseTo")]
    pub in_response_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Conditions {
    #[serde(rename = "@NotBefore")]
    pub not_before: Option<String>,
    #[serde(rename = "@NotOnOrAfter")]
    pub not_on_or_after: Option<String>,
    #[serde(rename = "saml.AudienceRestriction", default)]
    pub audience_restrictions: Vec<AudienceRestriction>,
}

#[derive(Debug, Deserialize)]
pub struct AudienceRestriction {
    #[serde(rename = "saml.Audience", default)]
    pub audiences: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthnStatement {
    #[serde(rename = "@AuthnInstant")]
    pub authn_instant: Option<String>,
    #[serde(rename = "saml.AuthnContext")]
    pub authn_context: Option<AuthnContext>,
}

#[derive(Debug, Deserialize)]
pub struct AuthnContext {
    #[serde(rename = "saml.AuthnContextClassRef")]
    pub class_ref: Option<String>,
    #[serde(rename = "saml.AuthenticatingAuthority", default)]
    pub authenticating_authorities: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct AttributeStatement {
    #[serde(rename = "saml.Attribute", default)]
    pub attributes: Vec<Attribute>,
}

/// `saml:Attribute` (eID §7.6.3.4).
#[derive(Debug, Deserialize)]
pub struct Attribute {
    #[serde(rename = "@Name")]
    pub name: Option<String>,
    #[serde(rename = "saml.AttributeValue", default)]
    pub values: Vec<AttributeValue>,
}

/// `saml:AttributeValue`: plain text (the ServiceUUID) or an `EncryptedID`
/// (the acting / legal SubjectID).
#[derive(Debug, Deserialize)]
pub struct AttributeValue {
    #[serde(rename = "$text")]
    pub text: Option<String>,
    #[serde(rename = "saml.EncryptedID")]
    pub encrypted_id: Option<EncryptedId>,
}

// -- XML-Enc (eID §7.6.3.4.4, §9.3) --

/// `saml:EncryptedID`. The `EncryptedKey` may sit in the `EncryptedData`'s
/// `KeyInfo` or beside it (SAML core §2.2.4).
#[derive(Debug, Deserialize)]
pub struct EncryptedId {
    #[serde(rename = "@src.index")]
    pub element: ElementRef,
    #[serde(rename = "xenc.EncryptedData")]
    pub encrypted_data: Option<EncryptedData>,
    #[serde(rename = "xenc.EncryptedKey", default)]
    pub encrypted_keys: Vec<EncryptedKey>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedData {
    #[serde(rename = "xenc.EncryptionMethod")]
    pub encryption_method: Option<Algorithm>,
    #[serde(rename = "ds.KeyInfo")]
    pub key_info: Option<EncryptedDataKeyInfo>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedDataKeyInfo {
    #[serde(rename = "xenc.EncryptedKey", default)]
    pub encrypted_keys: Vec<EncryptedKey>,
}

#[derive(Debug, Deserialize)]
pub struct EncryptedKey {
    #[serde(rename = "@Recipient")]
    pub recipient: Option<String>,
    #[serde(rename = "xenc.EncryptionMethod")]
    pub encryption_method: Option<Algorithm>,
}

/// The plaintext the crypto backend returns for an `EncryptedID`: the element
/// with its `EncryptedData` replaced by the decrypted `NameID`.
#[derive(Debug, Deserialize)]
pub struct DecryptedId {
    #[serde(rename = "saml.NameID")]
    pub name_id: Option<NameId>,
}

// -- XML-DSig (eID §9.1, §9.2) --

/// Any signed element: only its enveloping (direct-child) `ds:Signature`s.
#[derive(Debug, Deserialize)]
pub struct Signed {
    #[serde(rename = "ds.Signature", default)]
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Deserialize)]
pub struct Signature {
    #[serde(rename = "@src.index")]
    pub element: ElementRef,
    #[serde(rename = "ds.SignedInfo")]
    pub signed_info: Option<SignedInfo>,
    #[serde(rename = "ds.KeyInfo")]
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug, Deserialize)]
pub struct SignedInfo {
    #[serde(rename = "ds.CanonicalizationMethod")]
    pub canonicalization_method: Option<Algorithm>,
    #[serde(rename = "ds.SignatureMethod")]
    pub signature_method: Option<Algorithm>,
    #[serde(rename = "ds.Reference", default)]
    pub references: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
pub struct Reference {
    #[serde(rename = "@URI")]
    pub uri: Option<String>,
    #[serde(rename = "ds.Transforms")]
    pub transforms: Option<Transforms>,
    #[serde(rename = "ds.DigestMethod")]
    pub digest_method: Option<Algorithm>,
}

#[derive(Debug, Deserialize)]
pub struct Transforms {
    #[serde(rename = "ds.Transform", default)]
    pub transforms: Vec<Algorithm>,
}

/// Any `*Method` / `Transform` element: just its `@Algorithm`.
#[derive(Debug, Deserialize)]
pub struct Algorithm {
    #[serde(rename = "@Algorithm")]
    pub algorithm: Option<String>,
}

/// `ds:KeyInfo` of a signature or a metadata `KeyDescriptor`.
#[derive(Debug, Deserialize)]
pub struct KeyInfo {
    #[serde(rename = "ds.KeyName", default)]
    pub key_names: Vec<String>,
    #[serde(rename = "ds.X509Data", default)]
    pub x509_data: Vec<X509Data>,
}

#[derive(Debug, Deserialize)]
pub struct X509Data {
    #[serde(rename = "ds.X509Certificate", default)]
    pub certificates: Vec<String>,
}

impl KeyInfo {
    /// The first `X509Data/X509Certificate`.
    pub fn certificate(&self) -> Option<&str> {
        self.x509_data
            .iter()
            .flat_map(|d| &d.certificates)
            .next()
            .map(String::as_str)
    }
}

// -- Metadata (eID §8) --

/// `md:EntityDescriptor` of the RD.
#[derive(Debug, Deserialize)]
pub struct EntityDescriptor {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@entityID")]
    pub entity_id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<String>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<String>,
    #[serde(rename = "md.IDPSSODescriptor")]
    pub idp_sso_descriptor: Option<IdpSsoDescriptor>,
}

/// `md:IDPSSODescriptor`: the one role descriptor every endpoint and key is read
/// from (an `SPSSODescriptor` beside it is ignored).
#[derive(Debug, Deserialize)]
pub struct IdpSsoDescriptor {
    #[serde(rename = "md.KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "md.SingleSignOnService", default)]
    pub single_sign_on_services: Vec<Endpoint>,
    #[serde(rename = "md.ArtifactResolutionService", default)]
    pub artifact_resolution_services: Vec<Endpoint>,
    #[serde(rename = "md.SingleLogoutService", default)]
    pub single_logout_services: Vec<Endpoint>,
}

#[derive(Debug, Deserialize)]
pub struct KeyDescriptor {
    #[serde(rename = "@use")]
    pub key_use: Option<String>,
    #[serde(rename = "ds.KeyInfo")]
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug, Deserialize)]
pub struct Endpoint {
    #[serde(rename = "@Binding")]
    pub binding: Option<String>,
    #[serde(rename = "@Location")]
    pub location: Option<String>,
}

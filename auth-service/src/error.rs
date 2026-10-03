use gamlastan::profiles::nl_eid::NlEidError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    /// A value that arrived from outside is not well-formed for its type: a
    /// message ID that is not an XML `NCName`, an empty `NameID`, a
    /// certificate body that is not base64.
    #[error("XML error: {0}")]
    Xml(String),
    /// Key material could not be loaded, or the RD metadata failed its trust
    /// checks (PKIoverheid chain, OIN, signature).
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("Config error: {0}")]
    Config(String),
    #[error("Template error: {0}")]
    Template(String),
    /// A SAML protocol, format or trust failure reported by gamlastan's eID
    /// profile: the message handling this crate delegates to it.
    #[error("SAML error: {0}")]
    Saml(#[from] NlEidError),
}

impl From<askama::Error> for AuthError {
    fn from(e: askama::Error) -> Self {
        AuthError::Template(e.to_string())
    }
}

impl From<reqwest::Error> for AuthError {
    fn from(e: reqwest::Error) -> Self {
        AuthError::Http(e.to_string())
    }
}

/// A value (e.g. a metadata-derived URL) is not representable in an HTTP
/// header. `Config` rather than `Http`: it means the loaded metadata/config is
/// bad, not that a transient transport failure occurred.
impl From<axum::http::header::InvalidHeaderValue> for AuthError {
    fn from(e: axum::http::header::InvalidHeaderValue) -> Self {
        AuthError::Config(format!("value is not representable in an HTTP header: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_xml_error() {
        let err = AuthError::Xml("bad tag".to_string());
        assert_eq!(format!("{err}"), "XML error: bad tag");
    }

    #[test]
    fn display_crypto_error() {
        let err = AuthError::Crypto("key failed".to_string());
        assert_eq!(format!("{err}"), "Crypto error: key failed");
    }

    #[test]
    fn display_http_error() {
        let err = AuthError::Http("timeout".to_string());
        assert_eq!(format!("{err}"), "HTTP error: timeout");
    }

    #[test]
    fn display_config_error() {
        let err = AuthError::Config("missing var".to_string());
        assert_eq!(format!("{err}"), "Config error: missing var");
    }

    #[test]
    fn display_saml_error_carries_the_profile_detail() {
        let err = AuthError::from(NlEidError::MissingSignature("Assertion"));
        let rendered = format!("{err}");
        assert!(rendered.starts_with("SAML error: "), "{rendered}");
        assert!(rendered.contains("Assertion"), "{rendered}");
    }
}

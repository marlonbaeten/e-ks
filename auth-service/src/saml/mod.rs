//! SAML protocol layer: message building, signing/encryption adapters, trust
//! material, and the receive-side validators.

pub mod constants;
pub mod crypto;
pub mod decryption;
pub mod idp_metadata;
pub mod loa;
pub mod messages;
pub mod metadata;
pub mod model;
pub mod pki;
pub mod subject;
pub mod validation;
pub mod verification;
pub mod xml;
pub mod xml_builder;

//! Fetch and validate the real TVS (Toegang Verlening Service) metadata from
//! DICTU with the production trust material: the pinned RD identity, the
//! PKIoverheid chain and OIN of the signing certificates, the metadata
//! signature, and the endpoint domain pin.
//!
//! These tests hit external URLs and require network access, and they only
//! make sense against the real PKIoverheid roots, so they are left out of a
//! `tvs-mock` build (which pins the test CA instead).
//! Run with: cargo test --test tvs_metadata -- --ignored

#![cfg(not(feature = "tvs-mock"))]

use auth_service::{
    config::Environment,
    rd_metadata::{IdpMetadata, RdTrust, parse_idp_metadata},
};

async fn fetch_metadata(url: &str) -> String {
    reqwest::get(url)
        .await
        .unwrap_or_else(|e| panic!("Failed to fetch {url}: {e}"))
        .text()
        .await
        .unwrap_or_else(|e| panic!("Failed to read response from {url}: {e}"))
}

/// The document the deployment would load for `environment`: fetched from the
/// RD metadata URL the configuration derives, trusted exactly as at startup.
async fn validated_metadata(environment: Environment) -> IdpMetadata {
    let url = format!("{}/kvs/rd/metadata", environment.rd_base_url());
    let xml = fetch_metadata(&url).await;
    let metadata = parse_idp_metadata(&xml, &RdTrust::for_environment(environment))
        .unwrap_or_else(|e| panic!("{url}: the live RD metadata must pass the trust checks: {e}"));

    assert_eq!(metadata.entity_id, environment.rd_entity_id());
    assert!(
        metadata.signing_key_names.len() == 1 || metadata.signing_key_names.len() == 2,
        "{url}: expected 1 or 2 trusted signing keys, got {}",
        metadata.signing_key_names.len()
    );
    for url in [&metadata.sso_url, &metadata.ars_url, &metadata.slo_url] {
        assert!(
            url.as_str().starts_with("https://"),
            "{url}: every RD endpoint is https"
        );
    }
    metadata
}

#[tokio::test]
#[ignore] // requires network access; run with: cargo test --test tvs_metadata -- --ignored
async fn validate_preproduction_metadata() {
    let metadata = validated_metadata(Environment::Preproduction).await;
    println!("pre-production RD metadata: {metadata:?}");
}

#[tokio::test]
#[ignore] // requires network access; run with: cargo test --test tvs_metadata -- --ignored
async fn validate_production_metadata() {
    let metadata = validated_metadata(Environment::Production).await;
    println!("production RD metadata: {metadata:?}");
}

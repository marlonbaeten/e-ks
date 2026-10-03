//! SAML 2.0 Service Provider for the Dutch TVS *Routeringsdienst*.
//!
//! This crate is the **DV (Dienstverlener / Service Provider)** side of the
//! *Koppelvlakspecificatie eID SAML v4.4* interface, talking to the TVS RD
//! (the IdP). A non-authoritative extract of the requirements lives in
//! `eid-saml-4.4-requirements.md` next to this crate; `§` references in the
//! source point at it (and, where noted, at the OASIS `saml-*-2.0-os` specs
//! and the TVS "Checklist Testen").
//!
//! # What lives where
//!
//! The SAML protocol itself (message construction and signing, SOAP wrapping,
//! signature verification bound to the consumed element, the §7.6 processing
//! rules, Level-of-Assurance and `ServiceUUID` binding, `EncryptedID`
//! decryption, the DV metadata document and the RD metadata reader) is
//! [`gamlastan::profiles::nl_eid`]. This crate contains only what a deployment
//! adds around it:
//!
//! - the axum **handlers** ([`handlers`]) and the [`AuthState`] contract with
//!   the embedding application;
//! - **key management** ([`keys`]): the DV cert/key bundle on disk, loaded into
//!   gamlastan signers and decryptors;
//! - the **mTLS SOAP back-channel** ([`bindings::soap`], [`bindings::mtls`]):
//!   pinned PKIoverheid root, RD OIN check on the server certificate, client
//!   identity (§9.4);
//! - **trust in the RD metadata** ([`rd_metadata`]): the pinned RD `entityID`,
//!   the PKIoverheid chain and OIN of its signing certificates, the endpoint
//!   domain pin, the on-disk cache and the background refresh (§8.5, §9.1,
//!   §9.2);
//! - the browser-side **flow binding** ([`handlers::flow`]) and the
//!   **pending-request store** ([`pending`]) that consume each request ID once
//!   (§9.7);
//! - the HTTP-POST binding page and its CSP ([`bindings::http_post`], [`csp`]),
//!   and the deployment [`config`].
//!
//! # Endpoints
//!
//! An embedding application mounts [`router`] (the protocol endpoints) plus
//! [`handle_login`] / [`handle_logout`] on login and logout routes of its own
//! choosing:
//!
//! - `/login` (embedder-mounted [`handle_login`]): start SSO: a signed
//!   AuthnRequest (§7.3), auto-POSTed to the RD SSO endpoint (§3.1.1).
//! - `GET  /saml/sp/acs`: Assertion Consumer Service: receive the artifact
//!   (§7.4), resolve it over the mTLS SOAP back-channel (§7.5, §9.4), and
//!   validate the ArtifactResponse, Response and Assertion (§7.6).
//! - `GET  /saml/sp/metadata`: the signed DV SP metadata (§8.3).
//! - `/logout` (embedder-mounted [`handle_logout`]) + `POST /saml/sp/logout`:
//!   SP-initiated logout (§7.7, §3.1.1.1).
//! - `GET  /saml/sp/autosubmit.js`: the script the HTTP-POST binding page submits.
//!
//! The embedding application supplies an [`AuthConfig`](config::AuthConfig) and
//! implements [`AuthState`] (create a session on login, tear it down on logout,
//! store pending request IDs); the SAML state (keys, the verified RD descriptor)
//! lives in [`AuthServiceState`], which the handlers extract via `FromRef`.

// A failed SAML flow must reach the user as the embedding application's error
// page, never as a dead worker: the handlers turn every error into an
// `AuthFailure`, so nothing on a request path may panic. These make that a
// compile error rather than a review habit, and stricter than the workspace's
// `unwrap_used = "warn"`.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice
)]

pub mod bindings;
pub mod config;
pub mod csp;
pub mod error;
pub mod handlers;
pub mod keys;
pub mod pending;
pub mod pki;
pub mod rd_metadata;
pub mod state;
#[cfg(feature = "tvs-mock")]
mod tvs_mock;
pub mod types;

use axum::{Router, extract::FromRef};
use axum_extra::routing::{RouterExt, TypedPath};

use crate::handlers::{
    acs::handle_acs, autosubmit::handle_autosubmit_js, logout::handle_sls,
    metadata::handle_metadata,
};

pub use crate::{
    handlers::{login::handle_login, logout::handle_logout},
    pending::{PENDING_REQUEST_TTL, PendingRequests},
    state::{AuthFailure, AuthServiceState, AuthState, LoggedOutSession},
    types::{
        Artifact, EndpointUrl, EntityId, MessageId, NameId, RedirectTarget, ServiceUuid, SubjectId,
    },
};

/// Metadata endpoint path (eID §8.3): serves the signed SP metadata.
#[derive(TypedPath)]
#[typed_path("/saml/sp/metadata")]
pub struct SamlMetadataPath;

/// ACS endpoint path (eID §7.1): the HTTP-Artifact Assertion Consumer Service.
/// Also the source of truth for the ACS URL advertised in the SP metadata
/// ([`crate::config::DvConfig::acs_url`]), so route and metadata cannot drift.
#[derive(TypedPath)]
#[typed_path("/saml/sp/acs")]
pub struct SamlAcsPath;

/// SLS endpoint path. Exposed so the embedder can exempt it from CSRF (the RD
/// POSTs the LogoutResponse cross-site), keeping route and bypass in sync.
#[derive(TypedPath)]
#[typed_path("/saml/sp/logout")]
pub struct SamlLogoutPath;

/// Path at which the SP serves the auto-submit script referenced by the
/// HTTP-POST binding form ([`crate::bindings::http_post::create_post_form`]).
#[derive(TypedPath)]
#[typed_path("/saml/sp/autosubmit.js")]
pub struct AutosubmitJsPath;

/// Build the SAML SP router for the protocol endpoints (metadata, ACS, SLS).
///
/// The router is generic over the embedding application's state type `S`. The
/// caller plugs in any state that implements [`AuthState`] (the post-login /
/// pre-logout flow callbacks) and from which an [`AuthServiceState`] can be
/// extracted via `FromRef` (the SAML config, keys, and per-flow state).
///
/// The SSO *start* ([`handle_login`]) and SP-initiated logout *start*
/// ([`handle_logout`]) are intentionally **not** mounted here: they are
/// browser-facing entry points (not registered in the SP metadata), so the
/// embedding application mounts them at whatever URLs it likes, typically
/// alongside its own login/logout pages. The ACS and SLS endpoints below *are*
/// registered in the SP metadata, so their paths are fixed.
///
/// Routes exposed (each mounted via `typed_{get,post}` on the [`TypedPath`]
/// structs above, so path and handler cannot drift):
/// - `GET  /saml/sp/metadata` ([`SamlMetadataPath`]): signed SP metadata (eID §8.3).
/// - `GET  /saml/sp/acs` ([`SamlAcsPath`]): Assertion Consumer Service (HTTP-Artifact, eID §7.1).
/// - `POST /saml/sp/logout` ([`SamlLogoutPath`]): receives LogoutResponse from the IdP (eID §7.7.2).
/// - `GET  /saml/sp/autosubmit.js` ([`AutosubmitJsPath`]): script that submits the HTTP-POST binding form.
pub fn router<S>() -> Router<S>
where
    S: AuthState,
    AuthServiceState: FromRef<S>,
{
    Router::new()
        .typed_get(handle_metadata)
        .typed_get(handle_acs::<S>)
        .typed_post(handle_sls::<S>)
        .typed_get(handle_autosubmit_js)
}

//! The SLS endpoint: receiving and verifying the RD's LogoutResponse (eID §7.7.2).

use crate::{
    state::{AuthServiceState, AuthState},
    types::MessageId,
};
use axum::{
    Form,
    extract::{FromRef, State},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use gamlastan::profiles::nl_eid::{LogoutResponseOutcome, validate_logout_response};
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// POST /saml/sp/logout: receives the RD's LogoutResponse per eID §7.7.2.
///
/// Enforces the §7.7.2 mandatory checks as a gate on treating the response as a
/// genuine RD confirmation: it MUST be a `samlp:LogoutResponse`, MUST carry a
/// valid RD signature, MUST have an `@InResponseTo` matching a LogoutRequest this
/// DV issued (consumed once, so a replayed response is rejected), and SHOULD
/// report `Success`.
///
/// The user's local session was already terminated by [`super::handle_logout`] *before*
/// any LogoutResponse arrives, so this endpoint holds no session state. A
/// failed/forged/replayed response is therefore logged and dropped but never
/// strands the user: the browser is always redirected to the post-logout page.
pub async fn handle_sls<S>(
    _: crate::SamlLogoutPath,
    State(state): State<S>,
    State(auth_state): State<AuthServiceState>,
    Form(params): Form<HashMap<String, String>>,
) -> Response
where
    S: AuthState,
    AuthServiceState: FromRef<S>,
{
    debug!("[SLS] Handler entered, form fields: {}", params.len());
    process_logout_response(&state, &auth_state, &params).await;

    let target = &auth_state.auth_config().post_logout_redirect;
    debug!("[SLS] Redirecting browser to {target}");
    Redirect::to(target.as_str()).into_response()
}

/// Verify and correlate an incoming LogoutResponse (eID §7.7.2), logging the
/// outcome. Every failure is logged and dropped rather than surfaced: the local
/// session was already terminated in [`super::handle_logout`], so nothing hinges on
/// this confirmation and the caller always redirects to the post-logout page.
async fn process_logout_response<S: AuthState>(
    state: &S,
    auth_state: &AuthServiceState,
    params: &HashMap<String, String>,
) {
    let Some(saml_response) = decode_saml_response(params) else {
        return;
    };
    info!("[SLS] LogoutResponse received");

    let Some(outcome) = verified_logout_response(auth_state, &saml_response) else {
        return;
    };

    // eID §7.7.2: @InResponseTo MUST match a LogoutRequest this DV issued. Consume
    // it once (only after the signature verified, so a forged response cannot burn
    // a pending ID) to reject replays of a captured LogoutResponse.
    let in_response_to = match MessageId::parse(outcome.in_response_to) {
        Ok(id) => id,
        Err(e) => {
            warn!("[SLS] LogoutResponse InResponseTo is not a message ID: {e}; ignoring");
            return;
        }
    };
    if !state.consume_if_pending(in_response_to).await {
        warn!(
            "[SLS] LogoutResponse InResponseTo did not match an outstanding LogoutRequest \
             (unknown, expired, or replayed); ignoring"
        );
        return;
    }

    // eID §7.7.2: report the status. A non-Success status does not change the
    // outcome (the local logout already completed) but is surfaced for diagnostics.
    if outcome.status.is_success() {
        info!("[SLS] LogoutResponse confirmed by RD (signed, correlated, status Success)");
    } else {
        warn!(
            "[SLS] LogoutResponse status not Success ({}); local logout already completed",
            outcome.status.status_code.value
        );
    }
}

/// Verify the RD signature over the LogoutResponse and its §7.7.2 binding to
/// the RD and our SLS endpoint, or `None` (logged) when it fails either gate.
/// The `InResponseTo` is not known up front (the pending-request store is keyed
/// by it), so it is read from the verified response and consumed by the caller.
fn verified_logout_response(
    auth_state: &AuthServiceState,
    saml_response: &str,
) -> Option<LogoutResponseOutcome> {
    // Without the RD descriptor we cannot verify the signature; the user is
    // already logged out locally, so complete the logout rather than erroring.
    let Some(rd) = auth_state.rd_metadata() else {
        warn!("[SLS] RD metadata not loaded; cannot verify LogoutResponse, redirecting");
        return None;
    };

    match validate_logout_response(
        &auth_state.auth_config().nl_eid(),
        saml_response,
        rd.verifier(),
        None,
        chrono::Utc::now(),
    ) {
        Ok(outcome) => Some(outcome),
        Err(e) => {
            warn!("[SLS] LogoutResponse rejected: {e}; ignoring (local logout already done)");
            None
        }
    }
}

/// The base64-decoded `SAMLResponse` form field, or `None` (logged) when absent
/// or undecodable. Like every malformed-LogoutResponse case: log, drop, and
/// never strand the user (the local logout already happened).
fn decode_saml_response(params: &HashMap<String, String>) -> Option<String> {
    let Some(encoded) = params.get("SAMLResponse") else {
        // POST without a SAMLResponse field: nothing to verify; accept.
        info!("[SLS] LogoutResponse received without SAMLResponse");
        return None;
    };
    match BASE64.decode(encoded.as_bytes()) {
        Ok(bytes) => {
            debug!("[SLS] SAMLResponse base64 decoded ({} bytes)", bytes.len());
            Some(String::from_utf8_lossy(&bytes).to_string())
        }
        Err(e) => {
            warn!("[SLS] Invalid SAMLResponse base64: {e}; ignoring");
            None
        }
    }
}

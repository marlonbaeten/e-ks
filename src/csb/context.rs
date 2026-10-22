//! Request-scoped template context for the CSB domain, carrying locale and
//! helpers. Extracted from requests and passed into Askama templates.

use axum::{extract::FromRequestParts, http::request::Parts};

use crate::{
    AppError, AppRequestState, CsbActor, CsbUser, ElectionConfig, Session, SessionExpiry,
    utils::PeerIp,
};

#[cfg(test)]
use crate::Locale;

/// Request-scoped template context used by CSB Askama templates.
#[derive(Clone)]
pub struct CsbContext {
    /// Election the session is currently working on. Every CSB route sits
    /// behind `csb_store_middleware`, which guarantees the session has picked
    /// an election, so pages and templates can rely on it being present.
    pub election: ElectionConfig,
    /// Session data for locale and CSRF.
    pub session: Session,
    /// Remaining session lifetime at render time, for the expiry warning.
    pub session_expiry: SessionExpiry,
    /// Short identifier of the server this instance runs on (e.g. "S1"),
    /// rendered next to the version in the layout footer when set.
    pub server_name: Option<&'static str>,
    /// Whether to show the success alert based on the request query.
    pub show_success_alert: bool,
    /// Whether the page is part of an already-open overlay (suppresses animation).
    pub overlay_active: bool,
    /// The peer address of the request, recorded on the CSB events it causes.
    pub peer_ip: PeerIp,
}

impl CsbContext {
    pub fn new(session: Session, election: ElectionConfig) -> Self {
        Self {
            election,
            session_expiry: session.expiry(),
            session,
            server_name: None,
            show_success_alert: false,
            overlay_active: false,
            peer_ip: PeerIp(None),
        }
    }

    /// The committee member behind this request.
    pub fn user(&self) -> Result<CsbUser, AppError> {
        self.session.require_csb_user()
    }

    /// The committee member behind this request and the address it came
    /// from, recorded on CSB events.
    pub fn actor(&self) -> Result<CsbActor, AppError> {
        Ok(CsbActor::new(self.user()?, self.peer_ip))
    }

    #[cfg(test)]
    pub fn new_test() -> Self {
        let session = Session::for_committee(CsbUser::new_test(), ElectionConfig::EK27, Locale::En);
        Self::new(session, ElectionConfig::EK27)
    }
}

impl askama::Values for CsbContext {
    fn get_value<'a>(&'a self, key: &str) -> Option<&'a dyn std::any::Any> {
        match key {
            "election" => Some(&self.election as &dyn std::any::Any),
            "locale" => Some(&self.session.locale as &dyn std::any::Any),
            "csrf_token" => Some(&self.session.csrf_token().0 as &dyn std::any::Any),
            "session_expiry" => Some(&self.session_expiry as &dyn std::any::Any),
            "server_name" => Some(&self.server_name as &dyn std::any::Any),
            "show_success_alert" => Some(&self.show_success_alert as &dyn std::any::Any),
            "overlay_active" => Some(&self.overlay_active as &dyn std::any::Any),
            _ => None,
        }
    }
}

impl<S: AppRequestState> FromRequestParts<S> for CsbContext {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state).await?;
        let election = session.require_current_election()?;
        let mut context = CsbContext::new(session, election);

        context.server_name = state.config().server_name.as_deref();

        context.show_success_alert = crate::success_alert_requested(parts);
        context.overlay_active = crate::overlay_active(parts);
        context.peer_ip = PeerIp::from_extensions(&parts.extensions);

        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_context_carries_session_locale_and_election() {
        let context = CsbContext::new_test();
        assert_eq!(context.session.locale, Locale::En);
        assert_eq!(context.election, crate::ElectionConfig::EK27);
        assert_eq!(context.session.user.election(), Some(context.election));
    }
}

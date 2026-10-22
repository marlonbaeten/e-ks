//! The authenticated identity behind a CSB (committee) session.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::{CsbUsername, Locale, trans, utils::PeerIp};

/// The committee member behind a CSB session, recorded on every CSB event so
/// the audit log can show who triggered it.
///
/// Deliberately an enum over login methods rather than a single id: future
/// login methods add a variant here, and the events referencing the user
/// stay unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CsbUser {
    /// Dev-login bypass, with no identity beyond the login method itself.
    #[cfg(any(feature = "dev-features", test))]
    Developer,
    /// Security-key (WebAuthn) login, identified by the configured username.
    SecurityKey { username: CsbUsername },
}

/// A committee member and the peer address they act from: what every CSB
/// event records, so the audit log shows who triggered it and from where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsbActor {
    pub user: CsbUser,
    /// The peer address of the request behind the action; `None` when the
    /// server recorded none, or for an action without a request behind it.
    pub ip: Option<IpAddr>,
}

impl CsbActor {
    pub fn new(user: CsbUser, peer_ip: PeerIp) -> Self {
        Self {
            user,
            ip: peer_ip.0,
        }
    }

    /// The peer address as a log field: the address, or `unknown`.
    pub fn peer_ip(&self) -> PeerIp {
        PeerIp(self.ip)
    }
}

/// A member without a request behind them: fixtures, tests and the like.
impl From<CsbUser> for CsbActor {
    fn from(user: CsbUser) -> Self {
        Self { user, ip: None }
    }
}

/// Implemented by the CSB store events, which all record the committee member
/// that triggered them and the address they acted from. Lets the audit log
/// render both generically.
pub trait HasCsbUser {
    fn csb_user(&self) -> &CsbUser;

    /// The peer address the member acted from, when the event recorded one.
    fn peer_ip(&self) -> Option<IpAddr>;
}

impl CsbUser {
    /// Human-readable label shown in the audit log.
    pub fn describe(&self, locale: Locale) -> String {
        match self {
            #[cfg(any(feature = "dev-features", test))]
            CsbUser::Developer => trans!("audit_log.user.developer", locale),
            CsbUser::SecurityKey { username } => {
                format!(
                    "{} {username}",
                    trans!("audit_log.user.committee_member", locale)
                )
            }
        }
    }

    #[cfg(test)]
    pub fn new_test() -> Self {
        CsbUser::Developer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_shows_login_method_and_identity() {
        let member = CsbUser::SecurityKey {
            username: "alice".parse().expect("valid username"),
        };
        assert_eq!(member.describe(Locale::En), "Committee member alice");
        assert_eq!(member.describe(Locale::Nl), "CSB-lid alice");

        assert_eq!(CsbUser::Developer.describe(Locale::En), "Developer");
    }

    #[test]
    fn serde_roundtrips() {
        let user = CsbUser::SecurityKey {
            username: "alice".parse().expect("valid username"),
        };
        let json = serde_json::to_string(&user).expect("serialize");
        let back: CsbUser = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, user);
    }
}

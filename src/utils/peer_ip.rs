//! The peer address of a request, for log lines that identify the client.

use std::{
    convert::Infallible,
    fmt::{self, Display},
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{Extensions, request::Parts},
};

/// A peer address for a log field; `unknown` when none was recorded.
pub fn peer_ip_label(ip: Option<IpAddr>) -> String {
    ip.map_or_else(|| "unknown".to_string(), |ip| ip.to_string())
}

/// The connection's peer address, recorded by the server as [`ConnectInfo`]:
/// the TCP peer, or the client a listed proxy announced. `None` when the
/// server recorded none (a request built in a test, for one). An extractor,
/// so a handler can name the peer in a log line; it never rejects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIp(pub Option<IpAddr>);

impl PeerIp {
    pub fn from_extensions(extensions: &Extensions) -> Self {
        Self(
            extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(addr)| addr.ip()),
        )
    }
}

/// The address, or `unknown`, as [`peer_ip_label`] writes it.
impl Display for PeerIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&peer_ip_label(self.0))
    }
}

impl<S: Send + Sync> FromRequestParts<S> for PeerIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(Self::from_extensions(&parts.extensions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    #[tokio::test]
    async fn extracts_the_recorded_peer_address() {
        let mut request = Request::builder().body(Body::empty()).unwrap();
        let peer: SocketAddr = "203.0.113.8:4000".parse().unwrap();
        request.extensions_mut().insert(ConnectInfo(peer));
        let (mut parts, _) = request.into_parts();

        let ip = PeerIp::from_request_parts(&mut parts, &()).await.unwrap();

        assert_eq!(ip, PeerIp(Some(peer.ip())));
        assert_eq!(ip.to_string(), "203.0.113.8");
    }

    #[tokio::test]
    async fn a_request_without_peer_address_is_unknown_rather_than_rejected() {
        let request = Request::builder().body(Body::empty()).unwrap();
        let (mut parts, _) = request.into_parts();

        let ip = PeerIp::from_request_parts(&mut parts, &()).await.unwrap();

        assert_eq!(ip, PeerIp(None));
        assert_eq!(ip.to_string(), "unknown");
    }
}

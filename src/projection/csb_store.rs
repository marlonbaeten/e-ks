//! [`CsbStore`]: the request-scoped write handle for a CSB stream.

use std::{collections::HashMap, str::FromStr};

use axum::{
    extract::{FromRequestParts, Path},
    http::request::Parts,
};

use crate::{
    AppError, AppRequestState, CsbAction, CsbActor, CsbStoreData, CsbStream, CsbUser, PgStore,
    Session, StreamId, store::StoreRegistry, utils::PeerIp,
};

/// A CSB stream paired with the committee member acting on it in this request.
///
/// The [`CsbStream`] behind it is the process-wide handle handed out by the
/// store registry and shared by every session, so the acting user cannot live
/// there; it is bound here instead, once per request, by the extractor below.
/// [`CsbStore::update`] then attaches it to every event, which is why handlers
/// never pass a [`CsbUser`] and cannot attribute an event to anyone but the
/// requester.
///
/// Reads go through [`std::ops::Deref`], so the getters on the stream keep
/// working unchanged. Helpers that only read take `&CsbStream`.
#[derive(Clone)]
pub struct CsbStore {
    stream: CsbStream,
    actor: CsbActor,
}

impl std::ops::Deref for CsbStore {
    type Target = CsbStream;

    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl CsbStore {
    /// Bind `actor` to `stream` as the member acting on it, and the address
    /// they act from.
    pub fn acting_as(stream: CsbStream, actor: impl Into<CsbActor>) -> Self {
        Self {
            stream,
            actor: actor.into(),
        }
    }

    /// The committee member acting on the stream.
    pub fn user(&self) -> &CsbUser {
        &self.actor.user
    }

    /// The committee member acting on the stream and the address they act
    /// from, as recorded on every event.
    pub fn actor(&self) -> &CsbActor {
        &self.actor
    }

    /// Persist an action on the stream, recorded as triggered by the acting
    /// committee member.
    pub async fn update(&self, action: CsbAction) -> Result<(), AppError> {
        self.stream.update(action.by(self.actor.clone())).await
    }

    /// [`Self::update`] for an action decided on the projection it lands on;
    /// see [`CsbStream::update_when`].
    pub async fn update_when(
        &self,
        mut decide: impl FnMut(&CsbStoreData) -> Option<CsbAction>,
    ) -> Result<bool, AppError> {
        self.stream
            .update_when(|data| decide(data).map(|action| action.by(self.actor.clone())))
            .await
    }

    /// A paper-corrections handle over this stream, writing as the same member.
    pub fn paper_corrections(&self) -> PgStore {
        PgStore::paper_corrections(self.clone())
    }

    /// The stream named by the `stream_id` path parameter, looked up in
    /// `registry` under the session's election and bound to its committee
    /// member and the request's peer address. A deleted stream is not found.
    pub(crate) async fn from_registry<S: AppRequestState>(
        parts: &mut Parts,
        state: &S,
        registry: &StoreRegistry<CsbStoreData>,
    ) -> Result<Self, AppError> {
        let Path(params) =
            Path::<HashMap<String, String>>::from_request_parts(parts, state).await?;

        let stream_id = StreamId::from_str(
            params
                .get("stream_id")
                .ok_or(AppError::InternalServerError)?,
        )
        .map_err(|_| AppError::UserError("Invalid stream id".to_string()))?;

        let session = Session::from_request_parts(parts, state).await?;
        let election = session.require_current_election()?;
        let actor = CsbActor::new(
            session.require_csb_user()?,
            PeerIp::from_extensions(&parts.extensions),
        );

        let stream = registry.get_store(stream_id, election).await?;

        if stream.is_deleted() {
            return Err(AppError::NotFound("Stream deleted".to_string()));
        }

        Ok(Self::acting_as(stream, actor))
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        Self::acting_as(CsbStream::new_for_test(), CsbUser::new_test())
    }
}

#[cfg(test)]
impl CsbStream {
    /// Bind the test user to a stream taken from the registry, as the
    /// extractor does with the session's user for a real request.
    pub fn acting_as_test_user(self) -> CsbStore {
        CsbStore::acting_as(self, CsbUser::new_test())
    }
}

impl<S: AppRequestState> FromRequestParts<S> for CsbStore {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Self::from_registry(parts, state, state.csb_store_registry()).await
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, SocketAddr};

    use super::*;
    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
        routing::get,
    };
    use tower::ServiceExt;

    use crate::{
        AppState, CsbStoreData, ElectionConfig, HasCsbUser, PgStoreData,
        test_utils::response_body_string,
    };

    /// Persist a CSB stream carrying a single import event and return its id.
    async fn seed_csb_store(state: &AppState, election: ElectionConfig) -> StreamId {
        let stream_id = StreamId::new();
        let store = CsbStore::acting_as(
            state
                .csb_store_for_stream(stream_id, election)
                .await
                .unwrap(),
            CsbUser::new_test(),
        );
        store
            .update(CsbAction::Import {
                hash: [0u8; 32],
                source_stream_id: StreamId::new(),
                snapshot: Box::new(PgStoreData::default()),
            })
            .await
            .unwrap();
        stream_id
    }

    /// Build a router whose single handler echoes the extracted store's id, and
    /// drive a request for `uri` through it as a committee session.
    async fn request_store(
        state: AppState,
        uri: String,
        election: ElectionConfig,
    ) -> axum::response::Response {
        request_store_with_session(state, uri, election, Session::new_test_committee()).await
    }

    async fn request_store_with_session(
        state: AppState,
        uri: String,
        election: ElectionConfig,
        mut session: Session,
    ) -> axum::response::Response {
        let app = Router::new()
            .route(
                "/csb/examination/{stream_id}",
                get(|store: CsbStore| async move { store.stream_id.to_string() }),
            )
            .with_state(state);

        let mut request = Request::builder().uri(uri).body(Body::empty()).unwrap();
        session.set_test_election(election);
        request.extensions_mut().insert(session);

        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn loads_the_store_for_a_known_stream() {
        let state = AppState::new_for_tests().await;
        let stream_id = seed_csb_store(&state, ElectionConfig::EK27).await;

        let response = request_store(
            state,
            format!("/csb/examination/{stream_id}"),
            ElectionConfig::EK27,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = crate::test_utils::response_body_string(response).await;
        assert_eq!(body, stream_id.to_string());
    }

    #[tokio::test]
    async fn rejects_a_political_group_session() {
        let state = AppState::new_for_tests().await;
        let stream_id = seed_csb_store(&state, ElectionConfig::EK27).await;

        let response = request_store_with_session(
            state,
            format!("/csb/examination/{stream_id}"),
            ElectionConfig::EK27,
            Session::new_test(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_an_unparseable_stream_id() {
        let state = AppState::new_for_tests().await;

        let response = request_store(
            state,
            "/csb/examination/not-a-stream-id".to_string(),
            ElectionConfig::EK27,
        )
        .await;

        // The id fails to parse before any lookup, yielding a user error.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_not_found_for_an_unknown_stream() {
        let state = AppState::new_for_tests().await;
        let unknown = StreamId::new();

        let response = request_store(
            state,
            format!("/csb/examination/{unknown}"),
            ElectionConfig::EK27,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn store_data_type_reports_csb_scope() {
        // Guards the scope wiring the extractor relies on for registry lookups.
        assert_eq!(
            <CsbStoreData as crate::store::StoreData>::scope(),
            crate::Scope::ImportedByCsb
        );
    }

    #[tokio::test]
    async fn returns_not_found_for_a_deleted_stream() -> Result<(), AppError> {
        let state = AppState::new_for_tests().await;
        let stream_id = StreamId::new();
        // create a new store
        let csb_store = CsbStore::acting_as(
            state
                .csb_store_for_stream(stream_id, ElectionConfig::EK27)
                .await?,
            CsbUser::new_test(),
        );

        let response = request_store(
            state.clone(),
            format!("/csb/examination/{stream_id}"),
            ElectionConfig::EK27,
        )
        .await;

        // store exists && !deleted => OK
        assert_eq!(response.status(), StatusCode::OK);

        // delete the store
        csb_store.update(CsbAction::Delete).await?;

        let response = request_store(
            state,
            format!("/csb/examination/{stream_id}"),
            ElectionConfig::EK27,
        )
        .await;

        // store exists && deleted => Not Found
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        Ok(())
    }

    #[tokio::test]
    async fn update_records_the_acting_user() -> Result<(), AppError> {
        let user = CsbUser::SecurityKey {
            username: "bob".parse().expect("valid username"),
        };
        let store = CsbStore::acting_as(CsbStream::new_for_test(), user.clone());

        store.update(CsbAction::SetFinished(true)).await?;

        let events = store.snapshot().events.clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload.csb_user(), &user);
        assert_eq!(events[0].payload.peer_ip(), None);

        Ok(())
    }

    #[tokio::test]
    async fn update_records_the_address_the_user_acts_from() -> Result<(), AppError> {
        let ip: IpAddr = "203.0.113.8".parse().unwrap();
        let actor = CsbActor {
            user: CsbUser::new_test(),
            ip: Some(ip),
        };
        let store = CsbStore::acting_as(CsbStream::new_for_test(), actor);

        store.update(CsbAction::SetFinished(true)).await?;
        store
            .update_when(|_| Some(CsbAction::SetFinished(false)))
            .await?;

        let events = store.snapshot().events.clone();
        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.payload.peer_ip() == Some(ip))
        );

        Ok(())
    }

    /// The extractor binds the peer address the server recorded on the
    /// request, so every event of the request names it; a request without
    /// one (as in these tests) binds none.
    #[tokio::test]
    async fn the_extractor_binds_the_requests_peer_address() {
        let state = AppState::new_for_tests().await;
        let stream_id = seed_csb_store(&state, ElectionConfig::EK27).await;
        let app = Router::new()
            .route(
                "/csb/examination/{stream_id}",
                get(|store: CsbStore| async move { store.actor().peer_ip().to_string() }),
            )
            .with_state(state);

        for (peer, expected) in [(Some("203.0.113.8:4000"), "203.0.113.8"), (None, "unknown")] {
            let mut request = Request::builder()
                .uri(format!("/csb/examination/{stream_id}"))
                .body(Body::empty())
                .unwrap();
            let mut session = Session::new_test_committee();
            session.set_test_election(ElectionConfig::EK27);
            request.extensions_mut().insert(session);
            if let Some(peer) = peer {
                let addr: SocketAddr = peer.parse().unwrap();
                request.extensions_mut().insert(ConnectInfo(addr));
            }

            let response = app.clone().oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_body_string(response).await, expected);
        }
    }
}

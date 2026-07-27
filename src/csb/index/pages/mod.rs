use crate::AppState;
use axum::Router;
use axum_extra::routing::RouterExt;

mod election_definition;
mod index;

pub fn router() -> Router<AppState> {
    Router::new()
        .typed_get(index::index)
        .typed_get(election_definition::download_election_definition)
}

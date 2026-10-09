use std::sync::Arc;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use reqwest::Method;
use serde_json::{json, Value};
use crate::token_source::TokenSource;

#[derive(Clone)]
pub struct OrdersState {
    http: reqwest::Client,
    inventory_url: String,
    tokens: Arc<TokenSource>,
}

pub fn router(http: reqwest::Client, inventory_url: String, tokens: Arc<TokenSource>) -> Router {
    let state = OrdersState { http, inventory_url, tokens };
    Router::new()
        .route("/orders/{id}", get(get_order))
        .route("/orders/{id}/reserve", post(reserve_order))
        .with_state(state)
}

async fn get_order(State(st): State<OrdersState>, Path(id): Path<String>) -> Response {
    call_inventory(&st, Method::GET, &format!("/stock/sku-{id}"), &id).await
}

async fn reserve_order(State(st): State<OrdersState>, Path(id): Path<String>) -> Response {
    call_inventory(&st, Method::POST, &format!("/stock/sku-{id}/reserve"), &id).await
}

async fn call_inventory(st: &OrdersState, method: Method, path: &str, order_id: &str) -> Response {
    let token = match st.tokens.token().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "could not obtain access token");
            return (StatusCode::BAD_GATEWAY, Json(json!({ "error": "sts_unavailable", "detail": e.to_string() }))).into_response();
        }
    };
    let kid = jsonwebtoken::decode_header(&token).ok().and_then(|h| h.kid);

    let result = st.http
        .request(method, format!("{}{path}", st.inventory_url))
        .bearer_auth(&token)
        .send()
        .await;
    let response = match result {
        Ok(r) => r,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, Json(json!({ "error": "inventory_unavailable", "detail": e.to_string() }))).into_response();
        }
    };

    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    Json(json!({
        "order_id": order_id,
        "inventory_status": status,
        "inventory_response": body,
        "token_kid": kid,
    }))
        .into_response()
}

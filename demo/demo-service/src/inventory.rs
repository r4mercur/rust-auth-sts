use std::{collections::HashMap, sync::{Arc, Mutex}};
use axum::{
    extract::{FromRef, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use crate::verifier::{AuthError, Caller, Verifier};

const INITIAL_STOCK: u32 = 3;

#[derive(Clone)]
pub struct InventoryState {
    verifier: Arc<Verifier>,
    stock: Arc<Mutex<HashMap<String, u32>>>,
}

impl FromRef<InventoryState> for Arc<Verifier> {
    fn from_ref(state: &InventoryState) -> Self {
        state.verifier.clone()
    }
}

pub fn router(verifier: Arc<Verifier>) -> Router {
    let state = InventoryState { verifier, stock: Arc::default() };
    Router::new()
        .route("/stock/{sku}", get(get_stock))
        .route("/stock/{sku}/reserve", post(reserve))
        .with_state(state)
}

async fn get_stock(
    State(st): State<InventoryState>,
    caller: Caller,
    Path(sku): Path<String>,
) -> Result<Response, AuthError> {
    caller.require_scope("inventory.read")?;
    let available = *st.stock.lock().unwrap().get(&sku).unwrap_or(&INITIAL_STOCK);
    tracing::info!(%sku, caller = %caller.0.sub, "stock lookup");
    Ok(Json(json!({
        "sku": sku,
        "available": available,
        "served_to": caller.0.sub,
        "granted_scope": caller.0.scope,
    })).into_response())
}

async fn reserve(
    State(st): State<InventoryState>,
    caller: Caller,
    Path(sku): Path<String>,
) -> Result<Response, AuthError> {
    caller.require_scope("inventory.write")?;
    let mut stock = st.stock.lock().unwrap();
    let available = stock.entry(sku.clone()).or_insert(INITIAL_STOCK);
    if *available == 0 {
        return Ok((StatusCode::CONFLICT, Json(json!({ "sku": sku, "error": "out_of_stock" }))).into_response());
    }
    *available -= 1;
    tracing::info!(%sku, caller = %caller.0.sub, remaining = *available, "reserved item");
    Ok(Json(json!({
        "sku": sku,
        "reserved": true,
        "remaining": *available,
        "served_to": caller.0.sub,
    })).into_response())
}

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use rust_auth_sts::{
    config::AppConfig,
    crypto::keys::load_key,
    crypto::jwks::Jwks,
    http::{handlers::AppState, routes::routes},
    repository::memory::{ClientStore, UserStore},
    service::{
        client_service::ClientService,
        token_service::TokenService,
        user_service::UserService,
    },
};
use tower::ServiceExt;

fn test_app() -> axum::Router {
    let cfg = AppConfig {
        issuer: "http://localhost:8080".into(),
        key_path: "./secrets/private_rsa_pkcs8.pem".into(),
        kid: "test-kid".into(),
        bind_addr: "127.0.0.1:0".into(),
        token_ttl_seconds: 120,
    };

    let keys = load_key(std::path::Path::new("./tests/fixtures/private_rsa_pkcs8.pem"))
        .expect("test key must exist");

    let jwks = Jwks::single_rsa("test-kid", keys.n_b64.clone(), keys.e_b64.clone());

    let state = AppState {
        token_svc: TokenService::new(cfg, keys),
        client_svc: ClientService::new(ClientStore::with_example()),
        user_svc: UserService::new(UserStore::with_example()),
        jwks,
    };

    routes(state)
}

#[tokio::test]
async fn token_endpoint_returns_200_for_valid_client_credentials() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.read&audience=service-b"
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.get("access_token").is_some());
    assert_eq!(json["token_type"], "Bearer");
}

#[tokio::test]
async fn token_endpoint_returns_401_for_wrong_secret() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-a&client_secret=wrong-secret&scope=service.read&audience=service-b"
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_endpoint_returns_401_for_disallowed_scope() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=admin&audience=service-b"
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_endpoint_returns_400_for_unsupported_grant_type() {
    let app = test_app();

    let req = Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(
            "grant_type=password&client_id=service-a&client_secret=super-secret&scope=service.read&audience=service-b"
        ))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
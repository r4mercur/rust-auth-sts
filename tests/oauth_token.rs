use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use base64ct::{Base64, Encoding};
use http_body_util::BodyExt;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use rust_auth_sts::{
    config::AppConfig,
    crypto::keys::load_keys,
    http::{handlers::AppState, routes::routes},
    models::claims::Claims,
    repository::memory::{ClientStore, UserStore},
    service::{
        client_service::ClientService,
        token_service::TokenService,
        user_service::UserService,
    },
};
use serde_json::Value;
use tower::ServiceExt;

const VALID_FORM: &str =
    "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.read&audience=service-b";

fn test_app() -> axum::Router {
    build_app(true)
}

fn build_app(with_users: bool) -> axum::Router {
    let cfg = AppConfig {
        issuer: "http://localhost:8080".into(),
        keys_dir: "./tests/fixtures/keys".into(),
        active_kid: "key-2".into(),
        bind_addr: "127.0.0.1:0".into(),
        token_ttl_seconds: 120,
        clients_path: "./tests/fixtures/clients.json".into(),
        users_path: with_users.then(|| "./tests/fixtures/users.json".into()),
    };

    let keys = load_keys(&cfg.keys_dir, &cfg.active_kid).expect("test keys must load");
    let clients = ClientStore::from_file(&cfg.clients_path).expect("clients fixture must load");
    let user_svc = cfg.users_path.as_ref().map(|p| {
        UserService::new(UserStore::from_file(p).expect("users fixture must load"))
    });

    let state = AppState {
        token_svc: TokenService::new(cfg, keys.active),
        client_svc: ClientService::new(clients),
        user_svc,
        jwks: keys.jwks,
    };

    routes(state)
}

fn form_request(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn basic_request(user: &str, password: &str, body: &str) -> Request<Body> {
    let credentials = Base64::encode_string(format!("{user}:{password}").as_bytes());
    Request::builder()
        .method("POST")
        .uri("/oauth/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::AUTHORIZATION, format!("Basic {credentials}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn json_request(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn get_request(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

async fn send(req: Request<Body>) -> Response {
    test_app().oneshot(req).await.unwrap()
}

async fn json_body(response: Response) -> Value {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

async fn assert_error(response: Response, status: StatusCode, error: &str) {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(json_body(response).await["error"], error);
}

async fn verify_with_jwks(token: &str, audience: &str) -> (jsonwebtoken::Header, Claims) {
    let jwks: JwkSet = serde_json::from_value(json_body(send(get_request("/oauth/jwks.json")).await).await).unwrap();
    let header = decode_header(token).unwrap();
    let jwk = jwks.find(header.kid.as_deref().unwrap()).expect("kid must be published in JWKS");

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&["http://localhost:8080"]);
    validation.set_audience(&[audience]);
    let data = decode::<Claims>(token, &DecodingKey::from_jwk(jwk).unwrap(), &validation).unwrap();
    (header, data.claims)
}

#[tokio::test]
async fn token_endpoint_issues_verifiable_rfc9068_token() {
    let response = send(form_request("/oauth/token", VALID_FORM)).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    let json = json_body(response).await;
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["scope"], "service.read");

    let (header, claims) = verify_with_jwks(json["access_token"].as_str().unwrap(), "service-b").await;
    assert_eq!(header.typ.as_deref(), Some("at+jwt"));
    assert_eq!(header.kid.as_deref(), Some("key-2"));
    assert_eq!(claims.sub, "service-a");
    assert_eq!(claims.client_id.as_deref(), Some("service-a"));
    assert_eq!(claims.sub_type, "service");
    assert_eq!(claims.scope, "service.read");
}

#[tokio::test]
async fn token_endpoint_accepts_multiple_scopes() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.write%20service.read%20service.write&audience=service-b",
    )).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["scope"], "service.write service.read");
}

#[tokio::test]
async fn token_endpoint_accepts_client_secret_basic() {
    let response = send(basic_request(
        "service-a",
        "super-secret",
        "grant_type=client_credentials&scope=service.read&audience=service-b",
    )).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn client_secret_basic_decodes_form_encoded_credentials() {
    let response = send(basic_request(
        "service-c",
        "a+b%2Bc%3Ad",
        "grant_type=client_credentials&scope=service.read&audience=service-b",
    )).await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn client_secret_basic_with_wrong_secret_returns_401_with_challenge() {
    let response = send(basic_request(
        "service-a",
        "wrong",
        "grant_type=client_credentials&scope=service.read&audience=service-b",
    )).await;

    assert!(response.headers()[header::WWW_AUTHENTICATE].to_str().unwrap().starts_with("Basic"));
    assert_error(response, StatusCode::UNAUTHORIZED, "invalid_client").await;
}

#[tokio::test]
async fn token_endpoint_rejects_multiple_auth_methods() {
    let response = send(basic_request(
        "service-a",
        "super-secret",
        "grant_type=client_credentials&client_secret=super-secret&scope=service.read&audience=service-b",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
}

#[tokio::test]
async fn token_endpoint_returns_401_for_wrong_secret() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&client_secret=wrong-secret&scope=service.read&audience=service-b",
    )).await;

    assert_error(response, StatusCode::UNAUTHORIZED, "invalid_client").await;
}

#[tokio::test]
async fn token_endpoint_returns_401_for_unknown_client() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=unknown&client_secret=super-secret&scope=service.read&audience=service-b",
    )).await;

    assert_error(response, StatusCode::UNAUTHORIZED, "invalid_client").await;
}

#[tokio::test]
async fn token_endpoint_returns_401_for_missing_secret() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&scope=service.read&audience=service-b",
    )).await;

    assert_error(response, StatusCode::UNAUTHORIZED, "invalid_client").await;
}

#[tokio::test]
async fn token_endpoint_returns_invalid_scope_for_disallowed_scope() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.read%20admin&audience=service-b",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_scope").await;
}

#[tokio::test]
async fn token_endpoint_requires_scope() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&audience=service-b",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_scope").await;
}

#[tokio::test]
async fn token_endpoint_requires_audience() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.read",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
}

#[tokio::test]
async fn token_endpoint_returns_invalid_target_for_disallowed_audience() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=client_credentials&client_id=service-a&client_secret=super-secret&scope=service.read&audience=payment-service",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_target").await;
}

#[tokio::test]
async fn token_endpoint_returns_400_for_unsupported_grant_type() {
    let response = send(form_request(
        "/oauth/token",
        "grant_type=password&client_id=service-a&client_secret=super-secret&scope=service.read&audience=service-b",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "unsupported_grant_type").await;
}

#[tokio::test]
async fn token_endpoint_requires_grant_type() {
    let response = send(form_request(
        "/oauth/token",
        "client_id=service-a&client_secret=super-secret&scope=service.read&audience=service-b",
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
}

#[tokio::test]
async fn token_endpoint_rejects_non_form_body() {
    let response = send(json_request("/oauth/token", r#"{"grant_type":"client_credentials"}"#)).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_request").await;
}

#[tokio::test]
async fn jwks_publishes_all_keys_with_cache_header() {
    let response = send(get_request("/oauth/jwks.json")).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "public, max-age=300");
    let kids: Vec<String> = json_body(response).await["keys"]
        .as_array().unwrap()
        .iter().map(|k| k["kid"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(kids, ["key-1", "key-2"]);
}

#[tokio::test]
async fn authorization_server_metadata_is_published() {
    let response = send(get_request("/.well-known/oauth-authorization-server")).await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    assert_eq!(json["issuer"], "http://localhost:8080");
    assert_eq!(json["token_endpoint"], "http://localhost:8080/oauth/token");
    assert_eq!(json["jwks_uri"], "http://localhost:8080/oauth/jwks.json");
    assert_eq!(json["token_endpoint_auth_methods_supported"][0], "client_secret_basic");

    let old = send(get_request("/.well-known/openid-configuration")).await;
    assert_eq!(old.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn login_returns_user_token_for_valid_user() {
    let response = send(json_request(
        "/auth/login",
        r#"{"username":"alice","password":"hunter2","scope":"profile","audience":"general"}"#,
    )).await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = json_body(response).await;
    let (_, claims) = verify_with_jwks(json["access_token"].as_str().unwrap(), "general").await;
    assert_eq!(claims.sub, "user-001");
    assert_eq!(claims.sub_type, "user");
    assert_eq!(claims.client_id, None);
}

#[tokio::test]
async fn login_returns_invalid_grant_for_wrong_password() {
    let response = send(json_request(
        "/auth/login",
        r#"{"username":"alice","password":"wrong","scope":"profile","audience":"general"}"#,
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_grant").await;
}

#[tokio::test]
async fn login_returns_invalid_target_for_disallowed_audience() {
    let response = send(json_request(
        "/auth/login",
        r#"{"username":"alice","password":"hunter2","scope":"profile","audience":"service-b"}"#,
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_target").await;
}

#[tokio::test]
async fn login_returns_invalid_scope_for_empty_scope() {
    let response = send(json_request(
        "/auth/login",
        r#"{"username":"alice","password":"hunter2","scope":"  ","audience":"general"}"#,
    )).await;

    assert_error(response, StatusCode::BAD_REQUEST, "invalid_scope").await;
}

#[tokio::test]
async fn login_route_is_absent_without_users() {
    let response = build_app(false)
        .oneshot(json_request(
            "/auth/login",
            r#"{"username":"alice","password":"hunter2","scope":"profile","audience":"general"}"#,
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_endpoints_return_200() {
    for uri in ["/healthz", "/readyz"] {
        let response = send(get_request(uri)).await;
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
    }
}

//! Integration tests for brigid-api.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use brigid_crypto::MasterKey;
use brigid_identity::derive_vsid_salt;
use brigid_oidc::OidcSigningKey;
use brigid_store::EncryptedStore;
use brigid_webauthn::WebauthnService;
use http_body_util::BodyExt;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

use brigid_api::{AppState, build_router};

fn master() -> MasterKey {
    MasterKey::from_hex(&"ab".repeat(32)).unwrap()
}

async fn make_state() -> Arc<AppState> {
    let master = master();
    let vsid_salt = derive_vsid_salt(&master);
    let store = EncryptedStore::new("sqlite::memory:", master)
        .await
        .unwrap();
    let rp_origin = Url::parse("http://localhost:8080").unwrap();
    let webauthn = WebauthnService::new("localhost", &rp_origin).unwrap();
    let oidc_key = OidcSigningKey::generate();
    let base_url = Url::parse("http://localhost:8080").unwrap();

    let mut state = AppState::new(store, webauthn, oidc_key, base_url, vsid_salt);
    // Integration tests use `x-forwarded-for` to give each test its own
    // rate-limit bucket (oneshot requests carry no real peer address).
    state.trust_forwarded_for = true;
    Arc::new(state)
}

async fn response_body_json(body: Body) -> serde_json::Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_returns_200() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_body_json(resp.into_body()).await;
    assert_eq!(json["status"], "ok");
}

#[tokio::test]
async fn ready_returns_200_when_db_accessible() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openid_configuration_returns_valid_json() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_body_json(resp.into_body()).await;
    assert!(json["issuer"].is_string(), "missing issuer");
    // authorization_endpoint and token_endpoint are intentionally omitted —
    // brig·id uses WebAuthn passkeys instead of the standard OAuth 2.0 code flow.
    assert!(json["jwks_uri"].is_string());
}

#[tokio::test]
async fn jwks_returns_valid_json() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_body_json(resp.into_body()).await;
    assert!(json["keys"].is_array(), "missing keys array");
    assert!(!json["keys"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn did_document_returns_valid_json() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/did.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let json = response_body_json(resp.into_body()).await;
    assert!(json["id"].as_str().unwrap().starts_with("did:web:"));
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn security_headers_present() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let headers = resp.headers();
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert!(headers.contains_key("strict-transport-security"));
    assert!(headers.contains_key("content-security-policy"));
}

// ---------------------------------------------------------------------------
// Auth: error paths (no WebAuthn hardware required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_begin_rejects_invalid_username() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let body = serde_json::json!({ "username": "not-an-email" });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/begin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_finish_rejects_malformed_credential() {
    // Sending a malformed credential (`{}`) trips Axum's JSON extractor before
    // the handler runs, yielding 422. The unknown-session branch (400) requires
    // a well-formed `PublicKeyCredential` payload and is covered by the full
    // end-to-end flow exercised in `brigid-webauthn` integration tests.
    let state = make_state().await;
    let app = build_router(state, &[]);

    let body = serde_json::json!({
        "session_id": Uuid::new_v4(),
        "credential": {}
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn login_finish_rejects_malformed_credential() {
    // See `register_finish_rejects_malformed_credential` — 422 here also
    // reflects JSON extraction failure, not the unknown-session branch.
    let state = make_state().await;
    let app = build_router(state, &[]);

    let body = serde_json::json!({
        "session_id": Uuid::new_v4(),
        "credential": {}
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn login_begin_returns_404_for_unknown_user() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let body = serde_json::json!({ "username": "nobody@example.com" });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/begin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Auth: full register roundtrip using SoftPasskey
// ---------------------------------------------------------------------------

#[tokio::test]
async fn register_and_login_roundtrip() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);

    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // -- Register begin --
    let body = serde_json::json!({ "username": "alice@localhost" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/begin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register/begin failed");
    let begin_json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let session_id: Uuid = serde_json::from_value(begin_json["session_id"].clone()).unwrap();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(begin_json["challenge"].clone()).unwrap();

    // -- Perform registration with soft passkey --
    let reg_credential = auth_client.do_registration(rp_origin.clone(), ccr).unwrap();

    // -- Register finish --
    let finish_body = serde_json::json!({
        "session_id": session_id,
        "credential": reg_credential,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&finish_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "register/finish failed");

    // -- Login begin --
    let body = serde_json::json!({ "username": "alice@localhost" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/begin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login/begin failed");
    let begin_json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let login_session_id: Uuid = serde_json::from_value(begin_json["session_id"].clone()).unwrap();
    let rcr: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(begin_json["challenge"].clone()).unwrap();

    // -- Perform authentication with soft passkey --
    let auth_credential = auth_client.do_authentication(rp_origin, rcr).unwrap();

    // -- Login finish --
    let finish_body = serde_json::json!({
        "session_id": login_session_id,
        "credential": auth_credential,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&finish_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login/finish failed");
    let login_json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(
        login_json["id_token"].is_string(),
        "expected id_token in response"
    );
}

#[tokio::test]
async fn register_begin_conflict_for_duplicate_user() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);

    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let body = serde_json::json!({ "username": "bob@localhost" });

    // First registration.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/begin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let begin_json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let session_id: Uuid = serde_json::from_value(begin_json["session_id"].clone()).unwrap();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(begin_json["challenge"].clone()).unwrap();
    let reg_credential = auth_client.do_registration(rp_origin, ccr).unwrap();

    let finish_body = serde_json::json!({
        "session_id": session_id,
        "credential": reg_credential,
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&finish_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second registration attempt — must return 409 Conflict.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/begin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ---------------------------------------------------------------------------
// Auth: logout
// ---------------------------------------------------------------------------

#[tokio::test]
async fn logout_requires_bearer_token() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_blacklists_token() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);

    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // -- Register --
    let body = serde_json::json!({ "username": "charlie@localhost" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/begin")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.1.10")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let begin_json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let session_id: Uuid = serde_json::from_value(begin_json["session_id"].clone()).unwrap();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(begin_json["challenge"].clone()).unwrap();
    let reg_credential = auth_client.do_registration(rp_origin.clone(), ccr).unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.1.10")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "session_id": session_id,
                        "credential": reg_credential,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // -- Login --
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/begin")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.1.10")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let login_begin: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let auth_session_id: Uuid = serde_json::from_value(login_begin["session_id"].clone()).unwrap();
    let rcr: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(login_begin["challenge"].clone()).unwrap();
    let auth_credential = auth_client.do_authentication(rp_origin, rcr).unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/finish")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.1.10")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "session_id": auth_session_id,
                        "credential": auth_credential,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "login/finish failed");
    let login_json: serde_json::Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let id_token = login_json["id_token"].as_str().unwrap().to_owned();

    // -- Logout #1 — must succeed (200 OK) --
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", "10.0.1.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "first logout must succeed");

    // -- Logout #2 — token is now blacklisted, must return 401 --
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", "10.0.1.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "second logout must fail (token blacklisted)"
    );
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limit_triggers_after_burst() {
    let state = make_state().await;
    let app = build_router(state, &[]);
    let body = serde_json::to_vec(&serde_json::json!({ "username": "test@localhost" })).unwrap();

    // 5 requests within the burst quota — none should be rate-limited.
    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/auth/login/begin")
                    .header("content-type", "application/json")
                    .header("x-forwarded-for", "10.0.0.1")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    // 6th request — burst exhausted, must be throttled.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/begin")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.0.0.1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cors_rejects_unauthorized_origin() {
    let allowed = Url::parse("https://allowed.example.com").unwrap();
    let state = make_state().await;
    let app = build_router(state, &[allowed]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/health")
                .header("origin", "https://evil.example.com")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "evil origin must not be reflected"
    );
}

#[tokio::test]
async fn cors_allows_configured_origin() {
    let allowed = Url::parse("https://allowed.example.com").unwrap();
    let state = make_state().await;
    let app = build_router(state, &[allowed]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/health")
                .header("origin", "https://allowed.example.com")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://allowed.example.com"),
        "configured origin must be reflected"
    );
}

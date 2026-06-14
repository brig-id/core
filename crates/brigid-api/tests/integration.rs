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

    let body = serde_json::json!({ "username": "nobody@example.com", "client_id": "test-client" });
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
    let body = serde_json::json!({ "username": "alice@localhost", "client_id": "test-client" });
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
    assert!(
        login_json["user_id"].is_string(),
        "expected user_id in login response"
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
    let body = serde_json::json!({ "username": "charlie@localhost", "client_id": "test-client" });
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

    // -- Simulate a service restart --
    //
    // The previous assertion is satisfied by the in-process `JtiStore` alone,
    // so it does not exercise the persistent SQLite blacklist consulted by
    // `AuthenticatedClaims` after the in-memory check. Wipe the in-memory
    // store (equivalent to relaunching the binary with the same SQLite file)
    // and replay the logout: only the DB-backed blacklist can produce 401
    // now, proving revocations survive across restarts.
    {
        use brigid_oidc::JtiStore;
        *state.jti_store.lock().unwrap_or_else(|e| e.into_inner()) = JtiStore::new();
    }
    let app = build_router(Arc::clone(&state), &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/logout")
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", "10.0.1.12")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "logout after simulated restart must still fail (persistent JTI blacklist)"
    );
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limit_triggers_after_burst() {
    let state = make_state().await;
    let app = build_router(state, &[]);
    let body = serde_json::to_vec(
        &serde_json::json!({ "username": "test@localhost", "client_id": "test-client" }),
    )
    .unwrap();

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

// ---------------------------------------------------------------------------
// Passkey management: DELETE /auth/passkeys/{id}
// ---------------------------------------------------------------------------

/// Registers a user and completes a login, returning (id_token, user_id, passkey_id).
///
/// Each of the 5 setup requests uses a distinct IP derived from `xff_base` so
/// that no bucket exceeds the burst limit of 5. The caller is free to use any
/// IP it likes for the actual request under test.
async fn register_and_login_for_passkey_tests(
    app: axum::Router,
    username: &str,
    rp_origin: &url::Url,
    auth_client: &mut webauthn_authenticator_rs::WebauthnAuthenticator<
        webauthn_authenticator_rs::softpasskey::SoftPasskey,
    >,
    xff_base: &str,
) -> (String, Uuid, Uuid) {
    // Register begin (IP .1)
    let xff1 = format!("{xff_base}.1");
    let body = serde_json::json!({ "username": username });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/begin")
                .header("content-type", "application/json")
                .header("x-forwarded-for", &xff1)
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j: serde_json::Value = response_body_json(resp.into_body()).await;
    let session_id: Uuid = serde_json::from_value(j["session_id"].clone()).unwrap();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let reg_cred = auth_client.do_registration(rp_origin.clone(), ccr).unwrap();

    // Register finish (IP .2)
    let xff2 = format!("{xff_base}.2");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .header("x-forwarded-for", &xff2)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "session_id": session_id,
                        "credential": reg_cred,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Login begin (IP .3)
    let xff3 = format!("{xff_base}.3");
    let login_body = serde_json::json!({ "username": username, "client_id": "test-client" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/begin")
                .header("content-type", "application/json")
                .header("x-forwarded-for", &xff3)
                .body(Body::from(serde_json::to_vec(&login_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j: serde_json::Value = response_body_json(resp.into_body()).await;
    let login_session: Uuid = serde_json::from_value(j["session_id"].clone()).unwrap();
    let rcr: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let auth_cred = auth_client
        .do_authentication(rp_origin.clone(), rcr)
        .unwrap();

    // Login finish (IP .4)
    let xff4 = format!("{xff_base}.4");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/login/finish")
                .header("content-type", "application/json")
                .header("x-forwarded-for", &xff4)
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "session_id": login_session,
                        "credential": auth_cred,
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j: serde_json::Value = response_body_json(resp.into_body()).await;
    let id_token = j["id_token"].as_str().unwrap().to_owned();
    let user_id: Uuid = serde_json::from_value(j["user_id"].clone()).unwrap();

    // List passkeys to get the credential id (IP .5)
    let xff5 = format!("{xff_base}.5");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", &xff5)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let passkeys: Vec<serde_json::Value> =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(
        !passkeys.is_empty(),
        "user should have at least one passkey"
    );
    let passkey_id: Uuid = serde_json::from_value(passkeys[0]["id"].clone()).unwrap();

    (id_token, user_id, passkey_id)
}

#[tokio::test]
async fn delete_passkey_roundtrip() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // xff_base "10.20.1" → setup IPs 10.20.1.1–10.20.1.5 (one each), DELETE on 10.20.1.6
    let (id_token, user_id, passkey_id) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_alice@localhost",
        &rp_origin,
        &mut auth_client,
        "10.20.1",
    )
    .await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/passkeys/{passkey_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.20.1.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": user_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "delete passkey must return 200"
    );
}

#[tokio::test]
async fn delete_passkey_wrong_user_returns_403() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_alice = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut auth_bob = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // Each user's setup uses its own /24 so no bucket accumulates.
    // xff_base "10.20.2" → 10.20.2.1–5 for alice's setup
    // xff_base "10.20.3" → 10.20.3.1–5 for bob's setup; DELETE on 10.20.2.6
    let (alice_token, _, alice_passkey) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_alice2@localhost",
        &rp_origin,
        &mut auth_alice,
        "10.20.2",
    )
    .await;
    let (_, bob_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_bob@localhost",
        &rp_origin,
        &mut auth_bob,
        "10.20.3",
    )
    .await;

    // Alice's token but Bob's user_id — VSID mismatch → 403
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/passkeys/{alice_passkey}"))
                .header("authorization", format!("Bearer {alice_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.20.2.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": bob_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "wrong user must get 403"
    );
}

#[tokio::test]
async fn delete_passkey_unknown_id_returns_404() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // xff_base "10.20.4" → setup IPs 10.20.4.1–5, DELETE on 10.20.4.6
    let (id_token, user_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_carol@localhost",
        &rp_origin,
        &mut auth_client,
        "10.20.4",
    )
    .await;

    let nonexistent_id = Uuid::new_v4();
    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/passkeys/{nonexistent_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.20.4.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": user_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "unknown passkey id must return 404"
    );
}

#[tokio::test]
async fn delete_passkey_requires_bearer_token() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/passkeys/{}", Uuid::new_v4()))
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": Uuid::new_v4() })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "missing token must return 401"
    );
}

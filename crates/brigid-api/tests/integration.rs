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

/// The server asks for a discoverable credential (`residentKey: required`,
/// ADR-003); `SoftPasskey` keeps no resident keys and refuses such a request.
/// The tests check the request, then relax it for the software authenticator
/// (registration finish does not depend on it).
fn for_soft_passkey(
    mut ccr: webauthn_rs::prelude::CreationChallengeResponse,
) -> webauthn_rs::prelude::CreationChallengeResponse {
    let selection = ccr
        .public_key
        .authenticator_selection
        .as_mut()
        .expect("registration states an authenticator selection");
    assert!(
        selection.require_resident_key,
        "registration must ask for a discoverable credential"
    );
    assert_eq!(
        serde_json::to_value(selection.resident_key).unwrap(),
        "required"
    );
    selection.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Discouraged);
    selection.require_resident_key = false;
    ccr
}

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
async fn register_begin_rejects_a_username_on_another_server() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let body = serde_json::json!({ "username": "alice@elsewhere.example" });
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
    let json = response_body_json(resp.into_body()).await;
    assert_eq!(json["error"], "accounts on this server end with @localhost");
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
    let reg_credential = auth_client
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

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
    let reg_credential = auth_client
        .do_registration(rp_origin, for_soft_passkey(ccr))
        .unwrap();

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
    let reg_credential = auth_client
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

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

/// The account routes have their own, larger quota: a client that used up
/// the ceremonies' burst can still load its account pages.
#[tokio::test]
async fn account_routes_do_not_share_the_ceremony_quota() {
    let state = make_state().await;
    let app = build_router(state, &[]);
    let get = |uri: &'static str| {
        Request::builder()
            .uri(uri)
            .header("x-forwarded-for", "10.0.0.2")
            .body(Body::empty())
            .unwrap()
    };
    let begin = || {
        Request::builder()
            .method("POST")
            .uri("/auth/login/begin")
            .header("content-type", "application/json")
            .header("x-forwarded-for", "10.0.0.2")
            .body(Body::from(
                r#"{"username":"test@localhost","client_id":"c"}"#,
            ))
            .unwrap()
    };

    for _ in 0..5 {
        app.clone().oneshot(begin()).await.unwrap();
    }
    let throttled = app.clone().oneshot(begin()).await.unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // 30 account requests in a row pass; the 31st is throttled.
    for _ in 0..30 {
        let resp = app
            .clone()
            .oneshot(get("/account/identity-templates"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
    let resp = app
        .oneshot(get("/account/identity-templates"))
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
    let reg_cred = auth_client
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

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

/// Adds a second credential to `user_id` (already registered/logged in via
/// `register_and_login_for_passkey_tests`), using a distinct authenticator
/// to stand in for a different physical key. Uses two IPs starting at
/// `xff_base_start` (begin, finish).
async fn add_credential_for_tests(
    app: axum::Router,
    id_token: &str,
    user_id: Uuid,
    rp_origin: &url::Url,
    xff_base: &str,
    xff_start: u8,
) {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/passkeys/add/begin")
                .header("authorization", format!("Bearer {id_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", format!("{xff_base}.{xff_start}"))
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": user_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "add/begin must return 200");
    let j: serde_json::Value = response_body_json(resp.into_body()).await;
    let session_id: Uuid = serde_json::from_value(j["session_id"].clone()).unwrap();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();

    let mut second_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let reg_cred = second_authenticator
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/passkeys/add/finish")
                .header("content-type", "application/json")
                .header("x-forwarded-for", format!("{xff_base}.{}", xff_start + 1))
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
    assert_eq!(resp.status(), StatusCode::OK, "add/finish must return 200");
}

#[tokio::test]
async fn delete_passkey_roundtrip() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // xff_base "10.20.1" → setup IPs 10.20.1.1–10.20.1.5 (one each), add a
    // 2nd credential on .6/.7 (deleting the sole passkey is now refused —
    // see delete_passkey_last_one_returns_409), DELETE on .8, list on .9.
    let (id_token, user_id, passkey_id) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_alice@localhost",
        &rp_origin,
        &mut auth_client,
        "10.20.1",
    )
    .await;

    add_credential_for_tests(app.clone(), &id_token, user_id, &rp_origin, "10.20.1", 6).await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/passkeys/{passkey_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.20.1.8")
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

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", "10.20.1.9")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let passkeys: Vec<serde_json::Value> =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(passkeys.len(), 1, "one credential must remain, not zero");
}

#[tokio::test]
async fn delete_passkey_last_one_returns_409() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // xff_base "10.20.5" → setup IPs 10.20.5.1–5, DELETE attempt on .6.
    // brig·id is passkey-only: deleting someone's last credential would
    // permanently lock them out, so this must be refused.
    let (id_token, user_id, passkey_id) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_solo@localhost",
        &rp_origin,
        &mut auth_client,
        "10.20.5",
    )
    .await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(format!("/auth/passkeys/{passkey_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.20.5.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": user_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::CONFLICT,
        "deleting the last passkey must be refused"
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

// ---------------------------------------------------------------------------
// Passkey management: GET /auth/passkeys
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_passkeys_returns_registered_passkeys() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // xff_base "10.30.1" → setup IPs 10.30.1.1–5, list request on 10.30.1.6
    let (id_token, user_id, passkey_id) = register_and_login_for_passkey_tests(
        app.clone(),
        "lp_alice@localhost",
        &rp_origin,
        &mut auth_client,
        "10.30.1",
    )
    .await;

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", "10.30.1.6")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK, "list must return 200");
    let passkeys: Vec<serde_json::Value> =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(passkeys.len(), 1, "user should have exactly one passkey");
    let listed_id: Uuid = serde_json::from_value(passkeys[0]["id"].clone()).unwrap();
    assert_eq!(
        listed_id, passkey_id,
        "listed passkey id must match registered id"
    );
}

#[tokio::test]
async fn list_passkeys_wrong_user_returns_403() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_alice = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut auth_bob = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let (alice_token, _, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "lp_alice2@localhost",
        &rp_origin,
        &mut auth_alice,
        "10.30.2",
    )
    .await;
    let (_, bob_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "lp_bob@localhost",
        &rp_origin,
        &mut auth_bob,
        "10.30.3",
    )
    .await;

    // Alice's token + Bob's user_id — VSID mismatch → 403
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={bob_id}"))
                .header("authorization", format!("Bearer {alice_token}"))
                .header("x-forwarded-for", "10.30.2.6")
                .body(Body::empty())
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
async fn list_passkeys_requires_bearer_token() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={}", Uuid::new_v4()))
                .body(Body::empty())
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

// ---------------------------------------------------------------------------
// Passkey management: POST /auth/passkeys/add/begin + /finish
// ---------------------------------------------------------------------------

#[tokio::test]
async fn add_credential_roundtrip() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // xff_base "10.40.1" → setup IPs 10.40.1.1–5, add begin/finish on .6/.7,
    // list-passkeys check on .8.
    let (id_token, user_id, _first_passkey) = register_and_login_for_passkey_tests(
        app.clone(),
        "ac_alice@localhost",
        &rp_origin,
        &mut auth_client,
        "10.40.1",
    )
    .await;

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/passkeys/add/begin")
                .header("authorization", format!("Bearer {id_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.40.1.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": user_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "add/begin must return 200");
    let j: serde_json::Value = response_body_json(resp.into_body()).await;
    let session_id: Uuid = serde_json::from_value(j["session_id"].clone()).unwrap();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();

    // A distinct authenticator stands in for a second physical key.
    let mut second_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let reg_cred = second_authenticator
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/passkeys/add/finish")
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.40.1.7")
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
    assert_eq!(resp.status(), StatusCode::OK, "add/finish must return 200");

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("authorization", format!("Bearer {id_token}"))
                .header("x-forwarded-for", "10.40.1.8")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let passkeys: Vec<serde_json::Value> =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        passkeys.len(),
        2,
        "identity must now have two distinct credentials, not a second identity"
    );
}

#[tokio::test]
async fn add_credential_wrong_user_returns_403() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_alice = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut auth_bob = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let (alice_token, _, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "ac_alice2@localhost",
        &rp_origin,
        &mut auth_alice,
        "10.40.2",
    )
    .await;
    let (_, bob_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "ac_bob@localhost",
        &rp_origin,
        &mut auth_bob,
        "10.40.3",
    )
    .await;

    // Alice's token but Bob's user_id — VSID mismatch → 403, same as
    // delete_passkey/list_passkeys.
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/passkeys/add/begin")
                .header("authorization", format!("Bearer {alice_token}"))
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.40.2.6")
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
async fn add_credential_begin_requires_bearer_token() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/passkeys/add/begin")
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

// ---------------------------------------------------------------------------
// Identities: /account/identities
// ---------------------------------------------------------------------------

async fn identity_request(
    app: &axum::Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    xff: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", xff);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = match body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&b).unwrap())
        }
        None => Body::empty(),
    };
    let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn identities_require_a_bearer_token() {
    let app = build_router(make_state().await, &[]);
    let (status, _) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={}", Uuid::new_v4()),
        None,
        "10.40.0.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn identity_crud_roundtrip_and_isolation() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();

    let mut alice_dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (alice_token, alice_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "id_alice@localhost",
        &rp_origin,
        &mut alice_dev,
        "10.41.1",
    )
    .await;
    let mut bob_dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (bob_token, bob_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "id_bob@localhost",
        &rp_origin,
        &mut bob_dev,
        "10.41.2",
    )
    .await;

    // Create
    let (status, created) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&alice_token),
        "10.41.3.1",
        Some(serde_json::json!({
            "user_id": alice_id,
            "name": "  Pro  ",
            "logo": "icon:solid:briefcase",
            "description": "work"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["name"], "Pro");
    assert!(created.get("did").is_none(), "the DID must not be exposed");
    let ident_id = created["id"].as_str().unwrap().to_string();

    // Validation: no name, bad logo
    for bad in [
        serde_json::json!({"user_id": alice_id, "name": " ", "logo": "icon:solid:x"}),
        serde_json::json!({"user_id": alice_id, "name": "N", "logo": "https://x/y.png"}),
    ] {
        let (status, _) = identity_request(
            &app,
            "POST",
            "/account/identities",
            Some(&alice_token),
            "10.41.3.2",
            Some(bad),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // List
    let (status, list) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={alice_id}"),
        Some(&alice_token),
        "10.41.3.3",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // The three starter identities created at sign-up, plus this one.
    let names: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Public", "Personal", "Work", "Pro"]);

    // Update: rename, clear the description
    let (status, updated) = identity_request(
        &app,
        "PATCH",
        &format!("/account/identities/{ident_id}"),
        Some(&alice_token),
        "10.41.3.4",
        Some(serde_json::json!({"user_id": alice_id, "name": "Boulot", "description": ""})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(updated["name"], "Boulot");
    assert_eq!(updated["logo"], "icon:solid:briefcase");
    assert!(updated["description"].is_null());

    // Bob cannot act on Alice's account...
    let (status, _) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={alice_id}"),
        Some(&bob_token),
        "10.41.4.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // ...nor reach her identity through his own account.
    let (status, _) = identity_request(
        &app,
        "DELETE",
        &format!("/account/identities/{ident_id}?user_id={bob_id}"),
        Some(&bob_token),
        "10.41.4.2",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Delete
    let (status, _) = identity_request(
        &app,
        "DELETE",
        &format!("/account/identities/{ident_id}?user_id={alice_id}"),
        Some(&alice_token),
        "10.41.5.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, list) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={alice_id}"),
        Some(&alice_token),
        "10.41.5.2",
        None,
    )
    .await;
    assert_eq!(list.as_array().unwrap().len(), 3);

    // From a template, overriding only the name.
    let (status, from_template) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&alice_token),
        "10.41.6.1",
        Some(serde_json::json!({"user_id": alice_id, "template": "family", "name": "Les Dupont"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(from_template["name"], "Les Dupont");
    assert_eq!(from_template["logo"], "icon:solid:people-roof");
    assert_eq!(
        from_template["description"],
        "Shared within a restricted circle."
    );

    let (status, _) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&alice_token),
        "10.41.6.2",
        Some(serde_json::json!({"user_id": alice_id, "template": "nope"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn identity_templates_are_listed() {
    let app = build_router(make_state().await, &[]);
    let (status, list) = identity_request(
        &app,
        "GET",
        "/account/identity-templates",
        None,
        "10.42.0.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let keys: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["key"].as_str().unwrap())
        .collect();
    assert!(keys.contains(&"work") && keys.contains(&"isolated"));
}

#[tokio::test]
async fn passkey_can_be_renamed() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (token, user_id, passkey_id) = register_and_login_for_passkey_tests(
        app.clone(),
        "pk_label@localhost",
        &rp_origin,
        &mut dev,
        "10.43.1",
    )
    .await;

    let (status, _) = identity_request(
        &app,
        "PATCH",
        &format!("/auth/passkeys/{passkey_id}"),
        Some(&token),
        "10.43.2.1",
        Some(serde_json::json!({"user_id": user_id, "label": "Pixel 9"})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (_, list) = identity_request(
        &app,
        "GET",
        &format!("/auth/passkeys?user_id={user_id}"),
        Some(&token),
        "10.43.2.2",
        None,
    )
    .await;
    assert_eq!(list[0]["label"], "Pixel 9");

    let (status, _) = identity_request(
        &app,
        "PATCH",
        &format!("/auth/passkeys/{}", Uuid::new_v4()),
        Some(&token),
        "10.43.2.3",
        Some(serde_json::json!({"user_id": user_id, "label": "x"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Username-less login (core#18): no username at begin, the user is taken
/// from the passkey's user handle and the assertion is verified against that
/// user's passkeys.
#[tokio::test]
async fn discoverable_login_roundtrip() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::{PublicKeyCredential, RequestChallengeResponse};

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (_, user_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "disco@localhost",
        &rp_origin,
        &mut dev,
        "10.44.1",
    )
    .await;

    // A first named login only to learn the credential id SoftPasskey needs:
    // it keeps no resident keys, so the request must name the credential.
    let (_, named) = identity_request(
        &app,
        "POST",
        "/auth/login/begin",
        None,
        "10.44.2.1",
        Some(serde_json::json!({"username": "disco@localhost", "client_id": "test-client"})),
    )
    .await;
    let allow = named["challenge"]["publicKey"]["allowCredentials"].clone();

    let begin = |xff: &'static str| {
        let app = app.clone();
        async move {
            identity_request(
                &app,
                "POST",
                "/auth/login/begin",
                None,
                xff,
                Some(serde_json::json!({"client_id": "test-client"})),
            )
            .await
        }
    };

    let (status, j) = begin("10.44.2.2").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        j["challenge"]["publicKey"]["allowCredentials"]
            .as_array()
            .is_none_or(|a| a.is_empty()),
        "a discoverable challenge names no credential"
    );
    let session: Uuid = serde_json::from_value(j["session_id"].clone()).unwrap();
    let mut rcr: RequestChallengeResponse = serde_json::from_value(j["challenge"].clone()).unwrap();
    rcr.public_key.allow_credentials = serde_json::from_value(allow.clone()).unwrap();
    rcr.mediation = None;
    let mut cred: PublicKeyCredential = dev.do_authentication(rp_origin.clone(), rcr).unwrap();
    cred.response.user_handle = Some(user_id.as_bytes().to_vec().into());

    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/login/finish",
        None,
        "10.44.2.3",
        Some(serde_json::json!({"session_id": session, "credential": cred})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_value::<Uuid>(j["user_id"].clone()).unwrap(),
        user_id
    );
    assert!(j["id_token"].as_str().is_some());

    // An unknown user handle is refused cleanly.
    let (_, j) = begin("10.44.3.1").await;
    let session: Uuid = serde_json::from_value(j["session_id"].clone()).unwrap();
    let mut rcr: RequestChallengeResponse = serde_json::from_value(j["challenge"].clone()).unwrap();
    rcr.public_key.allow_credentials = serde_json::from_value(allow).unwrap();
    rcr.mediation = None;
    let mut cred: PublicKeyCredential = dev.do_authentication(rp_origin, rcr).unwrap();
    cred.response.user_handle = Some(Uuid::new_v4().as_bytes().to_vec().into());
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/login/finish",
        None,
        "10.44.3.2",
        Some(serde_json::json!({"session_id": session, "credential": cred})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// core#47: a session can be checked and refreshed; the old token dies on
/// refresh, and a session whose account is gone answers 401.
#[tokio::test]
async fn session_check_refresh_and_deleted_account() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (token, user_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "sess@localhost",
        &rp_origin,
        &mut dev,
        "10.45.1",
    )
    .await;

    let (status, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/session?user_id={user_id}"),
        Some(&token),
        "10.45.2.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(j["expires_at"].as_i64().unwrap() > 0);

    let (status, j) = identity_request(
        &app,
        "POST",
        &format!("/auth/session/refresh?user_id={user_id}"),
        Some(&token),
        "10.45.2.2",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let fresh = j["id_token"].as_str().unwrap().to_string();
    assert_ne!(fresh, token);

    // The old token is revoked, the new one works.
    let (status, _) = identity_request(
        &app,
        "GET",
        &format!("/auth/session?user_id={user_id}"),
        Some(&token),
        "10.45.2.3",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = identity_request(
        &app,
        "GET",
        &format!("/auth/session?user_id={user_id}"),
        Some(&fresh),
        "10.45.2.4",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Another account's id: refused.
    let (status, _) = identity_request(
        &app,
        "GET",
        &format!("/auth/session?user_id={}", Uuid::new_v4()),
        Some(&fresh),
        "10.45.3.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// ADR-002: a token for an identity carries the identity's VSID; two
/// identities of one account are different subjects at the same RP, and
/// neither equals the account's own subject.
#[tokio::test]
async fn identity_tokens_have_distinct_subjects() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    fn sub(token: &str) -> String {
        use base64ct::Encoding as _;
        let payload = token.split('.').nth(1).unwrap();
        let bytes = base64ct::Base64UrlUnpadded::decode_vec(payload).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        claims["sub"].as_str().unwrap().to_string()
    }

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (token, user_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "idtok@localhost",
        &rp_origin,
        &mut dev,
        "10.46.1",
    )
    .await;

    let (_, list) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={user_id}"),
        Some(&token),
        "10.46.2.1",
        None,
    )
    .await;
    let ids: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_string())
        .collect();

    let mut subs = Vec::new();
    for (n, id) in ids.iter().take(2).enumerate() {
        let (status, j) = identity_request(
            &app,
            "POST",
            &format!("/account/identities/{id}/token"),
            Some(&token),
            &format!("10.46.3.{n}"),
            Some(serde_json::json!({"user_id": user_id, "client_id": "rp.example"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        subs.push(sub(j["id_token"].as_str().unwrap()));
    }
    assert_ne!(subs[0], subs[1], "two identities, two subjects");
    assert_ne!(
        subs[0],
        sub(&token),
        "the account's subject is never reused"
    );

    // Stable for the same identity and RP.
    let (_, j) = identity_request(
        &app,
        "POST",
        &format!("/account/identities/{}/token", ids[0]),
        Some(&token),
        "10.46.4.1",
        Some(serde_json::json!({"user_id": user_id, "client_id": "rp.example"})),
    )
    .await;
    assert_eq!(sub(j["id_token"].as_str().unwrap()), subs[0]);
}

// ---------------------------------------------------------------------------
// Account recovery (ADR-004)
// ---------------------------------------------------------------------------

/// The whole recovery path: create a code, lose the passkey, enrol a new one
/// with the code, sign in; the code is consumed and a typo or a wrong code is
/// refused without a lookup or with a plain 401.
#[tokio::test]
async fn recovery_code_enrols_a_new_passkey_once() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut first_device = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (token, user_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "recover@localhost",
        &rp_origin,
        &mut first_device,
        "10.52.1",
    )
    .await;

    // No code yet.
    let uri = format!("/account/recovery-code?user_id={user_id}");
    let (status, j) = identity_request(&app, "GET", &uri, Some(&token), "10.52.2.1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(j["code_created_at"].is_null());

    // A code needs a session.
    let (status, _) = identity_request(&app, "POST", &uri, None, "10.52.2.2", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, j) = identity_request(&app, "POST", &uri, Some(&token), "10.52.2.3", None).await;
    assert_eq!(status, StatusCode::OK);
    let code = j["code"].as_str().unwrap().to_string();
    assert_eq!(code.len(), 49, "{code}");
    let (_, j) = identity_request(&app, "GET", &uri, Some(&token), "10.52.2.4", None).await;
    assert!(j["code_created_at"].is_string());

    // A typo is caught before any lookup; a well-formed wrong code is a 401.
    let mut typo: Vec<char> = code.chars().collect();
    typo[0] = if typo[0] == 'A' { 'C' } else { 'A' };
    let typo: String = typo.into_iter().collect();
    let begin = |code: &str| serde_json::json!({ "code": code, "client_id": "test-client" });
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        "10.52.3.1",
        Some(begin(&typo)),
    )
    .await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::UNAUTHORIZED,
        "{status}"
    );
    let other = brigid_identity::RecoveryCode::generate().unwrap().display();
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        "10.52.3.2",
        Some(begin(&other)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The first device is lost: a new one enrols with the code.
    let mut new_device = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        "10.52.4.1",
        Some(begin(&code.to_lowercase())),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let session_id = j["session_id"].clone();
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let cred = new_device
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

    // A recovery session can't be finished as a signup.
    let finish_body = serde_json::json!({
        "session_id": session_id,
        "credential": cred,
        "label": "New phone",
    });
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/register/finish",
        None,
        "10.52.4.2",
        Some(finish_body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/recovery/finish",
        None,
        "10.52.4.3",
        Some(finish_body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    assert_eq!(j["user_id"].as_str().unwrap(), user_id.to_string());
    let new_token = j["id_token"].as_str().unwrap().to_string();

    // Signed in: two passkeys now, the new one named.
    let (status, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/passkeys?user_id={user_id}"),
        Some(&new_token),
        "10.52.5.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let passkeys = j.as_array().unwrap();
    assert_eq!(passkeys.len(), 2);
    assert!(passkeys.iter().any(|p| p["label"] == "New phone"));

    // Consumed: the same code no longer works, and the status says when it was used.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        "10.52.6.1",
        Some(begin(&code)),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (_, j) = identity_request(&app, "GET", &uri, Some(&new_token), "10.52.6.2", None).await;
    assert!(j["code_created_at"].is_null());
    assert!(j["last_used_at"].is_string());
}

/// A session begun to add a passkey can't be completed as a new account.
#[tokio::test]
async fn registration_sessions_finish_only_as_what_they_began() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut device = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (token, user_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "purpose@localhost",
        &rp_origin,
        &mut device,
        "10.53.1",
    )
    .await;
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/passkeys/add/begin",
        Some(&token),
        "10.53.2.1",
        Some(serde_json::json!({ "user_id": user_id })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let mut second = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let cred = second
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();
    let body = serde_json::json!({ "session_id": j["session_id"], "credential": cred });
    for (uri, ip) in [
        ("/auth/register/finish", "10.53.3.1"),
        ("/auth/recovery/finish", "10.53.3.2"),
    ] {
        let (status, _) = identity_request(&app, "POST", uri, None, ip, Some(body.clone())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
    }
    // Still finishable as what it began.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/passkeys/add/finish",
        None,
        "10.53.3.3",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// ADR-003: signing up without a username. The server generates the handle,
/// and with a client_id the new account is signed in by the same ceremony.
#[tokio::test]
async fn signup_without_username_signs_in() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/register/begin",
        None,
        "10.54.1.1",
        Some(serde_json::json!({ "client_id": "test-client" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let name = j["challenge"]["publicKey"]["user"]["name"]
        .as_str()
        .unwrap();
    let (username, server) = name.split_once('@').unwrap();
    assert_eq!(server, "localhost");
    assert_eq!(username.split('-').count(), 3, "generated handle: {name}");

    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let cred = dev
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/register/finish",
        None,
        "10.54.1.2",
        Some(serde_json::json!({
            "session_id": j["session_id"],
            "credential": cred,
            "label": "1Password",
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let token = j["id_token"].as_str().expect("signed in at signup");
    let user_id: Uuid = serde_json::from_value(j["user_id"].clone()).unwrap();

    // The session works, the passkey has its name, the starter identities exist.
    let (status, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/passkeys?user_id={user_id}"),
        Some(token),
        "10.54.2.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j[0]["label"], "1Password");
    let (_, j) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={user_id}"),
        Some(token),
        "10.54.2.2",
        None,
    )
    .await;
    assert_eq!(j.as_array().unwrap().len(), 3);

    // Without client_id, signup still only creates the account.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/register/begin",
        None,
        "10.54.3.1",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let mut dev2 = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let cred = dev2
        .do_registration(rp_origin, for_soft_passkey(ccr))
        .unwrap();
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/register/finish",
        None,
        "10.54.3.2",
        Some(serde_json::json!({ "session_id": j["session_id"], "credential": cred })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(j.is_null(), "no token without client_id: {j}");
}

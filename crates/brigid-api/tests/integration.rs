// -- A restart (a new router on the same database) does not revive it --
//! Integration tests for brigid-api.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use brigid_crypto::MasterKey;
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

/// This server's origin, as a browser sends it on every request that changes
/// something (ADR-005: the API refuses those from any other origin).
const ORIGIN: &str = "http://localhost:8080";

/// The `name=value` of the session cookie a response sets.
fn cookie_of(resp: &axum::response::Response) -> String {
    let set = resp
        .headers()
        .get("set-cookie")
        .expect("the response opens a session")
        .to_str()
        .unwrap();
    assert!(set.contains("HttpOnly"), "{set}");
    assert!(set.contains("SameSite=Strict"), "{set}");
    set.split(';').next().unwrap().to_string()
}

fn master() -> MasterKey {
    MasterKey::from_hex(&"ab".repeat(32)).unwrap()
}

/// A server as it starts: nobody opened sign-up, nobody administers it.
async fn fresh_app_state() -> AppState {
    let master = master();
    let vsid_salt = [0x5a; 32];
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
    state
}

/// A server where anyone can create an account: what most tests need.
/// Who may sign up is tested on its own, from [`fresh_app_state`].
async fn make_state() -> Arc<AppState> {
    let state = fresh_app_state().await;
    state
        .store
        .set_signup_policy(brigid_store::SignupPolicy::Open)
        .await
        .unwrap();
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
async fn openid_configuration_describes_the_code_flow() {
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
    // A public client reads it from its own origin.
    assert_eq!(resp.headers()["access-control-allow-origin"], "*");
    let json = response_body_json(resp.into_body()).await;
    assert_eq!(json["issuer"], "http://localhost:8080");
    assert_eq!(
        json["authorization_endpoint"],
        "http://localhost:8080/authorize"
    );
    assert_eq!(json["token_endpoint"], "http://localhost:8080/token");
    assert_eq!(
        json["response_types_supported"],
        serde_json::json!(["code"])
    );
    assert_eq!(
        json["scopes_supported"],
        serde_json::json!(["openid", "profile", "email"])
    );
    assert_eq!(
        json["id_token_signing_alg_values_supported"],
        serde_json::json!(["EdDSA"])
    );
    assert_eq!(
        json["code_challenge_methods_supported"],
        serde_json::json!(["S256"])
    );
    assert!(json.get("userinfo_endpoint").is_none());
}

#[tokio::test]
async fn jwks_returns_valid_json() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
    // An API response loads nothing and names no origin at all.
    let csp = headers["content-security-policy"].to_str().unwrap();
    assert!(csp.starts_with("default-src 'none'"), "{csp}");
    assert!(!csp.contains("http"), "{csp}");
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&finish_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "register/finish failed"
    );

    // -- Login begin --
    let body = serde_json::json!({ "username": "alice@localhost", "client_id": "test-client" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/login/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&finish_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    // A session in a cookie, never a token (ADR-005).
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "login/finish failed");
    let cookie = cookie_of(&resp);
    assert!(cookie.starts_with("brigid_session="), "{cookie}");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(body.is_empty(), "no token in the body");
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/register/finish")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&finish_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Second registration attempt — must return 409 Conflict.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // -- Login --
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "login/finish failed");
    let id_token = cookie_of(&resp);

    // -- Logout #1 — must succeed (200 OK) --
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/logout")
                .header("cookie", &*id_token)
                .header("x-forwarded-for", "10.0.1.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NO_CONTENT,
        "first logout must succeed"
    );
    assert!(
        resp.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0"),
        "logout removes the cookie"
    );

    // -- Logout #2 — token is now blacklisted, must return 401 --
    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/logout")
                .header("cookie", &*id_token)
                .header("x-forwarded-for", "10.0.1.11")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "second logout must fail (session deleted)"
    );

    // -- A restart (a new router on the same database) does not revive it --
    let app = build_router(Arc::clone(&state), &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/logout")
                .header("cookie", &*id_token)
                .header("x-forwarded-for", "10.0.1.12")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "the session stays ended after a restart"
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
                    .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
            .header("origin", ORIGIN)
            .uri(uri)
            .header("x-forwarded-for", "10.0.0.2")
            .body(Body::empty())
            .unwrap()
    };
    let begin = || {
        Request::builder()
            .header("origin", ORIGIN)
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

/// Registers a user and signs in, returning (session cookie, user_id, passkey_id).
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
                .header("origin", ORIGIN)
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
    // The WebAuthn user handle is the account id.
    let user_id = Uuid::from_slice(ccr.public_key.user.id.as_ref()).unwrap();
    let reg_cred = auth_client
        .do_registration(rp_origin.clone(), for_soft_passkey(ccr))
        .unwrap();

    // Register finish (IP .2)
    let xff2 = format!("{xff_base}.2");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Login begin (IP .3)
    let xff3 = format!("{xff_base}.3");
    let login_body = serde_json::json!({ "username": username, "client_id": "test-client" });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
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
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let id_token = cookie_of(&resp);

    // List passkeys to get the credential id (IP .5)
    let xff5 = format!("{xff_base}.5");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("cookie", &*id_token)
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
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/passkeys/add/begin")
                .header("cookie", id_token)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("DELETE")
                .uri(format!("/auth/passkeys/{passkey_id}"))
                .header("cookie", &*id_token)
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
        StatusCode::NO_CONTENT,
        "delete passkey must succeed"
    );

    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("cookie", &*id_token)
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
                .header("origin", ORIGIN)
                .method("DELETE")
                .uri(format!("/auth/passkeys/{passkey_id}"))
                .header("cookie", &*id_token)
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
async fn another_accounts_passkey_is_not_found() {
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
    let (_, _, alice_passkey) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_alice2@localhost",
        &rp_origin,
        &mut auth_alice,
        "10.20.2",
    )
    .await;
    let (bob_token, bob_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "dp_bob@localhost",
        &rp_origin,
        &mut auth_bob,
        "10.20.3",
    )
    .await;

    // Bob's session, Alice's passkey (and a user_id naming Alice, ignored):
    // the account is the session's, and Alice's passkey is not Bob's.
    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("DELETE")
                .uri(format!("/auth/passkeys/{alice_passkey}"))
                .header("cookie", &*bob_token)
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.20.3.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": bob_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "another account's passkey must be 404"
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
                .header("origin", ORIGIN)
                .method("DELETE")
                .uri(format!("/auth/passkeys/{nonexistent_id}"))
                .header("cookie", &*id_token)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("cookie", &*id_token)
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
async fn a_user_id_parameter_never_names_the_account() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_alice = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut auth_bob = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let (alice_token, _, alice_passkey) = register_and_login_for_passkey_tests(
        app.clone(),
        "lp_alice2@localhost",
        &rp_origin,
        &mut auth_alice,
        "10.30.2",
    )
    .await;
    let (_, bob_id, bob_passkey) = register_and_login_for_passkey_tests(
        app.clone(),
        "lp_bob@localhost",
        &rp_origin,
        &mut auth_bob,
        "10.30.3",
    )
    .await;

    // Alice's session naming Bob: the parameter is ignored, Alice sees her
    // own passkeys and never Bob's (ADR-005: the account is the session's).
    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={bob_id}"))
                .header("cookie", &*alice_token)
                .header("x-forwarded-for", "10.30.2.6")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let list = response_body_json(resp.into_body()).await;
    let ids: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [alice_passkey.to_string().as_str()]);
    assert!(!ids.contains(&bob_passkey.to_string().as_str()));
}

#[tokio::test]
async fn list_passkeys_requires_a_session() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/passkeys/add/begin")
                .header("cookie", &*id_token)
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
                .header("origin", ORIGIN)
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
                .header("origin", ORIGIN)
                .method("GET")
                .uri(format!("/auth/passkeys?user_id={user_id}"))
                .header("cookie", &*id_token)
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
async fn add_credential_is_for_the_sessions_account() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut auth_alice = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut auth_bob = WebauthnAuthenticator::new(SoftPasskey::new(true));

    let (alice_token, alice_id, _) = register_and_login_for_passkey_tests(
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

    // Alice's session naming Bob: the ceremony is for Alice (her user handle,
    // her passkey excluded), never for Bob.
    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
                .method("POST")
                .uri("/auth/passkeys/add/begin")
                .header("cookie", &*alice_token)
                .header("content-type", "application/json")
                .header("x-forwarded-for", "10.40.2.6")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({ "user_id": bob_id })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let j = response_body_json(resp.into_body()).await;
    let ccr: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let handle = Uuid::from_slice(ccr.public_key.user.id.as_ref()).unwrap();
    assert_eq!(handle, alice_id);
    assert_ne!(handle, bob_id);
    let _ = alice_token;
}

#[tokio::test]
async fn add_credential_begin_requires_a_session() {
    let state = make_state().await;
    let app = build_router(state, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .header("origin", ORIGIN)
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
        .header("origin", ORIGIN)
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", xff);
    if let Some(t) = token {
        req = req.header("cookie", t);
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

/// Like [`identity_request`], also returning the session cookie the response
/// sets, as `name=value`.
async fn request_with_cookie(
    app: &axum::Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    xff: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, Option<String>, serde_json::Value) {
    let mut req = Request::builder()
        .header("origin", ORIGIN)
        .method(method)
        .uri(uri)
        .header("x-forwarded-for", xff);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
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
    let set = resp.headers().get("set-cookie").map(|_| cookie_of(&resp));
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, set, json)
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
    finish_onboarding(&app, &alice_token, "10.41.1").await;
    finish_onboarding(&app, &bob_token, "10.41.2").await;

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
            "logo": "icon:ph:briefcase",
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
        serde_json::json!({"user_id": alice_id, "name": " ", "logo": "icon:ph:x"}),
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
    assert_eq!(updated["logo"], "icon:ph:briefcase");
    assert!(updated["description"].is_null());

    // Bob naming Alice sees his own identities, never hers...
    let (status, bobs) = identity_request(
        &app,
        "GET",
        &format!("/account/identities?user_id={alice_id}"),
        Some(&bob_token),
        "10.41.4.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        bobs.as_array()
            .unwrap()
            .iter()
            .all(|i| i["id"] != ident_id.as_str()),
        "Bob must not see Alice's identity"
    );
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
    assert_eq!(from_template["logo"], "icon:ph:house-line");
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

    let (status, cookie, _) = request_with_cookie(
        &app,
        "POST",
        "/auth/login/finish",
        None,
        "10.44.2.3",
        Some(serde_json::json!({"session_id": session, "credential": cred})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let cookie = cookie.expect("a session");
    // The session is the account the passkey named.
    let (status, list) = identity_request(
        &app,
        "GET",
        "/auth/passkeys",
        Some(&cookie),
        "10.44.2.4",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    let _ = user_id;

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

/// ADR-005 §1: the session lives in a cookie; it can be checked, it ends at
/// sign-out (and stays ended), a forged or missing cookie is 401, and a
/// cross-origin request that changes something is refused.
#[tokio::test]
async fn cookie_session_check_sign_out_and_same_origin() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (cookie, _, _) = register_and_login_for_passkey_tests(
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
        "/auth/session",
        Some(&cookie),
        "10.45.2.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let idle = j["idle_expires_at"].as_i64().unwrap();
    let end = j["expires_at"].as_i64().unwrap();
    assert!(idle > 0 && idle <= end, "{j}");
    assert!(
        end - idle >= 11 * 3600,
        "1 h idle within a 12 h lifetime: {j}"
    );

    // No cookie, or a forged one: 401.
    let (status, _) = identity_request(&app, "GET", "/auth/session", None, "10.45.2.2", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some("brigid_session=forged"),
        "10.45.2.3",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A request that changes something must come from this origin; a GET may not.
    for origin in [Some("https://evil.example"), None] {
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/account/recovery-code")
            .header("cookie", &*cookie)
            .header("x-forwarded-for", "10.45.3.1");
        if let Some(o) = origin {
            req = req.header("origin", o);
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN, "origin {origin:?}");
    }
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/auth/session")
                .header("cookie", &*cookie)
                .header("x-forwarded-for", "10.45.3.2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "a GET needs no Origin");

    // No refresh endpoint: use extends the session, the lifetime ends it.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/session/refresh",
        Some(&cookie),
        "10.45.4.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Sign out ends it for good.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/logout",
        Some(&cookie),
        "10.45.5.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&cookie),
        "10.45.5.2",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// ADR-005 §3: no endpoint issues a token for a caller-supplied client_id.
/// Sign-in opens a session and returns no token, whatever `client_id` the
/// caller sends, and the identity token endpoint is gone.
#[tokio::test]
async fn no_token_for_a_caller_supplied_client_id() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    let app = build_router(make_state().await, &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (cookie, _, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "idtok@localhost",
        &rp_origin,
        &mut dev,
        "10.46.1",
    )
    .await;

    let id = finish_onboarding(&app, &cookie, "10.46.2").await[0];
    let (status, _) = identity_request(
        &app,
        "POST",
        &format!("/account/identities/{id}/token"),
        Some(&cookie),
        "10.46.3.1",
        Some(serde_json::json!({ "client_id": "rp.example" })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
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
    let begin = |code: &str| serde_json::json!({ "code": code });
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

    let (status, cookie, j) = request_with_cookie(
        &app,
        "POST",
        "/auth/recovery/finish",
        None,
        "10.52.4.3",
        Some(finish_body),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{j}");
    let new_token = cookie.expect("recovery signs in");

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

/// Every passkey of an account carries the same name, the one its first
/// passkey got: a passkey manager shows one account, of one server, and not
/// `name@server` for one passkey and `name` for the next.
#[tokio::test]
async fn every_passkey_of_an_account_has_the_same_name() {
    let app = build_router(make_state().await, &[]);
    let xff = Addresses::new("10.93");
    let name = "same-name@localhost";
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/register/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({ "username": name })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    assert_eq!(j["challenge"]["publicKey"]["user"]["name"], name);

    let mut key = new_key();
    let cookie = sign_up_with(&app, name, None, &mut key, &xff)
        .await
        .unwrap();
    let code = take_recovery_code(&app, &cookie, &xff).await;

    // A passkey added from the account.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/passkeys/add/begin",
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    assert_eq!(j["challenge"]["publicKey"]["user"]["name"], name);
    assert_eq!(j["challenge"]["publicKey"]["user"]["displayName"], name);

    // The passkey the recovery code makes.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({ "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    assert_eq!(j["challenge"]["publicKey"]["user"]["name"], name);
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
/// and the same ceremony signs the new account in (a session cookie).
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
    let (status, cookie, j) = request_with_cookie(
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
    assert_eq!(status, StatusCode::NO_CONTENT, "{j}");
    assert!(
        j.is_null(),
        "no token in the body: the session is the cookie (ADR-005)"
    );
    let cookie = cookie.expect("signed in at signup");
    let token = cookie.as_str();
    let user_id = Uuid::nil();

    // The session works and the passkey has its name.
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

    let _ = (user_id, rp_origin);
}

/// core#98: an account cannot leave onboarding without a recovery code, and
/// the server creates no identity for it.
#[tokio::test]
async fn an_account_without_a_recovery_code_can_do_nothing_else() {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (cookie, _, passkey) = register_and_login_for_passkey_tests(
        app.clone(),
        "onboarding@localhost",
        &rp_origin,
        &mut dev,
        "10.80.1",
    )
    .await;
    let xff = Addresses::new("10.81");
    let call = async |method: &str, uri: &str, body: Option<serde_json::Value>| {
        identity_request(&app, method, uri, Some(&cookie), &xff.next(), body).await
    };

    // Signed in, and told that the onboarding is not over.
    let (status, j) = call("GET", "/auth/session", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["recovery_code"], false);

    // Identities and applications are closed, by a refusal that says why.
    let some_id = Uuid::new_v4();
    for (method, uri, body) in [
        ("GET", "/account/identities".to_string(), None),
        (
            "POST",
            "/account/identities".to_string(),
            Some(serde_json::json!({ "template": "personal" })),
        ),
        (
            "PATCH",
            format!("/account/identities/{some_id}"),
            Some(serde_json::json!({ "name": "x" })),
        ),
        ("DELETE", format!("/account/identities/{some_id}"), None),
        (
            "GET",
            format!("/account/identities/{some_id}/applications"),
            None,
        ),
    ] {
        let (status, j) = call(method, &uri, body).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
        assert_eq!(j["error"], "a recovery code is required first");
    }
    // Nor can it present itself to an application: the page is told to send
    // the person to their onboarding, and learns nothing else.
    let (shop, _) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], false)
        .await
        .unwrap();
    let request = begin_authorization(&app, &shop.client_id, "", &xff.next()).await;
    let (status, j) = call("GET", &format!("/auth/authorize/{request}"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["needs_recovery_code"], true);
    assert_eq!(j["identities"], serde_json::json!([]));
    let (status, _) = call(
        "POST",
        &format!("/auth/authorize/{request}/approve"),
        Some(serde_json::json!({ "identity_id": some_id })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let silent = begin_authorization(&app, &shop.client_id, "&prompt=none", &xff.next()).await;
    let (_, j) = call("POST", &format!("/auth/authorize/{silent}/silent"), None).await;
    assert_eq!(
        query_of(j["redirect_to"].as_str().unwrap())["error"],
        "interaction_required"
    );

    // What the onboarding needs stays open: the passkey's name, the code.
    let (status, _) = call(
        "PATCH",
        &format!("/auth/passkeys/{passkey}"),
        Some(serde_json::json!({ "label": "This laptop" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, j) = call("GET", "/account/recovery-code", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["code_created_at"], serde_json::Value::Null);
    let (status, _) = call("POST", "/account/recovery-code", None).await;
    assert_eq!(status, StatusCode::OK);

    // With the code, the account is open, and starts with no identity: the
    // server proposes some, the browser creates the ones kept.
    let (_, j) = call("GET", "/auth/session", None).await;
    assert_eq!(j["recovery_code"], true);
    let (status, j) = call("GET", "/account/identities", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j, serde_json::json!([]));
    let (_, templates) = call("GET", "/account/identity-templates", None).await;
    let starters: Vec<&str> = templates
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["starter"] == true)
        .map(|t| t["key"].as_str().unwrap())
        .collect();
    assert_eq!(starters, ["public", "personal", "work"]);
    let (_, j) = call("GET", &format!("/auth/authorize/{request}"), None).await;
    assert_eq!(j["needs_recovery_code"], false);

    // A code can be replaced, never removed.
    let (status, _) = call("POST", "/account/recovery-code", None).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call("DELETE", "/account/recovery-code", None).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

// ---------------------------------------------------------------------------
// Relying parties: /authorize, /auth/authorize/*, /token (ADR-005 §2, ADR-008)
// ---------------------------------------------------------------------------

/// RFC 7636 appendix B.
const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "https://shop.example/cb";

/// An authorization request as a relying party sends the browser: from
/// another site, so without `Origin` and without the session cookie.
async fn authorize(app: &axum::Router, query: &str, xff: &str) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/authorize?{query}"))
                .header("x-forwarded-for", xff)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    resp.headers()["location"].to_str().unwrap().to_string()
}

/// The query of a valid authorization request for `client_id`.
fn authorize_query(client_id: &str, extra: &str) -> String {
    format!(
        "response_type=code&scope=openid&client_id={client_id}\
         &redirect_uri=https%3A%2F%2Fshop.example%2Fcb&state=xyz&nonce=n-0S6\
         &code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256{extra}"
    )
}

/// Starts a valid authorization request and returns its id.
async fn begin_authorization(
    app: &axum::Router,
    client_id: &str,
    extra: &str,
    xff: &str,
) -> String {
    let location = authorize(app, &authorize_query(client_id, extra), xff).await;
    location
        .strip_prefix("/continue/?request=")
        .unwrap_or_else(|| panic!("unexpected redirect: {location}"))
        .to_string()
}

fn query_of(uri: &str) -> std::collections::HashMap<String, String> {
    Url::parse(uri)
        .unwrap()
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

/// `POST /token`, as a relying party's server does: no cookie, no `Origin`.
async fn token_request(
    app: &axum::Router,
    form: &[(&str, &str)],
    basic: Option<(&str, &str)>,
    xff: &str,
) -> (StatusCode, axum::http::HeaderMap, serde_json::Value) {
    use base64ct::Encoding;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form)
        .finish();
    let mut req = Request::builder()
        .method("POST")
        .uri("/token")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("x-forwarded-for", xff);
    if let Some((id, secret)) = basic {
        req = req.header(
            "authorization",
            format!(
                "Basic {}",
                base64ct::Base64::encode_string(format!("{id}:{secret}").as_bytes())
            ),
        );
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, headers, json)
}

/// Checks an ID token the way a relying party does, without any brig·id
/// code: the EdDSA signature against the published key, then the payload.
fn verified_claims(state: &AppState, jwt: &str) -> serde_json::Value {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::{Signature, Verifier};
    let mut parts = jwt.split('.');
    let (header, payload, signature) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    assert!(parts.next().is_none());
    let head: serde_json::Value =
        serde_json::from_slice(&Base64UrlUnpadded::decode_vec(header).unwrap()).unwrap();
    assert_eq!(head["alg"], "EdDSA");
    assert_eq!(head["kid"], state.oidc_key.kid());
    let signature =
        Signature::from_slice(&Base64UrlUnpadded::decode_vec(signature).unwrap()).unwrap();
    state
        .oidc_key
        .verifying_key()
        .verify(format!("{header}.{payload}").as_bytes(), &signature)
        .expect("the ID token is signed by the server's key");
    serde_json::from_slice(&Base64UrlUnpadded::decode_vec(payload).unwrap()).unwrap()
}

/// What the onboarding does once the passkey exists: the recovery code, then
/// the starter identities, created by the browser from the templates marked
/// `starter`. Returns the identities' ids, in the order of the templates.
async fn finish_onboarding(app: &axum::Router, cookie: &str, xff_base: &str) -> Vec<Uuid> {
    let (status, j) = identity_request(
        app,
        "POST",
        "/account/recovery-code",
        Some(cookie),
        &format!("{xff_base}.20"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let (status, templates) = identity_request(
        app,
        "GET",
        "/account/identity-templates",
        Some(cookie),
        &format!("{xff_base}.21"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mut ids = Vec::new();
    for (n, template) in templates
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| t["starter"] == true)
        .enumerate()
    {
        let (status, j) = identity_request(
            app,
            "POST",
            "/account/identities",
            Some(cookie),
            &format!("{xff_base}.{}", 22 + n),
            Some(serde_json::json!({ "template": template["key"] })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{j}");
        ids.push(serde_json::from_value(j["id"].clone()).unwrap());
    }
    ids
}

/// A signed-in account past its onboarding, with its identities, and an
/// authenticator to go with.
async fn signed_in_account(
    app: &axum::Router,
    username: &str,
    xff_base: &str,
) -> (String, Uuid, Vec<Uuid>) {
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let mut dev = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (cookie, account_id, _) =
        register_and_login_for_passkey_tests(app.clone(), username, &rp_origin, &mut dev, xff_base)
            .await;
    let ids = finish_onboarding(app, &cookie, xff_base).await;
    (cookie, account_id, ids)
}

/// Approves request `id` as `identity` and returns the code sent back.
async fn approve(app: &axum::Router, id: &str, cookie: &str, identity: Uuid, xff: &str) -> String {
    let (status, j) = identity_request(
        app,
        "POST",
        &format!("/auth/authorize/{id}/approve"),
        Some(cookie),
        xff,
        Some(serde_json::json!({ "identity_id": identity })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let redirect_to = j["redirect_to"].as_str().unwrap();
    assert!(redirect_to.starts_with(REDIRECT), "{redirect_to}");
    let q = query_of(redirect_to);
    assert_eq!(q["state"], "xyz");
    assert_eq!(q["iss"], "http://localhost:8080");
    q["code"].clone()
}

#[tokio::test]
async fn a_site_signs_a_person_in_and_learns_an_identifier_only() {
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let (shop, secret) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], true)
        .await
        .unwrap();
    let secret = secret.unwrap();
    let (cookie, _, identities) = signed_in_account(&app, "site@localhost", "10.60.1").await;
    assert!(
        identities.len() >= 2,
        "an account starts with several identities"
    );

    // The site sends the browser; the request waits for the person.
    let id = begin_authorization(&app, &shop.client_id, "", "10.60.2.1").await;

    // The page reads it. Without a session: the site's name, nothing else.
    let uri = format!("/auth/authorize/{id}");
    let (status, j) = identity_request(&app, "GET", &uri, None, "10.60.2.2", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["client"]["name"], "Shop");
    assert_eq!(j["signed_in"], false);
    assert_eq!(j["must_sign_in"], true);
    assert_eq!(j["identities"], serde_json::json!([]));

    // With the session: the account's identities, none chosen yet.
    let (status, j) = identity_request(&app, "GET", &uri, Some(&cookie), "10.60.2.3", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["signed_in"], true);
    assert_eq!(j["must_sign_in"], false);
    assert_eq!(j["silent"], false);
    assert_eq!(j["identities"].as_array().unwrap().len(), identities.len());
    assert_eq!(j["chosen"], serde_json::Value::Null);

    // Nobody answers without a session, and not with someone else's identity.
    let approve_uri = format!("/auth/authorize/{id}/approve");
    let body = serde_json::json!({ "identity_id": identities[0] });
    let (status, _) =
        identity_request(&app, "POST", &approve_uri, None, "10.60.2.4", Some(body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = identity_request(
        &app,
        "POST",
        &approve_uri,
        Some(&cookie),
        "10.60.2.5",
        Some(serde_json::json!({ "identity_id": Uuid::new_v4() })),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The person continues as their first identity.
    let code = approve(&app, &id, &cookie, identities[0], "10.60.2.6").await;
    // The request is answered once.
    let (status, _) = identity_request(&app, "GET", &uri, Some(&cookie), "10.60.2.7", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The site exchanges the code.
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, headers, j) =
        token_request(&app, &form, Some((&shop.client_id, &secret)), "10.60.3.1").await;
    assert_eq!(status, StatusCode::OK, "{j}");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(j["token_type"], "Bearer");
    assert_eq!(j["expires_in"], 300);
    assert_eq!(j["access_token"].as_str().unwrap().len(), 64);

    let claims = verified_claims(&state, j["id_token"].as_str().unwrap());
    let expected = brigid_identity::identity_vsid(identities[0], &shop.client_id, &state.vsid_salt);
    assert_eq!(claims["sub"], expected.as_str());
    assert_eq!(claims["iss"], "http://localhost:8080");
    assert_eq!(claims["aud"], shop.client_id.as_str());
    assert_eq!(claims["nonce"], "n-0S6");
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        300
    );
    assert!(claims["auth_time"].as_i64().unwrap() <= claims["iat"].as_i64().unwrap());
    // The identifier and the token's own fields: no name, no logo, no account.
    let mut names: Vec<&str> = claims
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "aud",
            "auth_time",
            "exp",
            "iat",
            "iss",
            "jti",
            "nonce",
            "sub"
        ]
    );

    // The code worked once.
    let (status, _, j) =
        token_request(&app, &form, Some((&shop.client_id, &secret)), "10.60.3.2").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_grant");

    // Next time the choice is remembered; another identity is another person
    // for the site.
    let id = begin_authorization(&app, &shop.client_id, "", "10.60.4.1").await;
    let (_, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/authorize/{id}"),
        Some(&cookie),
        "10.60.4.2",
        None,
    )
    .await;
    assert_eq!(j["chosen"], serde_json::json!(identities[0]));
    let code = approve(&app, &id, &cookie, identities[1], "10.60.4.3").await;
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
        ("client_id", shop.client_id.as_str()),
        ("client_secret", secret.as_str()),
    ];
    let (status, _, j) = token_request(&app, &form, None, "10.60.4.4").await;
    assert_eq!(status, StatusCode::OK, "client_secret_post: {j}");
    let other = verified_claims(&state, j["id_token"].as_str().unwrap());
    assert_ne!(other["sub"], claims["sub"]);

    // The same identity at another site has another identifier.
    let (forum, _) = state
        .store
        .create_client("Forum", &[REDIRECT.to_string()], false)
        .await
        .unwrap();
    let id = begin_authorization(&app, &forum.client_id, "", "10.60.5.1").await;
    let code = approve(&app, &id, &cookie, identities[0], "10.60.5.2").await;
    // A public client: no secret, PKCE alone.
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
        ("client_id", forum.client_id.as_str()),
    ];
    let (status, _, j) = token_request(&app, &form, None, "10.60.5.3").await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let at_forum = verified_claims(&state, j["id_token"].as_str().unwrap());
    assert_ne!(at_forum["sub"], claims["sub"]);
    assert_eq!(at_forum["aud"], forum.client_id.as_str());
}

#[tokio::test]
async fn an_authorization_request_is_checked_before_anyone_is_asked() {
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let (shop, _) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], true)
        .await
        .unwrap();
    let id = &shop.client_id;

    // An unknown site, or a place it did not register: nothing is sent
    // anywhere but to this server's own page.
    let location = authorize(&app, &authorize_query("unknown", ""), "10.61.1.1").await;
    assert_eq!(location, "/continue/?error=unknown_client");
    for redirect in [
        "https%3A%2F%2Fevil.example%2Fcb",
        "https%3A%2F%2Fshop.example%2Fcb%2Fextra",
        "https%3A%2F%2Fshop.example%2Fcb%3Fx%3D1",
    ] {
        let query = format!(
            "response_type=code&scope=openid&client_id={id}&redirect_uri={redirect}\
             &code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256"
        );
        let location = authorize(&app, &query, "10.61.1.2").await;
        assert_eq!(
            location, "/continue/?error=invalid_redirect_uri",
            "{redirect}"
        );
    }

    // Everything else goes back to the site, as an error, with its state.
    let base = format!("client_id={id}&redirect_uri=https%3A%2F%2Fshop.example%2Fcb&state=xyz");
    let pkce = format!("code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256");
    let cases = [
        (
            format!("{base}&response_type=code&scope=openid"),
            "invalid_request",
        ),
        (
            format!(
                "{base}&response_type=code&scope=openid&code_challenge={PKCE_CHALLENGE}&code_challenge_method=plain"
            ),
            "invalid_request",
        ),
        (
            format!(
                "{base}&response_type=code&scope=openid&code_challenge=short&code_challenge_method=S256"
            ),
            "invalid_request",
        ),
        (
            format!("{base}&response_type=token&scope=openid&{pkce}"),
            "unsupported_response_type",
        ),
        (
            format!("{base}&response_type=id_token&scope=openid&{pkce}"),
            "unsupported_response_type",
        ),
        (
            format!("{base}&response_type=code&scope=profile&{pkce}"),
            "invalid_scope",
        ),
        (format!("{base}&response_type=code&{pkce}"), "invalid_scope"),
        (
            format!("{base}&response_type=code&scope=openid&{pkce}&request=x"),
            "request_not_supported",
        ),
        (
            format!("{base}&response_type=code&scope=openid&{pkce}&request_uri=https%3A%2F%2Fx"),
            "request_uri_not_supported",
        ),
        (
            format!("{base}&response_type=code&scope=openid&{pkce}&prompt=none+login"),
            "invalid_request",
        ),
        (
            format!("{base}&response_type=code&scope=openid&{pkce}&max_age=soon"),
            "invalid_request",
        ),
    ];
    for (n, (query, error)) in cases.iter().enumerate() {
        let location = authorize(&app, query, &format!("10.61.2.{n}")).await;
        assert!(location.starts_with(REDIRECT), "{query}: {location}");
        let q = query_of(&location);
        assert_eq!(q["error"], *error, "{query}");
        assert_eq!(q["state"], "xyz");
        assert_eq!(q["iss"], "http://localhost:8080");
        assert!(!q.contains_key("code"));
    }

    // A scope that carries attributes is refused to an application that is
    // not registered to ask for any of them: it asks for more than it may.
    for scope in ["profile", "email"] {
        let query = authorize_query(id, &format!("&scope=openid+{scope}"));
        let q = query_of(&authorize(&app, &query, "10.61.2.9").await);
        assert_eq!(q["error"], "invalid_scope", "{scope}");
        assert!(q["error_description"].contains(scope), "{q:?}");
    }

    // Unknown parameters and scopes this server does not know are ignored;
    // the form works too.
    let query = authorize_query(id, "&unknown=1&scope=openid+offline_access+phone");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/authorize")
                .header("content-type", "application/x-www-form-urlencoded")
                .header("origin", "https://shop.example")
                .header("x-forwarded-for", "10.61.3.1")
                .body(Body::from(query))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp.headers()["location"].to_str().unwrap();
    assert!(location.starts_with("/continue/?request="), "{location}");

    // The person may decline: the site is told, and gets no code.
    let request = location.strip_prefix("/continue/?request=").unwrap();
    let (status, j) = identity_request(
        &app,
        "POST",
        &format!("/auth/authorize/{request}/deny"),
        None,
        "10.61.3.2",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let q = query_of(j["redirect_to"].as_str().unwrap());
    assert_eq!(q["error"], "access_denied");
    assert_eq!(q["state"], "xyz");

    // The answer comes from this server's own page only.
    let request = begin_authorization(&app, id, "", "10.61.4.1").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/auth/authorize/{request}/deny"))
                .header("origin", "https://evil.example")
                .header("x-forwarded-for", "10.61.4.2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_token_endpoint_gives_nothing_without_the_client_the_code_and_the_verifier() {
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let (shop, secret) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], true)
        .await
        .unwrap();
    let secret = secret.unwrap();
    let (forum, _) = state
        .store
        .create_client("Forum", &[REDIRECT.to_string()], false)
        .await
        .unwrap();
    let (cookie, _, identities) = signed_in_account(&app, "tok@localhost", "10.62.1").await;

    // A fresh code for the shop each time: a code is spent at its first
    // presentation, valid or not.
    let mut n = 0u32;
    let mut fresh_code = async |client_id: &str| {
        n += 1;
        let id = begin_authorization(&app, client_id, "", &format!("10.62.2.{n}")).await;
        approve(&app, &id, &cookie, identities[0], &format!("10.62.3.{n}")).await
    };
    let shop_auth = Some((shop.client_id.as_str(), secret.as_str()));

    // The client does not prove who it is.
    let code = fresh_code(&shop.client_id).await;
    let form = |code: &'static str| {
        vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ]
    };
    let code: &'static str = Box::leak(code.into_boxed_str());
    for (auth, extra) in [
        (Some((shop.client_id.as_str(), "wrong")), None),
        (None, Some(("client_id", shop.client_id.as_str()))),
        (Some(("unknown", secret.as_str())), None),
        (None, None),
    ] {
        let mut f = form(code);
        f.extend(extra);
        let (status, headers, j) = token_request(&app, &f, auth, "10.62.4.1").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{j}");
        assert_eq!(j["error"], "invalid_client");
        assert!(headers.contains_key("www-authenticate"));
        assert!(j.get("id_token").is_none());
    }
    // A secret presented for a client that has none.
    let mut f = form(code);
    f.extend([
        ("client_id", forum.client_id.as_str()),
        ("client_secret", "x"),
    ]);
    let (status, _, j) = token_request(&app, &f, None, "10.62.4.2").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{j}");
    // Two authentication methods at once.
    let mut f = form(code);
    f.push(("client_secret", secret.as_str()));
    let (status, _, j) = token_request(&app, &f, shop_auth, "10.62.4.3").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_request");
    // None of these touched the code: the right client can still use it.
    let (status, _, _) = token_request(&app, &form(code), shop_auth, "10.62.4.4").await;
    assert_eq!(status, StatusCode::OK);

    // Another grant type.
    let (status, _, j) = token_request(
        &app,
        &[("grant_type", "client_credentials")],
        shop_auth,
        "10.62.5.1",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "unsupported_grant_type");

    // The code, with something missing or wrong: refused, and spent.
    let wrong_verifier = "a".repeat(43);
    let bad: [Vec<(&str, &str)>; 4] = [
        vec![("redirect_uri", REDIRECT)],
        vec![
            ("redirect_uri", REDIRECT),
            ("code_verifier", &wrong_verifier),
        ],
        vec![("code_verifier", PKCE_VERIFIER)],
        vec![
            ("redirect_uri", "https://shop.example/other"),
            ("code_verifier", PKCE_VERIFIER),
        ],
    ];
    for (i, extra) in bad.iter().enumerate() {
        let code = fresh_code(&shop.client_id).await;
        let mut f = vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
        ];
        f.extend(extra.iter().copied());
        let (status, _, j) = token_request(&app, &f, shop_auth, &format!("10.62.6.{i}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{extra:?}: {j}");
        assert_eq!(j["error"], "invalid_grant", "{extra:?}");
        // Presenting it again, correctly this time, changes nothing.
        let ok = [
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_verifier", PKCE_VERIFIER),
        ];
        let (status, _, j) = token_request(&app, &ok, shop_auth, &format!("10.62.7.{i}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{j}");
    }

    // A code issued to one client is worth nothing to another.
    let code = fresh_code(&forum.client_id).await;
    let f = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, _, j) = token_request(&app, &f, shop_auth, "10.62.8.1").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_grant");

    // An identity deleted between the choice and the exchange gives no token.
    let code = fresh_code(&shop.client_id).await;
    let (status, _) = identity_request(
        &app,
        "DELETE",
        &format!("/account/identities/{}", identities[0]),
        Some(&cookie),
        "10.62.9.1",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let f = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, _, j) = token_request(&app, &f, shop_auth, "10.62.9.2").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_grant");
}

#[tokio::test]
async fn prompt_and_max_age_decide_whether_the_person_is_asked() {
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let (shop, _) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], false)
        .await
        .unwrap();
    let id = &shop.client_id;
    let (cookie, account_id, identities) =
        signed_in_account(&app, "prompt@localhost", "10.63.1").await;

    let silent = async |request: &str, cookie: Option<&str>, xff: &str| {
        let (status, j) = identity_request(
            &app,
            "POST",
            &format!("/auth/authorize/{request}/silent"),
            cookie,
            xff,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{j}");
        query_of(j["redirect_to"].as_str().unwrap())
    };

    // prompt=none, nobody signed in: the site is told so, no page.
    let request = begin_authorization(&app, id, "&prompt=none", "10.63.2.1").await;
    let (_, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/authorize/{request}"),
        None,
        "10.63.2.2",
        None,
    )
    .await;
    assert_eq!(j["silent"], true);
    assert_eq!(
        silent(&request, None, "10.63.2.3").await["error"],
        "login_required"
    );

    // Signed in, but no identity was ever chosen for this site.
    let request = begin_authorization(&app, id, "&prompt=none", "10.63.3.1").await;
    assert_eq!(
        silent(&request, Some(&cookie), "10.63.3.2").await["error"],
        "interaction_required"
    );

    // Once chosen, a silent request gets its code.
    let request = begin_authorization(&app, id, "", "10.63.4.1").await;
    approve(&app, &request, &cookie, identities[0], "10.63.4.2").await;
    let request = begin_authorization(&app, id, "&prompt=none", "10.63.4.3").await;
    let q = silent(&request, Some(&cookie), "10.63.4.4").await;
    assert!(q.contains_key("code"), "{q:?}");
    assert_eq!(q["state"], "xyz");

    // `silent` only answers requests that asked for it.
    let request = begin_authorization(&app, id, "", "10.63.5.1").await;
    let (status, _) = identity_request(
        &app,
        "POST",
        &format!("/auth/authorize/{request}/silent"),
        Some(&cookie),
        "10.63.5.2",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // prompt=login and max_age need a passkey ceremony more recent than the
    // session has. Sessions are dated to the second.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    for extra in ["&prompt=login", "&max_age=0"] {
        let request = begin_authorization(&app, id, extra, "10.63.6.1").await;
        let uri = format!("/auth/authorize/{request}");
        let (_, j) = identity_request(&app, "GET", &uri, Some(&cookie), "10.63.6.2", None).await;
        assert_eq!(j["signed_in"], true, "{extra}");
        assert_eq!(j["must_sign_in"], true, "{extra}");
        let (status, _) = identity_request(
            &app,
            "POST",
            &format!("{uri}/approve"),
            Some(&cookie),
            "10.63.6.3",
            Some(serde_json::json!({ "identity_id": identities[0] })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{extra}");

        // A session opened after the request (what a new sign-in gives).
        let fresh = state
            .store
            .create_session(account_id, state.session_idle, state.session_lifetime)
            .await
            .unwrap();
        let fresh = format!("brigid_session={}", *fresh);
        let (_, j) = identity_request(&app, "GET", &uri, Some(&fresh), "10.63.6.4", None).await;
        assert_eq!(j["must_sign_in"], false, "{extra}");
        approve(&app, &request, &fresh, identities[0], "10.63.6.5").await;
    }

    // prompt=select_account asks for the choice to be shown again.
    let request = begin_authorization(&app, id, "&prompt=select_account", "10.63.7.1").await;
    let (_, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/authorize/{request}"),
        Some(&cookie),
        "10.63.7.2",
        None,
    )
    .await;
    assert_eq!(j["force_choice"], true);
    assert_eq!(j["chosen"], serde_json::json!(identities[0]));
}

// ---------------------------------------------------------------------------
// Sign-up can be closed; user verification is required
// ---------------------------------------------------------------------------

/// A registration response built by hand, as an authenticator that holds a
/// P-256 key would send it with attestation "none" (which carries no
/// signature). `flags` is the byte of the authenticator data that says whether
/// the user was present (0x01) and verified (0x04).
fn handmade_registration(challenge_b64: &str, flags: u8) -> serde_json::Value {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};

    fn bytes(out: &mut Vec<u8>, b: &[u8]) {
        match b.len() {
            n if n < 24 => out.push(0x40 | n as u8),
            n if n < 256 => out.extend([0x58, n as u8]),
            n => out.extend([0x59, (n >> 8) as u8, n as u8]),
        }
        out.extend(b);
    }
    fn text(out: &mut Vec<u8>, t: &str) {
        out.push(0x60 | t.len() as u8);
        out.extend(t.as_bytes());
    }

    // The public key of the passkey: a point of the P-256 curve, as two
    // 32-byte coordinates. Any valid key does: with attestation "none" a
    // registration carries no signature, so the private key (here the number
    // 7, repeated) is never used.
    let key = p256::SecretKey::from_slice(&[7u8; 32]).expect("a valid P-256 scalar");
    let point = key.public_key().to_encoded_point(false);
    let (x, y) = (
        point.x().expect("an uncompressed point has an x"),
        point.y().expect("an uncompressed point has a y"),
    );
    // COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    let mut cose = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    bytes(&mut cose, x);
    cose.push(0x22);
    bytes(&mut cose, y);

    let credential_id = [0x42u8; 16];
    let mut auth_data = Sha256::digest(b"localhost").to_vec();
    auth_data.push(flags | 0x40); // attested credential data follows
    auth_data.extend([0, 0, 0, 0]); // signature counter
    auth_data.extend([0u8; 16]); // AAGUID
    auth_data.extend([0, credential_id.len() as u8]);
    auth_data.extend(credential_id);
    auth_data.extend(&cose);

    // {"fmt": "none", "attStmt": {}, "authData": bytes}
    let mut attestation = vec![0xA3];
    text(&mut attestation, "fmt");
    text(&mut attestation, "none");
    text(&mut attestation, "attStmt");
    attestation.push(0xA0);
    text(&mut attestation, "authData");
    bytes(&mut attestation, &auth_data);

    let client_data = format!(
        r#"{{"type":"webauthn.create","challenge":"{challenge_b64}","origin":"http://localhost:8080","crossOrigin":false}}"#
    );
    let id = Base64UrlUnpadded::encode_string(&credential_id);
    serde_json::json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "response": {
            "attestationObject": Base64UrlUnpadded::encode_string(&attestation),
            "clientDataJSON": Base64UrlUnpadded::encode_string(client_data.as_bytes()),
        },
        "extensions": {},
    })
}

/// Every ceremony asks for user verification, and the server refuses a
/// response whose authenticator did not verify its user: a passkey proves the
/// device and what unlocks it, in one gesture.
#[tokio::test]
async fn a_passkey_that_does_not_verify_its_user_is_refused() {
    let app = build_router(make_state().await, &[]);

    // Sign-in states the requirement.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/login/begin",
        None,
        "10.71.1.1",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["challenge"]["publicKey"]["userVerification"], "required");

    // So does sign-up. The same response is then sent twice, on two
    // ceremonies: once saying the user was present only, once present and
    // verified. Nothing else differs.
    let mut outcomes = Vec::new();
    for (n, flags) in [(1, 0x01u8), (2, 0x01 | 0x04)] {
        let (status, j) = identity_request(
            &app,
            "POST",
            "/auth/register/begin",
            None,
            &format!("10.71.2.{n}"),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let options = &j["challenge"]["publicKey"];
        assert_eq!(
            options["authenticatorSelection"]["userVerification"],
            "required"
        );
        let credential = handmade_registration(options["challenge"].as_str().unwrap(), flags);
        let (status, body) = identity_request(
            &app,
            "POST",
            "/auth/register/finish",
            None,
            &format!("10.71.3.{n}"),
            Some(serde_json::json!({ "session_id": j["session_id"], "credential": credential })),
        )
        .await;
        outcomes.push((status, body));
    }
    assert_eq!(
        outcomes[0].0,
        StatusCode::BAD_REQUEST,
        "present but not verified must be refused: {:?}",
        outcomes[0].1
    );
    assert_eq!(
        outcomes[1].0,
        StatusCode::NO_CONTENT,
        "the same response, verified, is accepted: {:?}",
        outcomes[1].1
    );
}

// ---------------------------------------------------------------------------
// Attributes: what an identity shares, and with whom
// ---------------------------------------------------------------------------

/// A different client address for every call, so that no test meets the
/// rate limit.
struct Addresses(&'static str, std::cell::Cell<u32>);

impl Addresses {
    fn new(prefix: &'static str) -> Self {
        Self(prefix, std::cell::Cell::new(0))
    }

    fn next(&self) -> String {
        let n = self.1.get() + 1;
        self.1.set(n);
        format!("{}.{}.{}", self.0, n / 200, n % 200 + 1)
    }
}

/// Registers a public client that may ask for `attributes`.
async fn client_asking(
    state: &AppState,
    name: &str,
    attributes: &[(brigid_identity::Attribute, brigid_identity::Need)],
) -> String {
    let (client, _) = state
        .store
        .create_client(name, &[REDIRECT.to_string()], false)
        .await
        .unwrap();
    assert!(
        state
            .store
            .set_client_attributes(&client.client_id, &attributes.iter().copied().collect())
            .await
            .unwrap()
    );
    client.client_id
}

/// Changes attributes of an identity and returns the answer.
async fn set_attributes(
    app: &axum::Router,
    cookie: &str,
    identity: Uuid,
    attributes: serde_json::Value,
    xff: &str,
) -> (StatusCode, serde_json::Value) {
    identity_request(
        app,
        "PATCH",
        &format!("/account/identities/{identity}"),
        Some(cookie),
        xff,
        Some(serde_json::json!({ "attributes": attributes })),
    )
    .await
}

/// The person's answer to request `id`: continue as `identity`, accepting
/// to share `attributes`.
async fn answer(
    app: &axum::Router,
    id: &str,
    cookie: &str,
    identity: Uuid,
    attributes: &[&str],
    xff: &str,
) -> (StatusCode, serde_json::Value) {
    identity_request(
        app,
        "POST",
        &format!("/auth/authorize/{id}/approve"),
        Some(cookie),
        xff,
        Some(serde_json::json!({ "identity_id": identity, "attributes": attributes })),
    )
    .await
}

/// The verified claims of the ID token a public client gets for the code
/// carried by `redirect_to`.
async fn claims_from(
    app: &axum::Router,
    state: &AppState,
    client_id: &str,
    redirect_to: &serde_json::Value,
    xff: &str,
) -> serde_json::Value {
    let q = query_of(redirect_to.as_str().unwrap());
    let code = q
        .get("code")
        .unwrap_or_else(|| panic!("no code: {redirect_to}"));
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, _, j) = token_request(app, &form, None, xff).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    verified_claims(state, j["id_token"].as_str().unwrap())
}

/// The names of the claims that are attributes, sorted.
fn attribute_claims(claims: &serde_json::Value) -> Vec<String> {
    const TOKEN_FIELDS: [&str; 8] = [
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "jti",
    ];
    let mut names: Vec<String> = claims
        .as_object()
        .unwrap()
        .keys()
        .filter(|k| !TOKEN_FIELDS.contains(&k.as_str()))
        .cloned()
        .collect();
    names.sort_unstable();
    names
}

const ASK_ALL: &str = "&scope=openid+profile+email";

#[tokio::test]
async fn attributes_are_set_changed_and_removed_on_an_identity() {
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let (cookie, _, identities) = signed_in_account(&app, "attrs@localhost", "10.70.1").await;
    let xff = Addresses::new("10.71");
    let me = identities[0];

    // Created with attributes.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&cookie),
        &xff.next(),
        Some(serde_json::json!({
            "name": "Club",
            "logo": "icon:ph:users",
            "attributes": { "preferred_username": "ada_l", "locale": "" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{j}");
    assert_eq!(
        j["attributes"],
        serde_json::json!({ "preferred_username": "ada_l" })
    );

    // Set: values are trimmed, the others stay.
    let (status, j) = set_attributes(
        &app,
        &cookie,
        me,
        serde_json::json!({ "given_name": "  Ada ", "email": "ada@example.org" }),
        &xff.next(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    assert_eq!(
        j["attributes"],
        serde_json::json!({ "given_name": "Ada", "email": "ada@example.org" })
    );
    let (_, j) = set_attributes(
        &app,
        &cookie,
        me,
        serde_json::json!({ "zoneinfo": "Europe/Paris", "given_name": "" }),
        &xff.next(),
    )
    .await;
    assert_eq!(
        j["attributes"],
        serde_json::json!({ "email": "ada@example.org", "zoneinfo": "Europe/Paris" })
    );

    // A change of label leaves them alone.
    let (_, j) = identity_request(
        &app,
        "PATCH",
        &format!("/account/identities/{me}"),
        Some(&cookie),
        &xff.next(),
        Some(serde_json::json!({ "name": "Renamed" })),
    )
    .await;
    assert_eq!(j["name"], "Renamed");
    assert_eq!(j["attributes"]["email"], "ada@example.org");

    // An unknown attribute, a label passed off as one, a malformed value:
    // refused, and nothing changes.
    for bad in [
        serde_json::json!({ "phone_number": "+33 1 23 45 67 89" }),
        serde_json::json!({ "name": "Ada" }),
        serde_json::json!({ "email": "not an address" }),
        serde_json::json!({ "zoneinfo": "Europe/Paris", "locale": "français" }),
    ] {
        let (status, j) = set_attributes(&app, &cookie, me, bad.clone(), &xff.next()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}: {j}");
    }
    let (_, list) = identity_request(
        &app,
        "GET",
        "/account/identities",
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    let mine = list
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["id"] == serde_json::json!(me))
        .unwrap();
    assert_eq!(
        mine["attributes"],
        serde_json::json!({ "email": "ada@example.org", "zoneinfo": "Europe/Paris" })
    );
}

/// core#91: an application receives an attribute only after a recorded
/// grant for that exact value.
#[tokio::test]
async fn an_application_receives_an_attribute_only_once_its_exact_value_was_accepted() {
    use brigid_identity::{Attribute, Need};
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let shop = client_asking(
        &state,
        "Shop",
        &[
            (Attribute::Email, Need::Required),
            (Attribute::GivenName, Need::Optional),
            (Attribute::Locale, Need::Optional),
        ],
    )
    .await;
    let (cookie, _, identities) = signed_in_account(&app, "grant@localhost", "10.72.1").await;
    let xff = Addresses::new("10.73");
    let me = identities[0];
    let (status, _) = set_attributes(
        &app,
        &cookie,
        me,
        serde_json::json!({
            "email": "ada@example.org",
            "given_name": "Ada",
            "family_name": "Lovelace",
        }),
        &xff.next(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let view = async |request: &str| {
        let uri = format!("/auth/authorize/{request}");
        let (status, j) =
            identity_request(&app, "GET", &uri, Some(&cookie), &xff.next(), None).await;
        assert_eq!(status, StatusCode::OK, "{j}");
        j
    };
    let silent = async |extra: &str| {
        let request =
            begin_authorization(&app, &shop, &format!("{extra}&prompt=none"), &xff.next()).await;
        let (status, j) = identity_request(
            &app,
            "POST",
            &format!("/auth/authorize/{request}/silent"),
            Some(&cookie),
            &xff.next(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{j}");
        j["redirect_to"].clone()
    };
    let applications = async || {
        let (status, j) = identity_request(
            &app,
            "GET",
            &format!("/account/identities/{me}/applications"),
            Some(&cookie),
            &xff.next(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{j}");
        j
    };

    // The identity has attributes, and the application may ask for some: a
    // request that does not ask gets the identifier and nothing else.
    let request = begin_authorization(&app, &shop, "", &xff.next()).await;
    let j = view(&request).await;
    assert_eq!(j["asked"], serde_json::json!([]));
    let (status, j) = answer(&app, &request, &cookie, me, &[], &xff.next()).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let claims = claims_from(&app, &state, &shop, &j["redirect_to"], &xff.next()).await;
    assert!(attribute_claims(&claims).is_empty(), "{claims}");
    let apps = applications().await;
    assert_eq!(apps[0]["name"], "Shop");
    assert_eq!(apps[0]["shared"], serde_json::json!([]));

    // It asks. The page learns what is asked, in the order it is shown, and
    // that nothing is decided. Nothing was accepted: nothing passes silently.
    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    let j = view(&request).await;
    assert_eq!(
        j["asked"],
        serde_json::json!([
            { "name": "given_name", "required": false },
            { "name": "email", "required": true },
            { "name": "locale", "required": false },
        ])
    );
    assert_eq!(j["decisions"][me.to_string()], serde_json::json!({}));
    assert_eq!(j["identities"][0]["attributes"]["email"], "ada@example.org");
    assert_eq!(
        query_of(silent(ASK_ALL).await.as_str().unwrap())["error"],
        "consent_required"
    );

    // The person accepts both. The token carries them with the values
    // accepted, an address that is not said to be verified, and nothing
    // that was not asked: `family_name` is on the identity, the application
    // may not ask for it.
    let (status, j) = answer(
        &app,
        &request,
        &cookie,
        me,
        &["email", "given_name"],
        &xff.next(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let claims = claims_from(&app, &state, &shop, &j["redirect_to"], &xff.next()).await;
    assert_eq!(
        attribute_claims(&claims),
        ["email", "email_verified", "given_name"]
    );
    assert_eq!(claims["email"], "ada@example.org");
    assert_eq!(claims["email_verified"], false);
    assert_eq!(claims["given_name"], "Ada");

    // It is recorded, with the values, and shown on the identity's page.
    let apps = applications().await;
    assert_eq!(apps.as_array().unwrap().len(), 1);
    let shared = apps[0]["shared"].as_array().unwrap();
    assert_eq!(shared.len(), 2);
    assert_eq!(shared[0]["name"], "given_name");
    assert_eq!(shared[0]["value"], "Ada");
    assert_eq!(shared[1]["name"], "email");
    assert_eq!(shared[1]["value"], "ada@example.org");
    assert!(shared[1]["since"].as_i64().unwrap() > 0);

    // The same request again passes without a page, with the same values.
    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    assert_eq!(
        view(&request).await["decisions"][me.to_string()],
        serde_json::json!({ "given_name": true, "email": true })
    );
    let claims = claims_from(&app, &state, &shop, &silent(ASK_ALL).await, &xff.next()).await;
    assert_eq!(claims["email"], "ada@example.org");
    assert_eq!(claims["given_name"], "Ada");
    // Asking for less gives less.
    let claims = claims_from(
        &app,
        &state,
        &shop,
        &silent("&scope=openid+email").await,
        &xff.next(),
    )
    .await;
    assert_eq!(attribute_claims(&claims), ["email", "email_verified"]);

    // The value changes: what was accepted was the old one. Nothing passes
    // silently, and the new address is not sent until it is accepted.
    let (status, _) = set_attributes(
        &app,
        &cookie,
        me,
        serde_json::json!({ "email": "ada@new.example" }),
        &xff.next(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        query_of(silent(ASK_ALL).await.as_str().unwrap())["error"],
        "consent_required"
    );
    assert_eq!(
        view(&request).await["decisions"][me.to_string()],
        serde_json::json!({ "given_name": true })
    );
    let (status, j) = answer(
        &app,
        &request,
        &cookie,
        me,
        &["email", "given_name"],
        &xff.next(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let claims = claims_from(&app, &state, &shop, &j["redirect_to"], &xff.next()).await;
    assert_eq!(claims["email"], "ada@new.example");

    // One attribute withdrawn: it is asked again.
    let withdraw = async |path: &str| {
        let (status, _) = identity_request(
            &app,
            "DELETE",
            &format!("/account/identities/{me}/applications/{path}"),
            Some(&cookie),
            &xff.next(),
            None,
        )
        .await;
        status
    };
    assert_eq!(
        withdraw(&format!("{shop}/attributes/given_name")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        withdraw(&format!("{shop}/attributes/given_name")).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        withdraw(&format!("{shop}/attributes/label")).await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        query_of(silent(ASK_ALL).await.as_str().unwrap())["error"],
        "consent_required"
    );
    // The address is still accepted: asked alone, it still passes.
    let claims = claims_from(
        &app,
        &state,
        &shop,
        &silent("&scope=openid+email").await,
        &xff.next(),
    )
    .await;
    assert_eq!(claims["email"], "ada@new.example");

    // Everything withdrawn: nothing is recorded, and the identity is no
    // longer the one remembered for this application.
    assert_eq!(withdraw(&shop).await, StatusCode::NO_CONTENT);
    assert_eq!(withdraw(&shop).await, StatusCode::NOT_FOUND);
    assert_eq!(applications().await, serde_json::json!([]));
    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    let j = view(&request).await;
    assert_eq!(j["chosen"], serde_json::Value::Null);
    assert_eq!(j["decisions"], serde_json::json!({}));
    assert_eq!(
        query_of(silent("&scope=openid+email").await.as_str().unwrap())["error"],
        "interaction_required"
    );

    // Someone else cannot read or withdraw what this identity gave.
    let (other, _, _) = signed_in_account(&app, "other-grant@localhost", "10.72.2").await;
    let (status, _) = identity_request(
        &app,
        "GET",
        &format!("/account/identities/{me}/applications"),
        Some(&other),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// core#91: refusing an optional attribute continues; refusing a required
/// one stops.
#[tokio::test]
async fn refusing_an_optional_attribute_continues_and_a_required_one_stops() {
    use brigid_identity::{Attribute, Need};
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let shop = client_asking(
        &state,
        "Shop",
        &[
            (Attribute::Email, Need::Required),
            (Attribute::GivenName, Need::Optional),
            (Attribute::Zoneinfo, Need::Optional),
        ],
    )
    .await;
    let (cookie, _, identities) = signed_in_account(&app, "refuse@localhost", "10.74.1").await;
    let xff = Addresses::new("10.75");
    let (me, bare) = (identities[0], identities[1]);
    set_attributes(
        &app,
        &cookie,
        me,
        serde_json::json!({ "email": "ada@example.org", "given_name": "Ada" }),
        &xff.next(),
    )
    .await;

    // The required one refused, alone or with the optional one accepted:
    // the sign-in does not go on. The request is still there to be answered.
    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    for accepted in [&[][..], &["given_name"][..]] {
        let (status, j) = answer(&app, &request, &cookie, me, accepted, &xff.next()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{j}");
        assert!(j["error"].as_str().unwrap().contains("email"), "{j}");
    }
    // An attribute that was not asked, or that does not exist, is not an
    // answer either.
    for accepted in [&["email", "family_name"][..], &["email", "name"][..]] {
        let (status, j) = answer(&app, &request, &cookie, me, accepted, &xff.next()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{j}");
    }
    // An identity that lacks the required attribute cannot continue, and
    // cannot accept to share what it does not have.
    let (status, _) = answer(&app, &request, &cookie, bare, &[], &xff.next()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = answer(&app, &request, &cookie, bare, &["email"], &xff.next()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // None of this recorded anything.
    let (_, apps) = identity_request(
        &app,
        "GET",
        &format!("/account/identities/{me}/applications"),
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(apps, serde_json::json!([]));

    // The person gives up: the application is told, and gets no code.
    let (status, j) = identity_request(
        &app,
        "POST",
        &format!("/auth/authorize/{request}/deny"),
        None,
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let q = query_of(j["redirect_to"].as_str().unwrap());
    assert_eq!(q["error"], "access_denied");
    assert!(!q.contains_key("code"));

    // The optional one refused: the sign-in goes on without it.
    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    let (status, j) = answer(&app, &request, &cookie, me, &["email"], &xff.next()).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let claims = claims_from(&app, &state, &shop, &j["redirect_to"], &xff.next()).await;
    assert_eq!(attribute_claims(&claims), ["email", "email_verified"]);

    // The refusal is remembered: the next request passes without a page,
    // still without the first name. The time zone was never refused: the
    // identity has none, there was nothing to decide.
    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    let (_, j) = identity_request(
        &app,
        "GET",
        &format!("/auth/authorize/{request}"),
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(
        j["decisions"][me.to_string()],
        serde_json::json!({ "given_name": false, "email": true })
    );
    let silent =
        begin_authorization(&app, &shop, &format!("{ASK_ALL}&prompt=none"), &xff.next()).await;
    let (status, j) = identity_request(
        &app,
        "POST",
        &format!("/auth/authorize/{silent}/silent"),
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let claims = claims_from(&app, &state, &shop, &j["redirect_to"], &xff.next()).await;
    assert_eq!(attribute_claims(&claims), ["email", "email_verified"]);
    let (_, apps) = identity_request(
        &app,
        "GET",
        &format!("/account/identities/{me}/applications"),
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(apps[0]["refused"], serde_json::json!(["given_name"]));

    // The person may change their mind on the page.
    let (status, j) = answer(
        &app,
        &request,
        &cookie,
        me,
        &["email", "given_name"],
        &xff.next(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let claims = claims_from(&app, &state, &shop, &j["redirect_to"], &xff.next()).await;
    assert_eq!(claims["given_name"], "Ada");
}

/// core#91: the label of an identity appears in no token.
#[tokio::test]
async fn the_label_of_an_identity_appears_in_no_token() {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use brigid_identity::{Attribute, Need};
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    // The application may ask for everything there is, and requires it.
    let everything: Vec<_> = Attribute::ALL
        .into_iter()
        .map(|a| (a, Need::Required))
        .collect();
    let shop = client_asking(&state, "Shop", &everything).await;
    let (cookie, _, _) = signed_in_account(&app, "label@localhost", "10.76.1").await;
    let xff = Addresses::new("10.77");

    let (status, j) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&cookie),
        &xff.next(),
        Some(serde_json::json!({
            "name": "Zanzibar Nightshift",
            "logo": "icon:ph:rocket-launch",
            "description": "Quetzalcoatl only my friends know",
            "attributes": {
                "given_name": "Ada",
                "family_name": "Lovelace",
                "preferred_username": "ada_l",
                "email": "ada@example.org",
                "locale": "en-GB",
                "zoneinfo": "Europe/London",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{j}");
    let identity: Uuid = serde_json::from_value(j["id"].clone()).unwrap();

    let request = begin_authorization(&app, &shop, ASK_ALL, &xff.next()).await;
    let all: Vec<&str> = Attribute::ALL.into_iter().map(Attribute::claim).collect();
    let (status, j) = answer(&app, &request, &cookie, identity, &all, &xff.next()).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    // The address that goes back to the application carries no label.
    let redirect_to = j["redirect_to"].as_str().unwrap().to_owned();

    let q = query_of(&redirect_to);
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", shop.as_str()),
        ("code", q["code"].as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, _, response) = token_request(&app, &form, None, &xff.next()).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let jwt = response["id_token"].as_str().unwrap();
    let header = Base64UrlUnpadded::decode_vec(jwt.split('.').next().unwrap()).unwrap();
    let payload = Base64UrlUnpadded::decode_vec(jwt.split('.').nth(1).unwrap()).unwrap();
    let everything_sent = format!(
        "{redirect_to} {response} {} {}",
        String::from_utf8(header).unwrap(),
        String::from_utf8(payload).unwrap()
    )
    .to_lowercase();
    for label in [
        "zanzibar",
        "nightshift",
        "quetzalcoatl",
        "friends",
        "rocket",
        "icon:ph",
        &identity.to_string(),
    ] {
        assert!(
            !everything_sent.contains(label),
            "{label} reached the application"
        );
    }

    // With every attribute shared, the token holds the attributes and its
    // own fields: there is no claim a label could travel in.
    let claims = verified_claims(&state, jwt);
    assert_eq!(
        attribute_claims(&claims),
        [
            "email",
            "email_verified",
            "family_name",
            "given_name",
            "locale",
            "preferred_username",
            "zoneinfo",
        ]
    );
    assert_eq!(claims["preferred_username"], "ada_l");
}

// ---------------------------------------------------------------------------
// Leaving: /account/delete
// ---------------------------------------------------------------------------

/// core#98: deletion needs a fresh ceremony, and leaves nothing about the
/// account.
#[tokio::test]
async fn deleting_an_account_takes_its_own_passkey_ceremony_and_leaves_nothing() {
    use brigid_identity::{Attribute, Need};
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;
    use webauthn_rs::prelude::RequestChallengeResponse;

    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let rp_origin = url::Url::parse("http://localhost:8080").unwrap();
    let xff = Addresses::new("10.83");

    // Two accounts. The first has lived: identities, attributes, an
    // application it signed in to and shared an address with.
    let mut ada_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (ada, ada_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "leaving@localhost",
        &rp_origin,
        &mut ada_key,
        "10.82.1",
    )
    .await;
    let identities = finish_onboarding(&app, &ada, "10.82.1").await;
    let mut bob_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let (bob, bob_id, _) = register_and_login_for_passkey_tests(
        app.clone(),
        "staying@localhost",
        &rp_origin,
        &mut bob_key,
        "10.82.2",
    )
    .await;
    let bob_identities = finish_onboarding(&app, &bob, "10.82.2").await;
    let shop = client_asking(&state, "Shop", &[(Attribute::Email, Need::Required)]).await;
    for (cookie, identity) in [(&ada, identities[0]), (&bob, bob_identities[0])] {
        let (status, _) = set_attributes(
            &app,
            cookie,
            identity,
            serde_json::json!({ "email": "someone@example.org" }),
            &xff.next(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let request = begin_authorization(&app, &shop, "&scope=openid+email", &xff.next()).await;
        let (status, j) = answer(&app, &request, cookie, identity, &["email"], &xff.next()).await;
        assert_eq!(status, StatusCode::OK, "{j}");
    }

    let post = async |uri: &str, cookie: Option<&str>, body: serde_json::Value| {
        identity_request(&app, "POST", uri, cookie, &xff.next(), Some(body)).await
    };
    // The software authenticator of the tests keeps no discoverable passkey:
    // a sign-in ceremony names its account.
    let begin = async |uri: &str, cookie: Option<&str>| {
        let named = serde_json::json!({ "username": "leaving@localhost" });
        let (status, j) = post(uri, cookie, named).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {j}");
        let challenge: RequestChallengeResponse =
            serde_json::from_value(j["challenge"].clone()).unwrap();
        (j["session_id"].clone(), challenge)
    };

    // Not without a session.
    let (status, _) = post("/account/delete/begin", None, serde_json::json!({})).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A ceremony done to sign in deletes nothing: the session alone, even
    // with a passkey answer made for something else, is not enough.
    let (session_id, challenge) = begin("/auth/login/begin", None).await;
    let credential = ada_key
        .do_authentication(rp_origin.clone(), challenge)
        .unwrap();
    let (status, _) = post(
        "/account/delete/finish",
        Some(&ada),
        serde_json::json!({ "session_id": session_id, "credential": credential }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A ceremony begun to delete does not sign anyone in either.
    let (session_id, challenge) = begin("/account/delete/begin", Some(&ada)).await;
    let credential = ada_key
        .do_authentication(rp_origin.clone(), challenge)
        .unwrap();
    let answer_body = serde_json::json!({ "session_id": session_id, "credential": credential });
    let (status, _) = post("/auth/login/finish", None, answer_body.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Someone else's session cannot finish it: the ceremony was begun for
    // one account, and deletes that one or nothing.
    let (status, _) = post("/account/delete/finish", Some(&bob), answer_body).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Nor can another passkey answer this account's ceremony.
    let (session_id, challenge) = begin("/account/delete/begin", Some(&ada)).await;
    assert!(
        bob_key
            .do_authentication(rp_origin.clone(), challenge)
            .is_err(),
        "the challenge names this account's passkeys only"
    );
    let _ = session_id;
    for account in [ada_id, bob_id] {
        assert!(state.store.fetch_user(account).await.unwrap().is_some());
    }

    // The account's own passkey, for that purpose: it is gone.
    let (session_id, challenge) = begin("/account/delete/begin", Some(&ada)).await;
    let credential = ada_key
        .do_authentication(rp_origin.clone(), challenge)
        .unwrap();
    let (status, set_cookie, _) = request_with_cookie(
        &app,
        "POST",
        "/account/delete/finish",
        Some(&ada),
        &xff.next(),
        Some(serde_json::json!({ "session_id": session_id, "credential": credential })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(set_cookie.is_some(), "the session cookie is cleared");

    // Nothing is left of it: no account, no passkey, no session, no
    // identity, nothing about the application.
    let store = &state.store;
    assert!(store.fetch_user(ada_id).await.unwrap().is_none());
    assert!(store.fetch_credentials(ada_id).await.unwrap().is_empty());
    assert!(store.fetch_identities(ada_id).await.unwrap().is_empty());
    assert!(
        store
            .grants_for_client(ada_id, &shop)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.chosen_identity(ada_id, &shop).await.unwrap(), None);
    assert_eq!(
        store.recovery_status(ada_id).await.unwrap(),
        brigid_store::RecoveryStatus::default()
    );
    let (status, _) =
        identity_request(&app, "GET", "/auth/session", Some(&ada), &xff.next(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Its passkey opens nothing any more: there is no account to sign in to.
    let (status, _) = post(
        "/auth/login/begin",
        None,
        serde_json::json!({ "username": "leaving@localhost" }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The other account lost nothing.
    assert!(store.fetch_user(bob_id).await.unwrap().is_some());
    assert_eq!(store.fetch_identities(bob_id).await.unwrap().len(), 3);
    assert_eq!(
        store.grants_for_client(bob_id, &shop).await.unwrap().len(),
        1
    );
    let (status, _) =
        identity_request(&app, "GET", "/auth/session", Some(&bob), &xff.next(), None).await;
    assert_eq!(status, StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Administration: /admin, the links, who may sign up
// ---------------------------------------------------------------------------

type Key = webauthn_authenticator_rs::WebauthnAuthenticator<
    webauthn_authenticator_rs::softpasskey::SoftPasskey,
>;

fn new_key() -> Key {
    webauthn_authenticator_rs::WebauthnAuthenticator::new(
        webauthn_authenticator_rs::softpasskey::SoftPasskey::new(true),
    )
}

/// Creates an account, with the link a server may ask for. The session
/// cookie, or the refusal.
async fn sign_up_with(
    app: &axum::Router,
    username: &str,
    link: Option<&str>,
    key: &mut Key,
    xff: &Addresses,
) -> Result<String, (StatusCode, serde_json::Value)> {
    let mut body = serde_json::json!({ "username": username });
    if let Some(link) = link {
        body["link"] = serde_json::json!(link);
    }
    let (status, j) = identity_request(
        app,
        "POST",
        "/auth/register/begin",
        None,
        &xff.next(),
        Some(body),
    )
    .await;
    if status != StatusCode::OK {
        return Err((status, j));
    }
    let challenge: webauthn_rs::prelude::CreationChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let credential = key
        .do_registration(
            url::Url::parse(ORIGIN).unwrap(),
            for_soft_passkey(challenge),
        )
        .unwrap();
    let (status, cookie, j) = request_with_cookie(
        app,
        "POST",
        "/auth/register/finish",
        None,
        &xff.next(),
        Some(serde_json::json!({ "session_id": j["session_id"], "credential": credential })),
    )
    .await;
    if status != StatusCode::NO_CONTENT {
        return Err((status, j));
    }
    Ok(cookie.expect("signed in at sign-up"))
}

/// The account's recovery code, without which it is still in its onboarding.
async fn take_recovery_code(app: &axum::Router, cookie: &str, xff: &Addresses) -> String {
    let (status, j) = identity_request(
        app,
        "POST",
        "/account/recovery-code",
        Some(cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    j["code"].as_str().unwrap().to_owned()
}

/// A server with its first administrator, made as an operator makes one:
/// with the setup link. Sign-up is left as a server starts: by invitation.
async fn administered(state: AppState) -> (Arc<AppState>, axum::Router, String, Key) {
    let state = Arc::new(state);
    let app = build_router(Arc::clone(&state), &[]);
    let xff = Addresses::new("10.89");
    let link = brigid_api::setup_link(&state.store)
        .await
        .unwrap()
        .expect("a server without account has a setup link");
    let mut key = new_key();
    let cookie = sign_up_with(&app, "admin@localhost", Some(&link), &mut key, &xff)
        .await
        .unwrap();
    take_recovery_code(&app, &cookie, &xff).await;
    (state, app, cookie, key)
}

/// core#88: a fresh database refuses sign-up until the setup link is used.
#[tokio::test]
async fn a_fresh_server_takes_no_account_until_its_setup_link_is_used() {
    let state = Arc::new(fresh_app_state().await);
    let app = build_router(Arc::clone(&state), &[]);
    let xff = Addresses::new("10.90");

    // Nobody opened it: by invitation, and there is nobody to invite.
    let (_, j) = identity_request(&app, "GET", "/auth/server", None, &xff.next(), None).await;
    assert_eq!(j["sign_up"], false);
    assert_eq!(j["policy"], "invitation");
    let refused = sign_up_with(&app, "early@localhost", None, &mut new_key(), &xff)
        .await
        .unwrap_err();
    assert_eq!(refused.0, StatusCode::FORBIDDEN);
    assert_eq!(refused.1["code"], "invitation_required");
    let refused = sign_up_with(&app, "early@localhost", Some("guess"), &mut new_key(), &xff)
        .await
        .unwrap_err();
    assert_eq!(refused.1["code"], "link_invalid");
    assert_eq!(state.store.count_accounts().await.unwrap(), 0);
    // Signing in is still offered.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/login/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The operator reads the setup link on the machine. A restart renews
    // it: the earlier one opens nothing.
    let stale = brigid_api::setup_link(&state.store).await.unwrap().unwrap();
    let link = brigid_api::setup_link(&state.store).await.unwrap().unwrap();
    assert_ne!(stale, link);
    let refused = sign_up_with(&app, "first@localhost", Some(&stale), &mut new_key(), &xff)
        .await
        .unwrap_err();
    assert_eq!(refused.1["code"], "link_invalid");

    // Used, it makes the first account, and that account administers.
    let cookie = sign_up_with(&app, "first@localhost", Some(&link), &mut new_key(), &xff)
        .await
        .unwrap();
    let (_, j) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&cookie),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(j["admin"], true);
    assert_eq!(state.store.count_administrators().await.unwrap(), 1);

    // Once. And a server that has an account hands out no setup link.
    let refused = sign_up_with(&app, "second@localhost", Some(&link), &mut new_key(), &xff)
        .await
        .unwrap_err();
    assert_eq!(refused.1["code"], "link_invalid");
    assert_eq!(brigid_api::setup_link(&state.store).await.unwrap(), None);
    assert_eq!(state.store.count_accounts().await.unwrap(), 1);
    // It is in the log, with no name in it.
    let log = state.store.admin_log(10).await.unwrap();
    assert_eq!(log[0].action.action, "setup.redeemed");
    assert!(log[0].action.account.is_some());
}

/// Every endpoint of the administration, as (method, address, body).
fn administration(
    account: Uuid,
    application: &str,
) -> Vec<(&'static str, String, Option<serde_json::Value>)> {
    vec![
        ("GET", "/admin/accounts".into(), None),
        ("POST", format!("/admin/accounts/{account}/suspend"), None),
        ("POST", format!("/admin/accounts/{account}/unsuspend"), None),
        (
            "PUT",
            format!("/admin/accounts/{account}/administrator"),
            Some(serde_json::json!({ "admin": true })),
        ),
        ("DELETE", format!("/admin/accounts/{account}"), None),
        ("GET", "/admin/applications".into(), None),
        (
            "POST",
            "/admin/applications".into(),
            Some(serde_json::json!({ "name": "Shop", "redirect_uris": [REDIRECT] })),
        ),
        (
            "PUT",
            format!("/admin/applications/{application}/attributes"),
            Some(serde_json::json!({ "email": "required" })),
        ),
        ("DELETE", format!("/admin/applications/{application}"), None),
        ("GET", "/admin/server".into(), None),
        ("GET", "/admin/sign-up".into(), None),
        (
            "PUT",
            "/admin/sign-up".into(),
            Some(serde_json::json!({ "policy": "open" })),
        ),
        (
            "POST",
            "/admin/invitations".into(),
            Some(serde_json::json!({ "uses": 3 })),
        ),
        (
            "DELETE",
            format!("/admin/invitations/{}", Uuid::new_v4()),
            None,
        ),
        ("GET", "/admin/log".into(), None),
    ]
}

/// core#88: a non-administrator session gets 403 on every administration
/// endpoint; nobody gets anything without a session.
#[tokio::test]
async fn only_an_administrator_reaches_the_administration() {
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let xff = Addresses::new("10.91");
    let (person, person_id, _) = signed_in_account(&app, "person@localhost", "10.91.200").await;
    let (victim, victim_id, _) = signed_in_account(&app, "victim@localhost", "10.91.201").await;
    let (shop, _) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], false)
        .await
        .unwrap();

    for (method, uri, body) in administration(victim_id, &shop.client_id) {
        let (status, j) =
            identity_request(&app, method, &uri, Some(&person), &xff.next(), body.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {j}");
        assert_eq!(j["error"], "forbidden", "{method} {uri}");
        let (status, _) = identity_request(&app, method, &uri, None, &xff.next(), body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
    }
    // Nothing happened: the other account is as it was, the application is
    // there, sign-up is as it was, the log is empty.
    let (status, _) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&victim),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let standing = state
        .store
        .account_standing(victim_id)
        .await
        .unwrap()
        .unwrap();
    assert!(!standing.admin && !standing.suspended);
    assert!(
        state
            .store
            .fetch_client(&shop.client_id)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        state.store.signup_policy().await.unwrap(),
        brigid_store::SignupPolicy::Open
    );
    assert!(state.store.admin_log(10).await.unwrap().is_empty());
    // A link that is not an administrator link grants nothing.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/admin/claim",
        Some(&person),
        &xff.next(),
        Some(serde_json::json!({ "link": "guess" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "link_invalid");
    assert!(
        !state
            .store
            .account_standing(person_id)
            .await
            .unwrap()
            .unwrap()
            .admin
    );
}

/// core#88: no administration response contains identity data.
#[tokio::test]
async fn no_administration_response_holds_anything_of_an_identity() {
    use brigid_identity::{Attribute, Need};
    let (state, app, admin, _) = administered(fresh_app_state().await).await;
    let xff = Addresses::new("10.92");
    state
        .store
        .set_signup_policy(brigid_store::SignupPolicy::Open)
        .await
        .unwrap();

    // A person with a life: identities with labels and attributes, and an
    // application one of them signed in to and shared an address with.
    let mut key = new_key();
    let person = sign_up_with(&app, "private@localhost", None, &mut key, &xff)
        .await
        .unwrap();
    take_recovery_code(&app, &person, &xff).await;
    let (status, j) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&person),
        &xff.next(),
        Some(serde_json::json!({
            "name": "Zanzibar Nightshift",
            "logo": "icon:ph:rocket-launch",
            "description": "Quetzalcoatl only my friends know",
            "attributes": {
                "given_name": "Hypatia",
                "family_name": "Alexandrina",
                "email": "hypatia@private.example",
            },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{j}");
    let identity: Uuid = serde_json::from_value(j["id"].clone()).unwrap();
    let shop = client_asking(&state, "Shop", &[(Attribute::Email, Need::Required)]).await;
    let request = begin_authorization(&app, &shop, "&scope=openid+email", &xff.next()).await;
    let (status, j) = answer(&app, &request, &person, identity, &["email"], &xff.next()).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let vsid = brigid_identity::identity_vsid(identity, &shop, &state.vsid_salt);
    let person_id = state
        .store
        .list_accounts()
        .await
        .unwrap()
        .into_iter()
        .find(|a| !a.admin)
        .unwrap()
        .id;

    // Everything the administration answers, readings and changes alike
    // (the session is a moment old: changes are accepted).
    let mut said = String::new();
    for (method, uri, body) in administration(person_id, &shop) {
        // Keep the account and the application for the readings that follow.
        if method == "DELETE" && !uri.contains("/invitations/") {
            continue;
        }
        let (status, j) =
            identity_request(&app, method, &uri, Some(&admin), &xff.next(), body).await;
        assert!(
            status.is_success() || status == StatusCode::NOT_FOUND,
            "{method} {uri}: {status} {j}"
        );
        said.push_str(&j.to_string());
    }
    for (method, uri) in [("GET", "/admin/accounts"), ("GET", "/admin/log")] {
        let (_, j) = identity_request(&app, method, uri, Some(&admin), &xff.next(), None).await;
        said.push_str(&j.to_string());
    }
    // The account is there, by its generated handle.
    assert!(said.contains("private"), "{said}");
    let said = said.to_lowercase();
    for theirs in [
        "zanzibar",
        "nightshift",
        "quetzalcoatl",
        "rocket",
        "hypatia",
        "alexandrina",
        "private.example",
        &identity.to_string(),
        &vsid.as_str().to_lowercase(),
        "identit",
    ] {
        assert!(
            !said.contains(theirs),
            "{theirs} is in an answer of the administration"
        );
    }
    // And there is no way from the administration to an account's content:
    // the account's own endpoints answer for the session's account only.
    let (_, j) = identity_request(
        &app,
        "GET",
        "/account/identities",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(j, serde_json::json!([]), "the administrator's own, empty");
}

#[tokio::test]
async fn an_administrative_change_needs_a_passkey_ceremony_done_a_moment_ago() {
    // A server where no ceremony is ever recent enough.
    let (state, app, admin, mut key) = administered(
        fresh_app_state()
            .await
            .with_confirmation_ttl(std::time::Duration::ZERO),
    )
    .await;
    let xff = Addresses::new("10.93");
    let (shop, _) = state
        .store
        .create_client("Shop", &[REDIRECT.to_string()], false)
        .await
        .unwrap();
    let other = Uuid::new_v4();

    for (method, uri, body) in administration(other, &shop.client_id) {
        let (status, j) =
            identity_request(&app, method, &uri, Some(&admin), &xff.next(), body).await;
        if method == "GET" {
            // Reading asks for the role only.
            assert_eq!(status, StatusCode::OK, "{method} {uri}: {j}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}: {j}");
            assert_eq!(j["code"], "confirmation_required", "{method} {uri}");
        }
    }
    assert!(
        state
            .store
            .fetch_client(&shop.client_id)
            .await
            .unwrap()
            .is_some()
    );

    // The ceremony: for the session's account, with its passkey. The
    // session then says when it was done.
    let (_, before) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/confirm/begin",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let challenge: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let credential = key
        .do_authentication(url::Url::parse(ORIGIN).unwrap(), challenge)
        .unwrap();
    let answer_body =
        serde_json::json!({ "session_id": j["session_id"], "credential": credential });
    // It is not a sign-in, and a sign-in is not a confirmation.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/login/finish",
        None,
        &xff.next(),
        Some(answer_body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/confirm/finish",
        Some(&admin),
        &xff.next(),
        Some(answer_body.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Once.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/confirm/finish",
        Some(&admin),
        &xff.next(),
        Some(answer_body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (_, after) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    assert!(after["confirmed_at"].as_i64() >= before["confirmed_at"].as_i64());
    assert_eq!(
        after["expires_at"], before["expires_at"],
        "the session is not extended"
    );
    // Not without a session.
    let (status, _) =
        identity_request(&app, "POST", "/auth/confirm/begin", None, &xff.next(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_suspended_account_is_closed_and_keeps_everything() {
    use brigid_identity::{Attribute, Need};
    let (state, app, admin, _) = administered(fresh_app_state().await).await;
    let xff = Addresses::new("10.94");
    state
        .store
        .set_signup_policy(brigid_store::SignupPolicy::Open)
        .await
        .unwrap();
    let mut key = new_key();
    let person = sign_up_with(&app, "paused@localhost", None, &mut key, &xff)
        .await
        .unwrap();
    let code = take_recovery_code(&app, &person, &xff).await;
    let (_, j) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&person),
        &xff.next(),
        Some(serde_json::json!({ "template": "personal" })),
    )
    .await;
    let identity: Uuid = serde_json::from_value(j["id"].clone()).unwrap();
    let (_, accounts) = identity_request(
        &app,
        "GET",
        "/admin/accounts",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    let listed = accounts
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["own"] == false)
        .unwrap()
        .clone();
    assert_eq!(listed["username"], "paused");
    assert_eq!(listed["passkeys"], 1);
    assert_eq!(listed["recovery_code"], true);
    assert!(listed["last_sign_in_at"].as_i64().is_some());
    let person_id = listed["id"].as_str().unwrap().to_owned();
    let admin_id = accounts
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["own"] == true)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // A code issued to an application just before the suspension.
    let shop = client_asking(&state, "Shop", &[(Attribute::Email, Need::Optional)]).await;
    let request = begin_authorization(&app, &shop, "", &xff.next()).await;
    let (_, j) = answer(&app, &request, &person, identity, &[], &xff.next()).await;
    let pending = query_of(j["redirect_to"].as_str().unwrap())["code"].clone();

    let act = async |method: &str, uri: String, body: Option<serde_json::Value>| {
        identity_request(&app, method, &uri, Some(&admin), &xff.next(), body).await
    };
    let (status, _) = act("POST", format!("/admin/accounts/{person_id}/suspend"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Its session is over, whatever cookie it holds.
    let (status, _) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&person),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // Its passkey is right, and the person is told why it opens nothing.
    let (_, j) = identity_request(
        &app,
        "POST",
        "/auth/login/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({ "username": "paused@localhost" })),
    )
    .await;
    let challenge: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let credential = key
        .do_authentication(url::Url::parse(ORIGIN).unwrap(), challenge)
        .unwrap();
    let (status, cookie, j) = request_with_cookie(
        &app,
        "POST",
        "/auth/login/finish",
        None,
        &xff.next(),
        Some(serde_json::json!({ "session_id": j["session_id"], "credential": credential })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "suspended");
    assert!(cookie.is_none(), "no session is opened");
    // Its recovery code adds no passkey, and is not spent.
    let (status, j) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({ "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "suspended");
    // The application gets nothing for the code it was given.
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", shop.as_str()),
        ("code", pending.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, _, j) = token_request(&app, &form, None, &xff.next()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(j["error"], "invalid_grant");

    // Nothing was deleted, and the suspension is lifted by an administrator.
    let account = Uuid::parse_str(&person_id).unwrap();
    assert_eq!(
        state.store.fetch_identities(account).await.unwrap().len(),
        1
    );
    assert_eq!(
        state.store.fetch_credentials(account).await.unwrap().len(),
        1
    );
    let (status, _) = act(
        "POST",
        format!("/admin/accounts/{person_id}/unsuspend"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/recovery/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({ "code": code })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the code was not spent");

    // An administrator does not suspend or delete their own account from
    // here, and the last one keeps the role.
    for (method, uri) in [
        ("POST", format!("/admin/accounts/{admin_id}/suspend")),
        ("DELETE", format!("/admin/accounts/{admin_id}")),
    ] {
        let (status, _) = act(method, uri, None).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
    let (status, _) = act(
        "PUT",
        format!("/admin/accounts/{admin_id}/administrator"),
        Some(serde_json::json!({ "admin": false })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(state.store.count_administrators().await.unwrap(), 1);
    // With a second administrator, the first may give the role up.
    let (status, _) = act(
        "PUT",
        format!("/admin/accounts/{person_id}/administrator"),
        Some(serde_json::json!({ "admin": true })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = act(
        "PUT",
        format!("/admin/accounts/{admin_id}/administrator"),
        Some(serde_json::json!({ "admin": false })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // It no longer administers anything.
    let (status, _) = act("GET", "/admin/accounts".to_owned(), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // An unknown account is not found.
    let (_, j) = identity_request(
        &app,
        "POST",
        "/auth/login/begin",
        None,
        &xff.next(),
        Some(serde_json::json!({ "username": "paused@localhost" })),
    )
    .await;
    let challenge: webauthn_rs::prelude::RequestChallengeResponse =
        serde_json::from_value(j["challenge"].clone()).unwrap();
    let credential = key
        .do_authentication(url::Url::parse(ORIGIN).unwrap(), challenge)
        .unwrap();
    let (status, new_admin, _) = request_with_cookie(
        &app,
        "POST",
        "/auth/login/finish",
        None,
        &xff.next(),
        Some(serde_json::json!({ "session_id": j["session_id"], "credential": credential })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = identity_request(
        &app,
        "POST",
        &format!("/admin/accounts/{}/suspend", Uuid::new_v4()),
        new_admin.as_deref(),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_invitation_opens_a_server_to_as_many_accounts_as_it_says() {
    let (state, app, admin, _) = administered(fresh_app_state().await).await;
    let xff = Addresses::new("10.95");
    let act = async |method: &str, uri: &str, body: Option<serde_json::Value>| {
        identity_request(&app, method, uri, Some(&admin), &xff.next(), body).await
    };

    // By invitation, as a server starts.
    let (_, j) = act("GET", "/admin/sign-up", None).await;
    assert_eq!(
        j,
        serde_json::json!({ "policy": "invitation", "invitations": [] })
    );
    for bad in [
        serde_json::json!({ "uses": 0 }),
        serde_json::json!({ "uses": 101 }),
        serde_json::json!({ "uses": 1, "days": 0 }),
        serde_json::json!({ "uses": 1, "days": 91 }),
    ] {
        let (status, _) = act("POST", "/admin/invitations", Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, j) = act(
        "POST",
        "/admin/invitations",
        Some(serde_json::json!({ "uses": 2 })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{j}");
    let link = j["link"].as_str().unwrap().to_owned();
    assert_eq!(j["uses_left"], 2);
    assert_eq!(
        j["expires_at"].as_i64().unwrap() - j["created_at"].as_i64().unwrap(),
        7 * 24 * 3600
    );
    // The list shows it, never the link.
    let (_, j) = act("GET", "/admin/sign-up", None).await;
    assert_eq!(j["invitations"].as_array().unwrap().len(), 1);
    assert!(!j.to_string().contains(&link));

    // Two accounts, ordinary ones; not a third.
    for name in ["guest-one@localhost", "guest-two@localhost"] {
        let cookie = sign_up_with(&app, name, Some(&link), &mut new_key(), &xff)
            .await
            .unwrap();
        let (_, j) = identity_request(
            &app,
            "GET",
            "/auth/session",
            Some(&cookie),
            &xff.next(),
            None,
        )
        .await;
        assert_eq!(j["admin"], false);
    }
    let refused = sign_up_with(
        &app,
        "guest-three@localhost",
        Some(&link),
        &mut new_key(),
        &xff,
    )
    .await
    .unwrap_err();
    assert_eq!(refused.1["code"], "link_invalid");
    let (_, j) = act("GET", "/admin/sign-up", None).await;
    assert_eq!(
        j["invitations"],
        serde_json::json!([]),
        "used up, it is gone"
    );

    // Revoked, an invitation opens nothing.
    let (_, j) = act("POST", "/admin/invitations", Some(serde_json::json!({}))).await;
    let (revoked, id) = (j["link"].as_str().unwrap().to_owned(), j["id"].clone());
    let uri = format!("/admin/invitations/{}", id.as_str().unwrap());
    let (status, _) = act("DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = act("DELETE", &uri, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let refused = sign_up_with(&app, "late@localhost", Some(&revoked), &mut new_key(), &xff)
        .await
        .unwrap_err();
    assert_eq!(refused.1["code"], "link_invalid");

    // Closed, the server takes nobody, invited or not; open, it takes anyone.
    let (_, j) = act("POST", "/admin/invitations", Some(serde_json::json!({}))).await;
    let invitation = j["link"].as_str().unwrap().to_owned();
    let (status, _) = act(
        "PUT",
        "/admin/sign-up",
        Some(serde_json::json!({ "policy": "closed" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    for link in [None, Some(invitation.as_str())] {
        let refused = sign_up_with(&app, "nobody@localhost", link, &mut new_key(), &xff)
            .await
            .unwrap_err();
        assert_eq!(refused.1["code"], "signup_closed", "{link:?}");
    }
    let (status, _) = act(
        "PUT",
        "/admin/sign-up",
        Some(serde_json::json!({ "policy": "open" })),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, j) = identity_request(&app, "GET", "/auth/server", None, &xff.next(), None).await;
    assert_eq!(j["sign_up"], true);
    sign_up_with(&app, "anyone@localhost", None, &mut new_key(), &xff)
        .await
        .unwrap();
    let (status, _) = act(
        "PUT",
        "/admin/sign-up",
        Some(serde_json::json!({ "policy": "whenever" })),
    )
    .await;
    assert!(status.is_client_error());
    assert_eq!(state.store.count_accounts().await.unwrap(), 4);
}

/// What runs here is told to those who administer the server, and to them
/// only: a visitor asking a sign-in server its version is told nothing.
#[tokio::test]
async fn the_version_of_a_server_is_for_its_administrators() {
    let (_, app, admin, _) =
        administered(fresh_app_state().await.with_edition("seedling", "9.8.7")).await;
    let xff = Addresses::new("10.97");
    let (status, j) = identity_request(
        &app,
        "GET",
        "/admin/server",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        j,
        serde_json::json!({ "edition": "seedling", "version": "9.8.7" })
    );

    // Nowhere else: not in what the server says of itself before sign-in,
    // not in its discovery document, not in the session of an account.
    for uri in [
        "/auth/server",
        "/.well-known/openid-configuration",
        "/auth/session",
        "/health",
    ] {
        let (_, j) = identity_request(&app, "GET", uri, Some(&admin), &xff.next(), None).await;
        assert!(!j.to_string().contains("9.8.7"), "{uri}: {j}");
    }

    // A program that did not say what it is: the answer says so.
    let (_, app, admin, _) = administered(fresh_app_state().await).await;
    let (status, j) = identity_request(
        &app,
        "GET",
        "/admin/server",
        Some(&admin),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j, serde_json::json!({ "edition": null, "version": null }));
}

#[tokio::test]
async fn the_role_is_claimed_with_a_link_made_on_the_machine_and_the_log_names_nobody_who_left() {
    // A server that has accounts and no administrator: as one upgraded from
    // a version without administration.
    let state = make_state().await;
    let app = build_router(Arc::clone(&state), &[]);
    let xff = Addresses::new("10.96");
    let owner = sign_up_with(&app, "owner@localhost", None, &mut new_key(), &xff)
        .await
        .unwrap();
    let guest = sign_up_with(&app, "guest@localhost", None, &mut new_key(), &xff)
        .await
        .unwrap();
    assert_eq!(brigid_api::setup_link(&state.store).await.unwrap(), None);
    let link = brigid_api::administrator_link(&state.store).await.unwrap();

    // The account that claims the role has finished its onboarding.
    let claim = async |cookie: &str| {
        identity_request(
            &app,
            "POST",
            "/admin/claim",
            Some(cookie),
            &xff.next(),
            Some(serde_json::json!({ "link": link })),
        )
        .await
    };
    let (status, j) = claim(&owner).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "recovery_code_required");
    take_recovery_code(&app, &owner, &xff).await;
    take_recovery_code(&app, &guest, &xff).await;
    let (status, _) = claim(&owner).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, j) = identity_request(
        &app,
        "GET",
        "/auth/session",
        Some(&owner),
        &xff.next(),
        None,
    )
    .await;
    assert_eq!(j["admin"], true);
    // Once.
    let (status, j) = claim(&guest).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(j["code"], "link_invalid");

    // The administrator registers an application, with what it may ask;
    // its secret is shown once.
    let act = async |method: &str, uri: String, body: Option<serde_json::Value>| {
        identity_request(&app, method, &uri, Some(&owner), &xff.next(), body).await
    };
    let (status, j) = act(
        "POST",
        "/admin/applications".into(),
        Some(serde_json::json!({
            "name": "Shop",
            "redirect_uris": [REDIRECT],
            "attributes": { "email": "required", "given_name": "optional" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{j}");
    let (client_id, secret) = (
        j["client_id"].as_str().unwrap().to_owned(),
        j["client_secret"].as_str().unwrap().to_owned(),
    );
    assert_eq!(j["attributes"]["email"], "required");
    let (_, listed) = act("GET", "/admin/applications".into(), None).await;
    assert_eq!(listed[0]["name"], "Shop");
    assert!(!listed.to_string().contains(&secret), "never shown again");
    let (status, j) = act(
        "POST",
        "/admin/applications".into(),
        Some(serde_json::json!({ "name": "Bad", "redirect_uris": ["http://shop.example/cb"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{j}");
    // An application registered here signs a person in.
    let (_, j) = identity_request(
        &app,
        "POST",
        "/account/identities",
        Some(&guest),
        &xff.next(),
        Some(serde_json::json!({ "template": "personal" })),
    )
    .await;
    let identity: Uuid = serde_json::from_value(j["id"].clone()).unwrap();
    let request = begin_authorization(&app, &client_id, "", &xff.next()).await;
    let (_, j) = answer(&app, &request, &guest, identity, &[], &xff.next()).await;
    let code = query_of(j["redirect_to"].as_str().unwrap())["code"].clone();
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", PKCE_VERIFIER),
    ];
    let (status, _, j) = token_request(&app, &form, Some((&client_id, &secret)), &xff.next()).await;
    assert_eq!(status, StatusCode::OK, "{j}");
    let (status, _) = act(
        "PUT",
        format!("/admin/applications/{client_id}/attributes"),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = act(
        "PUT",
        "/admin/applications/no-such-application/attributes".into(),
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The guest is suspended, then deleted.
    let (_, accounts) = act("GET", "/admin/accounts".into(), None).await;
    let guest_id = accounts
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["username"] == "guest")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = act("POST", format!("/admin/accounts/{guest_id}/suspend"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, log) = act("GET", "/admin/log".into(), None).await;
    let entry = |log: &serde_json::Value, action: &str| {
        log.as_array()
            .unwrap()
            .iter()
            .find(|e| e["action"] == action)
            .unwrap_or_else(|| panic!("no {action} in {log}"))
            .clone()
    };
    // While the account exists, the log can name it.
    let suspended = entry(&log, "account.suspend");
    assert_eq!(suspended["by"], "administrator");
    assert_eq!(suspended["by_username"], "owner");
    assert_eq!(suspended["account_username"], "guest");
    let (status, _) = act("DELETE", format!("/admin/accounts/{guest_id}"), None).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = act("DELETE", format!("/admin/accounts/{guest_id}"), None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Deleted, it is named nowhere: the log knows an account was concerned,
    // and no longer which.
    let (_, log) = act("GET", "/admin/log".into(), None).await;
    assert!(!log.to_string().contains("guest"), "{log}");
    assert!(!log.to_string().contains(&guest_id), "{log}");
    for action in ["account.suspend", "account.delete"] {
        let e = entry(&log, action);
        assert_eq!(e["about_account"], true, "{action}");
        assert_eq!(e["account_username"], serde_json::Value::Null, "{action}");
    }
    // What was done on the machine is said to be so; applications are named.
    assert_eq!(entry(&log, "administrator.link")["by"], "machine");
    assert_eq!(
        entry(&log, "administrator.claimed")["account_username"],
        "owner"
    );
    assert_eq!(entry(&log, "application.register")["detail"], "Shop");
    // The newest first.
    assert_eq!(log[0]["action"], "account.delete");
}

// -- A restart (a new router on the same database) does not revive it --
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
    assert_eq!(json["scopes_supported"], serde_json::json!(["openid"]));
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

    let (_, list) = identity_request(
        &app,
        "GET",
        "/account/identities",
        Some(&cookie),
        "10.46.2.1",
        None,
    )
    .await;
    let id = list[0]["id"].as_str().unwrap();
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

    let _ = (user_id, rp_origin);
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

/// A signed-in account with its identities, and an authenticator to go with.
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
    let (status, list) = identity_request(
        app,
        "GET",
        "/account/identities",
        Some(&cookie),
        &format!("{xff_base}.9"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ids = list
        .as_array()
        .unwrap()
        .iter()
        .map(|i| serde_json::from_value(i["id"].clone()).unwrap())
        .collect();
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

    // Unknown parameters and extra scopes are ignored; the form works too.
    let query = authorize_query(id, "&unknown=1&scope=openid+profile+email");
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

#[tokio::test]
async fn a_server_with_sign_up_closed_creates_no_account() {
    let master = master();
    let vsid_salt = derive_vsid_salt(&master);
    let store = EncryptedStore::new("sqlite::memory:", master)
        .await
        .unwrap();
    let origin = Url::parse("http://localhost:8080").unwrap();
    let webauthn = WebauthnService::new("localhost", &origin).unwrap();
    let mut state = AppState::new(
        store,
        webauthn,
        OidcSigningKey::generate(),
        origin,
        vsid_salt,
    )
    .with_signup_open(false);
    state.trust_forwarded_for = true;
    let app = build_router(Arc::new(state), &[]);

    let (status, j) = identity_request(&app, "GET", "/auth/server", None, "10.70.1.1", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(j["sign_up"], false);

    for body in [
        serde_json::json!({}),
        serde_json::json!({ "username": "closed@localhost" }),
    ] {
        let (status, j) = identity_request(
            &app,
            "POST",
            "/auth/register/begin",
            None,
            "10.70.1.2",
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(j["error"], "sign-up is closed on this server");
    }

    // Signing in is still offered.
    let (status, _) = identity_request(
        &app,
        "POST",
        "/auth/login/begin",
        None,
        "10.70.1.3",
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // An open server says so.
    let app = build_router(make_state().await, &[]);
    let (_, j) = identity_request(&app, "GET", "/auth/server", None, "10.70.1.4", None).await;
    assert_eq!(j["sign_up"], true);
}

/// A registration response built by hand, as an authenticator that holds a
/// P-256 key would send it with attestation "none" (which carries no
/// signature). `flags` is the byte of the authenticator data that says whether
/// the user was present (0x01) and verified (0x04).
fn handmade_registration(challenge_b64: &str, flags: u8) -> serde_json::Value {
    use base64ct::{Base64UrlUnpadded, Encoding};
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

    // The base point of P-256: a valid public key, whose private key is 1.
    let x: [u8; 32] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40,
        0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98,
        0xC2, 0x96,
    ];
    let y: [u8; 32] = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E,
        0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF,
        0x51, 0xF5,
    ];
    // COSE_Key: {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    let mut cose = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    bytes(&mut cose, &x);
    cose.push(0x22);
    bytes(&mut cose, &y);

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

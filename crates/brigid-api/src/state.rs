//! Shared application state passed to all Axum handlers via [`axum::extract::State`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use brigid_oidc::{JtiStore, OidcSigningKey};
use brigid_store::EncryptedStore;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

/// In-flight registration session keyed by a temporary session UUID.
pub struct PendingRegistration {
    pub username: String,
    pub server: String,
    pub state: PasskeyRegistration,
}

/// In-flight authentication session keyed by a temporary session UUID.
pub struct PendingAuthentication {
    pub user_id: Uuid,
    pub state: PasskeyAuthentication,
}

/// Central application state shared (via `Arc`) across all request handlers.
pub struct AppState {
    pub store: Arc<EncryptedStore>,
    pub webauthn: Arc<brigid_webauthn::WebauthnService>,
    pub oidc_key: Arc<OidcSigningKey>,
    pub jti_store: Arc<Mutex<JtiStore>>,
    pub base_url: Url,
    /// Pre-computed VSID salt — caller must use `brigid_identity::derive_vsid_salt(&master)`.
    pub vsid_salt: [u8; 32],
    pub pending_registrations: Arc<Mutex<HashMap<Uuid, PendingRegistration>>>,
    pub pending_authentications: Arc<Mutex<HashMap<Uuid, PendingAuthentication>>>,
}

impl AppState {
    pub fn new(
        store: EncryptedStore,
        webauthn: brigid_webauthn::WebauthnService,
        oidc_key: OidcSigningKey,
        base_url: Url,
        vsid_salt: [u8; 32],
    ) -> Self {
        Self {
            store: Arc::new(store),
            webauthn: Arc::new(webauthn),
            oidc_key: Arc::new(oidc_key),
            jti_store: Arc::new(Mutex::new(JtiStore::new())),
            base_url,
            vsid_salt,
            pending_registrations: Arc::new(Mutex::new(HashMap::new())),
            pending_authentications: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

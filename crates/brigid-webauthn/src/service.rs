use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

use brigid_store::{Credential, EncryptedStore};

use crate::error::{Error, Result};

/// Result returned after a successful passkey authentication.
#[derive(Debug)]
pub struct AuthResult {
    /// Base64url-encoded credential ID of the authenticator that was used.
    pub credential_id: String,
    /// `true` if the stored passkey must be re-persisted (counter advanced).
    pub credential_updated: bool,
}

/// High-level WebAuthn service bound to a single relying party.
pub struct WebauthnService {
    webauthn: Webauthn,
}

impl WebauthnService {
    /// Build a `WebauthnService` for the given RP ID and origin.
    pub fn new(rp_id: &str, rp_origin: &Url) -> Result<Self> {
        let webauthn = WebauthnBuilder::new(rp_id, rp_origin)?
            .rp_name("Brig·id")
            .build()?;
        Ok(Self { webauthn })
    }

    /// Start a passkey registration challenge.
    pub fn begin_registration(
        &self,
        user_id: Uuid,
        username: &str,
    ) -> Result<(CreationChallengeResponse, PasskeyRegistration)> {
        Ok(self
            .webauthn
            .start_passkey_registration(user_id, username, username, None)?)
    }

    /// Verify the registration response and return the passkey.
    pub fn finish_registration(
        &self,
        state: &PasskeyRegistration,
        response: &RegisterPublicKeyCredential,
    ) -> Result<Passkey> {
        Ok(self.webauthn.finish_passkey_registration(response, state)?)
    }

    /// Start a passkey authentication challenge.
    ///
    /// Returns `Err(NoCredentials)` when `credentials` is empty.
    pub fn begin_authentication(
        &self,
        credentials: &[Passkey],
    ) -> Result<(RequestChallengeResponse, PasskeyAuthentication)> {
        if credentials.is_empty() {
            return Err(Error::NoCredentials);
        }
        Ok(self.webauthn.start_passkey_authentication(credentials)?)
    }

    /// Verify the authentication response and update in-place counters.
    pub fn finish_authentication(
        &self,
        credentials: &mut [Passkey],
        state: &PasskeyAuthentication,
        response: &PublicKeyCredential,
    ) -> Result<AuthResult> {
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, state)?;

        let mut credential_updated = false;
        for passkey in credentials.iter_mut() {
            if passkey.update_credential(&auth_result) == Some(true) {
                credential_updated = true;
            }
        }

        // CredentialID always serialises; HumanBinaryData::Serialize is infallible.
        let json = serde_json::to_string(auth_result.cred_id())
            .expect("CredentialID always serializes to a valid JSON string");
        let credential_id = json.trim_matches('"').to_string();

        Ok(AuthResult {
            credential_id,
            credential_updated,
        })
    }
}

// ---------------------------------------------------------------------------
// Store integration helpers
// ---------------------------------------------------------------------------

/// Serialise a `Passkey` to JSON and persist it encrypted via `brigid-store`.
pub async fn store_passkey(
    store: &EncryptedStore,
    user_id: Uuid,
    passkey: &Passkey,
) -> Result<Credential> {
    let data = serde_json::to_vec(passkey)?;
    let cred = Credential {
        id: Uuid::new_v4(),
        user_id,
        data,
    };
    store.store_credential(&cred).await?;
    Ok(cred)
}

/// Load and deserialise all `Passkey`s for `user_id` from the encrypted store.
pub async fn load_passkeys(store: &EncryptedStore, user_id: Uuid) -> Result<Vec<Passkey>> {
    let creds = store.fetch_credentials(user_id).await?;
    creds
        .iter()
        .map(|c| serde_json::from_slice::<Passkey>(&c.data).map_err(Error::from))
        .collect()
}

/// UPDATE an existing `Passkey` row for `user_id` in the encrypted store.
///
/// Finds the raw credential whose deserialised passkey has the same `cred_id`
/// as `passkey`, then overwrites the encrypted data blob in-place. This
/// prevents duplicate rows accumulating on each successful authentication
/// when the signature counter advances.
pub async fn update_passkey(
    store: &EncryptedStore,
    user_id: Uuid,
    passkey: &Passkey,
) -> Result<()> {
    let creds = store.fetch_credentials(user_id).await?;
    let target_id =
        serde_json::to_string(passkey.cred_id()).expect("CredentialID always serializes");
    let target_id = target_id.trim_matches('"');

    for cred in creds {
        let existing: Passkey = serde_json::from_slice(&cred.data)?;
        let existing_id =
            serde_json::to_string(existing.cred_id()).expect("CredentialID always serializes");
        let existing_id_str = existing_id.trim_matches('"');
        if existing_id_str == target_id {
            let updated_cred = Credential {
                id: cred.id,
                user_id,
                data: serde_json::to_vec(passkey)?,
            };
            store.update_credential(&updated_cred).await?;
            return Ok(());
        }
    }
    // No matching credential found — the auth was valid but counter state
    // could not be persisted. This should not happen in practice.
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use brigid_crypto::MasterKey;
    use webauthn_authenticator_rs::WebauthnAuthenticator;
    use webauthn_authenticator_rs::softpasskey::SoftPasskey;

    fn master() -> MasterKey {
        MasterKey::from_hex(&"ab".repeat(32)).unwrap()
    }

    fn test_service() -> WebauthnService {
        let rp_origin = Url::parse("http://localhost:8080").unwrap();
        WebauthnService::new("localhost", &rp_origin).unwrap()
    }

    // ------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------

    #[test]
    fn new_rejects_invalid_rp_id() {
        let origin = Url::parse("http://127.0.0.1:8080").unwrap();
        let result = WebauthnService::new("invalid domain!", &origin);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // begin_authentication: empty slice
    // ------------------------------------------------------------------

    #[test]
    fn begin_authentication_returns_no_credentials_on_empty_slice() {
        let svc = test_service();
        let err = svc.begin_authentication(&[]).unwrap_err();
        assert!(matches!(err, Error::NoCredentials));
    }

    // ------------------------------------------------------------------
    // Registration round-trip (happy path)
    // ------------------------------------------------------------------

    fn register_passkey(
        svc: &WebauthnService,
        rp_origin: &Url,
        auth_client: &mut WebauthnAuthenticator<SoftPasskey>,
        username: &str,
    ) -> Passkey {
        let user_id = Uuid::new_v4();
        let (ccr, reg_state) = svc.begin_registration(user_id, username).unwrap();
        let reg_resp = auth_client.do_registration(rp_origin.clone(), ccr).unwrap();
        svc.finish_registration(&reg_state, &reg_resp).unwrap()
    }

    #[test]
    fn register_and_authenticate_roundtrip() {
        let rp_origin = Url::parse("http://localhost:8080").unwrap();
        let svc = test_service();
        let user_id = Uuid::new_v4();
        let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let (ccr, reg_state) = svc.begin_registration(user_id, "alice").unwrap();
        let reg_resp = auth_client.do_registration(rp_origin.clone(), ccr).unwrap();
        let passkey = svc.finish_registration(&reg_state, &reg_resp).unwrap();

        let creds = vec![passkey];
        let (rcr, auth_state) = svc.begin_authentication(&creds).unwrap();
        let auth_resp = auth_client
            .do_authentication(rp_origin.clone(), rcr)
            .unwrap();
        let mut creds_mut = creds.clone();
        let result = svc
            .finish_authentication(&mut creds_mut, &auth_state, &auth_resp)
            .unwrap();

        assert!(!result.credential_id.is_empty());
        assert!(result.credential_updated);
    }

    // ------------------------------------------------------------------
    // Error paths: wrong state triggers From<WebauthnError>
    // ------------------------------------------------------------------

    #[test]
    fn finish_registration_fails_with_wrong_state() {
        let rp_origin = Url::parse("http://localhost:8080").unwrap();
        let svc = test_service();
        let mut auth_a = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let auth_b = WebauthnAuthenticator::new(SoftPasskey::new(true));

        let uid = Uuid::new_v4();
        let (ccr_a, _state_a) = svc.begin_registration(uid, "alice").unwrap();
        let (_ccr_b, state_b) = svc.begin_registration(uid, "bob").unwrap();

        // Respond to challenge A, but try to finish with state B → mismatch.
        let resp_a = auth_a.do_registration(rp_origin.clone(), ccr_a).unwrap();
        let _ = auth_b; // suppress unused warning
        let result = svc.finish_registration(&state_b, &resp_a);
        assert!(result.is_err());
    }

    #[test]
    fn finish_authentication_fails_with_wrong_state() {
        let rp_origin = Url::parse("http://localhost:8080").unwrap();
        let svc = test_service();
        let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));

        // Register once.
        let passkey = register_passkey(&svc, &rp_origin, &mut auth_client, "charlie");
        let creds = vec![passkey];

        // Start two challenges; respond to the first but verify with the second.
        let (rcr1, _state1) = svc.begin_authentication(&creds).unwrap();
        let (_rcr2, state2) = svc.begin_authentication(&creds).unwrap();
        let auth_resp = auth_client
            .do_authentication(rp_origin.clone(), rcr1)
            .unwrap();

        let mut creds_mut = creds.clone();
        let result = svc.finish_authentication(&mut creds_mut, &state2, &auth_resp);
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // Store helpers
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn store_and_load_passkeys() {
        use brigid_store::User;
        use time::OffsetDateTime;

        let rp_origin = Url::parse("http://localhost:8080").unwrap();
        let svc = test_service();
        let user_id = Uuid::new_v4();

        // EncryptedStore::new runs migrations automatically.
        let store = EncryptedStore::new("sqlite::memory:", master())
            .await
            .unwrap();

        // FK constraint: user must exist before storing credentials.
        let user = User {
            id: user_id,
            username: "bob".to_string(),
            server: "localhost".to_string(),
            did_web: "did:web:localhost:u:bob".to_string(),
            created_at: OffsetDateTime::now_utc(),
        };
        store.store_user(&user).await.unwrap();

        // Register a passkey.
        let mut auth_client = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let passkey = register_passkey(&svc, &rp_origin, &mut auth_client, "bob");

        // Store and reload the passkey.
        let cred = store_passkey(&store, user_id, &passkey).await.unwrap();
        assert_eq!(cred.user_id, user_id);

        let loaded = load_passkeys(&store, user_id).await.unwrap();
        assert_eq!(loaded.len(), 1);

        // Unknown user -> empty vec.
        let empty = load_passkeys(&store, Uuid::new_v4()).await.unwrap();
        assert!(empty.is_empty());
    }
}

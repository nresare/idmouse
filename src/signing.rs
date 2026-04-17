use crate::config::{Config, SigningKeyStorage};
use crate::kubernetes;
use crate::service::Jwk;
use anyhow::Context;
use base64::Engine;
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use tracing::{debug, info};

const ROTATION_HOURS: i64 = 8;
const RETIRED_KEY_GRACE_HOURS: i64 = 1;
const SECRET_NAME: &str = "idmouse-signing-keys";
const SECRET_DATA_KEY: &str = "keys";

#[derive(Clone)]
pub struct SigningState {
    backend: Box<dyn SigningBackend>,
}

#[derive(Clone)]
struct InMemorySigningState {
    key: MaterializedSigningKey,
}

#[derive(Clone)]
struct KubernetesSecretSigningState {
    client: Client,
    namespace: String,
}

pub struct SigningRequest {
    pub expires_at: u64,
    pub issued_at: u64,
    pub issuer: String,
    pub extra: Map<String, Value>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredSigningKey {
    kid: String,
    private_key_pem: String,
    active_from: DateTime<Utc>,
    retire_after: DateTime<Utc>,
    created_at: DateTime<Utc>,
}

#[derive(Default, Serialize, Deserialize)]
struct StoredSigningKeysDocument {
    keys: Vec<StoredSigningKey>,
}

#[derive(Deserialize)]
struct SecretResponse {
    metadata: SecretMetadata,
    #[serde(default)]
    data: HashMap<String, String>,
}

#[derive(Serialize)]
struct SecretUpsertRequest {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    metadata: SecretMetadata,
    #[serde(rename = "type")]
    type_: &'static str,
    data: HashMap<String, String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SecretMetadata {
    name: Option<String>,
    namespace: Option<String>,
    #[serde(rename = "resourceVersion")]
    resource_version: Option<String>,
}

trait SigningBackend: Send + Sync {
    fn sign(&self, request: &SigningRequest, now: DateTime<Utc>) -> anyhow::Result<String>;
    fn jwks(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<Jwk>>;
    fn box_clone(&self) -> Box<dyn SigningBackend>;
}

impl Clone for Box<dyn SigningBackend> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[derive(Clone)]
struct MaterializedSigningKey {
    kid: String,
    encoding_key: EncodingKey,
    jwk: Jwk,
}

#[derive(Serialize)]
struct SignedClaims<'a> {
    exp: u64,
    iat: u64,
    nbf: u64,
    iss: &'a str,
    #[serde(flatten)]
    extra: &'a Map<String, Value>,
}

impl SigningState {
    pub fn build(config: &Config) -> anyhow::Result<Self> {
        let backend: Box<dyn SigningBackend> = match config.signing_key_storage {
            SigningKeyStorage::InMemory => {
                info!("using in-memory signing key storage");
                Box::new(InMemorySigningState {
                    key: materialize_key(&prepare_in_memory_key()?)?,
                })
            }
            SigningKeyStorage::KubernetesSecret => {
                info!(
                    secret_name = SECRET_NAME,
                    "using Kubernetes Secret-backed signing key storage"
                );
                let client = kubernetes::configure_in_cluster_client(Client::builder())?
                    .build()
                    .context("failed to build Kubernetes API client for signing key storage")?;
                let namespace = kubernetes::local_namespace()?;
                Box::new(KubernetesSecretSigningState { client, namespace })
            }
        };

        Ok(Self { backend })
    }

    pub fn sign(&self, request: &SigningRequest, now: DateTime<Utc>) -> anyhow::Result<String> {
        self.backend.sign(request, now)
    }

    pub fn jwks(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<Jwk>> {
        self.backend.jwks(now)
    }
}

impl SigningBackend for InMemorySigningState {
    fn sign(&self, request: &SigningRequest, _now: DateTime<Utc>) -> anyhow::Result<String> {
        sign_with_key(&self.key, request)
    }

    fn jwks(&self, _now: DateTime<Utc>) -> anyhow::Result<Vec<Jwk>> {
        Ok(vec![self.key.jwk.clone()])
    }

    fn box_clone(&self) -> Box<dyn SigningBackend> {
        Box::new(self.clone())
    }
}

impl SigningBackend for KubernetesSecretSigningState {
    fn sign(&self, request: &SigningRequest, now: DateTime<Utc>) -> anyhow::Result<String> {
        let key = self.active_signing_key(now)?;
        sign_with_key(&key, request)
    }

    fn jwks(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<Jwk>> {
        self.jwks_for_time(now)
    }

    fn box_clone(&self) -> Box<dyn SigningBackend> {
        Box::new(self.clone())
    }
}

impl KubernetesSecretSigningState {
    fn active_signing_key(&self, now: DateTime<Utc>) -> anyhow::Result<MaterializedSigningKey> {
        let keys = self.reconciled_keys(now)?;
        let key = keys
            .iter()
            .filter(|key| key.active_from <= now && key.retire_after > now)
            .max_by_key(|key| key.active_from)
            .ok_or_else(|| {
                anyhow::anyhow!("no active signing key available after reconciliation")
            })?;
        materialize_key(key)
    }

    fn jwks_for_time(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<Jwk>> {
        let keys = self.reconciled_keys(now)?;
        keys.iter()
            .map(|key| materialize_key(key).map(|materialized| materialized.jwk))
            .collect()
    }

    fn reconciled_keys(&self, now: DateTime<Utc>) -> anyhow::Result<Vec<StoredSigningKey>> {
        for attempt in 1..=3 {
            let stored = self.fetch_secret()?;
            let mut document = stored
                .as_ref()
                .map(parse_secret_document)
                .transpose()?
                .unwrap_or_default();

            let original = serde_json::to_vec(&document)
                .context("failed to serialize stored signing keys before reconciliation")?;
            reconcile_stored_keys(&mut document.keys, now)?;
            let updated = serde_json::to_vec(&document)
                .context("failed to serialize stored signing keys after reconciliation")?;

            if original == updated {
                return Ok(list_visible_keys(document.keys, now));
            }

            match self.upsert_secret(stored.as_ref(), &updated) {
                Ok(()) => return Ok(list_visible_keys(document.keys, now)),
                Err(error) if is_conflict(&error) && attempt < 3 => {
                    debug!(attempt, "signing key secret update conflicted; retrying");
                }
                Err(error) => return Err(error),
            }
        }

        anyhow::bail!("failed to reconcile Kubernetes signing keys after repeated update conflicts")
    }

    fn fetch_secret(&self) -> anyhow::Result<Option<SecretResponse>> {
        let response = self
            .client
            .get(self.secret_url())
            .send()
            .with_context(|| format!("failed to fetch Kubernetes Secret '{SECRET_NAME}'"))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        response
            .error_for_status()
            .with_context(|| {
                format!("Kubernetes Secret fetch for '{SECRET_NAME}' returned an error status")
            })?
            .json()
            .with_context(|| format!("failed to parse Kubernetes Secret '{SECRET_NAME}'"))
            .map(Some)
    }

    fn upsert_secret(
        &self,
        existing: Option<&SecretResponse>,
        serialized_document: &[u8],
    ) -> anyhow::Result<()> {
        let mut data = HashMap::new();
        data.insert(
            SECRET_DATA_KEY.to_string(),
            base64::engine::general_purpose::STANDARD.encode(serialized_document),
        );

        let metadata = SecretMetadata {
            name: Some(SECRET_NAME.to_string()),
            namespace: Some(self.namespace.clone()),
            resource_version: existing.and_then(|secret| secret.metadata.resource_version.clone()),
        };

        let request = SecretUpsertRequest {
            api_version: "v1",
            kind: "Secret",
            metadata,
            type_: "Opaque",
            data,
        };

        let response = if existing.is_some() {
            self.client.put(self.secret_url()).json(&request).send()
        } else {
            self.client
                .post(self.secrets_collection_url())
                .json(&request)
                .send()
        }
        .with_context(|| format!("failed to write Kubernetes Secret '{SECRET_NAME}'"))?;

        response.error_for_status().with_context(|| {
            format!("Kubernetes Secret write for '{SECRET_NAME}' returned an error status")
        })?;
        Ok(())
    }

    fn secret_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets/{}",
            kubernetes::KUBERNETES_SERVICE_HOST,
            self.namespace,
            SECRET_NAME
        )
    }

    fn secrets_collection_url(&self) -> String {
        format!(
            "{}/api/v1/namespaces/{}/secrets",
            kubernetes::KUBERNETES_SERVICE_HOST,
            self.namespace
        )
    }
}

fn prepare_in_memory_key() -> anyhow::Result<StoredSigningKey> {
    let now = Utc::now();
    let signing_key = SigningKey::random(&mut OsRng);
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode generated ES256 private key")?;
    Ok(StoredSigningKey {
        kid: "idmouse".to_string(),
        private_key_pem: private_key_pem.to_string(),
        active_from: now,
        retire_after: now + Duration::days(365 * 100),
        created_at: now,
    })
}

fn materialize_key(key: &StoredSigningKey) -> anyhow::Result<MaterializedSigningKey> {
    let signing_key = SigningKey::from_pkcs8_pem(&key.private_key_pem)
        .context("failed to decode stored ES256 private key")?;
    let verifying_key = VerifyingKey::from(&signing_key);
    let encoding_key = EncodingKey::from_ec_pem(key.private_key_pem.as_bytes())
        .context("failed to create JWT encoding key from ES256 private key")?;
    Ok(MaterializedSigningKey {
        kid: key.kid.clone(),
        encoding_key,
        jwk: build_jwk(&verifying_key, &key.kid),
    })
}

fn sign_with_key(key: &MaterializedSigningKey, request: &SigningRequest) -> anyhow::Result<String> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(key.kid.clone());
    let claims = SignedClaims {
        exp: request.expires_at,
        iat: request.issued_at,
        nbf: request.issued_at,
        iss: &request.issuer,
        extra: &request.extra,
    };

    encode(&header, &claims, &key.encoding_key)
        .map_err(|error| anyhow::anyhow!("failed to encode token: {error}"))
}

fn build_jwk(verifying_key: &VerifyingKey, kid: &str) -> Jwk {
    let encoded = verifying_key.to_encoded_point(false);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        encoded
            .x()
            .expect("uncompressed P-256 points always have x"),
    );
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
        encoded
            .y()
            .expect("uncompressed P-256 points always have y"),
    );
    Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        use_: "sig".to_string(),
        alg: "ES256".to_string(),
        kid: kid.to_string(),
        x,
        y,
    }
}

fn reconcile_stored_keys(
    keys: &mut Vec<StoredSigningKey>,
    now: DateTime<Utc>,
) -> anyhow::Result<()> {
    keys.retain(|key| key.retire_after > now);

    let current_slot = slot_start(now)?;
    let next_slot = current_slot + Duration::hours(ROTATION_HOURS);
    ensure_key_for_slot(keys, current_slot)?;
    ensure_key_for_slot(keys, next_slot)?;
    keys.sort_by_key(|key| key.active_from);
    Ok(())
}

fn ensure_key_for_slot(
    keys: &mut Vec<StoredSigningKey>,
    active_from: DateTime<Utc>,
) -> anyhow::Result<()> {
    if keys.iter().any(|key| key.active_from == active_from) {
        return Ok(());
    }

    let signing_key = SigningKey::random(&mut OsRng);
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode rotated ES256 private key")?;
    keys.push(StoredSigningKey {
        kid: random_kid(),
        private_key_pem: private_key_pem.to_string(),
        active_from,
        retire_after: active_from + Duration::hours(ROTATION_HOURS + RETIRED_KEY_GRACE_HOURS),
        created_at: Utc::now(),
    });
    Ok(())
}

fn slot_start(now: DateTime<Utc>) -> anyhow::Result<DateTime<Utc>> {
    let hour = now.hour() as i64;
    let slot_hour = hour - (hour % ROTATION_HOURS);
    Utc.with_ymd_and_hms(now.year(), now.month(), now.day(), slot_hour as u32, 0, 0)
        .single()
        .ok_or_else(|| anyhow::anyhow!("failed to calculate signing key rotation slot"))
}

fn random_kid() -> String {
    let mut bytes = [0_u8; 24];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_secret_document(secret: &SecretResponse) -> anyhow::Result<StoredSigningKeysDocument> {
    let encoded = secret.data.get(SECRET_DATA_KEY).ok_or_else(|| {
        anyhow::anyhow!("Kubernetes Secret '{SECRET_NAME}' is missing data['{SECRET_DATA_KEY}']")
    })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to base64-decode signing key secret data")?;
    serde_json::from_slice(&decoded)
        .context("failed to parse signing key JSON from Kubernetes Secret")
}

fn list_visible_keys(keys: Vec<StoredSigningKey>, now: DateTime<Utc>) -> Vec<StoredSigningKey> {
    keys.into_iter()
        .filter(|key| key.retire_after > now)
        .collect()
}

fn is_conflict(error: &anyhow::Error) -> bool {
    error.to_string().contains("409 Conflict")
}

#[cfg(test)]
mod tests {
    use super::{reconcile_stored_keys, slot_start, StoredSigningKey};
    use anyhow::Result;
    use chrono::{Duration, TimeZone, Utc};

    #[test]
    fn slot_start_rounds_down_to_8_hour_boundary() -> Result<()> {
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 15, 7, 11).unwrap();
        assert_eq!(
            slot_start(now)?,
            Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap()
        );
        Ok(())
    }

    #[test]
    fn reconcile_creates_current_and_next_slots() -> Result<()> {
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 10, 0, 0).unwrap();
        let mut keys = Vec::new();
        reconcile_stored_keys(&mut keys, now)?;
        assert_eq!(keys.len(), 2);
        assert_eq!(
            keys[0].active_from,
            Utc.with_ymd_and_hms(2026, 4, 12, 8, 0, 0).unwrap()
        );
        assert_eq!(
            keys[1].active_from,
            Utc.with_ymd_and_hms(2026, 4, 12, 16, 0, 0).unwrap()
        );
        Ok(())
    }

    #[test]
    fn reconcile_keeps_recently_retired_key_for_one_hour() -> Result<()> {
        let now = Utc.with_ymd_and_hms(2026, 4, 12, 8, 1, 0).unwrap();
        let mut keys = vec![StoredSigningKey {
            kid: "old".to_string(),
            private_key_pem: "pem".to_string(),
            active_from: Utc.with_ymd_and_hms(2026, 4, 12, 0, 0, 0).unwrap(),
            retire_after: Utc.with_ymd_and_hms(2026, 4, 12, 9, 0, 0).unwrap(),
            created_at: now - Duration::hours(8),
        }];
        reconcile_stored_keys(&mut keys, now)?;
        assert_eq!(keys.len(), 3);
        Ok(())
    }
}

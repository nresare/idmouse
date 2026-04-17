use crate::config::{Config, SigningKeyStorage};
use crate::kubernetes;
use crate::service::Jwk;
use crate::signing_kubernetes_secret::{KubernetesSecretSigningState, StoredSigningKey};
use anyhow::Context;
use base64::Engine;
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use reqwest::blocking::Client;
use serde_json::{Map, Value};
use std::sync::Arc;
use tracing::info;

const ROTATION_HOURS: i64 = 8;
const RETIRED_KEY_GRACE_HOURS: i64 = 1;
pub const TOKEN_TTL_SECONDS: u64 = 600;

pub trait SigningBackend: Send + Sync {
    fn sign(&self, claims: &Map<String, Value>) -> anyhow::Result<String>;
    fn jwks(&self) -> anyhow::Result<Vec<Jwk>>;
}

#[derive(Clone)]
struct InMemorySigningBackend {
    key: MaterializedSigningKey,
}

#[derive(Clone)]
pub(crate) struct MaterializedSigningKey {
    pub(crate) kid: String,
    pub(crate) encoding_key: EncodingKey,
    pub(crate) jwk: Jwk,
}

pub fn build_signing_backend(config: &Config) -> anyhow::Result<Arc<dyn SigningBackend>> {
    let backend: Arc<dyn SigningBackend> = match config.signing_key_storage {
        SigningKeyStorage::InMemory => {
            info!("using in-memory signing key storage");
            Arc::new(InMemorySigningBackend {
                key: materialize_key(&prepare_in_memory_key()?)?,
            })
        }
        SigningKeyStorage::KubernetesSecret => {
            info!(
                secret_name = "idmouse-signing-keys",
                "using Kubernetes Secret-backed signing key storage"
            );
            let client = kubernetes::configure_in_cluster_client(Client::builder())?
                .build()
                .context("failed to build Kubernetes API client for signing key storage")?;
            let namespace = kubernetes::local_namespace()?;
            Arc::new(KubernetesSecretSigningState { client, namespace })
        }
    };

    Ok(backend)
}

impl SigningBackend for InMemorySigningBackend {
    fn sign(&self, claims: &Map<String, Value>) -> anyhow::Result<String> {
        sign_with_key(&self.key, claims)
    }

    fn jwks(&self) -> anyhow::Result<Vec<Jwk>> {
        Ok(vec![self.key.jwk.clone()])
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

pub(crate) fn materialize_key(key: &StoredSigningKey) -> anyhow::Result<MaterializedSigningKey> {
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

pub(crate) fn sign_with_key(
    key: &MaterializedSigningKey,
    claims: &Map<String, Value>,
) -> anyhow::Result<String> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(key.kid.clone());

    encode(&header, claims, &key.encoding_key)
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

pub(crate) fn reconcile_stored_keys(
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

pub(crate) fn list_visible_keys(
    keys: Vec<StoredSigningKey>,
    now: DateTime<Utc>,
) -> Vec<StoredSigningKey> {
    keys.into_iter()
        .filter(|key| key.retire_after > now)
        .collect()
}

pub(crate) fn is_conflict(error: &anyhow::Error) -> bool {
    error.to_string().contains("409 Conflict")
}

#[cfg(test)]
mod tests {
    use super::{reconcile_stored_keys, slot_start};
    use crate::signing_kubernetes_secret::StoredSigningKey;
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

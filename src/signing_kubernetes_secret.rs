use crate::kubernetes;
use crate::service::Jwk;
use crate::signing::{
    is_conflict, list_visible_keys, materialize_key, reconcile_stored_keys, MaterializedSigningKey,
    SigningBackend,
};
use anyhow::Context;
use base64::Engine;
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;
use tracing::debug;

const SECRET_NAME: &str = "idmouse-signing-keys";
const SECRET_DATA_KEY: &str = "keys";

#[derive(Clone)]
pub(crate) struct KubernetesSecretSigningState {
    pub(crate) client: Client,
    pub(crate) namespace: String,
}

#[derive(Default, Serialize, Deserialize)]
struct StoredSigningKeysDocument {
    keys: Vec<StoredSigningKey>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct SecretMetadata {
    name: Option<String>,
    namespace: Option<String>,
    #[serde(rename = "resourceVersion")]
    resource_version: Option<String>,
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

impl SigningBackend for KubernetesSecretSigningState {
    fn sign(&self, claims: &Map<String, Value>) -> anyhow::Result<String> {
        let key = self.active_signing_key(Utc::now())?;
        crate::signing::sign_with_key(&key, claims)
    }

    fn jwks(&self) -> anyhow::Result<Vec<Jwk>> {
        self.jwks_for_time(Utc::now())
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

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredSigningKey {
    pub(crate) kid: String,
    pub(crate) private_key_pem: String,
    pub(crate) active_from: DateTime<Utc>,
    pub(crate) retire_after: DateTime<Utc>,
    pub(crate) created_at: DateTime<Utc>,
}

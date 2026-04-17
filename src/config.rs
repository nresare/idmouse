use crate::auth;
use anyhow::Context;
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    pub origin: String,
    #[serde(default = "default_signing_key_storage")]
    pub signing_key_storage: SigningKeyStorage,
    pub authentication: AuthenticationConfig,
    #[serde(rename = "mapping", default)]
    pub mappings: Vec<MappingConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SigningKeyStorage {
    InMemory,
    KubernetesSecret,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationConfig {
    pub audience: String,
    pub issuer: String,
    pub validation_key: Option<String>,
    #[serde(default = "default_authentication_algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MappingConfig {
    pub name: String,
    #[serde(default)]
    pub allowed_subjects: Vec<String>,
    #[serde(default)]
    pub additional_claims: Map<String, Value>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file '{path}'"))?;
        toml::from_str(&content)
            .map_err(|error| anyhow::anyhow!("Could not parse config file '{path}': {error}"))
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.origin.is_empty() {
            anyhow::bail!("origin must not be empty");
        }
        if self.mappings.is_empty() {
            anyhow::bail!("at least one [[mapping]] entry is required");
        }

        let mut names = std::collections::HashSet::new();
        for mapping in &self.mappings {
            if mapping.name.is_empty() {
                anyhow::bail!("mapping names must not be empty");
            }
            if mapping.allowed_subjects.is_empty() {
                anyhow::bail!(
                    "mapping '{}' must define at least one allowed_subject",
                    mapping.name
                );
            }
            if !names.insert(mapping.name.clone()) {
                anyhow::bail!("duplicate mapping name '{}'", mapping.name);
            }
        }

        self.authentication.validate()?;
        Ok(())
    }
}

impl AuthenticationConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.audience.is_empty() {
            anyhow::bail!("authentication.audience must not be empty");
        }
        if self.issuer.is_empty() {
            anyhow::bail!("authentication.issuer must not be empty");
        }
        auth::algorithm(self)?;
        Ok(())
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_authentication_algorithm() -> String {
    "RS256".to_string()
}

fn default_signing_key_storage() -> SigningKeyStorage {
    SigningKeyStorage::InMemory
}

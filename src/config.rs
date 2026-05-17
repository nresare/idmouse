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
    #[serde(rename = "role", default)]
    pub roles: Vec<authzoo::RoleConfig>,
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
pub struct MappingConfig {
    pub name: String,
    pub role: Option<String>,
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

    pub fn validate(&self, disable_auth: bool) -> anyhow::Result<()> {
        if self.origin.is_empty() {
            anyhow::bail!("origin must not be empty");
        }
        if self.mappings.is_empty() {
            anyhow::bail!("at least one [[mapping]] entry is required");
        }

        let role_validator = authzoo::TokenValidator::new(self.roles.clone())?;
        if !disable_auth && self.roles.is_empty() {
            anyhow::bail!("at least one [[role]] entry is required");
        }

        let mut names = std::collections::HashSet::new();
        for mapping in &self.mappings {
            if mapping.name.is_empty() {
                anyhow::bail!("mapping names must not be empty");
            }
            if !disable_auth {
                let role = mapping.role.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("mapping '{}' must define role", mapping.name)
                })?;
                if role.is_empty() {
                    anyhow::bail!("mapping '{}' role must not be empty", mapping.name);
                }
                role_validator.ensure_roles_exist([role])?;
            }
            if !names.insert(mapping.name.clone()) {
                anyhow::bail!("duplicate mapping name '{}'", mapping.name);
            }
        }

        Ok(())
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_signing_key_storage() -> SigningKeyStorage {
    SigningKeyStorage::InMemory
}

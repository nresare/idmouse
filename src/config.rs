use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    pub origin: String,
    pub authentication: AuthenticationConfig,
    #[serde(rename = "mapping", default)]
    pub mappings: Vec<MappingConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthenticationConfig {
    pub audience: String,
    pub issuer: String,
    pub validation_key: String,
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
        toml::from_str(&content).with_context(|| format!("Could not parse config file '{path}'"))
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

    pub fn mapping(&self, name: &str) -> Option<&MappingConfig> {
        self.mappings.iter().find(|mapping| mapping.name == name)
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
        self.algorithm()?;
        self.decoding_key()?;
        Ok(())
    }

    pub fn algorithm(&self) -> anyhow::Result<Algorithm> {
        match self.algorithm.as_str() {
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "RS512" => Ok(Algorithm::RS512),
            "ES256" => Ok(Algorithm::ES256),
            "ES384" => Ok(Algorithm::ES384),
            other => anyhow::bail!(
                "unsupported authentication algorithm '{other}'; supported values are RS256, RS384, RS512, ES256 and ES384"
            ),
        }
    }

    pub fn decoding_key(&self) -> anyhow::Result<DecodingKey> {
        match self.algorithm()? {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                DecodingKey::from_rsa_pem(self.validation_key.as_bytes())
                    .context("failed to parse RSA validation key")
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                DecodingKey::from_ec_pem(self.validation_key.as_bytes())
                    .context("failed to parse EC validation key")
            }
            other => anyhow::bail!("unsupported authentication algorithm '{other:?}'"),
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_authentication_algorithm() -> String {
    "RS256".to_string()
}

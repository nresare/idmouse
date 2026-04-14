use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

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

#[derive(Clone)]
pub struct LoadedConfig {
    pub bind_address: String,
    pub origin: String,
    pub authentication: LoadedAuthenticationConfig,
    pub mappings: HashMap<String, MappingConfig>,
    pub signing: SigningState,
}

#[derive(Clone)]
pub struct LoadedAuthenticationConfig {
    pub audience: String,
    pub issuer: String,
    pub algorithm: Algorithm,
    pub decoding_key: DecodingKey,
}

#[derive(Clone)]
pub struct SigningState {
    pub encoding_key: EncodingKey,
    pub signing_key: SigningKey,
    pub public_key_pem: String,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Could not read config file '{path}'"))?;
        toml::from_str(&content).with_context(|| format!("Could not parse config file '{path}'"))
    }

    pub fn validate(self) -> anyhow::Result<LoadedConfig> {
        if self.origin.is_empty() {
            anyhow::bail!("origin must not be empty");
        }
        if self.mappings.is_empty() {
            anyhow::bail!("at least one [[mapping]] entry is required");
        }

        let mut mappings = HashMap::new();
        for mapping in self.mappings {
            if mapping.name.is_empty() {
                anyhow::bail!("mapping names must not be empty");
            }
            if mapping.allowed_subjects.is_empty() {
                anyhow::bail!(
                    "mapping '{}' must define at least one allowed_subject",
                    mapping.name
                );
            }
            let mapping_name = mapping.name.clone();
            if mappings.insert(mapping_name.clone(), mapping).is_some() {
                anyhow::bail!("duplicate mapping name '{mapping_name}'");
            }
        }

        Ok(LoadedConfig {
            bind_address: self.bind_address,
            origin: self.origin,
            authentication: self.authentication.validate()?,
            mappings,
            signing: build_signing_state()?,
        })
    }
}

impl AuthenticationConfig {
    fn validate(self) -> anyhow::Result<LoadedAuthenticationConfig> {
        if self.audience.is_empty() {
            anyhow::bail!("authentication.audience must not be empty");
        }
        if self.issuer.is_empty() {
            anyhow::bail!("authentication.issuer must not be empty");
        }
        let algorithm = parse_authentication_algorithm(&self.algorithm)?;
        let decoding_key = match algorithm {
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                DecodingKey::from_rsa_pem(self.validation_key.as_bytes())
                    .context("failed to parse RSA validation key")?
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                DecodingKey::from_ec_pem(self.validation_key.as_bytes())
                    .context("failed to parse EC validation key")?
            }
            other => anyhow::bail!("unsupported authentication algorithm '{other:?}'"),
        };

        Ok(LoadedAuthenticationConfig {
            audience: self.audience,
            issuer: self.issuer,
            algorithm,
            decoding_key,
        })
    }
}

fn parse_authentication_algorithm(value: &str) -> anyhow::Result<Algorithm> {
    match value {
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

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_authentication_algorithm() -> String {
    "RS256".to_string()
}

fn build_signing_state() -> anyhow::Result<SigningState> {
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode generated ES256 private key")?;
    let public_key_pem = verifying_key
        .to_public_key_pem(LineEnding::LF)
        .context("failed to encode ES256 public key")?;
    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .context("failed to create JWT encoding key from ES256 private key")?;

    Ok(SigningState {
        encoding_key,
        signing_key,
        public_key_pem,
    })
}

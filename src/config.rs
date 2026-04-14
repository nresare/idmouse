use anyhow::Context;
use jsonwebtoken::{Algorithm, EncodingKey};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey, LineEnding};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    #[serde(default)]
    pub issuer: Option<String>,
    pub kubernetes: KubernetesConfig,
    pub surreal: SurrealConfig,
    pub signing: SigningConfig,
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct KubernetesConfig {
    #[serde(default)]
    pub api_url: Option<String>,
    #[serde(default)]
    pub reviewer_token_file: Option<String>,
    #[serde(default)]
    pub ca_cert_file: Option<String>,
    #[serde(default)]
    pub audiences: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SurrealConfig {
    pub access_method: String,
    pub namespace: String,
    pub database: String,
    #[serde(default = "default_token_ttl_seconds")]
    pub token_ttl_seconds: u64,
    #[serde(default)]
    pub audience: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigningConfig {
    #[serde(default = "default_signing_algorithm")]
    pub algorithm: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub private_key_pem: Option<String>,
    #[serde(default)]
    pub private_key_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub subject: String,
    #[serde(default)]
    pub kubernetes_usernames: Vec<String>,
    #[serde(default)]
    pub kubernetes_groups: Vec<String>,
    #[serde(default)]
    pub surreal_roles: Vec<String>,
    #[serde(default)]
    pub claims: Map<String, Value>,
    #[serde(default)]
    pub token_ttl_seconds: Option<u64>,
}

#[derive(Clone)]
pub struct LoadedConfig {
    pub bind_address: String,
    pub issuer: Option<String>,
    pub kubernetes: LoadedKubernetesConfig,
    pub surreal: SurrealConfig,
    pub signing: LoadedSigningConfig,
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone)]
pub struct LoadedKubernetesConfig {
    pub api_url: String,
    pub reviewer_token_file: String,
    pub ca_cert_file: String,
    pub audiences: Vec<String>,
}

#[derive(Clone)]
pub struct LoadedSigningConfig {
    pub algorithm: Algorithm,
    pub key_id: Option<String>,
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
        if self.users.is_empty() {
            anyhow::bail!("at least one [[users]] entry is required");
        }

        let mut subjects = HashMap::new();
        for user in &self.users {
            if user.subject.is_empty() {
                anyhow::bail!("user subjects must not be empty");
            }
            if subjects.insert(user.subject.clone(), ()).is_some() {
                anyhow::bail!("duplicate user subject '{}'", user.subject);
            }
            for role in &user.surreal_roles {
                if !matches!(role.as_str(), "Viewer" | "Editor" | "Owner") {
                    anyhow::bail!(
                        "user '{}' has unsupported surreal role '{}'; expected Viewer, Editor or Owner",
                        user.subject,
                        role
                    );
                }
            }
        }

        if self.surreal.access_method.is_empty() {
            anyhow::bail!("surreal.access_method must not be empty");
        }
        if self.surreal.namespace.is_empty() {
            anyhow::bail!("surreal.namespace must not be empty");
        }
        if self.surreal.database.is_empty() {
            anyhow::bail!("surreal.database must not be empty");
        }

        Ok(LoadedConfig {
            bind_address: self.bind_address,
            issuer: self.issuer,
            kubernetes: self.kubernetes.validate()?,
            surreal: self.surreal,
            signing: self.signing.validate()?,
            users: self.users,
        })
    }
}

impl KubernetesConfig {
    fn validate(self) -> anyhow::Result<LoadedKubernetesConfig> {
        let api_url = match self.api_url {
            Some(api_url) => api_url,
            None => kube_api_url_from_env()?,
        };

        Ok(LoadedKubernetesConfig {
            api_url,
            reviewer_token_file: self.reviewer_token_file.unwrap_or_else(|| {
                "/var/run/secrets/kubernetes.io/serviceaccount/token".to_string()
            }),
            ca_cert_file: self.ca_cert_file.unwrap_or_else(|| {
                "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt".to_string()
            }),
            audiences: self.audiences,
        })
    }
}

impl SigningConfig {
    fn validate(self) -> anyhow::Result<LoadedSigningConfig> {
        let algorithm = parse_algorithm(&self.algorithm)?;
        let private_key_pem = load_private_key(&self)?;
        let signing_key = SigningKey::from_pkcs8_pem(&private_key_pem)
            .context("failed to parse ES256 private key")?;
        let verifying_key = VerifyingKey::from(&signing_key);
        let public_key_pem = verifying_key
            .to_public_key_pem(LineEnding::LF)
            .context("failed to encode ES256 public key")?;
        let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
            .context("failed to create JWT encoding key from ES256 private key")?;

        Ok(LoadedSigningConfig {
            algorithm,
            key_id: self.key_id,
            encoding_key,
            signing_key,
            public_key_pem,
        })
    }
}

fn load_private_key(config: &SigningConfig) -> anyhow::Result<String> {
    match (&config.private_key_pem, &config.private_key_file) {
        (Some(pem), None) => Ok(pem.clone()),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| format!("Could not read private key file '{path}'")),
        (Some(_), Some(_)) => anyhow::bail!(
            "configure only one of signing.private_key_pem or signing.private_key_file"
        ),
        (None, None) => {
            anyhow::bail!("one of signing.private_key_pem or signing.private_key_file is required")
        }
    }
}

fn parse_algorithm(value: &str) -> anyhow::Result<Algorithm> {
    match value {
        "ES256" => Ok(Algorithm::ES256),
        other => anyhow::bail!("unsupported signing algorithm '{other}'; only ES256 is supported"),
    }
}

fn kube_api_url_from_env() -> anyhow::Result<String> {
    let host = std::env::var("KUBERNETES_SERVICE_HOST")
        .context("KUBERNETES_SERVICE_HOST is not set and kubernetes.api_url was not configured")?;
    let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
        .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
        .unwrap_or_else(|_| "443".to_string());
    Ok(format!("https://{host}:{port}"))
}

fn default_bind_address() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_token_ttl_seconds() -> u64 {
    3600
}

fn default_signing_algorithm() -> String {
    "ES256".to_string()
}

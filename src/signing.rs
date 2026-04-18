use crate::config::{Config, SigningKeyStorage};
use crate::jwt::{jwk_for_signing_key, Jwk};
use crate::signing_kubernetes_secret::KubernetesSecretTokenBuilder;
use crate::{jwt, kubernetes};
use anyhow::{Context, Result};
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::rand_core::OsRng;
use reqwest::blocking::Client;
use serde_json::{Map, Value};
use std::sync::Arc;
use tracing::info;

pub const TOKEN_TTL_SECONDS: u64 = 600;

pub trait TokenBuilder: Send + Sync {
    fn build(&self, claims: &Map<String, Value>) -> Result<String>;
    fn jwks(&self) -> Result<Vec<Jwk>>;
}

#[derive(Clone)]
pub(crate) struct InMemoryTokenBuilder {
    signing_key: SigningKey,
}

impl InMemoryTokenBuilder {
    pub fn new() -> Self {
        Self {
            signing_key: SigningKey::random(&mut OsRng),
        }
    }
}

pub fn build_token_builder(config: &Config) -> Result<Arc<dyn TokenBuilder>> {
    let builder: Arc<dyn TokenBuilder> = match config.signing_key_storage {
        SigningKeyStorage::InMemory => {
            info!("using in-memory signing key storage");
            Arc::new(InMemoryTokenBuilder::new())
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
            Arc::new(KubernetesSecretTokenBuilder { client, namespace })
        }
    };

    Ok(builder)
}

impl TokenBuilder for InMemoryTokenBuilder {
    fn build(&self, claims: &Map<String, Value>) -> Result<String> {
        jwt::build_token(&self.signing_key, claims)
    }

    fn jwks(&self) -> Result<Vec<Jwk>> {
        Ok(vec![jwk_for_signing_key(&self.signing_key)])
    }
}

#[cfg(test)]
mod tests {
    use super::{InMemoryTokenBuilder, TokenBuilder};
    use crate::jwt::{build_token, jwk_for_signing_key, kid_for_signing_key};
    use crate::signing::TOKEN_TTL_SECONDS;
    use anyhow::Result;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;
    use serde_json::{json, Map, Value};

    #[test]
    fn in_memory_builder_builds_es256_token_with_matching_kid() -> Result<()> {
        let signing_key = SigningKey::random(&mut OsRng);
        let builder = InMemoryTokenBuilder {
            signing_key: signing_key.clone(),
        };
        let claims = sample_claims();

        let token = builder.build(&claims)?;
        let header = decode_header(&token)?;
        let jwk = builder.jwks()?.pop().unwrap();

        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some(jwk.kid.as_str()));
        assert_eq!(jwk.kid, kid_for_signing_key(&signing_key));
        Ok(())
    }

    #[test]
    fn in_memory_builder_emits_jwks_that_validates_issued_tokens() -> Result<()> {
        let builder = InMemoryTokenBuilder {
            signing_key: SigningKey::random(&mut OsRng),
        };
        let claims = sample_claims();
        let token = builder.build(&claims)?;
        let jwk = builder.jwks()?.pop().unwrap();

        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let decoded = decode::<Value>(
            &token,
            &DecodingKey::from_ec_components(&jwk.x, &jwk.y)?,
            &validation,
        )?;

        assert_eq!(decoded.claims["sub"], json!("idelephant"));
        assert_eq!(decoded.claims["iss"], json!("http://idmouse.idmouse.svc"));
        assert_eq!(
            decoded.claims["exp"],
            json!(4_102_444_800_u64 + TOKEN_TTL_SECONDS)
        );
        Ok(())
    }

    #[test]
    fn jwks_is_derived_from_signing_key_coordinates() {
        let signing_key = SigningKey::random(&mut OsRng);
        let expected = jwk_for_signing_key(&signing_key);

        assert_eq!(expected.alg, "ES256");
        assert_eq!(expected.kty, "EC");
        assert_eq!(expected.crv, "P-256");
        assert_eq!(expected.use_, "sig");
        assert!(!expected.kid.is_empty());
        assert!(!expected.x.is_empty());
        assert!(!expected.y.is_empty());
    }

    #[test]
    fn build_token_preserves_all_supplied_claims() -> Result<()> {
        let signing_key = SigningKey::random(&mut OsRng);
        let claims = sample_claims();

        let token = build_token(&signing_key, &claims)?;
        let jwk = jwk_for_signing_key(&signing_key);

        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let decoded = decode::<Value>(
            &token,
            &DecodingKey::from_ec_components(&jwk.x, &jwk.y)?,
            &validation,
        )?;

        let decoded_claims = decoded.claims.as_object().unwrap();
        assert_eq!(decoded_claims.get("ns"), Some(&json!("default")));
        assert_eq!(decoded_claims.get("db"), Some(&json!("idelephant")));
        assert_eq!(decoded_claims.get("ac"), Some(&json!("token_name")));
        Ok(())
    }

    fn sample_claims() -> Map<String, Value> {
        Map::from_iter([
            ("iss".to_string(), json!("http://idmouse.idmouse.svc")),
            ("sub".to_string(), json!("idelephant")),
            ("ns".to_string(), json!("default")),
            ("db".to_string(), json!("idelephant")),
            ("ac".to_string(), json!("token_name")),
            ("iat".to_string(), json!(4_102_444_800_u64)),
            ("nbf".to_string(), json!(4_102_444_800_u64)),
            (
                "exp".to_string(),
                json!(4_102_444_800_u64 + TOKEN_TTL_SECONDS),
            ),
        ])
    }
}

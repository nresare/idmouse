use crate::auth;
use crate::config::{AuthenticationConfig, Config, MappingConfig};
use crate::error::AppError;
use crate::signing::{build_signing_backend, SigningBackend};
use jsonwebtoken::{decode, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct AppState {
    pub subject_validator: Arc<SubjectValidator>,
    pub mapping_resolver: Arc<MappingResolver>,
    pub token_signer: Arc<dyn SigningBackend>,
}

#[derive(Clone)]
pub struct SubjectValidator {
    authentication: AuthenticationConfig,
}

#[derive(Clone)]
pub struct MappingResolver {
    origin: String,
    mappings: Arc<Vec<MappingConfig>>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
    pub kid: String,
    pub x: String,
    pub y: String,
}

#[derive(Debug, Deserialize)]
struct SourceClaims {
    sub: String,
}

pub fn build_app_state(config: Config) -> anyhow::Result<AppState> {
    Ok(AppState {
        subject_validator: Arc::new(SubjectValidator::new(config.authentication.clone())),
        mapping_resolver: Arc::new(MappingResolver::new(
            config.origin.clone(),
            config.mappings.clone(),
        )),
        token_signer: build_signing_backend(&config)?,
    })
}

impl SubjectValidator {
    pub fn new(authentication: AuthenticationConfig) -> Self {
        Self { authentication }
    }

    pub fn validate(&self, bearer_token: &str) -> Result<String, AppError> {
        let algorithm = auth::algorithm(&self.authentication)?;
        debug!(
            issuer = %self.authentication.issuer,
            audience = %self.authentication.audience,
            algorithm = ?algorithm,
            "preparing source token validation"
        );
        let mut validation = Validation::new(algorithm);
        validation.set_audience(&[&self.authentication.audience]);
        validation.set_issuer(&[&self.authentication.issuer]);
        debug!("resolving decoding key for source token validation");
        let decoding_key = auth::resolving_decoding_key(&self.authentication, bearer_token)
            .map_err(AppError::from)?;
        debug!("resolved decoding key for source token validation");

        debug!("validating source token signature and claims");
        let decoded = decode::<SourceClaims>(bearer_token, &decoding_key, &validation)
            .map_err(|e| AppError::Unauthorized(format!("failed to validate source token: {e}")))?;
        debug!(subject = %decoded.claims.sub, "source token validation succeeded");

        Ok(decoded.claims.sub)
    }
}

impl MappingResolver {
    pub fn new(origin: String, mappings: Vec<MappingConfig>) -> Self {
        Self {
            origin,
            mappings: Arc::new(mappings),
        }
    }

    pub fn resolve(
        &self,
        mapping_name: &str,
        subject: &str,
    ) -> Result<Map<String, Value>, AppError> {
        let mapping = self
            .mappings
            .iter()
            .find(|mapping| mapping.name == mapping_name)
            .ok_or_else(|| AppError::NotFound(format!("unknown mapping '{mapping_name}'")))?;

        if !mapping
            .allowed_subjects
            .iter()
            .any(|allowed_subject| allowed_subject == subject)
        {
            return Err(AppError::Unauthorized(format!(
                "subject '{subject}' is not allowed to use mapping '{mapping_name}'"
            )));
        }

        let mut claims = mapping.additional_claims.clone();
        claims.insert("iss".to_string(), Value::String(self.origin.clone()));
        Ok(claims)
    }
}

impl AppState {
    pub fn jwks(&self) -> Result<JwksResponse, AppError> {
        Ok(JwksResponse {
            keys: self.token_signer.jwks().map_err(AppError::from)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{build_app_state, AppState};
    use crate::config::Config;
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use p256::pkcs8::EncodePublicKey;
    use serde::Serialize;
    use serde_json::{json, Map, Value};

    const SOURCE_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhTPJsY5BW6Omc
OftqnA1qKDVmifo0rOOws5g0/KBW7mmcQcoUuc0h0W668RXvG+Sm9XfCXp/jSkLN
ST3gQaIwj4lnzMyaoTFjxBWWaQuNhbaxlm1nL2j9U9eaCxw0iUex0KDfbNUfjVHu
KQwHkjHaUJ0ufQ/0xRScLtiCMLlcWjfbEFjoYhi69N1vekjboNL/ORAcbWAbsKGC
Az0b3xM6L4d5pyO7enyBJWw8z/lGkVNJNQi1r3Zgs/Wf9AflzacypjX2lGbPkWcg
kkyFmlHhk1MtzjlQoirIIt0N1PiRRD9HJJHuG4/ebPOJ7GndWapnKp8rngoZw7FH
j11eMX+JAgMBAAECggEAb5U2c2wULpcILDGjTTeghTUIzZIEc1Y1JmysM4Hyv1sw
vwzuUrl62Qbqundwj43W/sGP4JoQwfcjgpyFoq2e8EIGoXwS0XqIBYs1zdqUuDDD
PMztvi8C5oRBwa9C9toOwgg7xKwYGZpaO4Pky1MikadfUYjrACUjgf7JiCEtjIjM
KsmqJnzeIjHxtFyL/X2VNhmUWNQKPHYWe3zvBieshQPy7LLmYzzJGv7c9nyDJnPx
mM7Tm4UTkjW/KSoED0kbfXmcJRJRNWo9P+tZ1ABJAx0V0cipbI+NDXqMhPGfPfTi
08rJDae96+yPSu1c+cpFEFM7z2OMR403RouyVnMQoQKBgQD21y7eZmGqGrQ8O6wS
UWM3+Ox6xTx+NsVBzNK8ypDqxWeVB7l38Taomm3FTHeE80lcd728MAmd66tcGGdb
5SO5kgdvboLt9ZKvVBTMJbHVfXJHailZx2Qa5W8iigXfMIIQx3Xf0T5qauNb9mQj
w3Fyf/ANPA4AZoNDkU579SwHfQKBgQDpqSYSwm5vzPjHY62m+npIk0Be3nOxkuQQ
HUW+vlDFb5ZupW7CQGOQEuKvPcD6MZAddYvVbIObWnmkkHPhg6jZdp7bfXbd2yaf
HGHJwvAYzCC5Hb4eQrVJZ/M8UzUcEBqXC4YmOTAnVMIV9qcEwVc7DasSIMiHLPAl
oCVlE5vN/QKBgDiju69wkqxzoDPKBXvWjQvE5I5vP6g+bRjiJOEJIiOc1F3P/fDV
upMJjHKfTzWElarQFwtdgndoIlPpjZ36gC4OogIhu41asiPlCTim1Z2FQXm9lGtz
YzcAunWUcjB6cv3iptuKqeXFTRJHAUdri1aYoL6IrzXMUAZrCzVKVqYJAoGBALaA
e1BjtMZ2Hkn+PQAS27gb60cuEMc9qAw+EN+u3n+XbLP3Ws82Y42AcrXVUgkY9StN
SG7mVtTcke5LNXeK0jMoR2PAVztplHzqOibQr59usJBl/ry79cTkAEO56d2FZn9b
bOgl+sp9lSp6gHFiYbOqNVfvazDJlLiOoSaVbjgxAoGATUH1geYvMl8W93MmA9vf
bzyzl4KklDegSMtja84vVDt5nCYPO32q3VDbihuOAHKpEK+GWuGLRlNp0t8e1ih/
KMueZKFHEwc6u9xKIEY3csS4Pbom5m0IU89tiZ22SzvWvGoMuwtJbFiGdMWFbyG+
5XvOGTJeQmnvXyNmqhP9WSY=
-----END PRIVATE KEY-----"#;

    const SOURCE_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4UzybGOQVujpnDn7apwN
aig1Zon6NKzjsLOYNPygVu5pnEHKFLnNIdFuuvEV7xvkpvV3wl6f40pCzUk94EGi
MI+JZ8zMmqExY8QVlmkLjYW2sZZtZy9o/VPXmgscNIlHsdCg32zVH41R7ikMB5Ix
2lCdLn0P9MUUnC7YgjC5XFo32xBY6GIYuvTdb3pI26DS/zkQHG1gG7ChggM9G98T
Oi+Heacju3p8gSVsPM/5RpFTSTUIta92YLP1n/QH5c2nMqY19pRmz5FnIJJMhZpR
4ZNTLc45UKIqyCLdDdT4kUQ/RySR7huP3mzziexp3VmqZyqfK54KGcOxR49dXjF/
iQIDAQAB
-----END PUBLIC KEY-----"#;

    #[derive(Serialize)]
    struct SourceTokenClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        nbf: u64,
        iat: u64,
    }

    fn test_state() -> AppState {
        let config_text = format!(
            r#"
bind_address = "127.0.0.1:8080"
origin = "http://idmouse.idmouse.svc"

[authentication]
audience = "idmouse"
issuer = "https://kubernetes.default.svc"
validation_key = """
{SOURCE_PUBLIC_KEY}
"""

[[mapping]]
name = "idelephant"
allowed_subjects = ["system:serviceaccount:idelephant:idelephant"]
additional_claims = {{ ns = "default", db = "idelephant", sub = "idelephant", ac = "token_name", id = "idelephant" }}

"#
        );
        let config: Config = toml::from_str(&config_text).unwrap();
        config.validate().unwrap();
        build_app_state(config).unwrap()
    }

    fn public_key_pem(state: &AppState) -> String {
        let jwk = state
            .token_signer
            .jwks()
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        let key = jsonwebtoken::DecodingKey::from_ec_components(&jwk.x, &jwk.y).unwrap();
        let pem = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.as_bytes()).unwrap();
        pem.to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap()
    }

    fn finalize_claims(mut claims: Map<String, Value>) -> Map<String, Value> {
        let issued_at = 4_102_444_800_u64;
        claims.insert("iat".to_string(), Value::from(issued_at));
        claims.insert("nbf".to_string(), Value::from(issued_at));
        claims.insert(
            "exp".to_string(),
            Value::from(issued_at + crate::signing::TOKEN_TTL_SECONDS),
        );
        claims
    }

    #[test]
    fn issues_mapping_claims() {
        let state = test_state();
        let claims = state
            .mapping_resolver
            .resolve("idelephant", "system:serviceaccount:idelephant:idelephant")
            .unwrap();
        let access_token = state.token_signer.sign(&finalize_claims(claims)).unwrap();

        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["http://idmouse.idmouse.svc"]);

        let decoded = decode::<serde_json::Value>(
            &access_token,
            &DecodingKey::from_ec_pem(public_key_pem(&state).as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims["ns"], json!("default"));
        assert_eq!(decoded.claims["db"], json!("idelephant"));
        assert_eq!(decoded.claims["sub"], json!("idelephant"));
        assert_eq!(decoded.claims["ac"], json!("token_name"));
        assert_eq!(decoded.claims["id"], json!("idelephant"));
    }

    #[test]
    fn authenticates_source_token_subject() {
        let state = test_state();
        let now = 4_102_444_800;
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::RS256),
            &SourceTokenClaims {
                sub: "system:serviceaccount:idelephant:idelephant",
                iss: "https://kubernetes.default.svc",
                aud: "idmouse",
                exp: now + 60,
                nbf: now - 60,
                iat: now - 60,
            },
            &EncodingKey::from_rsa_pem(SOURCE_PRIVATE_KEY.as_bytes()).unwrap(),
        )
        .unwrap();

        let subject = state.subject_validator.validate(&token).unwrap();
        let claims = state
            .mapping_resolver
            .resolve("idelephant", &subject)
            .unwrap();
        let access_token = state.token_signer.sign(&finalize_claims(claims)).unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["http://idmouse.idmouse.svc"]);
        let decoded = decode::<serde_json::Value>(
            &access_token,
            &DecodingKey::from_ec_pem(public_key_pem(&state).as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.claims["sub"], json!("idelephant"));
    }

    #[test]
    fn publishes_ec_jwks() {
        let state = test_state();
        let jwks = state.token_signer.jwks().unwrap();
        assert_eq!(jwks.len(), 1);
        assert_eq!(jwks[0].alg, "ES256");
        assert_eq!(jwks[0].kid, "idmouse");
    }
}

use crate::config::{Config, MappingConfig};
use crate::error::AppError;
use anyhow::Context;
use axum::http::{header, HeaderMap};
use base64::Engine;
use jsonwebtoken::{decode, encode, EncodingKey, Header, Validation};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::elliptic_curve::rand_core::OsRng;
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const TOKEN_TTL_SECONDS: u64 = 600;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing: Arc<SigningState>,
}

#[derive(Clone)]
pub struct SigningState {
    pub encoding_key: EncodingKey,
    pub signing_key: SigningKey,
    pub public_key_pem: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub mapping: String,
    pub source_subject: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Debug, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
struct IssuedClaims {
    exp: u64,
    iat: u64,
    nbf: u64,
    iss: String,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

pub fn build_signing_state() -> anyhow::Result<SigningState> {
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

pub fn issue_token_from_headers(
    state: &AppState,
    mapping_name: &str,
    headers: &HeaderMap,
) -> Result<TokenResponse, AppError> {
    let bearer_token = extract_bearer_token(headers)?;
    let source_subject = authenticate_subject(state, &bearer_token)?;
    let mapping = state
        .config
        .mapping(mapping_name)
        .ok_or_else(|| AppError::NotFound(format!("unknown mapping '{mapping_name}'")))?;

    if !mapping
        .allowed_subjects
        .iter()
        .any(|subject| subject == &source_subject)
    {
        return Err(AppError::Unauthorized(format!(
            "subject '{source_subject}' is not allowed to use mapping '{mapping_name}'"
        )));
    }

    issue_token_for_mapping(state, mapping, source_subject)
}

pub fn issue_token_for_mapping(
    state: &AppState,
    mapping: &MappingConfig,
    source_subject: String,
) -> Result<TokenResponse, AppError> {
    let issued_at = now()?;
    let expires_at = issued_at
        .checked_add(TOKEN_TTL_SECONDS)
        .ok_or_else(|| AppError::Internal("token expiration overflow".to_string()))?;

    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid());

    let claims = IssuedClaims {
        exp: expires_at,
        iat: issued_at,
        nbf: issued_at,
        iss: state.config.origin.clone(),
        extra: mapping.additional_claims.clone(),
    };

    let access_token = encode(&header, &claims, &state.signing.encoding_key)
        .map_err(|e| AppError::Internal(format!("failed to encode token: {e}")))?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: TOKEN_TTL_SECONDS,
        mapping: mapping.name.clone(),
        source_subject,
    })
}

pub fn jwks(state: &AppState) -> JwksResponse {
    let verifying_key = VerifyingKey::from(&state.signing.signing_key);
    JwksResponse {
        keys: vec![build_jwk(&verifying_key, &kid())],
    }
}

fn authenticate_subject(state: &AppState, bearer_token: &str) -> Result<String, AppError> {
    let mut validation = Validation::new(state.config.authentication.algorithm()?);
    validation.set_audience(&[&state.config.authentication.audience]);
    validation.set_issuer(&[&state.config.authentication.issuer]);

    let decoded = decode::<SourceClaims>(
        bearer_token,
        &state.config.authentication.decoding_key()?,
        &validation,
    )
    .map_err(|e| AppError::Unauthorized(format!("failed to validate source token: {e}")))?;

    Ok(decoded.claims.sub)
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| AppError::Unauthorized("missing Authorization header".to_string()))?;
    let value = value
        .to_str()
        .map_err(|_| AppError::Unauthorized("invalid Authorization header".to_string()))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::Unauthorized("expected a Bearer token".to_string()))?;
    if token.is_empty() {
        return Err(AppError::Unauthorized("empty bearer token".to_string()));
    }
    Ok(token.to_string())
}

fn now() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| AppError::Internal(format!("system time error: {e}")))
}

fn kid() -> String {
    "idmouse".to_string()
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

#[cfg(test)]
mod tests {
    use super::{
        build_signing_state, issue_token_for_mapping, issue_token_from_headers, jwks, AppState,
    };
    use crate::config::Config;
    use axum::http::{header, HeaderMap, HeaderValue};
    use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
    use serde::Serialize;
    use serde_json::json;
    use std::sync::Arc;

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

        AppState {
            config: Arc::new(config),
            signing: Arc::new(build_signing_state().unwrap()),
        }
    }

    #[test]
    fn issues_mapping_claims() {
        let state = test_state();
        let mapping = state.config.mapping("idelephant").unwrap();
        let response = issue_token_for_mapping(
            &state,
            mapping,
            "system:serviceaccount:idelephant:idelephant".to_string(),
        )
        .unwrap();

        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["http://idmouse.idmouse.svc"]);

        let decoded = decode::<serde_json::Value>(
            &response.access_token,
            &DecodingKey::from_ec_pem(state.signing.public_key_pem.as_bytes()).unwrap(),
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

        let mut headers = HeaderMap::new();
        let header_value = HeaderValue::from_str(&format!("Bearer {token}")).unwrap();
        headers.insert(header::AUTHORIZATION, header_value);

        let response = issue_token_from_headers(&state, "idelephant", &headers).unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::ES256);
        validation.set_issuer(&["http://idmouse.idmouse.svc"]);
        let decoded = decode::<serde_json::Value>(
            &response.access_token,
            &DecodingKey::from_ec_pem(state.signing.public_key_pem.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();
        assert_eq!(decoded.claims["sub"], json!("idelephant"));
    }

    #[test]
    fn publishes_ec_jwks() {
        let state = test_state();
        let jwks = jwks(&state);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].alg, "ES256");
        assert_eq!(jwks.keys[0].kid, "idmouse");
    }
}

use crate::config::{LoadedConfig, UserConfig};
use crate::error::AppError;
use axum::http::{header, HeaderMap};
use base64::Engine;
use jsonwebtoken::{encode, Header};
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<LoadedConfig>,
    pub token_reviewer: Arc<KubernetesTokenReviewer>,
}

#[derive(Clone)]
pub struct KubernetesTokenReviewer {
    api_url: String,
    reviewer_token: String,
    client: reqwest::Client,
    audiences: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReviewedIdentity {
    pub username: String,
    pub uid: Option<String>,
    pub groups: Vec<String>,
    pub extra: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub issued_subject: String,
    pub kubernetes_username: String,
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

#[derive(Debug, Serialize)]
struct SurrealClaims {
    exp: u64,
    iat: u64,
    nbf: u64,
    ac: String,
    ns: String,
    db: String,
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    rl: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct TokenReviewRequest<'a> {
    #[serde(rename = "apiVersion")]
    api_version: &'static str,
    kind: &'static str,
    spec: TokenReviewSpec<'a>,
}

#[derive(Debug, Serialize)]
struct TokenReviewSpec<'a> {
    token: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    audiences: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TokenReviewResponse {
    status: TokenReviewStatus,
}

#[derive(Debug, Deserialize)]
struct TokenReviewStatus {
    authenticated: Option<bool>,
    user: Option<TokenReviewUser>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenReviewUser {
    username: String,
    #[serde(default)]
    uid: Option<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    extra: BTreeMap<String, Vec<String>>,
}

impl KubernetesTokenReviewer {
    pub fn from_config(config: &LoadedConfig) -> anyhow::Result<Self> {
        let ca_bytes = std::fs::read(&config.kubernetes.ca_cert_file)?;
        let reviewer_token = std::fs::read_to_string(&config.kubernetes.reviewer_token_file)?
            .trim()
            .to_string();
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(reqwest::Certificate::from_pem(&ca_bytes)?)
            .build()?;

        Ok(Self {
            api_url: config.kubernetes.api_url.clone(),
            reviewer_token,
            client,
            audiences: config.kubernetes.audiences.clone(),
        })
    }

    pub async fn review(&self, bearer_token: &str) -> Result<ReviewedIdentity, AppError> {
        let request = TokenReviewRequest {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: TokenReviewSpec {
                token: bearer_token,
                audiences: self.audiences.clone(),
            },
        };

        let response = self
            .client
            .post(format!(
                "{}/apis/authentication.k8s.io/v1/tokenreviews",
                self.api_url
            ))
            .bearer_auth(&self.reviewer_token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                AppError::Internal(format!("failed to call Kubernetes TokenReview API: {e}"))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<response body unavailable>".to_string());
            return Err(AppError::Internal(format!(
                "Kubernetes TokenReview API returned {status}: {body}"
            )));
        }

        let review: TokenReviewResponse = response.json().await.map_err(|e| {
            AppError::Internal(format!("failed to decode TokenReview response: {e}"))
        })?;

        if review.status.authenticated != Some(true) {
            let detail = review
                .status
                .error
                .unwrap_or_else(|| "token was not authenticated by Kubernetes".to_string());
            return Err(AppError::Unauthorized(detail));
        }

        let user = review.status.user.ok_or_else(|| {
            AppError::Internal(
                "Kubernetes authenticated the token but returned no user".to_string(),
            )
        })?;

        Ok(ReviewedIdentity {
            username: user.username,
            uid: user.uid,
            groups: user.groups,
            extra: user.extra,
        })
    }
}

pub async fn issue_token_from_headers(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<TokenResponse, AppError> {
    let bearer_token = extract_bearer_token(headers)?;
    let identity = state.token_reviewer.review(&bearer_token).await?;
    issue_token_for_identity(state, identity)
}

pub fn issue_token_for_identity(
    state: &AppState,
    identity: ReviewedIdentity,
) -> Result<TokenResponse, AppError> {
    let user = match_user(&state.config.users, &identity)?;
    let issued_at = now()?;
    let ttl = user
        .token_ttl_seconds
        .unwrap_or(state.config.surreal.token_ttl_seconds);
    let expires_at = issued_at
        .checked_add(ttl)
        .ok_or_else(|| AppError::Internal("token expiration overflow".to_string()))?;

    let mut header = Header::new(state.config.signing.algorithm);
    header.kid = Some(kid(state));

    let claims = SurrealClaims {
        exp: expires_at,
        iat: issued_at,
        nbf: issued_at,
        ac: state.config.surreal.access_method.clone(),
        ns: state.config.surreal.namespace.clone(),
        db: state.config.surreal.database.clone(),
        sub: user.subject.clone(),
        id: Some(user.subject.clone()),
        rl: user.surreal_roles.clone(),
        iss: state.config.issuer.clone(),
        aud: state.config.surreal.audience.clone(),
        extra: extra_claims(user, &identity),
    };

    let access_token = encode(&header, &claims, &state.config.signing.encoding_key)
        .map_err(|e| AppError::Internal(format!("failed to encode surreal token: {e}")))?;

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ttl,
        issued_subject: user.subject.clone(),
        kubernetes_username: identity.username,
    })
}

pub fn jwks(state: &AppState) -> JwksResponse {
    let verifying_key = VerifyingKey::from(&state.config.signing.signing_key);
    JwksResponse {
        keys: vec![build_jwk(&verifying_key, &kid(state))],
    }
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

fn match_user<'a>(
    users: &'a [UserConfig],
    identity: &ReviewedIdentity,
) -> Result<&'a UserConfig, AppError> {
    let matches = users
        .iter()
        .filter(|user| user_matches(user, identity))
        .collect::<Vec<_>>();

    match matches.as_slice() {
        [] => Err(AppError::Unauthorized(format!(
            "no configured user matched Kubernetes identity '{}'",
            identity.username
        ))),
        [user] => Ok(*user),
        _ => Err(AppError::Internal(format!(
            "multiple configured users matched Kubernetes identity '{}'",
            identity.username
        ))),
    }
}

fn user_matches(user: &UserConfig, identity: &ReviewedIdentity) -> bool {
    let username_matches = if !user.kubernetes_usernames.is_empty() {
        user.kubernetes_usernames
            .iter()
            .any(|candidate| candidate == &identity.username)
    } else if user.kubernetes_groups.is_empty() {
        user.subject == identity.username
    } else {
        true
    };

    let group_matches = if user.kubernetes_groups.is_empty() {
        true
    } else {
        identity.groups.iter().any(|group| {
            user.kubernetes_groups
                .iter()
                .any(|candidate| candidate == group)
        })
    };

    username_matches && group_matches
}

fn extra_claims(user: &UserConfig, identity: &ReviewedIdentity) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert(
        "kubernetes_username".to_string(),
        Value::String(identity.username.clone()),
    );
    if let Some(uid) = &identity.uid {
        claims.insert("kubernetes_uid".to_string(), Value::String(uid.clone()));
    }
    if !identity.groups.is_empty() {
        claims.insert(
            "kubernetes_groups".to_string(),
            Value::Array(identity.groups.iter().cloned().map(Value::String).collect()),
        );
    }
    if !identity.extra.is_empty() {
        let extra = identity
            .extra
            .iter()
            .map(|(key, values)| {
                (
                    key.clone(),
                    Value::Array(values.iter().cloned().map(Value::String).collect()),
                )
            })
            .collect();
        claims.insert("kubernetes_extra".to_string(), Value::Object(extra));
    }
    claims.extend(user.claims.clone());
    claims
}

fn now() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| AppError::Internal(format!("system time error: {e}")))
}

fn kid(state: &AppState) -> String {
    state
        .config
        .signing
        .key_id
        .clone()
        .unwrap_or_else(|| "idmouse".to_string())
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
    use super::{issue_token_for_identity, jwks, AppState, ReviewedIdentity};
    use crate::config::Config;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_state() -> AppState {
        let config: Config = toml::from_str(
            r#"
bind_address = "127.0.0.1:8080"
issuer = "https://idmouse.default.svc.cluster.local"

[kubernetes]
api_url = "https://kubernetes.default.svc"
reviewer_token_file = "/tmp/reviewer-token"
ca_cert_file = "/tmp/ca.crt"
audiences = ["idmouse"]

[surreal]
access_method = "idmouse"
namespace = "app"
database = "main"
token_ttl_seconds = 900
audience = "surrealdb"

[signing]
algorithm = "ES256"
key_id = "test-key"
private_key_pem = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN+6VmUXG/ef3u67r
ATInaYskFnH49T8PsjkoXN2yDeqhRANCAAQaTpxRpVzE+CCkLWI9uVtIcez7yDmX
iJSzcPn+34vupXwZBL8U/4mXcCbJbNaitEhq4SajOVtqk9WWsU7wJoWj
-----END PRIVATE KEY-----
"""

[[users]]
subject = "alice"
kubernetes_usernames = ["system:serviceaccount:team-a:alice"]
surreal_roles = ["Editor"]
claims = { email = "alice@example.com" }
"#,
        )
        .unwrap();

        AppState {
            config: Arc::new(config.validate().unwrap()),
            token_reviewer: Arc::new(super::KubernetesTokenReviewer {
                api_url: "https://kubernetes.default.svc".to_string(),
                reviewer_token: "unused".to_string(),
                client: reqwest::Client::new(),
                audiences: vec!["idmouse".to_string()],
            }),
        }
    }

    #[test]
    fn issues_surreal_claims_for_kubernetes_identity() {
        let state = test_state();
        let response = issue_token_for_identity(
            &state,
            ReviewedIdentity {
                username: "system:serviceaccount:team-a:alice".to_string(),
                uid: Some("uid-123".to_string()),
                groups: vec![
                    "system:serviceaccounts".to_string(),
                    "system:serviceaccounts:team-a".to_string(),
                ],
                extra: BTreeMap::new(),
            },
        )
        .unwrap();

        let mut validation = Validation::new(state.config.signing.algorithm);
        validation.set_audience(&["surrealdb"]);
        validation.set_issuer(&["https://idmouse.default.svc.cluster.local"]);

        let decoded = decode::<serde_json::Value>(
            &response.access_token,
            &DecodingKey::from_ec_pem(state.config.signing.public_key_pem.as_bytes()).unwrap(),
            &validation,
        )
        .unwrap();

        assert_eq!(decoded.claims["ac"], json!("idmouse"));
        assert_eq!(decoded.claims["ns"], json!("app"));
        assert_eq!(decoded.claims["db"], json!("main"));
        assert_eq!(decoded.claims["id"], json!("alice"));
        assert_eq!(decoded.claims["rl"], json!(["Editor"]));
        assert_eq!(
            decoded.claims["kubernetes_username"],
            json!("system:serviceaccount:team-a:alice")
        );
        assert_eq!(decoded.claims["email"], json!("alice@example.com"));
    }

    #[test]
    fn publishes_ec_jwks() {
        let state = test_state();
        let jwks = jwks(&state);
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].alg, "ES256");
        assert_eq!(jwks.keys[0].kid, "test-key");
    }
}

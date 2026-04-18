use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

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

pub(crate) fn kid_for_signing_key(signing_key: &SigningKey) -> String {
    let verifying_key = VerifyingKey::from(signing_key);
    let encoded = verifying_key.to_encoded_point(true);
    let digest = Sha256::digest(encoded.as_bytes());
    B64_URL_SAFE_NO_PAD.encode(&digest[..6])
}

pub(crate) fn build_token(
    signing_key: &SigningKey,
    claims: &Map<String, Value>,
) -> anyhow::Result<String> {
    let mut header = Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(kid_for_signing_key(signing_key));

    let private_key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode ES256 private key for token signing")?;
    let encoding_key = EncodingKey::from_ec_pem(private_key_pem.as_bytes())
        .context("failed to create JWT encoding key from ES256 private key")?;

    encode(&header, claims, &encoding_key)
        .map_err(|error| anyhow::anyhow!("failed to encode token: {error}"))
}

pub(crate) fn jwk_for_signing_key(signing_key: &SigningKey) -> Jwk {
    let verifying_key = VerifyingKey::from(signing_key);
    let encoded = verifying_key.to_encoded_point(false);
    let x = B64_URL_SAFE_NO_PAD.encode(
        encoded
            .x()
            .expect("uncompressed P-256 points always have x"),
    );
    let y = B64_URL_SAFE_NO_PAD.encode(
        encoded
            .y()
            .expect("uncompressed P-256 points always have y"),
    );

    Jwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        use_: "sig".to_string(),
        alg: "ES256".to_string(),
        kid: kid_for_signing_key(signing_key),
        x,
        y,
    }
}

#[cfg(test)]
mod tests {
    use super::{jwk_for_signing_key, kid_for_signing_key};
    use anyhow::Result;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL_SAFE_NO_PAD;
    use base64::Engine;
    use p256::ecdsa::{SigningKey, VerifyingKey};
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn kid_is_stable_for_same_signing_key() {
        let signing_key = SigningKey::random(&mut OsRng);

        assert_eq!(
            kid_for_signing_key(&signing_key),
            kid_for_signing_key(&signing_key)
        );
    }

    #[test]
    fn kid_differs_for_different_signing_keys() {
        let first = SigningKey::random(&mut OsRng);
        let second = SigningKey::random(&mut OsRng);

        assert_ne!(kid_for_signing_key(&first), kid_for_signing_key(&second));
    }

    #[test]
    fn kid_has_expected_short_encoded_length() {
        let signing_key = SigningKey::random(&mut OsRng);

        assert_eq!(kid_for_signing_key(&signing_key).len(), 8);
    }

    #[test]
    fn jwk_contains_expected_metadata_and_coordinates() -> Result<()> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);
        let encoded = verifying_key.to_encoded_point(false);
        let jwk = jwk_for_signing_key(&signing_key);

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.use_, "sig");
        assert_eq!(jwk.alg, "ES256");
        assert_eq!(jwk.kid, kid_for_signing_key(&signing_key));
        assert_eq!(jwk.x, B64_URL_SAFE_NO_PAD.encode(encoded.x().unwrap()));
        assert_eq!(jwk.y, B64_URL_SAFE_NO_PAD.encode(encoded.y().unwrap()));
        Ok(())
    }

    #[test]
    fn jwk_round_trips_into_jsonwebtoken_decoding_key() -> Result<()> {
        let signing_key = SigningKey::random(&mut OsRng);
        let jwk = jwk_for_signing_key(&signing_key);
        let decoding_key = jsonwebtoken::DecodingKey::from_ec_components(&jwk.x, &jwk.y)?;

        let expected = VerifyingKey::from(&signing_key).to_encoded_point(false);

        assert_eq!(decoding_key.as_bytes(), expected.as_bytes());
        Ok(())
    }
}

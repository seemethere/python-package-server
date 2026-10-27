//! OIDC Bearer JWT validation via issuer discovery and JWKS.
//!
//! Stack 1: validator + config only, no middleware wiring. The validator
//! fetches `/.well-known/openid-configuration` once at construction, then
//! the JWKS, failing fast at startup like S3/Policy. Tokens are validated
//! offline against the cached JWKS (RS256/RS384/RS512/ES256/ES384 only).

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

/// Total timeout for OIDC discovery and JWKS fetches (small JSON bodies).
const HTTP_TIMEOUT_SECS: u64 = 10;

/// Max JWKS cache age before a proactive refresh. Stale caches refresh on
/// the next validation; fresh caches with an unknown `kid` still force one
/// refresh to handle key rotation.
const JWKS_MAX_AGE_SECS: u64 = 300;

/// Clock-skew leeway for `exp`/`nbf` checks.
const LEEWAY_SECS: u64 = 60;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("oidc discovery failed: {0}")]
    Discovery(String),
    #[error("oidc discovery issuer mismatch: expected '{expected}', got '{actual}'")]
    IssuerMismatch { expected: String, actual: String },
    #[error("oidc JWKS fetch failed: {0}")]
    Jwks(String),
    #[error("oidc token header invalid: {0}")]
    Header(String),
    #[error("oidc token algorithm not allowed: {0}")]
    Algorithm(String),
    #[error("oidc token missing kid")]
    MissingKid,
    #[error("oidc signing key not found")]
    UnknownKid,
    #[error("oidc signing key invalid: {0}")]
    Key(String),
    #[error("oidc token invalid: {0}")]
    Validation(String),
    #[error("oidc principal missing (no preferred_username, email, or sub)")]
    MissingPrincipal,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize, Clone)]
struct Jwk {
    #[serde(default)]
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    crv: Option<String>,
}

/// Minimal claims for principal extraction. `iss`/`aud`/`exp`/`nbf` are
/// enforced by `jsonwebtoken` against the raw payload JSON, so they are
/// intentionally absent here; unknown claims are ignored.
#[derive(Debug, Deserialize)]
struct Claims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Clone)]
struct JwksCache {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

#[derive(Debug, Clone)]
pub struct OidcValidator {
    issuer: String,
    audience: String,
    jwks_uri: String,
    http: reqwest::Client,
    cache: Arc<tokio::sync::RwLock<JwksCache>>,
}

fn http_client() -> Result<reqwest::Client, OidcError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .build()
        .map_err(|e| OidcError::Discovery(e.to_string()))
}

async fn fetch_jwks(http: &reqwest::Client, uri: &str) -> Result<Jwks, OidcError> {
    let response = http
        .get(uri)
        .send()
        .await
        .map_err(|e| OidcError::Jwks(e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        return Err(OidcError::Jwks(format!("status {}", status.as_u16())));
    }
    response
        .json::<Jwks>()
        .await
        .map_err(|e| OidcError::Jwks(e.to_string()))
}

fn find_jwk<'a>(keys: &'a [Jwk], kid: &str) -> Option<&'a Jwk> {
    keys.iter().find(|k| k.kid.as_deref() == Some(kid))
}

fn decoding_key_for_jwk(jwk: &Jwk) -> Result<jsonwebtoken::DecodingKey, OidcError> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_deref()
                .ok_or_else(|| OidcError::Key("RSA JWK missing n".to_string()))?;
            let e = jwk
                .e
                .as_deref()
                .ok_or_else(|| OidcError::Key("RSA JWK missing e".to_string()))?;
            jsonwebtoken::DecodingKey::from_rsa_components(n, e)
                .map_err(|e| OidcError::Key(e.to_string()))
        }
        "EC" => {
            let crv = jwk.crv.as_deref().unwrap_or("");
            if crv != "P-256" && crv != "P-384" {
                return Err(OidcError::Key(format!("unsupported EC crv '{crv}'")));
            }
            let x = jwk
                .x
                .as_deref()
                .ok_or_else(|| OidcError::Key("EC JWK missing x".to_string()))?;
            let y = jwk
                .y
                .as_deref()
                .ok_or_else(|| OidcError::Key("EC JWK missing y".to_string()))?;
            jsonwebtoken::DecodingKey::from_ec_components(x, y)
                .map_err(|e| OidcError::Key(e.to_string()))
        }
        other => Err(OidcError::Key(format!("unsupported kty '{other}'"))),
    }
}

fn principal_from_claims(claims: &Claims) -> Result<String, OidcError> {
    for value in [
        claims.preferred_username.as_deref(),
        claims.email.as_deref(),
        claims.sub.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err(OidcError::MissingPrincipal)
}

impl OidcValidator {
    /// Discover the issuer and fetch JWKS once, failing fast at startup.
    pub async fn new(issuer: &str, audience: &str) -> Result<Self, OidcError> {
        let issuer = issuer.trim_end_matches('/');
        let http = http_client()?;
        let discovery_url = format!("{issuer}/.well-known/openid-configuration");
        let response = http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(OidcError::Discovery(format!("status {}", status.as_u16())));
        }
        let doc = response
            .json::<DiscoveryDoc>()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;
        if doc.issuer != issuer {
            return Err(OidcError::IssuerMismatch {
                expected: issuer.to_string(),
                actual: doc.issuer,
            });
        }
        let jwks = fetch_jwks(&http, &doc.jwks_uri).await?;
        Ok(Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            jwks_uri: doc.jwks_uri,
            http,
            cache: Arc::new(tokio::sync::RwLock::new(JwksCache {
                keys: jwks.keys,
                fetched_at: Instant::now(),
            })),
        })
    }

    /// Test-only constructor: inject JWKS JSON without network. The dummy
    /// `jwks_uri` fails fast (closed loopback port) if a refresh is ever
    /// attempted, keeping unit tests fully offline.
    #[doc(hidden)]
    pub fn new_with_jwks(issuer: &str, audience: &str, jwks_json: &str) -> Result<Self, OidcError> {
        let http = http_client()?;
        let jwks: Jwks =
            serde_json::from_str(jwks_json).map_err(|e| OidcError::Jwks(e.to_string()))?;
        Ok(Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            audience: audience.to_string(),
            jwks_uri: "http://127.0.0.1:9/jwks".to_string(),
            http,
            cache: Arc::new(tokio::sync::RwLock::new(JwksCache {
                keys: jwks.keys,
                fetched_at: Instant::now(),
            })),
        })
    }

    async fn refresh_jwks(&self) -> Result<(), OidcError> {
        let jwks = fetch_jwks(&self.http, &self.jwks_uri).await?;
        let mut cache = self.cache.write().await;
        *cache = JwksCache {
            keys: jwks.keys,
            fetched_at: Instant::now(),
        };
        Ok(())
    }

    /// Validate a Bearer JWT and return the principal
    /// (`preferred_username` > `email` > `sub`). Fails closed on every
    /// error; error messages never contain the token.
    pub async fn validate(&self, token: &str) -> Result<String, OidcError> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|e| OidcError::Header(e.to_string()))?;
        let allowed = matches!(
            header.alg,
            jsonwebtoken::Algorithm::RS256
                | jsonwebtoken::Algorithm::RS384
                | jsonwebtoken::Algorithm::RS512
                | jsonwebtoken::Algorithm::ES256
                | jsonwebtoken::Algorithm::ES384
        );
        if !allowed {
            return Err(OidcError::Algorithm(format!("{:?}", header.alg)));
        }
        let kid = header.kid.ok_or(OidcError::MissingKid)?;
        if kid.trim().is_empty() {
            return Err(OidcError::MissingKid);
        }

        // Proactive refresh when stale; fail closed if it errors, even when
        // the kid exists in the stale cache (spec: no stale-while-revalidate).
        let stale = {
            let cache = self.cache.read().await;
            cache.fetched_at.elapsed() > Duration::from_secs(JWKS_MAX_AGE_SECS)
        };
        let mut refreshed = false;
        if stale {
            self.refresh_jwks().await?;
            refreshed = true;
        }

        let jwk = {
            let cache = self.cache.read().await;
            find_jwk(&cache.keys, &kid).cloned()
        };
        let jwk = match jwk {
            Some(jwk) => jwk,
            None => {
                if refreshed {
                    return Err(OidcError::UnknownKid);
                }
                // Fresh cache with unknown kid: force one refresh for rotation.
                self.refresh_jwks().await?;
                let cache = self.cache.read().await;
                find_jwk(&cache.keys, &kid)
                    .cloned()
                    .ok_or(OidcError::UnknownKid)?
            }
        };
        let key = decoding_key_for_jwk(&jwk)?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = jsonwebtoken::decode::<Claims>(token, &key, &validation)
            .map_err(|e| OidcError::Validation(e.to_string()))?;
        principal_from_claims(&data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde::Serialize;

    // TEST ONLY: throwaway RSA-2048 keypair generated locally via
    // `openssl genrsa 2048` for offline unit tests. Never use in production.
    // The JWKS `n` below is the base64url modulus of this exact private key;
    // `e` is AQAB (65537).
    const TEST_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8qApOzwBt/nBp\nIQxpoKGN1f4/At9M1IThskb3XP78Kil+pfR+ux4SuDMYc1nE/CcHiN1eG85H55GD\nelT4t2DWomH7aLlFWUMGveMMAgOU+K7cQLDVSG6FiHZxqBB9LjnZXDFFItUew+L+\n/x9SqR5CN7Ps49FoonO3SYo7fh2vJe+YmybRoAdXz1tIraEj7TeqsfLRMyh0TsZy\nmAGOZbZNF2RYhOCEPX5mwihodxBOdNyCx4TEafSmVsPTyJK8pYqp6VbmXpg/gzA1\nxwVKakoYDSycgIA6lm0GL7y3zYFWoCI0z3I/jHpfnZV92UtqTnJz+uUDgkEwYpI4\nBIVcGfSXAgMBAAECggEAUcKX2QjAPGtJZ15hxUNO0Kv9yGwjv2XZAwFi3SBqB3n0\nSsV8fRH2GhHHXyDatlK7TXokyfzN/P6gYzU4ryO2Lb7pLO55YNMrB7hytkkHKWBP\nU/gbSwvdjjSSdHZsUvweKRPZ7IcIixFFBtMlTYsqqHMAoLkpD6pb8QLHjDn/fmB3\nUB7vMlvod21VdQFNJVeL+jN/cRMQnkh9H1Bcmi7rC2oGfkN6pFlgJ8XBZxOYYW5M\nXcc+ZSXyKgM4BFpIw4/XlWSlqXiNSzwgtFyo22d0vi4qkM/PwFcmSPet87w+e4br\nNFcl0Z0idtpHcEJcgpb94Uvkt3vWNvHBBHjlBo9lFQKBgQD/5fX4+xIH4TpoBsqD\nKddEKA6lpy42ld3qB8P5xcYrykHzsMCbNfFt1m0hsvdNBo/xGusWw+FVyrf6hLRO\ntW7WmJp7XMJlUAhrxUBkXJJ2t3XMVWQgWBd5P8RMIjQEg6VIaOUZMabm4Vd3Q+MP\nhKswvYdBiBJvAp49uzQ0SwTMVQKBgQC8uzy3dsKuoi0pyOPzEDYuC33OCj9V7muj\nfuIJrjpEArfb+Vd7LOJ7o+6tv9LltPU7Hlonj0dSKN/NsE/UOoxFDsu2tCMvI2a9\nh+z1hKstUdis12RnWKywZlDXoAWLxS5x/PZrc9sFWEIWJUmDrMAU2v+GVrv0WaKH\n0PL34XBpOwKBgQDyY2NrFH6OwjNtp8kZFn/WCk9db47hm3FZJUPnigNdJTb1Wh4G\npsDp9mrmubtv1WBw07uMk7wUZHGCNUMJLugvEtt5MHLePkHLu0p0Bg+hrcNB6jxu\nOqL5cYJBT0CQahYcEWe4RoS+OwJ7cO1ZnKP/BfdhBj/XsNYsyO74/XotBQKBgB5u\n8vOCqxIOBMpgIqHnU1VJdRfsfxoUQDc1Fq4I8kxVQ+Cs7HZoXn0hijNqY0+3RnQq\nCM+oQw/0l2JLtBO8/TGFmUP0+Fd5le+qI4PTyOad9BqrAP3JRs+LMC4VF8/aFAs9\nh178Z60M9lsr2BbrnG3AgsPe6KAWdCcCgquGJuJRAoGBAL98E8AxwRYhPdiWl2xP\nGTdDMQWtTyqtvh0l1UGxZOy2Xnu7144QO6VK51KBFKPeRnqkuviSZjjlJVydSC+3\njqW6LelF+8bZ4GLF3LixAqbXk7ujmWsebyRJMbLdtdo4MG2QBEsHmE7MJFtomsNp\nqLMq05g6ZbSslJQCNMoVJTXw\n-----END PRIVATE KEY-----\n";

    const TEST_N: &str = "vKgKTs8Abf5waSEMaaChjdX-PwLfTNSE4bJG91z-_CopfqX0frseErgzGHNZxPwnB4jdXhvOR-eRg3pU-Ldg1qJh-2i5RVlDBr3jDAIDlPiu3ECw1UhuhYh2cagQfS452VwxRSLVHsPi_v8fUqkeQjez7OPRaKJzt0mKO34dryXvmJsm0aAHV89bSK2hI-03qrHy0TModE7GcpgBjmW2TRdkWITghD1-ZsIoaHcQTnTcgseExGn0plbD08iSvKWKqelW5l6YP4MwNccFSmpKGA0snICAOpZtBi-8t82BVqAiNM9yP4x6X52VfdlLak5yc_rlA4JBMGKSOASFXBn0lw";

    const TEST_ISSUER: &str = "https://issuer.example.com";
    const TEST_AUDIENCE: &str = "test-audience";
    const TEST_KID: &str = "test-key";

    fn test_jwks_json() -> String {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": TEST_KID,
                "use": "sig",
                "alg": "RS256",
                "n": TEST_N,
                "e": "AQAB",
            }]
        })
        .to_string()
    }

    fn test_validator() -> OidcValidator {
        OidcValidator::new_with_jwks(TEST_ISSUER, TEST_AUDIENCE, &test_jwks_json()).unwrap()
    }

    #[derive(Debug, Serialize)]
    struct TestClaims {
        iss: String,
        aud: String,
        exp: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        sub: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        preferred_username: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn base_claims() -> TestClaims {
        TestClaims {
            iss: TEST_ISSUER.to_string(),
            aud: TEST_AUDIENCE.to_string(),
            exp: now_secs() + 3600,
            sub: Some("sub-123".to_string()),
            preferred_username: Some("alice".to_string()),
            email: Some("alice@example.com".to_string()),
        }
    }

    fn encode_rs256(claims: &TestClaims, kid: Option<&str>) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = kid.map(str::to_string);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    #[tokio::test]
    async fn valid_token_returns_principal() {
        let validator = test_validator();
        let token = encode_rs256(&base_claims(), Some(TEST_KID));
        assert_eq!(validator.validate(&token).await.unwrap(), "alice");
    }

    #[tokio::test]
    async fn preferred_username_wins_over_email_and_sub() {
        let validator = test_validator();
        let claims = TestClaims {
            preferred_username: Some("  alice  ".to_string()),
            email: Some("alice@example.com".to_string()),
            sub: Some("sub-123".to_string()),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert_eq!(validator.validate(&token).await.unwrap(), "alice");
    }

    #[tokio::test]
    async fn falls_back_to_email_then_sub() {
        let validator = test_validator();
        let claims = TestClaims {
            preferred_username: None,
            email: Some("fallback@example.com".to_string()),
            sub: Some("sub-123".to_string()),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert_eq!(
            validator.validate(&token).await.unwrap(),
            "fallback@example.com"
        );

        let claims = TestClaims {
            preferred_username: Some("   ".to_string()),
            email: None,
            sub: Some("sub-only".to_string()),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert_eq!(validator.validate(&token).await.unwrap(), "sub-only");
    }

    #[tokio::test]
    async fn rejects_missing_principal() {
        let validator = test_validator();
        let claims = TestClaims {
            preferred_username: Some("  ".to_string()),
            email: None,
            sub: Some("".to_string()),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert!(matches!(
            validator.validate(&token).await.unwrap_err(),
            OidcError::MissingPrincipal
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_audience() {
        let validator = test_validator();
        let claims = TestClaims {
            aud: "other-audience".to_string(),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert!(validator.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn rejects_wrong_issuer() {
        let validator = test_validator();
        let claims = TestClaims {
            iss: "https://other.example.com".to_string(),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert!(validator.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let validator = test_validator();
        let claims = TestClaims {
            exp: now_secs().saturating_sub(3600),
            ..base_claims()
        };
        let token = encode_rs256(&claims, Some(TEST_KID));
        assert!(validator.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let validator = test_validator();
        let token = encode_rs256(&base_claims(), Some(TEST_KID));
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'a' { 'b' } else { 'a' });
        assert_ne!(token, tampered);
        assert!(validator.validate(&tampered).await.is_err());
    }

    #[tokio::test]
    async fn rejects_none_algorithm() {
        let validator = test_validator();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(r#"{"alg":"none","typ":"JWT","kid":"test-key"}"#);
        let payload = b64.encode(
            serde_json::json!({
                "iss": TEST_ISSUER,
                "aud": TEST_AUDIENCE,
                "sub": "sub-123",
                "exp": now_secs() + 3600,
            })
            .to_string(),
        );
        let token = format!("{header}.{payload}.");
        assert!(validator.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn rejects_hs256_algorithm() {
        let validator = test_validator();
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(TEST_KID.to_string());
        let key = jsonwebtoken::EncodingKey::from_secret(b"test-secret");
        let token = jsonwebtoken::encode(&header, &base_claims(), &key).unwrap();
        assert!(matches!(
            validator.validate(&token).await.unwrap_err(),
            OidcError::Algorithm(_)
        ));
    }

    #[tokio::test]
    async fn rejects_missing_kid() {
        let validator = test_validator();
        let token = encode_rs256(&base_claims(), None);
        assert!(matches!(
            validator.validate(&token).await.unwrap_err(),
            OidcError::MissingKid
        ));
    }

    fn encode_value(claims: &serde_json::Value, kid: Option<&str>) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = kid.map(str::to_string);
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(&header, claims, &key).unwrap()
    }

    fn value_claims() -> serde_json::Value {
        serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": TEST_AUDIENCE,
            "exp": now_secs() + 3600,
            "sub": "sub-123",
            "preferred_username": "alice",
        })
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let validator = test_validator();
        let token = encode_rs256(&base_claims(), Some("unknown-kid"));
        // Unknown kid on a fresh cache forces a JWKS refresh; the dummy
        // loopback URI fails, proving the refresh was attempted.
        assert!(matches!(
            validator.validate(&token).await.unwrap_err(),
            OidcError::Jwks(_)
        ));
    }

    #[tokio::test]
    async fn rejects_missing_or_wrong_type_iss_and_aud() {
        let validator = test_validator();
        for claims in [
            serde_json::json!({"aud": TEST_AUDIENCE, "exp": now_secs() + 3600, "sub": "s"}),
            serde_json::json!({"iss": TEST_ISSUER, "exp": now_secs() + 3600, "sub": "s"}),
            serde_json::json!({"iss": 12345, "aud": TEST_AUDIENCE, "exp": now_secs() + 3600, "sub": "s"}),
            serde_json::json!({"iss": TEST_ISSUER, "aud": 12345, "exp": now_secs() + 3600, "sub": "s"}),
            serde_json::json!({"iss": null, "aud": TEST_AUDIENCE, "exp": now_secs() + 3600, "sub": "s"}),
        ] {
            let token = encode_value(&claims, Some(TEST_KID));
            assert!(
                validator.validate(&token).await.is_err(),
                "accepted claims {claims}"
            );
        }
    }

    #[tokio::test]
    async fn stale_cache_refresh_failure_fails_closed() {
        let validator = test_validator();
        {
            let mut cache = validator.cache.write().await;
            cache.fetched_at = Instant::now() - Duration::from_secs(JWKS_MAX_AGE_SECS + 1);
        }
        let token = encode_rs256(&base_claims(), Some(TEST_KID));
        assert!(matches!(
            validator.validate(&token).await.unwrap_err(),
            OidcError::Jwks(_)
        ));
    }

    #[tokio::test]
    async fn leeway_allows_recent_expiry_and_near_nbf() {
        let validator = test_validator();
        let mut claims = value_claims();
        claims["exp"] = serde_json::json!(now_secs() - 30);
        let token = encode_value(&claims, Some(TEST_KID));
        assert_eq!(validator.validate(&token).await.unwrap(), "alice");

        let mut claims = value_claims();
        claims["nbf"] = serde_json::json!(now_secs() + 30);
        let token = encode_value(&claims, Some(TEST_KID));
        assert_eq!(validator.validate(&token).await.unwrap(), "alice");

        let mut claims = value_claims();
        claims["nbf"] = serde_json::json!(now_secs() + 3600);
        let token = encode_value(&claims, Some(TEST_KID));
        assert!(validator.validate(&token).await.is_err());
    }

    #[tokio::test]
    async fn error_messages_do_not_contain_token() {
        let validator = test_validator();
        let token = encode_rs256(&base_claims(), Some("unknown-kid"));
        let err = validator.validate(&token).await.unwrap_err().to_string();
        assert!(!err.contains(&token));
        assert!(err.len() < token.len());
    }
}

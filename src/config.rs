//! Runtime configuration, sourced entirely from the environment (12-factor).

use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Settings {
    /// Socket address to bind, e.g. `0.0.0.0:8000`.
    pub bind_addr: String,
    /// Postgres connection string, e.g. `postgres://user:pass@db:5432/packages`.
    pub database_url: String,
    /// Storage backend selector: `filesystem` or `s3`.
    pub storage_backend: String,
    /// Root directory for the filesystem backend. For `s3` this is the
    /// local staging directory uploads are buffered in before transfer.
    pub storage_dir: PathBuf,
    /// S3 bucket holding file bytes; required for the `s3` backend.
    pub s3_bucket: Option<String>,
    /// Explicit S3 region override; `None` lets the AWS SDK chain
    /// (`AWS_REGION`, profile, IMDS) decide.
    pub s3_region: Option<String>,
    /// Custom S3 endpoint (e.g. MinIO); `None` means AWS S3.
    pub s3_endpoint_url: Option<String>,
    /// Path to the auth token file (`user:token` per line, `#` comments allowed).
    pub auth_token_file: PathBuf,
    /// Maximum accepted upload body in bytes.
    pub max_upload_bytes: u64,
}

impl Settings {
    pub fn from_env() -> Result<Self, String> {
        let storage_backend = env_or("STORAGE_BACKEND", "filesystem");
        if storage_backend != "filesystem" && storage_backend != "s3" {
            return Err(format!(
                "unsupported STORAGE_BACKEND '{storage_backend}' (supported: filesystem, s3)"
            ));
        }
        // The bucket is the only S3 setting without a usable default;
        // region/endpoint/credentials follow AWS SDK conventions.
        let s3_bucket = if storage_backend == "s3" {
            Some(required_non_blank("S3_BUCKET")?)
        } else {
            None
        };
        let s3_endpoint_url = match env::var("S3_ENDPOINT_URL") {
            Ok(value) if !value.trim().is_empty() => {
                let value = value.trim().to_string();
                validate_endpoint_url(&value)?;
                Some(value)
            }
            _ => None,
        };
        let s3_region = match env::var("S3_REGION") {
            Ok(value) if value.trim().is_empty() => {
                return Err("env var S3_REGION must not be blank".to_string());
            }
            Ok(value) => Some(value.trim().to_string()),
            Err(_) => None,
        };
        let max_upload_bytes = parse_max_upload_bytes(&env_or("MAX_UPLOAD_BYTES", "1073741824"))?;
        Ok(Self {
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8000"),
            database_url: required_non_blank("DATABASE_URL")?,
            storage_backend,
            storage_dir: PathBuf::from(env_or("STORAGE_DIR", "/data")),
            s3_bucket,
            s3_region,
            s3_endpoint_url,
            auth_token_file: PathBuf::from(required_non_blank("AUTH_TOKEN_FILE")?),
            max_upload_bytes,
        })
    }
}

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read a required var, rejecting missing or blank (whitespace-only) values.
fn required_non_blank(key: &str) -> Result<String, String> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => Err(format!("env var {key} must not be blank")),
        Err(_) => Err(format!("missing required env var {key}")),
    }
}

/// Require an `http`/`https` endpoint with a host, so malformed values
/// fail at startup instead of as per-request endpoint-resolution errors.
fn validate_endpoint_url(value: &str) -> Result<(), String> {
    let invalid =
        || format!("invalid S3_ENDPOINT_URL '{value}' (want http:// or https:// with a host)");
    let rest = value
        .strip_prefix("http://")
        .or_else(|| value.strip_prefix("https://"))
        .ok_or_else(invalid)?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || value.chars().any(|c| c.is_whitespace()) {
        return Err(invalid());
    }
    Ok(())
}

/// Parse the upload cap, rejecting non-numeric, zero, and over-i64 values.
fn parse_max_upload_bytes(raw: &str) -> Result<u64, String> {
    match raw.parse::<u64>() {
        Ok(0) => Err("invalid MAX_UPLOAD_BYTES (must be a positive integer, got 0)".to_string()),
        Ok(n) if n > i64::MAX as u64 => {
            Err(format!("invalid MAX_UPLOAD_BYTES (must fit i64, got {n})"))
        }
        Ok(n) => Ok(n),
        Err(_) => Err("invalid MAX_UPLOAD_BYTES (want a positive integer)".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sequential env-var rejection cases in one test to avoid parallel env races.
    #[test]
    fn rejects_invalid_config() {
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_auth = env::var("AUTH_TOKEN_FILE").ok();
        let saved_cap = env::var("MAX_UPLOAD_BYTES").ok();
        let saved_backend = env::var("STORAGE_BACKEND").ok();
        let saved_bucket = env::var("S3_BUCKET").ok();
        let saved_region = env::var("S3_REGION").ok();
        let saved_endpoint = env::var("S3_ENDPOINT_URL").ok();

        let restore = || {
            restore_var("DATABASE_URL", saved_db.as_deref());
            restore_var("AUTH_TOKEN_FILE", saved_auth.as_deref());
            restore_var("MAX_UPLOAD_BYTES", saved_cap.as_deref());
            restore_var("STORAGE_BACKEND", saved_backend.as_deref());
            restore_var("S3_BUCKET", saved_bucket.as_deref());
            restore_var("S3_REGION", saved_region.as_deref());
            restore_var("S3_ENDPOINT_URL", saved_endpoint.as_deref());
        };

        // Valid baseline.
        env::set_var("DATABASE_URL", "postgres://localhost/packages");
        env::set_var("AUTH_TOKEN_FILE", "/tmp/tokens");
        env::set_var("MAX_UPLOAD_BYTES", "1024");
        assert!(Settings::from_env().is_ok());

        // Zero cap rejected.
        env::set_var("MAX_UPLOAD_BYTES", "0");
        let err = Settings::from_env().unwrap_err();
        assert!(err.contains("MAX_UPLOAD_BYTES"), "unexpected: {err}");
        env::set_var("MAX_UPLOAD_BYTES", "1024");

        // Non-numeric cap rejected.
        env::set_var("MAX_UPLOAD_BYTES", "huge");
        assert!(Settings::from_env()
            .unwrap_err()
            .contains("MAX_UPLOAD_BYTES"));
        env::set_var("MAX_UPLOAD_BYTES", "1024");

        // Blank DATABASE_URL rejected.
        for blank in ["", "   ", "\t\n"] {
            env::set_var("DATABASE_URL", blank);
            let err = Settings::from_env().unwrap_err();
            assert!(err.contains("DATABASE_URL"), "unexpected: {err}");
        }
        env::set_var("DATABASE_URL", "postgres://localhost/packages");

        // Blank AUTH_TOKEN_FILE rejected.
        for blank in ["", "   "] {
            env::set_var("AUTH_TOKEN_FILE", blank);
            let err = Settings::from_env().unwrap_err();
            assert!(err.contains("AUTH_TOKEN_FILE"), "unexpected: {err}");
        }
        env::set_var("AUTH_TOKEN_FILE", "/tmp/tokens");

        // Missing required vars rejected.
        env::remove_var("DATABASE_URL");
        assert!(Settings::from_env().unwrap_err().contains("DATABASE_URL"));
        env::set_var("DATABASE_URL", "postgres://localhost/packages");

        // The s3 backend requires a bucket and rejects unknown backends.
        env::set_var("STORAGE_BACKEND", "s3");
        env::remove_var("S3_BUCKET");
        assert!(Settings::from_env().unwrap_err().contains("S3_BUCKET"));
        env::set_var("S3_BUCKET", "  ");
        assert!(Settings::from_env().unwrap_err().contains("S3_BUCKET"));
        env::set_var("S3_BUCKET", "packages");
        env::remove_var("S3_REGION");
        env::remove_var("S3_ENDPOINT_URL");
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.s3_bucket.as_deref(), Some("packages"));
        assert_eq!(settings.s3_region, None);
        assert_eq!(settings.s3_endpoint_url, None);
        env::set_var("S3_REGION", "eu-west-1");
        env::set_var("S3_ENDPOINT_URL", "http://minio:9000");
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.s3_region.as_deref(), Some("eu-west-1"));
        assert_eq!(
            settings.s3_endpoint_url.as_deref(),
            Some("http://minio:9000")
        );
        // Blank region and malformed endpoints fail fast.
        env::set_var("S3_REGION", "  ");
        assert!(Settings::from_env().unwrap_err().contains("S3_REGION"));
        env::remove_var("S3_REGION");
        for bad in ["minio:9000", "://x", "ftp://minio", "http://", "http://a b"] {
            env::set_var("S3_ENDPOINT_URL", bad);
            let err = Settings::from_env().unwrap_err();
            assert!(err.contains("S3_ENDPOINT_URL"), "{bad}: {err}");
        }
        env::remove_var("S3_ENDPOINT_URL");
        env::set_var("STORAGE_BACKEND", "tape");
        assert!(Settings::from_env()
            .unwrap_err()
            .contains("STORAGE_BACKEND"));
        env::remove_var("STORAGE_BACKEND");

        restore();
        assert!(Settings::from_env().is_err() || saved_db.is_some());
    }

    fn restore_var(key: &str, saved: Option<&str>) {
        match saved {
            Some(value) => env::set_var(key, value),
            None => env::remove_var(key),
        }
    }

    #[test]
    fn parses_cap_boundaries() {
        assert_eq!(parse_max_upload_bytes("1").unwrap(), 1);
        assert!(parse_max_upload_bytes("0").is_err());
        assert!(parse_max_upload_bytes("-5").is_err());
        assert!(parse_max_upload_bytes("").is_err());
    }
}

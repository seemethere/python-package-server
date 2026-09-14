//! Runtime configuration, sourced entirely from the environment (12-factor).

use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Settings {
    /// Socket address to bind, e.g. `0.0.0.0:8000`.
    pub bind_addr: String,
    /// Postgres connection string, e.g. `postgres://user:pass@db:5432/packages`.
    pub database_url: String,
    /// Storage backend selector. Only `filesystem` in this release; `s3` is planned.
    pub storage_backend: String,
    /// Root directory for the filesystem backend (also stages temp uploads).
    pub storage_dir: PathBuf,
    /// Path to the auth token file (`user:token` per line, `#` comments allowed).
    pub auth_token_file: PathBuf,
    /// Maximum accepted upload body in bytes.
    pub max_upload_bytes: u64,
}

impl Settings {
    pub fn from_env() -> Result<Self, String> {
        let storage_backend = env_or("STORAGE_BACKEND", "filesystem");
        if storage_backend != "filesystem" {
            return Err(format!(
                "unsupported STORAGE_BACKEND '{storage_backend}' (supported: filesystem; s3 is planned)"
            ));
        }
        let max_upload_bytes = parse_max_upload_bytes(&env_or("MAX_UPLOAD_BYTES", "1073741824"))?;
        Ok(Self {
            bind_addr: env_or("BIND_ADDR", "0.0.0.0:8000"),
            database_url: required_non_blank("DATABASE_URL")?,
            storage_backend,
            storage_dir: PathBuf::from(env_or("STORAGE_DIR", "/data")),
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

        let restore = || {
            restore_var("DATABASE_URL", saved_db.as_deref());
            restore_var("AUTH_TOKEN_FILE", saved_auth.as_deref());
            restore_var("MAX_UPLOAD_BYTES", saved_cap.as_deref());
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

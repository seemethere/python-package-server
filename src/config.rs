//! Runtime configuration, sourced entirely from the environment (12-factor).

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};

use crate::packaging::normalize_project;

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
    /// Optional upstream index base URL (e.g. `https://pypi.org/simple`).
    /// `None` disables the upstream pull-through cache.
    pub upstream_url: Option<String>,
    /// TTL in seconds for cached upstream project index responses.
    pub upstream_index_ttl_secs: u64,
    /// Max age in days for pull-through cached file bytes; entries older
    /// than this are re-fetched on demand and swept in the background.
    /// `0` disables age expiry (cached bytes never expire).
    pub upstream_cache_max_age_days: u32,
    /// Normalized project names that must never be fetched from upstream.
    pub upstream_private_only_projects: HashSet<String>,
    /// Path to the JSON policy file (`POLICY_FILE`); `None` disables
    /// file-based policy (upstream quarantine off).
    pub policy_file: Option<PathBuf>,
    /// Policy parsed once at startup from [`Settings::policy_file`].
    pub policy: Policy,
}

/// Upstream quarantine policy, read once at startup (no hot reload).
///
/// An upstream file is hidden and blocked until
/// `upload_time + quarantine_days`, where the days come from the
/// per-project override or the global default. `0` disables quarantine.
/// Hosted files are never quarantined.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Quarantine days for projects without a per-package override.
    pub quarantine_days_default: u32,
    /// Per-project override by normalized project name.
    pub quarantine_days_by_project: HashMap<String, u32>,
}

impl Policy {
    /// Quarantine days for one normalized project: per-package override
    /// when present, otherwise the global default.
    pub fn quarantine_days_for(&self, normalized: &str) -> u32 {
        self.quarantine_days_by_project
            .get(normalized)
            .copied()
            .unwrap_or(self.quarantine_days_default)
    }

    /// Load and validate a policy file, failing fast on any problem.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read policy file {}: {err}", path.display()))?;
        Self::parse_json(&text)
            .map_err(|err| format!("invalid policy file {}: {err}", path.display()))
    }

    fn parse_json(text: &str) -> Result<Self, String> {
        let raw: PolicyFileJson =
            serde_json::from_str(text).map_err(|err| format!("malformed JSON: {err}"))?;
        let mut by_project = HashMap::with_capacity(raw.packages.len());
        // Sorted so duplicate detection (and its error) is deterministic
        // rather than HashMap-order dependent.
        let mut names: Vec<&String> = raw.packages.keys().collect();
        names.sort();
        for name in names {
            let entry = &raw.packages[name];
            let normalized = normalize_project(name)
                .map(|n| n.to_string())
                .map_err(|_| format!("invalid project name '{name}'"))?;
            if by_project.contains_key(&normalized) {
                return Err(format!(
                    "duplicate project '{normalized}' (distinct package keys normalize to the same project)"
                ));
            }
            by_project.insert(normalized, entry.upstream_quarantine_days);
        }
        Ok(Self {
            quarantine_days_default: raw
                .default
                .map(|entry| entry.upstream_quarantine_days)
                .unwrap_or(0),
            quarantine_days_by_project: by_project,
        })
    }
}

/// Top-level policy file shape. Unknown keys are rejected so typos fail
/// fast at startup instead of silently disabling quarantine.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFileJson {
    #[serde(default)]
    default: Option<PolicyEntryJson>,
    #[serde(default)]
    packages: HashMap<String, PolicyEntryJson>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyEntryJson {
    upstream_quarantine_days: u32,
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
        let upstream_url = parse_upstream_url()?;
        let upstream_index_ttl_secs = parse_upstream_index_ttl_secs()?;
        let upstream_cache_max_age_days = parse_upstream_cache_max_age_days()?;
        let upstream_private_only_projects = parse_upstream_private_only_projects()?;
        let policy_file = parse_policy_file();
        let policy = match &policy_file {
            Some(path) => Policy::load(path)?,
            None => Policy::default(),
        };
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
            upstream_url,
            upstream_index_ttl_secs,
            upstream_cache_max_age_days,
            upstream_private_only_projects,
            policy_file,
            policy,
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
    validate_http_url(value, "S3_ENDPOINT_URL")
}

fn validate_upstream_url(value: &str) -> Result<(), String> {
    validate_http_url(value, "UPSTREAM_URL")
}

fn validate_http_url(value: &str, env_name: &str) -> Result<(), String> {
    let invalid = || format!("invalid {env_name} '{value}' (want http:// or https:// with a host)");
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

fn parse_upstream_url() -> Result<Option<String>, String> {
    match env::var("UPSTREAM_URL") {
        Ok(value) if !value.trim().is_empty() => {
            let value = value.trim().to_string();
            validate_upstream_url(&value)?;
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}

fn parse_upstream_index_ttl_secs() -> Result<u64, String> {
    match env::var("UPSTREAM_INDEX_TTL_SECS") {
        Ok(value) => {
            let trimmed = value.trim();
            match trimmed.parse::<u64>() {
                Ok(0) => Err(
                    "invalid UPSTREAM_INDEX_TTL_SECS (must be a positive integer, got 0)"
                        .to_string(),
                ),
                Ok(n) => Ok(n),
                Err(_) => {
                    Err("invalid UPSTREAM_INDEX_TTL_SECS (want a positive integer)".to_string())
                }
            }
        }
        Err(_) => Ok(300),
    }
}

/// Default 30 days; `0` disables age expiry. Rejects non-numeric and
/// negative values like the other integer parsers.
fn parse_upstream_cache_max_age_days() -> Result<u32, String> {
    match env::var("UPSTREAM_CACHE_MAX_AGE_DAYS") {
        Ok(value) => match value.trim().parse::<u32>() {
            Ok(n) => Ok(n),
            Err(_) => {
                Err("invalid UPSTREAM_CACHE_MAX_AGE_DAYS (want a non-negative integer)".to_string())
            }
        },
        Err(_) => Ok(30),
    }
}

fn parse_upstream_private_only_projects() -> Result<HashSet<String>, String> {
    let raw = match env::var("UPSTREAM_PRIVATE_ONLY_PROJECTS") {
        Ok(value) => value,
        Err(_) => return Ok(HashSet::new()),
    };
    if raw.trim().is_empty() {
        return Ok(HashSet::new());
    }
    let mut set = HashSet::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let normalized = normalize_project(entry).map_err(|_| {
            format!("invalid UPSTREAM_PRIVATE_ONLY_PROJECTS entry '{entry}' (invalid project name)")
        })?;
        set.insert(normalized.to_string());
    }
    Ok(set)
}

/// `POLICY_FILE`: blank or unset means no policy file (quarantine off).
/// A set path is loaded in [`Settings::from_env`]; a missing or invalid
/// file is a startup error.
fn parse_policy_file() -> Option<PathBuf> {
    match env::var("POLICY_FILE") {
        Ok(value) if !value.trim().is_empty() => Some(PathBuf::from(value.trim())),
        _ => None,
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
        let saved_backend = env::var("STORAGE_BACKEND").ok();
        let saved_bucket = env::var("S3_BUCKET").ok();
        let saved_region = env::var("S3_REGION").ok();
        let saved_endpoint = env::var("S3_ENDPOINT_URL").ok();
        let saved_upstream_url = env::var("UPSTREAM_URL").ok();
        let saved_upstream_ttl = env::var("UPSTREAM_INDEX_TTL_SECS").ok();
        let saved_cache_age = env::var("UPSTREAM_CACHE_MAX_AGE_DAYS").ok();
        let saved_private_only = env::var("UPSTREAM_PRIVATE_ONLY_PROJECTS").ok();
        let saved_policy_file = env::var("POLICY_FILE").ok();

        let restore = || {
            restore_var("DATABASE_URL", saved_db.as_deref());
            restore_var("AUTH_TOKEN_FILE", saved_auth.as_deref());
            restore_var("MAX_UPLOAD_BYTES", saved_cap.as_deref());
            restore_var("STORAGE_BACKEND", saved_backend.as_deref());
            restore_var("S3_BUCKET", saved_bucket.as_deref());
            restore_var("S3_REGION", saved_region.as_deref());
            restore_var("S3_ENDPOINT_URL", saved_endpoint.as_deref());
            restore_var("UPSTREAM_URL", saved_upstream_url.as_deref());
            restore_var("UPSTREAM_INDEX_TTL_SECS", saved_upstream_ttl.as_deref());
            restore_var("UPSTREAM_CACHE_MAX_AGE_DAYS", saved_cache_age.as_deref());
            restore_var(
                "UPSTREAM_PRIVATE_ONLY_PROJECTS",
                saved_private_only.as_deref(),
            );
            restore_var("POLICY_FILE", saved_policy_file.as_deref());
        };

        // Valid baseline: upstream disabled by default.
        env::remove_var("UPSTREAM_URL");
        env::remove_var("UPSTREAM_INDEX_TTL_SECS");
        env::remove_var("UPSTREAM_CACHE_MAX_AGE_DAYS");
        env::remove_var("UPSTREAM_PRIVATE_ONLY_PROJECTS");
        env::remove_var("POLICY_FILE");
        env::remove_var("STORAGE_BACKEND");
        env::remove_var("S3_BUCKET");
        env::remove_var("S3_REGION");
        env::remove_var("S3_ENDPOINT_URL");
        env::set_var("DATABASE_URL", "postgres://localhost/packages");
        env::set_var("AUTH_TOKEN_FILE", "/tmp/tokens");
        env::set_var("MAX_UPLOAD_BYTES", "1024");
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.upstream_url, None);
        assert_eq!(settings.upstream_index_ttl_secs, 300);
        assert_eq!(settings.upstream_cache_max_age_days, 30);
        assert!(settings.upstream_private_only_projects.is_empty());
        assert_eq!(settings.policy_file, None);
        assert_eq!(settings.policy.quarantine_days_for("anything"), 0);

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

        // Upstream URL: blank means disabled, valid URL is kept, bad fails fast.
        env::set_var("UPSTREAM_URL", "   ");
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.upstream_url, None);
        env::set_var("UPSTREAM_URL", "https://pypi.org/simple");
        let settings = Settings::from_env().unwrap();
        assert_eq!(
            settings.upstream_url.as_deref(),
            Some("https://pypi.org/simple")
        );
        for bad in [
            "pypi.org/simple",
            "ftp://pypi.org/simple",
            "http://",
            "http://a b",
        ] {
            env::set_var("UPSTREAM_URL", bad);
            let err = Settings::from_env().unwrap_err();
            assert!(err.contains("UPSTREAM_URL"), "{bad}: {err}");
        }
        env::remove_var("UPSTREAM_URL");

        // Upstream TTL: default 300, valid override, zero/invalid rejected.
        env::set_var("UPSTREAM_INDEX_TTL_SECS", "60");
        assert_eq!(Settings::from_env().unwrap().upstream_index_ttl_secs, 60);
        for bad in ["0", "-1", "abc", ""] {
            env::set_var("UPSTREAM_INDEX_TTL_SECS", bad);
            let err = Settings::from_env().unwrap_err();
            assert!(err.contains("UPSTREAM_INDEX_TTL_SECS"), "{bad}: {err}");
        }
        env::remove_var("UPSTREAM_INDEX_TTL_SECS");

        // Cache max age: default 30, 0 disables expiry, invalid rejected.
        env::set_var("UPSTREAM_CACHE_MAX_AGE_DAYS", "7");
        assert_eq!(Settings::from_env().unwrap().upstream_cache_max_age_days, 7);
        env::set_var("UPSTREAM_CACHE_MAX_AGE_DAYS", "0");
        assert_eq!(Settings::from_env().unwrap().upstream_cache_max_age_days, 0);
        for bad in ["-1", "abc", "", "3.5"] {
            env::set_var("UPSTREAM_CACHE_MAX_AGE_DAYS", bad);
            let err = Settings::from_env().unwrap_err();
            assert!(err.contains("UPSTREAM_CACHE_MAX_AGE_DAYS"), "{bad}: {err}");
        }
        env::remove_var("UPSTREAM_CACHE_MAX_AGE_DAYS");

        // Private-only list: normalized, deduped, invalid fails startup.
        env::set_var(
            "UPSTREAM_PRIVATE_ONLY_PROJECTS",
            "Demo_Pkg, demo-pkg , Other.Name",
        );
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.upstream_private_only_projects.len(), 2);
        assert!(settings.upstream_private_only_projects.contains("demo-pkg"));
        assert!(settings
            .upstream_private_only_projects
            .contains("other-name"));
        env::set_var("UPSTREAM_PRIVATE_ONLY_PROJECTS", "!!!invalid");
        let err = Settings::from_env().unwrap_err();
        assert!(
            err.contains("UPSTREAM_PRIVATE_ONLY_PROJECTS"),
            "unexpected: {err}"
        );
        env::remove_var("UPSTREAM_PRIVATE_ONLY_PROJECTS");

        // POLICY_FILE: blank/unset means no policy (quarantine off).
        env::set_var("POLICY_FILE", "   ");
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.policy_file, None);
        assert_eq!(settings.policy.quarantine_days_for("requests"), 0);

        // A set path loads at startup; overrides beat the default.
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.json");
        std::fs::write(
            &policy_path,
            r#"{"default": {"upstream_quarantine_days": 3},
                "packages": {"Requests": {"upstream_quarantine_days": 10}}}"#,
        )
        .unwrap();
        env::set_var("POLICY_FILE", &policy_path);
        let settings = Settings::from_env().unwrap();
        assert_eq!(settings.policy_file.as_deref(), Some(policy_path.as_path()));
        assert_eq!(settings.policy.quarantine_days_for("other"), 3);
        assert_eq!(settings.policy.quarantine_days_for("requests"), 10);

        // Missing file when POLICY_FILE is set fails startup.
        env::set_var("POLICY_FILE", dir.path().join("does-not-exist.json"));
        let err = Settings::from_env().unwrap_err();
        assert!(err.contains("policy file"), "unexpected: {err}");

        // Malformed content fails startup.
        std::fs::write(&policy_path, "{not json").unwrap();
        env::set_var("POLICY_FILE", &policy_path);
        let err = Settings::from_env().unwrap_err();
        assert!(err.contains("policy file"), "unexpected: {err}");
        env::remove_var("POLICY_FILE");

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

    #[test]
    fn parses_policy_defaults_and_overrides() {
        // Empty object: everything 0 (feature off).
        let policy = Policy::parse_json("{}").unwrap();
        assert_eq!(policy.quarantine_days_for("requests"), 0);

        // Default only.
        let policy = Policy::parse_json(r#"{"default": {"upstream_quarantine_days": 3}}"#).unwrap();
        assert_eq!(policy.quarantine_days_for("requests"), 3);

        // Per-package keys normalize; 0 disables one project.
        let policy = Policy::parse_json(
            r#"{"default": {"upstream_quarantine_days": 3},
                "packages": {
                  "Requests": {"upstream_quarantine_days": 10},
                  "Torch": {"upstream_quarantine_days": 0}
                }}"#,
        )
        .unwrap();
        assert_eq!(policy.quarantine_days_for("other"), 3);
        assert_eq!(policy.quarantine_days_for("requests"), 10);
        assert_eq!(policy.quarantine_days_for("torch"), 0);
    }

    #[test]
    fn rejects_invalid_policy() {
        // Malformed JSON and non-object shapes.
        for bad in ["{not json", "[1, 2]", "\"str\"", "42", ""] {
            assert!(Policy::parse_json(bad).is_err(), "accepted {bad:?}");
        }
        // Unknown top-level keys fail fast (likely typos).
        for bad in [
            r#"{"defaults": {"upstream_quarantine_days": 3}}"#,
            r#"{"default": {"upstream_quarantine_days": 3}, "extra": 1}"#,
            r#"{"packages": {"a": {"upstream_quarantine_days": 1, "typo": 2}}}"#,
        ] {
            assert!(Policy::parse_json(bad).is_err(), "accepted {bad:?}");
        }
        // Negative, fractional, or non-numeric days.
        for bad in [
            r#"{"default": {"upstream_quarantine_days": -1}}"#,
            r#"{"default": {"upstream_quarantine_days": 1.5}}"#,
            r#"{"default": {"upstream_quarantine_days": "3"}}"#,
            r#"{"packages": {"a": {"upstream_quarantine_days": -7}}}"#,
            r#"{"default": {}}"#,
        ] {
            assert!(Policy::parse_json(bad).is_err(), "accepted {bad:?}");
        }
        // Invalid project names.
        for bad in [
            r#"{"packages": {"!!!invalid": {"upstream_quarantine_days": 1}}}"#,
            r#"{"packages": {"": {"upstream_quarantine_days": 1}}}"#,
        ] {
            assert!(Policy::parse_json(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rejects_normalized_duplicate_projects() {
        // Distinct keys that normalize to the same project must fail fast
        // instead of one silently winning (HashMap order is random).
        for (bad, normalized) in [
            (
                r#"{"packages": {"Foo": {"upstream_quarantine_days": 0}, "foo": {"upstream_quarantine_days": 10}}}"#,
                "foo",
            ),
            (
                r#"{"packages": {"Demo_Pkg": {"upstream_quarantine_days": 1}, "demo-pkg": {"upstream_quarantine_days": 2}}}"#,
                "demo-pkg",
            ),
        ] {
            let err = Policy::parse_json(bad).unwrap_err();
            assert!(
                err.contains("duplicate") && err.contains(normalized),
                "error should name the duplicate normalized project '{normalized}': {err}"
            );
        }
    }
}

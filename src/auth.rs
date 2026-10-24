//! Token authentication via HTTP Basic or Bearer [REDACTED]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use base64::Engine;
use subtle::ConstantTimeEq;

use crate::error::AppError;

/// Credential store: `users` maps user -> token, `tokens` maps token -> user.
///
/// When built with [`Auth::from_file`], the token file's modification time
/// is checked on every verification and credentials reload automatically
/// after rotation, with no restart. A malformed or empty replacement file
/// keeps the previously loaded credentials and is retried only once the
/// file changes again. In-memory stores ([`Auth::from_pairs`]) never reload.
#[derive(Clone, Debug)]
pub struct Auth {
    inner: Arc<RwLock<Credentials>>,
    /// Token file to watch for rotation; `None` for in-memory credentials.
    file: Option<Arc<std::path::PathBuf>>,
}

#[derive(Debug)]
struct Credentials {
    users: HashMap<String, String>,
    tokens: HashMap<String, String>,
    /// File mtime already loaded (or attempted); `None` when in-memory.
    seen_mtime: Option<std::time::SystemTime>,
}

impl Credentials {
    /// Later pairs win on duplicate users, and the token map is rebuilt from
    /// the final user map so no stale token survives.
    fn from_pairs(pairs: Vec<(String, String)>, seen_mtime: Option<std::time::SystemTime>) -> Self {
        let mut users = HashMap::with_capacity(pairs.len());
        for (user, token) in &pairs {
            users.insert(user.clone(), token.clone());
        }
        let mut tokens = HashMap::with_capacity(users.len());
        for (user, token) in &pairs {
            if users.get(user).is_some_and(|current| current == token) {
                tokens.insert(token.clone(), user.clone());
            }
        }
        Self {
            users,
            tokens,
            seen_mtime,
        }
    }
}

/// Parse `user:token` lines; blank lines and `#` comments are skipped.
fn parse_pairs(content: &str) -> std::io::Result<Vec<(String, String)>> {
    let mut pairs = Vec::new();
    for (index, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let malformed = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("auth token file line {} malformed", index + 1),
            )
        };
        let (user, token) = line.split_once(':').ok_or_else(malformed)?;
        let (user, token) = (user.trim(), token.trim());
        if user.is_empty() || token.is_empty() {
            return Err(malformed());
        }
        pairs.push((user.to_string(), token.to_string()));
    }
    Ok(pairs)
}

fn load_pairs(path: &std::path::Path) -> std::io::Result<Vec<(String, String)>> {
    parse_pairs(&std::fs::read_to_string(path)?)
}

impl Auth {
    /// Load `user:token` pairs from a file and watch it for rotation.
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let pairs = load_pairs(path)?;
        let seen_mtime = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok();
        Ok(Self {
            inner: Arc::new(RwLock::new(Credentials::from_pairs(pairs, seen_mtime))),
            file: Some(Arc::new(path.to_path_buf())),
        })
    }

    /// Build from `(user, token)` pairs held only in memory; never reloads.
    pub fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Credentials::from_pairs(pairs, None))),
            file: None,
        }
    }

    /// Reload credentials when the token file's mtime has advanced.
    ///
    /// Failures (file briefly missing during an atomic replace, malformed
    /// contents, or an empty file) keep the current credentials.
    fn maybe_reload(&self) {
        let Some(path) = &self.file else {
            return;
        };
        let Ok(mtime) = std::fs::metadata(path.as_path()).and_then(|meta| meta.modified()) else {
            return;
        };
        {
            let inner = self.inner.read().unwrap_or_else(|err| err.into_inner());
            if inner.seen_mtime == Some(mtime) {
                return;
            }
        }
        match load_pairs(path.as_path()) {
            Ok(pairs) if !pairs.is_empty() => {
                let mut inner = self.inner.write().unwrap_or_else(|err| err.into_inner());
                // Another request may have loaded this mtime first.
                if inner.seen_mtime != Some(mtime) {
                    *inner = Credentials::from_pairs(pairs, Some(mtime));
                    tracing::info!("auth tokens reloaded from {}", path.display());
                }
            }
            Ok(_) => {
                tracing::warn!(
                    "auth token reload skipped ({}): no users found; keeping current credentials",
                    path.display()
                );
                self.mark_seen(mtime);
            }
            Err(err) => {
                tracing::warn!(
                    "auth token reload failed ({}): {err}; keeping current credentials",
                    path.display()
                );
                self.mark_seen(mtime);
            }
        }
    }

    /// Record `mtime` as attempted so a bad file is not reparsed per request;
    /// fixing the file advances its mtime and triggers a fresh attempt.
    fn mark_seen(&self, mtime: std::time::SystemTime) {
        let mut inner = self.inner.write().unwrap_or_else(|err| err.into_inner());
        inner.seen_mtime = Some(mtime);
    }

    /// Check HTTP Basic credentials (password is the user's token).
    pub fn verify_basic(&self, user: &str, pass: &str) -> bool {
        self.maybe_reload();
        let inner = self.inner.read().unwrap_or_else(|err| err.into_inner());
        inner
            .users
            .get(user)
            .is_some_and(|token| ct_equal(token, pass))
    }

    /// Check whether a Bearer [REDACTED] is known.
    pub fn verify_bearer(&self, token: &str) -> bool {
        self.maybe_reload();
        let inner = self.inner.read().unwrap_or_else(|err| err.into_inner());
        inner.tokens.keys().any(|known| ct_equal(known, token))
    }

    /// Resolve a Bearer [REDACTED] to its user, if known.
    pub fn user_for_token(&self, token: &str) -> Option<String> {
        self.maybe_reload();
        let inner = self.inner.read().unwrap_or_else(|err| err.into_inner());
        inner
            .tokens
            .iter()
            .find(|(known, _)| ct_equal(known, token))
            .map(|(_, user)| user.clone())
    }

    /// Whether the store holds zero users (empty token file).
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.read().unwrap_or_else(|err| err.into_inner());
        inner.users.is_empty()
    }
}

/// Constant-time string equality; length mismatch is `false` (no panic, no leak).
fn ct_equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff.ct_eq(&0u8).into()
}

/// Split an `Authorization` value into `(scheme, credentials)`; the caller must
/// compare the scheme case-insensitively (RFC 7617).
fn split_scheme(header: &str) -> Option<(&str, &str)> {
    let (scheme, credentials) = header.split_once(' ')?;
    if scheme.is_empty() {
        return None;
    }
    Some((scheme, credentials))
}

/// The authenticated principal, inserted into request extensions by [`require_auth`].
#[derive(Clone)]
pub struct AuthenticatedUser(pub String);

/// Middleware requiring Basic (`user:token`) or Bearer (`token`) credentials.
pub async fn require_auth(
    axum::extract::State(auth): axum::extract::State<Auth>,
    mut req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Result<axum::response::Response, AppError> {
    let header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let Some(header) = header else {
        tracing::warn!("auth rejected: missing authorization header");
        return Err(AppError::Unauthorized);
    };
    let Some((scheme, credentials)) = split_scheme(header) else {
        tracing::warn!("auth rejected: malformed authorization header");
        return Err(AppError::Unauthorized);
    };
    let user = if scheme.eq_ignore_ascii_case("Basic") {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(credentials.trim())
            .map_err(|_| {
                tracing::warn!("auth rejected: basic credentials are not valid base64");
                AppError::Unauthorized
            })?;
        let credentials = String::from_utf8(decoded).map_err(|_| {
            tracing::warn!("auth rejected: basic credentials are not valid utf-8");
            AppError::Unauthorized
        })?;
        let Some((user, pass)) = credentials.split_once(':') else {
            tracing::warn!("auth rejected: basic credentials missing user separator");
            return Err(AppError::Unauthorized);
        };
        if !auth.verify_basic(user, pass) {
            tracing::warn!("auth rejected: unknown user or bad token");
            return Err(AppError::Unauthorized);
        }
        user.to_string()
    } else if scheme.eq_ignore_ascii_case("Bearer") {
        let token = credentials.trim();
        if token.is_empty() {
            tracing::warn!("auth rejected: empty bearer token");
            return Err(AppError::Unauthorized);
        }
        if !auth.verify_bearer(token) {
            tracing::warn!("auth rejected: unknown bearer token");
            return Err(AppError::Unauthorized);
        }
        auth.user_for_token(token)
            .unwrap_or_else(|| "token".to_string())
    } else {
        tracing::warn!("auth rejected: unsupported auth scheme");
        return Err(AppError::Unauthorized);
    };
    req.extensions_mut().insert(AuthenticatedUser(user));
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_auth() -> Auth {
        Auth::from_pairs(vec![
            ("alice".to_string(), "secret-1".to_string()),
            ("bob".to_string(), "secret-2".to_string()),
        ])
    }

    #[test]
    fn verifies_basic_and_bearer() {
        let auth = test_auth();
        assert!(auth.verify_basic("alice", "secret-1"));
        assert!(!auth.verify_basic("alice", "wrong"));
        assert!(!auth.verify_basic("mallory", "secret-1"));
        assert!(auth.verify_bearer("secret-2"));
        assert!(!auth.verify_bearer("nope"));
        assert_eq!(auth.user_for_token("secret-1"), Some("alice".to_string()));
        assert_eq!(auth.user_for_token("nope"), None);
    }

    #[test]
    fn constant_time_compare_handles_length_mismatch() {
        assert!(ct_equal("secret-1", "secret-1"));
        assert!(!ct_equal("secret-1", "secret-2"));
        assert!(!ct_equal("short", "much-longer-token"));
        assert!(!ct_equal("", "nonempty"));
        assert!(ct_equal("", ""));
        let auth = test_auth();
        assert!(!auth.verify_basic("alice", "secret-1-plus-extra"));
        assert!(!auth.verify_bearer("secret-1-plus-extra"));
    }

    #[test]
    fn duplicate_users_last_wins_without_stale_tokens() {
        let auth = Auth::from_pairs(vec![
            ("alice".to_string(), "old-token".to_string()),
            ("bob".to_string(), "bob-token".to_string()),
            ("alice".to_string(), "new-token".to_string()),
        ]);
        assert!(auth.verify_basic("alice", "new-token"));
        assert!(!auth.verify_basic("alice", "old-token"));
        assert!(auth.verify_bearer("new-token"));
        assert!(!auth.verify_bearer("old-token"));
        assert_eq!(auth.user_for_token("old-token"), None);
        assert_eq!(auth.user_for_token("new-token"), Some("alice".to_string()));
        assert!(auth.verify_bearer("bob-token"));
    }

    #[test]
    fn schemes_match_case_insensitively() {
        for scheme in ["Basic", "basic", "BASIC", "bAsIc"] {
            let header = format!("{scheme} dXNlcjpwYXNz");
            let (parsed, _) = split_scheme(&header).unwrap();
            assert!(parsed.eq_ignore_ascii_case("Basic"), "scheme {scheme}");
        }
        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            let header = format!("{scheme} tok");
            let (parsed, _) = split_scheme(&header).unwrap();
            assert!(parsed.eq_ignore_ascii_case("Bearer"), "scheme {scheme}");
        }
        assert!(split_scheme("NoSpaceHere").is_none());
        assert!(split_scheme(" Basic x").is_none());
    }

    #[test]
    fn loads_token_file() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "alice:secret-1").unwrap();
        writeln!(file, "  bob : secret-2  ").unwrap();
        file.flush().unwrap();

        let auth = Auth::from_file(file.path()).unwrap();
        assert!(auth.verify_basic("alice", "secret-1"));
        assert!(auth.verify_bearer("secret-2"));
        assert_eq!(auth.user_for_token("secret-2"), Some("bob".to_string()));
    }

    #[test]
    fn rejects_malformed_token_file() {
        for contents in ["alice-without-colon\n", "alice:\n", ":token\n", ":\n"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(contents.as_bytes()).unwrap();
            file.flush().unwrap();
            let err = Auth::from_file(file.path()).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        }
    }

    /// Rewrite a token file and force a distinct, later mtime so the reload
    /// check observes the rotation deterministically.
    fn rewrite_token_file(path: &std::path::Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(later)
            .unwrap();
    }

    #[test]
    fn reloads_rotated_token_file_without_restart() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "alice:old-token").unwrap();
        writeln!(file, "bob:bob-token").unwrap();
        file.flush().unwrap();
        let auth = Auth::from_file(file.path()).unwrap();
        assert!(auth.verify_basic("alice", "old-token"));

        rewrite_token_file(file.path(), "alice:new-token\nbob:bob-token\n");
        assert!(auth.verify_basic("alice", "new-token"));
        assert!(!auth.verify_basic("alice", "old-token"));
        assert!(auth.verify_bearer("new-token"));
        assert!(!auth.verify_bearer("old-token"));
        assert_eq!(auth.user_for_token("new-token"), Some("alice".to_string()));
        // Untouched users survive the reload.
        assert!(auth.verify_basic("bob", "bob-token"));
    }

    #[test]
    fn bad_reload_keeps_current_credentials() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "alice:good-token").unwrap();
        file.flush().unwrap();
        let auth = Auth::from_file(file.path()).unwrap();

        rewrite_token_file(file.path(), "garbage-without-colon\n");
        assert!(auth.verify_basic("alice", "good-token"));

        rewrite_token_file(file.path(), "# only comments\n");
        assert!(auth.verify_basic("alice", "good-token"));

        // Fixing the file reloads again.
        rewrite_token_file(file.path(), "alice:fixed-token\n");
        assert!(auth.verify_basic("alice", "fixed-token"));
        assert!(!auth.verify_basic("alice", "good-token"));
    }
}

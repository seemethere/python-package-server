//! Pluggable artifact storage.
//!
//! [`StorageBackend`] is the seam future backends (S3) plug into. [`FsBackend`]
//! stores objects under `{root}/{project}/{filename}` with atomic renames out of
//! a staging directory.

use axum::body::Body;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio_util::io::ReaderStream;

use crate::error::{internal, AppError};

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("storage error: {0}")]
    Io(String),
}

impl StorageError {
    pub(crate) fn io<E: std::fmt::Display>(what: &str, err: E) -> Self {
        Self::Io(format!("{what}: {err}"))
    }
}

impl From<StorageError> for AppError {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::NotFound(what) => AppError::NotFound(what),
            other => internal(other),
        }
    }
}

pub(crate) fn bad_segment(s: &str) -> bool {
    s.is_empty()
        || s == "."
        || s == ".."
        || s.contains('/')
        || s.contains('\\')
        || s.chars().any(|c| c.is_control())
}

/// Object-store-like interface shared by all storage backends.
///
/// Notes for the future S3 implementation:
/// - `put_file` takes a staged file path so uploads stay disk-buffered and are
///   never fully loaded into RAM.
/// - `get` returns a streaming body; backends must not load whole objects.
// Intentional native async fn: trait is crate-internal with Send+Sync supertraits.
#[allow(async_fn_in_trait)]
pub trait StorageBackend: Clone + Send + Sync + 'static {
    async fn put_file(
        &self,
        project: &str,
        filename: &str,
        src: &Path,
    ) -> Result<u64, StorageError>;
    async fn get(&self, project: &str, filename: &str)
        -> Result<Option<(u64, Body)>, StorageError>;
    /// Stream up to `len` bytes starting at `start`; returns the total
    /// object size and the number of bytes the body will actually serve
    /// (clamped at the object end) alongside the body. Used for HTTP
    /// range downloads.
    async fn get_range(
        &self,
        project: &str,
        filename: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<(u64, u64, Body)>, StorageError>;
    async fn stat(&self, project: &str, filename: &str) -> Result<Option<u64>, StorageError>;
    async fn delete(&self, project: &str, filename: &str) -> Result<(), StorageError>;
    /// List filenames directly under `project` (non-recursive, files only).
    /// A missing project lists as empty. Used by the upstream-cache sweep
    /// to enumerate sidecars; callers filter names themselves.
    async fn list(&self, project: &str) -> Result<Vec<String>, StorageError>;
    async fn health_check(&self) -> Result<(), StorageError>;
}

/// Backend dispatch. New backends add a variant here without touching routes.
#[derive(Debug, Clone)]
pub enum Storage {
    Filesystem(FsBackend),
    S3(crate::s3::S3Backend),
}

impl Storage {
    pub fn filesystem(root: PathBuf) -> Self {
        Self::Filesystem(FsBackend::new(root))
    }

    pub fn s3(backend: crate::s3::S3Backend) -> Self {
        Self::S3(backend)
    }

    /// Local staging backend. Every backend stages uploads on local disk
    /// first, so staging operations always land here.
    fn staging(&self) -> &FsBackend {
        match self {
            Self::Filesystem(fs) => fs,
            Self::S3(s3) => s3.staging(),
        }
    }

    pub async fn ensure_dirs(&self) -> Result<(), StorageError> {
        self.staging().ensure_dirs().await
    }

    /// Unique staging path for an in-progress upload.
    pub fn stage_path(&self) -> Result<PathBuf, StorageError> {
        Ok(self.staging().stage_path())
    }

    /// Create a new staging file with [`tokio::fs::OpenOptions::create_new`],
    /// retrying with a fresh [`Self::stage_path`] on [`std::io::ErrorKind::AlreadyExists`]
    /// (up to ~100 tries) so colliding cross-process names never truncate a peer.
    pub async fn create_staging_file(&self) -> Result<(PathBuf, tokio::fs::File), StorageError> {
        self.staging().create_staging_file().await
    }

    /// Remove staging files older than `max_age`; returns the removal count.
    /// Best-effort per file: entries that error are skipped, never fatal.
    pub fn sweep_staging_older_than(
        &self,
        max_age: std::time::Duration,
    ) -> Result<usize, StorageError> {
        self.staging().sweep_staging_older_than(max_age)
    }

    pub async fn put_file(
        &self,
        project: &str,
        filename: &str,
        src: &Path,
    ) -> Result<u64, StorageError> {
        match self {
            Self::Filesystem(fs) => fs.put_file(project, filename, src).await,
            Self::S3(s3) => s3.put_file(project, filename, src).await,
        }
    }

    pub async fn get(
        &self,
        project: &str,
        filename: &str,
    ) -> Result<Option<(u64, Body)>, StorageError> {
        match self {
            Self::Filesystem(fs) => fs.get(project, filename).await,
            Self::S3(s3) => s3.get(project, filename).await,
        }
    }

    pub async fn get_range(
        &self,
        project: &str,
        filename: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<(u64, u64, Body)>, StorageError> {
        match self {
            Self::Filesystem(fs) => fs.get_range(project, filename, start, len).await,
            Self::S3(s3) => s3.get_range(project, filename, start, len).await,
        }
    }

    pub async fn stat(&self, project: &str, filename: &str) -> Result<Option<u64>, StorageError> {
        match self {
            Self::Filesystem(fs) => fs.stat(project, filename).await,
            Self::S3(s3) => s3.stat(project, filename).await,
        }
    }

    pub async fn delete(&self, project: &str, filename: &str) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(fs) => fs.delete(project, filename).await,
            Self::S3(s3) => s3.delete(project, filename).await,
        }
    }

    pub async fn list(&self, project: &str) -> Result<Vec<String>, StorageError> {
        match self {
            Self::Filesystem(fs) => fs.list(project).await,
            Self::S3(s3) => s3.list(project).await,
        }
    }

    pub async fn health_check(&self) -> Result<(), StorageError> {
        match self {
            Self::Filesystem(fs) => fs.health_check().await,
            Self::S3(s3) => s3.health_check().await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FsBackend {
    root: PathBuf,
}

impl FsBackend {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join(".tmp")
    }

    /// Create root + staging directories if missing. Called once at startup.
    pub async fn ensure_dirs(&self) -> Result<(), StorageError> {
        fs::create_dir_all(&self.root)
            .await
            .map_err(|e| StorageError::io("create storage root", e))?;
        fs::create_dir_all(self.staging_dir())
            .await
            .map_err(|e| StorageError::io("create staging dir", e))?;
        Ok(())
    }

    fn stage_path(&self) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.staging_dir()
            .join(format!("upload-{}-{}-{n}", std::process::id(), nanos))
    }

    /// Create a staging file exclusively, retrying on name collision.
    async fn create_staging_file(&self) -> Result<(PathBuf, tokio::fs::File), StorageError> {
        fs::create_dir_all(self.staging_dir())
            .await
            .map_err(|e| StorageError::io("create staging dir", e))?;
        for _ in 0..100 {
            let path = self.stage_path();
            match tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await
            {
                Ok(file) => return Ok((path, file)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(StorageError::io("create staging file", e)),
            }
        }
        Err(StorageError::io(
            "create staging file",
            "exhausted 100 staging-name retries",
        ))
    }

    /// Delete staging entries older than `max_age`; best-effort per file.
    fn sweep_staging_older_than(
        &self,
        max_age: std::time::Duration,
    ) -> Result<usize, StorageError> {
        let entries = match std::fs::read_dir(self.staging_dir()) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(StorageError::io("read staging dir", e)),
        };
        let mut removed = 0usize;
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let age = entry
                .metadata()
                .and_then(|meta| meta.modified())
                .ok()
                .and_then(|modified| std::time::SystemTime::now().duration_since(modified).ok());
            let Some(age) = age else { continue };
            if age <= max_age {
                continue;
            }
            if std::fs::remove_file(entry.path()).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn object_path(&self, project: &str, filename: &str) -> Result<PathBuf, StorageError> {
        if bad_segment(project) || bad_segment(filename) {
            return Err(StorageError::NotFound(format!("{project}/{filename}")));
        }
        Ok(self.root.join(project).join(filename))
    }
}

impl StorageBackend for FsBackend {
    async fn put_file(
        &self,
        project: &str,
        filename: &str,
        src: &Path,
    ) -> Result<u64, StorageError> {
        let dest = self.object_path(project, filename)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| StorageError::io("create project dir", e))?;
        }
        fs::rename(src, &dest)
            .await
            .map_err(|e| StorageError::io("publish staged upload", e))?;
        let size = fs::metadata(&dest)
            .await
            .map_err(|e| StorageError::io("stat published object", e))?
            .len();
        Ok(size)
    }

    async fn get(
        &self,
        project: &str,
        filename: &str,
    ) -> Result<Option<(u64, Body)>, StorageError> {
        let path = self.object_path(project, filename)?;
        let file = match fs::File::open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StorageError::io("open object", e)),
        };
        let size = file
            .metadata()
            .await
            .map_err(|e| StorageError::io("stat object", e))?
            .len();
        Ok(Some((size, Body::from_stream(ReaderStream::new(file)))))
    }

    async fn get_range(
        &self,
        project: &str,
        filename: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<(u64, u64, Body)>, StorageError> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let path = self.object_path(project, filename)?;
        let mut file = match fs::File::open(&path).await {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StorageError::io("open object", e)),
        };
        let total = file
            .metadata()
            .await
            .map_err(|e| StorageError::io("stat object", e))?
            .len();
        // Clamp against the opened object so callers can trust that the
        // body serves exactly `served` bytes from this same handle.
        let served = len.min(total.saturating_sub(start));
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|e| StorageError::io("seek object", e))?;
        Ok(Some((
            total,
            served,
            Body::from_stream(ReaderStream::new(file.take(served))),
        )))
    }

    async fn stat(&self, project: &str, filename: &str) -> Result<Option<u64>, StorageError> {
        let path = self.object_path(project, filename)?;
        match fs::metadata(&path).await {
            Ok(meta) => Ok(Some(meta.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::io("stat object", e)),
        }
    }

    async fn delete(&self, project: &str, filename: &str) -> Result<(), StorageError> {
        let path = self.object_path(project, filename)?;
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::io("delete object", e)),
        }
    }

    async fn list(&self, project: &str) -> Result<Vec<String>, StorageError> {
        if bad_segment(project) {
            return Err(StorageError::NotFound(project.to_string()));
        }
        let mut entries = match fs::read_dir(self.root.join(project)).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StorageError::io("list project", e)),
        };
        let mut names = Vec::new();
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(e) => return Err(StorageError::io("list project", e)),
            };
            // Best-effort per entry: only regular files with UTF-8 names
            // are listable objects; anything else is skipped, never fatal.
            let is_file = entry
                .file_type()
                .await
                .map(|t| t.is_file())
                .unwrap_or(false);
            if !is_file {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        fs::metadata(&self.root)
            .await
            .map(|_| ())
            .map_err(|e| StorageError::io("storage root unreachable", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn collect(body: Body) -> Vec<u8> {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    #[tokio::test]
    async fn filesystem_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();

        let staged = storage.stage_path().unwrap();
        tokio::fs::write(&staged, b"wheel-bytes").await.unwrap();
        let size = storage
            .put_file("demo-pkg", "demo_pkg-1.0-py3-none-any.whl", &staged)
            .await
            .unwrap();
        assert_eq!(size, 11);
        assert!(!staged.exists());

        assert_eq!(
            storage
                .stat("demo-pkg", "demo_pkg-1.0-py3-none-any.whl")
                .await
                .unwrap(),
            Some(11)
        );

        let (size, body) = storage
            .get("demo-pkg", "demo_pkg-1.0-py3-none-any.whl")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(size, 11);
        assert_eq!(collect(body).await, b"wheel-bytes");

        // Ranged reads stream exactly the requested slice plus total size.
        let (total, served, body) = storage
            .get_range("demo-pkg", "demo_pkg-1.0-py3-none-any.whl", 2, 4)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(total, 11);
        assert_eq!(served, 4);
        assert_eq!(collect(body).await, b"eel-");
        // Requests past the end clamp to what the object can serve.
        let (total, served, body) = storage
            .get_range("demo-pkg", "demo_pkg-1.0-py3-none-any.whl", 9, 100)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(total, 11);
        assert_eq!(served, 2);
        assert_eq!(collect(body).await, b"es");
        assert!(storage
            .get_range("demo-pkg", "missing.whl", 0, 4)
            .await
            .unwrap()
            .is_none());

        assert!(storage
            .get("demo-pkg", "missing.whl")
            .await
            .unwrap()
            .is_none());

        storage
            .delete("demo-pkg", "demo_pkg-1.0-py3-none-any.whl")
            .await
            .unwrap();
        assert!(storage
            .get("demo-pkg", "demo_pkg-1.0-py3-none-any.whl")
            .await
            .unwrap()
            .is_none());
        // Deleting again is a no-op.
        storage
            .delete("demo-pkg", "demo_pkg-1.0-py3-none-any.whl")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_path_traversal_segments() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();
        assert!(storage.get("..", "x.whl").await.is_err());
        assert!(storage.get("pkg", "../x.whl").await.is_err());
        assert!(storage.get("pkg", "a/b.whl").await.is_err());
        assert!(storage.stat("", "").await.is_err());
    }

    #[tokio::test]
    async fn rejects_nul_and_control_segments() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();
        for (project, filename) in [
            ("pkg\0", "x.whl"),
            ("pkg", "x\0.whl"),
            ("pk\ng", "x.whl"),
            ("pkg", "x\r.whl"),
            ("pkg", "x\t.whl"),
            ("pkg\x7f", "x.whl"),
        ] {
            let err = storage.get(project, filename).await.unwrap_err();
            assert!(
                matches!(err, StorageError::NotFound(_)),
                "expected NotFound for {project:?}/{filename:?}, got {err:?}"
            );
            let err = storage.stat(project, filename).await.unwrap_err();
            assert!(matches!(err, StorageError::NotFound(_)));
        }
        assert!(storage
            .get("demo-pkg", "ok-1.0-py3-none-any.whl")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn list_returns_sorted_filenames() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();

        // A missing project lists as empty, not an error.
        assert!(storage.list("no-such-project").await.unwrap().is_empty());

        for filename in ["b.whl", "a.whl"] {
            let staged = storage.stage_path().unwrap();
            tokio::fs::write(&staged, b"x").await.unwrap();
            storage
                .put_file("listpkg", filename, &staged)
                .await
                .unwrap();
        }
        // A subdirectory is not a listable object.
        tokio::fs::create_dir_all(dir.path().join("listpkg").join("subdir"))
            .await
            .unwrap();
        assert_eq!(
            storage.list("listpkg").await.unwrap(),
            vec!["a.whl".to_string(), "b.whl".to_string()]
        );
        // Other projects are unaffected.
        assert!(storage.list("other").await.unwrap().is_empty());

        for bad in ["..", "a/b", ""] {
            assert!(
                matches!(storage.list(bad).await, Err(StorageError::NotFound(_))),
                "expected NotFound for {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn staging_create_is_exclusive_and_sweep_removes_old() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::filesystem(dir.path().to_path_buf());
        storage.ensure_dirs().await.unwrap();

        let (first, file) = storage.create_staging_file().await.unwrap();
        assert!(first.exists());
        // A second create never reuses the same live path.
        let (second, file2) = storage.create_staging_file().await.unwrap();
        assert_ne!(first, second);
        drop(file);
        drop(file2);

        // Backdate one entry so the sweep decision is deterministic.
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(7200);
        std::fs::File::options()
            .write(true)
            .open(&first)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let removed = storage
            .sweep_staging_older_than(std::time::Duration::from_secs(3600))
            .unwrap();
        assert_eq!(removed, 1);
        assert!(!first.exists());
        assert!(second.exists());

        // Missing staging dir sweeps to zero instead of erroring.
        let bare = Storage::filesystem(dir.path().join("no-such-root"));
        assert_eq!(
            bare.sweep_staging_older_than(std::time::Duration::from_secs(0))
                .unwrap(),
            0
        );
    }
}

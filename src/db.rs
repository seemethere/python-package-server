//! Package metadata storage: Postgres-backed with an in-memory fallback.

use std::collections::HashMap;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;

use crate::error::{internal, AppError};

/// A stored file joined with its project's display name.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct FileRecord {
    pub project: String,
    pub project_display: String,
    pub filename: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub requires_python: Option<String>,
    pub uploaded_by: String,
}

/// A project row.
#[derive(Clone, Debug, sqlx::FromRow)]
pub struct ProjectRecord {
    pub name: String,
    pub display_name: String,
}

/// A file to insert; `project_display` seeds the project row on first use.
#[derive(Clone, Debug)]
pub struct NewFile {
    pub project_normalized: String,
    pub project_display: String,
    pub filename: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub requires_python: Option<String>,
    pub uploaded_by: String,
}

#[derive(Debug, Error)]
pub enum DbError {
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("database error: {0}")]
    Internal(String),
}

impl From<DbError> for AppError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::Conflict(msg) => AppError::Conflict(msg),
            DbError::Internal(msg) => internal(msg),
        }
    }
}

fn db_err<E: std::fmt::Display>(what: &str, err: E) -> DbError {
    DbError::Internal(format!("{what}: {err}"))
}

/// Metadata operations shared by all backends.
// Intentional native async fn: trait is crate-internal with Send+Sync supertraits.
#[allow(async_fn_in_trait)]
pub trait MetadataStore: Clone + Send + Sync + 'static {
    async fn upsert_project(&self, display_name: &str, normalized: &str) -> Result<(), DbError>;
    async fn insert_file(&self, file: &NewFile) -> Result<(), DbError>;
    async fn delete_file(&self, project: &str, filename: &str) -> Result<(), DbError>;
    async fn list_projects(&self) -> Result<Vec<ProjectRecord>, DbError>;
    async fn list_files(&self, project: &str) -> Result<Vec<FileRecord>, DbError>;
    async fn get_file(&self, project: &str, filename: &str) -> Result<Option<FileRecord>, DbError>;
    /// `(project, filename)` rows created more than `older_than_secs` ago, used
    /// by startup orphan reconciliation to find rows whose bytes never landed.
    async fn list_orphan_candidates(
        &self,
        older_than_secs: i64,
    ) -> Result<Vec<(String, String)>, DbError>;
    async fn health_check(&self) -> Result<(), DbError>;
}

/// Postgres-backed metadata store.
#[derive(Clone, Debug)]
pub struct PgStore {
    pool: sqlx::PgPool,
}

impl PgStore {
    pub async fn connect(url: &str) -> Result<Self, DbError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .idle_timeout(std::time::Duration::from_secs(60))
            .max_lifetime(std::time::Duration::from_secs(30 * 60))
            .connect(url)
            .await
            .map_err(|err| db_err("connect to postgres", err))?;
        Ok(Self { pool })
    }

    pub async fn run_migrations(&self) -> Result<(), DbError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|err| db_err("run migrations", err))?;
        Ok(())
    }
}

const LIST_FILES_SQL: &str = "SELECT f.project, p.display_name AS project_display, \
    f.filename, f.version, f.sha256, f.size_bytes, f.requires_python, f.uploaded_by \
    FROM files f JOIN projects p ON p.name = f.project \
    WHERE f.project = $1 ORDER BY f.filename";
const GET_FILE_SQL: &str = "SELECT f.project, p.display_name AS project_display, \
    f.filename, f.version, f.sha256, f.size_bytes, f.requires_python, f.uploaded_by \
    FROM files f JOIN projects p ON p.name = f.project \
    WHERE f.project = $1 AND f.filename = $2";

impl MetadataStore for PgStore {
    async fn upsert_project(&self, display_name: &str, normalized: &str) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO projects (name, display_name) VALUES ($1, $2) \
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(normalized)
        .bind(display_name)
        .execute(&self.pool)
        .await
        .map_err(|err| db_err("upsert project", err))?;
        Ok(())
    }

    async fn insert_file(&self, file: &NewFile) -> Result<(), DbError> {
        let result = sqlx::query(
            "INSERT INTO files (project, filename, version, sha256, size_bytes, \
             requires_python, uploaded_by) VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (project, filename) DO NOTHING",
        )
        .bind(&file.project_normalized)
        .bind(&file.filename)
        .bind(&file.version)
        .bind(&file.sha256)
        .bind(file.size_bytes)
        .bind(file.requires_python.as_deref())
        .bind(&file.uploaded_by)
        .execute(&self.pool)
        .await
        .map_err(|err| db_err("insert file", err))?;
        if result.rows_affected() == 0 {
            return Err(DbError::Conflict(format!(
                "{}/{} already exists",
                file.project_normalized, file.filename
            )));
        }
        Ok(())
    }

    async fn delete_file(&self, project: &str, filename: &str) -> Result<(), DbError> {
        sqlx::query("DELETE FROM files WHERE project = $1 AND filename = $2")
            .bind(project)
            .bind(filename)
            .execute(&self.pool)
            .await
            .map_err(|err| db_err("delete file", err))?;
        Ok(())
    }

    async fn list_projects(&self) -> Result<Vec<ProjectRecord>, DbError> {
        sqlx::query_as::<_, ProjectRecord>(
            "SELECT p.name, p.display_name FROM projects p \
             WHERE EXISTS (SELECT 1 FROM files f WHERE f.project = p.name) \
             ORDER BY p.name",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|err| db_err("list projects", err))
    }

    async fn list_files(&self, project: &str) -> Result<Vec<FileRecord>, DbError> {
        sqlx::query_as::<_, FileRecord>(LIST_FILES_SQL)
            .bind(project)
            .fetch_all(&self.pool)
            .await
            .map_err(|err| db_err("list files", err))
    }

    async fn get_file(&self, project: &str, filename: &str) -> Result<Option<FileRecord>, DbError> {
        sqlx::query_as::<_, FileRecord>(GET_FILE_SQL)
            .bind(project)
            .bind(filename)
            .fetch_optional(&self.pool)
            .await
            .map_err(|err| db_err("get file", err))
    }

    async fn list_orphan_candidates(
        &self,
        older_than_secs: i64,
    ) -> Result<Vec<(String, String)>, DbError> {
        sqlx::query_as::<_, (String, String)>(
            "SELECT project, filename FROM files \
             WHERE created_at < now() - make_interval(secs => $1::double precision)",
        )
        .bind(older_than_secs)
        .fetch_all(&self.pool)
        .await
        .map_err(|err| db_err("list orphan candidates", err))
    }

    async fn health_check(&self) -> Result<(), DbError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|err| db_err("health check", err))
    }
}

/// In-memory file row, mirroring [`FileRecord`].
#[derive(Clone, Debug)]
struct StoredFile {
    project: String,
    project_display: String,
    filename: String,
    version: String,
    sha256: String,
    size_bytes: i64,
    requires_python: Option<String>,
    uploaded_by: String,
}

impl StoredFile {
    fn record(&self) -> FileRecord {
        FileRecord {
            project: self.project.clone(),
            project_display: self.project_display.clone(),
            filename: self.filename.clone(),
            version: self.version.clone(),
            sha256: self.sha256.clone(),
            size_bytes: self.size_bytes,
            requires_python: self.requires_python.clone(),
            uploaded_by: self.uploaded_by.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Inner {
    /// Normalized project name -> first-seen display name.
    projects: HashMap<String, String>,
    files: HashMap<(String, String), StoredFile>,
    /// Insertion time per file, backing orphan-candidate age checks.
    inserted_at: HashMap<(String, String), std::time::Instant>,
}

/// In-memory metadata store with Postgres-equivalent semantics.
#[derive(Clone, Debug)]
pub struct MemoryStore {
    inner: Arc<RwLock<Inner>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner::default())),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MetadataStore for MemoryStore {
    async fn upsert_project(&self, display_name: &str, normalized: &str) -> Result<(), DbError> {
        self.inner
            .write()
            .await
            .projects
            .entry(normalized.to_string())
            .or_insert_with(|| display_name.to_string());
        Ok(())
    }

    async fn insert_file(&self, file: &NewFile) -> Result<(), DbError> {
        let mut inner = self.inner.write().await;
        let key = (file.project_normalized.clone(), file.filename.clone());
        if inner.files.contains_key(&key) {
            return Err(DbError::Conflict(format!(
                "{}/{} already exists",
                file.project_normalized, file.filename
            )));
        }
        // First display name wins, matching the Postgres upsert.
        let display = inner
            .projects
            .entry(file.project_normalized.clone())
            .or_insert_with(|| file.project_display.clone())
            .clone();
        inner.files.insert(
            key.clone(),
            StoredFile {
                project: file.project_normalized.clone(),
                project_display: display,
                filename: file.filename.clone(),
                version: file.version.clone(),
                sha256: file.sha256.clone(),
                size_bytes: file.size_bytes,
                requires_python: file.requires_python.clone(),
                uploaded_by: file.uploaded_by.clone(),
            },
        );
        inner.inserted_at.insert(key, std::time::Instant::now());
        Ok(())
    }

    async fn delete_file(&self, project: &str, filename: &str) -> Result<(), DbError> {
        let mut inner = self.inner.write().await;
        let key = (project.to_string(), filename.to_string());
        inner.files.remove(&key);
        inner.inserted_at.remove(&key);
        Ok(())
    }

    async fn list_projects(&self) -> Result<Vec<ProjectRecord>, DbError> {
        let inner = self.inner.read().await;
        let mut projects: Vec<ProjectRecord> = inner
            .projects
            .iter()
            .filter(|(name, _)| inner.files.keys().any(|(project, _)| project == *name))
            .map(|(name, display_name)| ProjectRecord {
                name: name.clone(),
                display_name: display_name.clone(),
            })
            .collect();
        projects.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(projects)
    }

    async fn list_files(&self, project: &str) -> Result<Vec<FileRecord>, DbError> {
        let inner = self.inner.read().await;
        let mut files: Vec<FileRecord> = inner
            .files
            .values()
            .filter(|f| f.project == project)
            .map(|f| f.record())
            .collect();
        files.sort_by(|a, b| a.filename.cmp(&b.filename));
        Ok(files)
    }

    async fn get_file(&self, project: &str, filename: &str) -> Result<Option<FileRecord>, DbError> {
        Ok(self
            .inner
            .read()
            .await
            .files
            .get(&(project.to_string(), filename.to_string()))
            .map(|f| f.record()))
    }

    async fn list_orphan_candidates(
        &self,
        older_than_secs: i64,
    ) -> Result<Vec<(String, String)>, DbError> {
        let cutoff = std::time::Duration::from_secs(older_than_secs.max(0) as u64);
        let inner = self.inner.read().await;
        Ok(inner
            .inserted_at
            .iter()
            .filter(|(_, inserted)| inserted.elapsed() > cutoff)
            .map(|(key, _)| key.clone())
            .collect())
    }

    async fn health_check(&self) -> Result<(), DbError> {
        Ok(())
    }
}

/// Backend dispatch for metadata storage.
#[derive(Clone, Debug)]
pub enum MetadataBackend {
    Postgres(PgStore),
    Memory(MemoryStore),
}

impl MetadataStore for MetadataBackend {
    async fn upsert_project(&self, display_name: &str, normalized: &str) -> Result<(), DbError> {
        match self {
            Self::Postgres(store) => store.upsert_project(display_name, normalized).await,
            Self::Memory(store) => store.upsert_project(display_name, normalized).await,
        }
    }

    async fn insert_file(&self, file: &NewFile) -> Result<(), DbError> {
        match self {
            Self::Postgres(store) => store.insert_file(file).await,
            Self::Memory(store) => store.insert_file(file).await,
        }
    }

    async fn delete_file(&self, project: &str, filename: &str) -> Result<(), DbError> {
        match self {
            Self::Postgres(store) => store.delete_file(project, filename).await,
            Self::Memory(store) => store.delete_file(project, filename).await,
        }
    }

    async fn list_projects(&self) -> Result<Vec<ProjectRecord>, DbError> {
        match self {
            Self::Postgres(store) => store.list_projects().await,
            Self::Memory(store) => store.list_projects().await,
        }
    }

    async fn list_files(&self, project: &str) -> Result<Vec<FileRecord>, DbError> {
        match self {
            Self::Postgres(store) => store.list_files(project).await,
            Self::Memory(store) => store.list_files(project).await,
        }
    }

    async fn get_file(&self, project: &str, filename: &str) -> Result<Option<FileRecord>, DbError> {
        match self {
            Self::Postgres(store) => store.get_file(project, filename).await,
            Self::Memory(store) => store.get_file(project, filename).await,
        }
    }

    async fn list_orphan_candidates(
        &self,
        older_than_secs: i64,
    ) -> Result<Vec<(String, String)>, DbError> {
        match self {
            Self::Postgres(store) => store.list_orphan_candidates(older_than_secs).await,
            Self::Memory(store) => store.list_orphan_candidates(older_than_secs).await,
        }
    }

    async fn health_check(&self) -> Result<(), DbError> {
        match self {
            Self::Postgres(store) => store.health_check().await,
            Self::Memory(store) => store.health_check().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_file(project: &str, filename: &str) -> NewFile {
        NewFile {
            project_normalized: project.to_string(),
            project_display: "Demo-Pkg".to_string(),
            filename: filename.to_string(),
            version: "1.2.3".to_string(),
            sha256: "abc".to_string(),
            size_bytes: 42,
            requires_python: Some(">=3.8".to_string()),
            uploaded_by: "alice".to_string(),
        }
    }

    #[tokio::test]
    async fn first_display_name_wins() {
        let store = MemoryStore::new();
        store.upsert_project("Demo-Pkg", "demo-pkg").await.unwrap();
        store.upsert_project("Other", "demo-pkg").await.unwrap();
        store
            .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
            .await
            .unwrap();
        let projects = store.list_projects().await.unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].display_name, "Demo-Pkg");
    }

    #[tokio::test]
    async fn list_projects_skips_empty_projects() {
        let store = MemoryStore::new();
        store.upsert_project("Empty", "empty").await.unwrap();
        assert!(store.list_projects().await.unwrap().is_empty());
        store
            .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
            .await
            .unwrap();
        let projects = store.list_projects().await.unwrap();
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].name, "demo-pkg");
        // Deleting the last file hides the project again.
        store
            .delete_file("demo-pkg", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap();
        assert!(store.list_projects().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn orphan_candidates_respect_age_cutoff() {
        let store = MemoryStore::new();
        store
            .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
            .await
            .unwrap();
        // Fresh rows are younger than any positive cutoff.
        assert!(store.list_orphan_candidates(900).await.unwrap().is_empty());
        // A zero cutoff matches everything already inserted.
        let candidates = store.list_orphan_candidates(0).await.unwrap();
        assert_eq!(
            candidates,
            vec![("demo-pkg".to_string(), "demo-pkg-1.2.3.tar.gz".to_string())]
        );
        // Deleted rows disappear from candidates.
        store
            .delete_file("demo-pkg", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap();
        assert!(store.list_orphan_candidates(0).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn insert_get_and_list_files() {
        let store = MemoryStore::new();
        store.upsert_project("Demo-Pkg", "demo-pkg").await.unwrap();
        store
            .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
            .await
            .unwrap();
        store
            .insert_file(&new_file("demo-pkg", "demo_pkg-1.2.3-py3-none-any.whl"))
            .await
            .unwrap();

        let file = store
            .get_file("demo-pkg", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(file.project_display, "Demo-Pkg");
        assert_eq!(file.version, "1.2.3");
        assert_eq!(file.uploaded_by, "alice");
        assert!(store
            .get_file("demo-pkg", "missing.whl")
            .await
            .unwrap()
            .is_none());
        assert!(store
            .get_file("other", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap()
            .is_none());

        let files = store.list_files("demo-pkg").await.unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].filename, "demo-pkg-1.2.3.tar.gz");
        assert_eq!(files[1].filename, "demo_pkg-1.2.3-py3-none-any.whl");
        assert!(store.list_files("other").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicate_insert_conflicts() {
        let store = MemoryStore::new();
        store
            .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
            .await
            .unwrap();
        assert!(matches!(
            store
                .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
                .await,
            Err(DbError::Conflict(_))
        ));
    }

    #[tokio::test]
    async fn delete_is_idempotent() {
        let store = MemoryStore::new();
        store
            .insert_file(&new_file("demo-pkg", "demo-pkg-1.2.3.tar.gz"))
            .await
            .unwrap();
        store
            .delete_file("demo-pkg", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap();
        assert!(store
            .get_file("demo-pkg", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap()
            .is_none());
        store
            .delete_file("demo-pkg", "demo-pkg-1.2.3.tar.gz")
            .await
            .unwrap();
        store.delete_file("other", "x.whl").await.unwrap();
    }

    #[tokio::test]
    async fn projects_sorted_by_name() {
        let store = MemoryStore::new();
        store.upsert_project("Zebra", "zebra").await.unwrap();
        store.upsert_project("Apple", "apple").await.unwrap();
        store
            .insert_file(&new_file("zebra", "zebra-1.2.3.tar.gz"))
            .await
            .unwrap();
        store
            .insert_file(&new_file("apple", "apple-1.2.3.tar.gz"))
            .await
            .unwrap();
        let projects = store.list_projects().await.unwrap();
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].name, "apple");
        assert_eq!(projects[1].name, "zebra");
    }

    #[tokio::test]
    async fn health_ok() {
        assert!(MemoryStore::new().health_check().await.is_ok());
    }
}

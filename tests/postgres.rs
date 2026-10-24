//! Postgres-backed metadata tests.
//!
//! Skipped unless `TEST_DATABASE_URL` is set (CI provides a Postgres
//! service). Exercises the production `PgStore` path — migrations, conflict
//! handling, and listing — that the in-memory store cannot cover.

use python_package_server::db::{DbError, MetadataStore, NewFile, PgStore};

fn unique_project() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("ci-pg-{}-{nanos}", std::process::id())
}

fn new_file(project: &str, filename: &str) -> NewFile {
    NewFile {
        project_normalized: project.to_string(),
        project_display: "Ci-Pg".to_string(),
        filename: filename.to_string(),
        version: "1.2.3".to_string(),
        sha256: "abc123".to_string(),
        size_bytes: 42,
        requires_python: Some(">=3.8".to_string()),
        uploaded_by: "ci".to_string(),
    }
}

#[tokio::test]
async fn postgres_metadata_roundtrip() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL unset; skipping Postgres tests");
        return;
    };
    let store = PgStore::connect(&url).await.expect("connect to postgres");
    store.run_migrations().await.expect("run migrations");
    store.health_check().await.expect("health check");

    let project = unique_project();
    let filename = format!("{project}-1.2.3.tar.gz");

    store
        .upsert_project("Ci-Pg", &project)
        .await
        .expect("upsert project");
    // Re-upserting is a no-op and keeps the first display name.
    store
        .upsert_project("Other", &project)
        .await
        .expect("re-upsert project");

    store
        .insert_file(&new_file(&project, &filename))
        .await
        .expect("insert file");

    // Duplicate (project, filename) conflicts, matching MemoryStore.
    let dup = store.insert_file(&new_file(&project, &filename)).await;
    assert!(
        matches!(dup, Err(DbError::Conflict(_))),
        "expected conflict, got {dup:?}"
    );

    let got = store
        .get_file(&project, &filename)
        .await
        .expect("get file")
        .expect("file present");
    assert_eq!(got.version, "1.2.3");
    assert_eq!(got.project_display, "Ci-Pg");
    assert_eq!(got.uploaded_by, "ci");

    let files = store.list_files(&project).await.expect("list files");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].filename, filename);

    let projects = store.list_projects().await.expect("list projects");
    assert!(
        projects.iter().any(|p| p.name == project),
        "project {project} missing from {projects:?}"
    );

    // A zero age cutoff lists every already-inserted row.
    let candidates = store
        .list_orphan_candidates(0)
        .await
        .expect("orphan candidates");
    assert!(
        candidates.contains(&(project.clone(), filename.clone())),
        "({project}, {filename}) missing from {candidates:?}"
    );

    store
        .delete_file(&project, &filename)
        .await
        .expect("delete file");
    assert!(store
        .get_file(&project, &filename)
        .await
        .expect("get deleted file")
        .is_none());
    // The project disappears once its last file is gone.
    let projects = store.list_projects().await.expect("list projects");
    assert!(!projects.iter().any(|p| p.name == project));
}

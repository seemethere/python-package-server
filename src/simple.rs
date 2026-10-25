//! PEP 503 (HTML) and PEP 691 (JSON) simple-index handlers.

use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    db::{FileRecord, MetadataStore, ProjectRecord},
    error::AppError,
    packaging::normalize_project,
    state::AppState,
};

const JSON_CONTENT_TYPE: &str = "application/vnd.pypi.simple.v1+json";
const HTML_CONTENT_TYPE: &str = "text/html; charset=utf-8";
const HTML_HEAD: &str = "<!DOCTYPE html><html><head><meta name=\"pypi:repository-version\" content=\"1.1\"><title>Simple index</title></head><body>";
const HTML_TAIL: &str = "</body></html>";

/// Project list (`GET /simple/`), HTML or JSON via content negotiation.
pub async fn simple_index(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let projects = state.db.list_projects().await?;
    if wants_json(&headers) {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
            index_json(&projects),
        )
            .into_response())
    } else {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, HTML_CONTENT_TYPE)],
            index_html(&projects),
        )
            .into_response())
    }
}

/// Project detail (`GET /simple/{project}/`), HTML or JSON via content negotiation.
pub async fn simple_project(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let normalized = normalize_project(&project)
        .map_err(|_| AppError::NotFound(format!("project {project} not found")))?;
    let hosted = state.db.list_files(normalized.as_str()).await?;
    let upstream_files = match &state.upstream {
        Some(client) if !client.is_private_only(normalized.as_str()) => {
            match client.fetch_project(normalized.as_str()).await {
                Ok(Some(files)) => files,
                Ok(None) => Vec::new(),
                Err(err) => return Err(AppError::BadGateway(err.to_string())),
            }
        }
        _ => Vec::new(),
    };
    if hosted.is_empty() && upstream_files.is_empty() {
        return Err(AppError::NotFound(format!(
            "project {} not found",
            normalized.as_str()
        )));
    }
    let display_owned = hosted
        .first()
        .map(|f| f.project_display.clone())
        .unwrap_or_else(|| normalized.as_str().to_string());
    let display = display_owned.as_str();
    let files = merge_files(&hosted, upstream_files, normalized.as_str(), display);
    if wants_json(&headers) {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, JSON_CONTENT_TYPE)],
            project_json(display, &files),
        )
            .into_response())
    } else {
        Ok((
            StatusCode::OK,
            [(header::CONTENT_TYPE, HTML_CONTENT_TYPE)],
            project_html(display, &files),
        )
            .into_response())
    }
}

fn merge_files(
    hosted: &[FileRecord],
    upstream: Vec<crate::upstream::UpstreamFile>,
    normalized: &str,
    display: &str,
) -> Vec<FileRecord> {
    let hosted_names: std::collections::HashSet<&str> =
        hosted.iter().map(|f| f.filename.as_str()).collect();
    let mut merged = hosted.to_vec();
    for file in upstream {
        if hosted_names.contains(file.filename.as_str()) {
            continue;
        }
        merged.push(FileRecord {
            project: normalized.to_string(),
            project_display: display.to_string(),
            filename: file.filename,
            version: String::new(),
            sha256: file.sha256,
            size_bytes: 0,
            requires_python: file.requires_python,
            uploaded_by: String::new(),
            yanked: file.yanked,
            yank_reason: file.yank_reason,
        });
    }
    merged
}

/// True when the client prefers the PEP 691 JSON representation.
///
/// A JSON media type with an explicit `q=0` parameter declines JSON; with
/// `q>0` or no `q` it selects JSON. Unparseable parameters fall back to a
/// plain substring match.
fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(accepts_json)
}

/// Check one `Accept` header value for a non-declined JSON media type.
fn accepts_json(value: &str) -> bool {
    value.match_indices(JSON_CONTENT_TYPE).any(|(start, _)| {
        let params = value[start + JSON_CONTENT_TYPE.len()..]
            .split(',')
            .next()
            .unwrap_or("");
        !declined_by_q(params)
    })
}

/// True when a media-type parameter string carries `q=0` (any zero spelling).
fn declined_by_q(params: &str) -> bool {
    params.split(';').skip(1).any(|param| {
        let param = param.trim();
        let Some(q) = param
            .strip_prefix("q=")
            .or_else(|| param.strip_prefix("Q="))
        else {
            return false;
        };
        q.trim().parse::<f32>().is_ok_and(|q| q == 0.0)
    })
}

/// Percent-encode a URL path segment (RFC 3986 unreserved set passes through).
fn percent_encode(segment: &str) -> String {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if UNRESERVED.contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Escape `&<>"'` for HTML text and attribute values.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Render the PEP 503 project-list page.
fn index_html(projects: &[ProjectRecord]) -> String {
    let mut body = String::from(HTML_HEAD);
    for project in projects {
        let href = escape(&format!("/simple/{}/", percent_encode(&project.name)));
        body.push_str(&format!(
            "<a href=\"{href}\">{}</a><br/>",
            escape(&project.display_name)
        ));
    }
    body.push_str(HTML_TAIL);
    body
}

/// Render the PEP 691 project-list document.
fn index_json(projects: &[ProjectRecord]) -> String {
    serde_json::json!({
        "meta": {"api-version": "1.1"},
        "projects": projects
            .iter()
            .map(|project| serde_json::json!({"name": project.display_name}))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

/// Render the PEP 503 per-project page.
fn project_html(display: &str, files: &[FileRecord]) -> String {
    let mut body = String::from(HTML_HEAD);
    body.push_str(&format!("<h1>{}</h1>", escape(display)));
    for file in files {
        let href = escape(&format!(
            "/files/{}/{}#sha256={}",
            percent_encode(&file.project),
            percent_encode(&file.filename),
            file.sha256
        ));
        body.push_str(&format!("<a href=\"{href}\""));
        if let Some(requires_python) = &file.requires_python {
            body.push_str(&format!(
                " data-requires-python=\"{}\"",
                escape(requires_python)
            ));
        }
        if file.yanked {
            body.push_str(&format!(
                " data-yanked=\"{}\"",
                escape(file.yank_reason.as_deref().unwrap_or(""))
            ));
        }
        body.push_str(&format!(">{}</a><br/>", escape(&file.filename)));
    }
    body.push_str(HTML_TAIL);
    body
}

/// PEP 691 yank value: `false`, `true`, or the yank reason string.
fn yanked_value(file: &FileRecord) -> serde_json::Value {
    if !file.yanked {
        serde_json::Value::Bool(false)
    } else if let Some(reason) = &file.yank_reason {
        serde_json::Value::String(reason.clone())
    } else {
        serde_json::Value::Bool(true)
    }
}

/// Render the PEP 691 per-project document.
fn project_json(display: &str, files: &[FileRecord]) -> String {
    serde_json::json!({
        "meta": {"api-version": "1.1"},
        "name": display,
        "files": files
            .iter()
            .map(|file| serde_json::json!({
                "filename": file.filename,
                "url": format!(
                    "/files/{}/{}",
                    percent_encode(&file.project),
                    percent_encode(&file.filename)
                ),
                "hashes": {"sha256": file.sha256},
                "requires-python": file.requires_python,
                "yanked": yanked_value(file),
                "data-dist-info-metadata": false,
            }))
            .collect::<Vec<_>>(),
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn projects() -> Vec<ProjectRecord> {
        vec![
            ProjectRecord {
                name: "demo-pkg".to_string(),
                display_name: "Demo-Pkg".to_string(),
                owner: Some("alice".to_string()),
            },
            ProjectRecord {
                name: "other".to_string(),
                display_name: "Other & <Co>".to_string(),
                owner: None,
            },
        ]
    }

    fn files() -> Vec<FileRecord> {
        vec![FileRecord {
            project: "demo-pkg".to_string(),
            project_display: "Demo-Pkg".to_string(),
            filename: "demo-pkg-1.2.3.tar.gz".to_string(),
            version: "1.2.3".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 42,
            requires_python: Some(">=3.8".to_string()),
            uploaded_by: "alice".to_string(),
            yanked: false,
            yank_reason: None,
        }]
    }

    #[test]
    fn renders_index_html() {
        let html = index_html(&projects());
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<meta name=\"pypi:repository-version\" content=\"1.1\">"));
        assert!(html.contains("<a href=\"/simple/demo-pkg/\">Demo-Pkg</a><br/>"));
        assert!(html.contains("<a href=\"/simple/other/\">Other &amp; &lt;Co&gt;</a><br/>"));
        assert!(html.ends_with("</body></html>"));
    }

    #[test]
    fn renders_index_json() {
        let value: serde_json::Value = serde_json::from_str(&index_json(&projects())).unwrap();
        assert_eq!(value["meta"]["api-version"], "1.1");
        assert_eq!(value["projects"][0]["name"], "Demo-Pkg");
        assert_eq!(value["projects"][1]["name"], "Other & <Co>");
    }

    #[test]
    fn renders_project_html() {
        let html = project_html("Demo-Pkg", &files());
        assert!(html.contains("<h1>Demo-Pkg</h1>"));
        assert!(html.contains(
            "<a href=\"/files/demo-pkg/demo-pkg-1.2.3.tar.gz#sha256=abc123\" \
             data-requires-python=\"&gt;=3.8\">demo-pkg-1.2.3.tar.gz</a><br/>"
        ));
    }

    #[test]
    fn escapes_heading_and_hrefs() {
        let files = vec![FileRecord {
            project: "demo-pkg".to_string(),
            project_display: "Demo-Pkg".to_string(),
            filename: "evil\"><script>alert(1)</script>.whl".to_string(),
            version: "1.2.3".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 42,
            requires_python: None,
            uploaded_by: "alice".to_string(),
            yanked: false,
            yank_reason: None,
        }];
        let html = project_html("Evil & <Pkg>", &files);
        assert!(html.contains("<h1>Evil &amp; &lt;Pkg&gt;</h1>"));
        assert!(!html.contains("<script>"));
        assert!(!html.contains("\"><script>"));
        // Every reserved byte is percent-encoded; the href is inert text.
        assert!(html.contains(
            "/files/demo-pkg/evil%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E.whl#sha256=abc123"
        ));
        // Link text is HTML-escaped, not raw.
        assert!(html.contains("evil&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;.whl</a>"));

        let projects = vec![ProjectRecord {
            name: "weird pkg/x".to_string(),
            display_name: "Weird <Pkg>".to_string(),
            owner: None,
        }];
        let index = index_html(&projects);
        assert!(index.contains("<a href=\"/simple/weird%20pkg%2Fx/\">Weird &lt;Pkg&gt;</a>"));
    }

    #[test]
    fn encodes_only_unreserved_bytes() {
        assert_eq!(percent_encode("Abc-09_.~"), "Abc-09_.~");
        assert_eq!(percent_encode("a b/c?"), "a%20b%2Fc%3F");
        assert_eq!(percent_encode("\"<>&"), "%22%3C%3E%26");
        // Non-ASCII is encoded byte-wise as UTF-8.
        assert_eq!(percent_encode("naïve"), "na%C3%AFve");
    }

    #[test]
    fn omits_requires_python_attribute_when_absent() {
        let mut files = files();
        files[0].requires_python = None;
        let html = project_html("Demo-Pkg", &files);
        assert!(html.contains(
            "<a href=\"/files/demo-pkg/demo-pkg-1.2.3.tar.gz#sha256=abc123\">\
             demo-pkg-1.2.3.tar.gz</a><br/>"
        ));
        assert!(!html.contains("data-requires-python"));
    }

    #[test]
    fn renders_project_json() {
        let value: serde_json::Value =
            serde_json::from_str(&project_json("Demo-Pkg", &files())).unwrap();
        assert_eq!(value["meta"]["api-version"], "1.1");
        assert_eq!(value["name"], "Demo-Pkg");
        let file = &value["files"][0];
        assert_eq!(file["filename"], "demo-pkg-1.2.3.tar.gz");
        assert_eq!(file["url"], "/files/demo-pkg/demo-pkg-1.2.3.tar.gz");
        assert_eq!(file["hashes"]["sha256"], "abc123");
        assert_eq!(file["requires-python"], ">=3.8");
        assert_eq!(file["yanked"], false);
        assert_eq!(file["data-dist-info-metadata"], false);

        let mut files = files();
        files[0].requires_python = None;
        let value: serde_json::Value =
            serde_json::from_str(&project_json("Demo-Pkg", &files)).unwrap();
        assert!(value["files"][0]["requires-python"].is_null());
    }

    #[test]
    fn renders_yanked_files() {
        let mut files = files();
        files[0].yanked = true;
        files[0].yank_reason = Some("bad <build>".to_string());

        let html = project_html("Demo-Pkg", &files);
        assert!(html.contains("data-yanked=\"bad &lt;build&gt;\""), "{html}");

        let value: serde_json::Value =
            serde_json::from_str(&project_json("Demo-Pkg", &files)).unwrap();
        assert_eq!(value["files"][0]["yanked"], "bad <build>");

        // Yanked without a reason renders as boolean true / empty attribute.
        files[0].yank_reason = None;
        let html = project_html("Demo-Pkg", &files);
        assert!(html.contains("data-yanked=\"\""), "{html}");
        let value: serde_json::Value =
            serde_json::from_str(&project_json("Demo-Pkg", &files)).unwrap();
        assert_eq!(value["files"][0]["yanked"], true);

        // Unyanked files carry no yank marker in either format.
        files[0].yanked = false;
        let html = project_html("Demo-Pkg", &files);
        assert!(!html.contains("data-yanked"), "{html}");
        let value: serde_json::Value =
            serde_json::from_str(&project_json("Demo-Pkg", &files)).unwrap();
        assert_eq!(value["files"][0]["yanked"], false);
    }

    #[test]
    fn project_json_percent_encodes_file_urls() {
        let mut files = files();
        files[0].filename = "demo pkg-1.2.3.tar.gz".to_string();
        let value: serde_json::Value =
            serde_json::from_str(&project_json("Demo-Pkg", &files)).unwrap();
        // The filename field stays raw; only the URL is percent-encoded,
        // matching the HTML rendering.
        assert_eq!(value["files"][0]["filename"], "demo pkg-1.2.3.tar.gz");
        assert_eq!(
            value["files"][0]["url"],
            "/files/demo-pkg/demo%20pkg-1.2.3.tar.gz"
        );
    }

    #[test]
    fn detects_json_accept_header() {
        let mut json = HeaderMap::new();
        json.insert(
            header::ACCEPT,
            "application/vnd.pypi.simple.v1+json".parse().unwrap(),
        );
        assert!(wants_json(&json));

        let mut html = HeaderMap::new();
        html.insert(header::ACCEPT, "text/html".parse().unwrap());
        assert!(!wants_json(&html));

        assert!(!wants_json(&HeaderMap::new()));
    }

    #[test]
    fn honors_json_q_values() {
        fn check(accept: &str) -> bool {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, accept.parse().unwrap());
            wants_json(&headers)
        }
        // Explicit q=0 (any zero spelling) declines JSON.
        assert!(!check("application/vnd.pypi.simple.v1+json;q=0"));
        assert!(!check("application/vnd.pypi.simple.v1+json; q=0"));
        assert!(!check("application/vnd.pypi.simple.v1+json;q=0.0"));
        assert!(!check("application/vnd.pypi.simple.v1+json;q=0.00"));
        assert!(!check("text/html, application/vnd.pypi.simple.v1+json;q=0"));
        // q>0 or absent selects JSON.
        assert!(check("application/vnd.pypi.simple.v1+json;q=1"));
        assert!(check("application/vnd.pypi.simple.v1+json;q=0.9"));
        assert!(check("application/vnd.pypi.simple.v1+json; q=0.5"));
        assert!(check(
            "text/html;q=0.9, application/vnd.pypi.simple.v1+json;q=0.8"
        ));
        // Unparseable q falls back to substring detection.
        assert!(check("application/vnd.pypi.simple.v1+json;q=bogus"));
        assert!(!check("text/html;q=0.9"));
    }

    #[test]
    fn escapes_html_specials() {
        assert_eq!(escape("&<>\"'"), "&amp;&lt;&gt;&quot;&#x27;");
        assert_eq!(escape("plain"), "plain");
    }
}

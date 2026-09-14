//! Project name normalization and distribution filename parsing.

use std::str::FromStr;

use crate::error::AppError;

/// A successfully parsed distribution filename.
#[derive(Clone, Debug)]
pub struct ParsedFile {
    /// PEP 440 version extracted from the filename.
    pub version: pep440_rs::Version,
    /// True for wheels (`*.whl`), false for sdists.
    pub is_wheel: bool,
}

/// Normalize a project name (PEP 503: lowercase, `-_.` runs become `-`).
pub fn normalize_project(name: &str) -> Result<uv_normalize::PackageName, AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::BadRequest("invalid project name".to_string()));
    }
    uv_normalize::PackageName::from_str(trimmed)
        .map_err(|err| AppError::BadRequest(format!("invalid project name '{trimmed}': {err}")))
}

/// Parse a distribution filename, verifying it belongs to `name`.
pub fn parse_filename(
    filename: &str,
    name: &uv_normalize::PackageName,
) -> Result<ParsedFile, AppError> {
    if filename.contains('/') || filename.contains('\\') || filename.contains("..") {
        return Err(AppError::BadRequest(format!(
            "invalid distribution filename '{filename}'"
        )));
    }
    let dist = uv_distribution_filename::DistFilename::try_from_filename(filename, name)
        .ok_or_else(|| {
            AppError::BadRequest(format!("invalid distribution filename '{filename}'"))
        })?;
    let is_wheel = matches!(
        dist,
        uv_distribution_filename::DistFilename::WheelFilename(_)
    );
    // uv-distribution-filename carries a uv-pep440 Version; convert through its
    // normalized string form (infallible for PEP 440 output).
    let version =
        pep440_rs::Version::from_str(&dist.into_version().to_string()).map_err(|err| {
            AppError::BadRequest(format!("invalid distribution filename '{filename}': {err}"))
        })?;
    Ok(ParsedFile { version, is_wheel })
}

/// Validate an optional `Requires-Python` specifier, returning its trimmed form.
pub fn check_requires_python(value: Option<&str>) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    pep440_rs::VersionSpecifiers::from_str(trimmed).map_err(|err| {
        AppError::BadRequest(format!("invalid requires-python '{trimmed}': {err}"))
    })?;
    Ok(Some(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_separators() {
        assert_eq!(
            normalize_project("Demo__Pkg.Name").unwrap().to_string(),
            "demo-pkg-name"
        );
        assert_eq!(
            normalize_project("  demo-pkg  ").unwrap().to_string(),
            "demo-pkg"
        );
    }

    #[test]
    fn rejects_invalid_names() {
        for name in ["", "   ", "!!!", "a b", "-foo"] {
            assert!(
                matches!(normalize_project(name), Err(AppError::BadRequest(_))),
                "expected BadRequest for {name:?}"
            );
        }
    }

    #[test]
    fn parses_wheel_filename() {
        let name = normalize_project("demo-pkg").unwrap();
        let parsed = parse_filename("demo_pkg-1.2.3-py3-none-any.whl", &name).unwrap();
        assert!(parsed.is_wheel);
        assert_eq!(parsed.version.to_string(), "1.2.3");
    }

    #[test]
    fn parses_sdist_filename() {
        let name = normalize_project("demo-pkg").unwrap();
        let parsed = parse_filename("demo-pkg-1.2.3.tar.gz", &name).unwrap();
        assert!(!parsed.is_wheel);
        assert_eq!(parsed.version.to_string(), "1.2.3");
    }

    #[test]
    fn rejects_invalid_filenames() {
        let name = normalize_project("demo-pkg").unwrap();
        for filename in [
            "demo-pkg-1.2.3.txt",
            "demo-pkg-1.2.3-py3-none-any.whlX",
            "other-1.0.tar.gz",
            "../demo-pkg-1.2.3.tar.gz",
            "sub/demo-pkg-1.2.3.tar.gz",
            "..\\demo-pkg-1.2.3.tar.gz",
            "demo-pkg-..-1.2.3.tar.gz",
        ] {
            assert!(
                matches!(
                    parse_filename(filename, &name),
                    Err(AppError::BadRequest(_))
                ),
                "expected BadRequest for {filename:?}"
            );
        }
    }

    #[test]
    fn validates_requires_python() {
        assert_eq!(check_requires_python(None).unwrap(), None);
        assert_eq!(check_requires_python(Some("")).unwrap(), None);
        assert_eq!(check_requires_python(Some("   ")).unwrap(), None);
        assert_eq!(
            check_requires_python(Some(">=3.8")).unwrap(),
            Some(">=3.8".to_string())
        );
        assert_eq!(
            check_requires_python(Some("  >=3.8, <4  ")).unwrap(),
            Some(">=3.8, <4".to_string())
        );
        assert!(matches!(
            check_requires_python(Some("bogus!!!")),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            check_requires_python(Some("=>1.0")),
            Err(AppError::BadRequest(_))
        ));
    }
}

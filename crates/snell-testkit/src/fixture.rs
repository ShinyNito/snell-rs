//! Golden fixture schema for Phase 1 and later codec tests.
//!
//! Fixtures are JSON files under `tests/golden/`.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GoldenFixture {
    pub name: String,
    pub kind: String,
    pub notes: String,
    pub psk_utf8: Option<String>,
    /// Wire bytes, decoded from the fixture's `hex` once at load.
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("{path}: {message}")]
    Invalid { path: PathBuf, message: String },
}

pub fn load_golden_dir(dir: impl AsRef<Path>) -> Result<Vec<GoldenFixture>, FixtureError> {
    let mut fixtures = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir.as_ref())?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        fixtures.push(load_golden_file(&path)?);
    }
    Ok(fixtures)
}

pub fn load_golden_file(path: impl AsRef<Path>) -> Result<GoldenFixture, FixtureError> {
    let path = path.as_ref();
    let raw = fs::read_to_string(path)?;
    parse_fixture(path, &raw)
}

fn parse_fixture(path: &Path, raw: &str) -> Result<GoldenFixture, FixtureError> {
    let name = required_field(path, raw, "name")?;
    let kind = required_field(path, raw, "kind")?;
    let notes = optional_field(raw, "notes").unwrap_or_default();
    let psk_utf8 = optional_field(raw, "psk_utf8");
    let hex: String = required_field(path, raw, "hex")?
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();
    let bytes = decode_hex(&hex).map_err(|message| FixtureError::Invalid {
        path: path.to_path_buf(),
        message,
    })?;
    Ok(GoldenFixture {
        name,
        kind,
        notes,
        psk_utf8,
        bytes,
    })
}

fn required_field(path: &Path, raw: &str, key: &str) -> Result<String, FixtureError> {
    optional_field(raw, key).ok_or_else(|| FixtureError::Invalid {
        path: path.to_path_buf(),
        message: format!("missing `{key}`"),
    })
}

fn optional_field(raw: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\"");
    let rest = raw.split_once(&pattern)?.1;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                other => out.push(other),
            },
            '"' => return Some(out),
            other => out.push(other),
        }
    }
    None
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let (pairs, []) = hex.as_bytes().as_chunks::<2>() else {
        return Err("odd hex length".to_owned());
    };
    pairs
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| format!("invalid hex pair {}", pair.escape_ascii()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_fixture() {
        let raw = r#"{
  "name": "connect-v2",
  "kind": "plaintext-control",
  "notes": "reuse CONNECT",
  "hex": "010503"
}"#;
        let fixture = parse_fixture(Path::new("connect-v2.json"), raw).unwrap();
        assert_eq!(fixture.name, "connect-v2");
        assert_eq!(fixture.bytes, [0x01, 0x05, 0x03]);
        assert!(parse_fixture(Path::new("odd.json"), &raw.replace("010503", "01050")).is_err());
    }
}

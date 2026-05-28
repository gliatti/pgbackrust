//! Google Cloud Storage backend.
//!
//! Implements the [`Storage`] trait over Google Cloud Storage using the same
//! synchronous [`ureq`] HTTP client as the S3 and Azure backends (blocking, no
//! async runtime). The C reference is `src/storage/gcs/`.
//!
//! ## Authentication
//!
//! pgBackRest's gcs backend authenticates several ways: a service-account key
//! (JWT → `OAuth2` bearer token), an auto-discovered GCE instance token, and a
//! pre-supplied bearer token. This backend implements the **bearer-token** path
//! ([`GcsAuth::Token`]): every request carries an `Authorization: Bearer
//! <token>` header. The [`GcsAuth`] enum is left open so service-account JWT
//! (RS256) auth — which needs an RSA signing dependency and a token-refresh
//! flow — can be added later without changing the public surface.
//!
//! ## Addressing
//!
//! This backend uses GCS's **XML API**, which is closest to the S3 backend: an
//! object with key `k` lives at `<endpoint>/<bucket>/<k>`, where `endpoint`
//! defaults to `https://storage.googleapis.com`. GET / PUT / HEAD / DELETE map
//! directly onto the object URL; listing is `GET <endpoint>/<bucket>?prefix=<p>`
//! which returns an S3-compatible `ListBucketResult` document parsed with
//! [`quick_xml`].
//!
//! ## Error mapping
//!
//! HTTP responses are mapped to [`StorageError`] via [`status_to_error`]:
//! `404 -> NotFound`, `401`/`403 -> PermissionDenied`, any other non-2xx ->
//! `Backend`.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use pgbr_io::{IoError, IoRead, IoWrite};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

use crate::{Storage, StorageError, StorageInfo, StorageKind};

/// Default GCS XML/JSON API endpoint base URL.
const DEFAULT_ENDPOINT: &str = "https://storage.googleapis.com";

/// Authentication mechanism for a [`Gcs`] backend.
///
/// Only the pre-supplied bearer-token path is implemented for now. The enum is
/// non-exhaustive in spirit — service-account JWT auth is a planned follow-up.
#[derive(Debug, Clone)]
pub enum GcsAuth {
    /// A pre-acquired `OAuth2` access token, sent verbatim as the bearer token in
    /// the `Authorization: Bearer <token>` header.
    Token(String),
    // TODO: service-account JWT auth. Load a service-account key file, build an
    // RS256-signed JWT assertion, exchange it at the OAuth2 token endpoint for a
    // short-lived access token, and refresh on expiry. Mirrors
    // `storageGcsAuthService` / `storageGcsAuthJwt` in `src/storage/gcs/storage.c`.
    // Requires an RSA signing dependency, so it is deferred.
}

/// Immutable configuration for a [`Gcs`] backend.
///
/// Mirrors the credential / addressing inputs the C `storage/gcs` driver takes,
/// minus the live HTTP agent (which [`Gcs::new`] constructs).
#[derive(Debug, Clone)]
pub struct GcsConfig {
    /// Bucket name (appears as the first path segment in the XML API).
    pub bucket: String,
    /// Optional endpoint base URL including scheme. Defaults to
    /// `https://storage.googleapis.com`.
    pub endpoint: Option<String>,
    /// Pre-acquired `OAuth2` access token used for bearer-token auth.
    pub token: String,
}

/// Google Cloud Storage backend speaking the XML API over a synchronous
/// [`ureq`] client.
///
/// Cloning is cheap: [`ureq::Agent`] clones share the underlying connection
/// pool, and the remaining fields are short strings. The `open_write` writer
/// holds an owned clone so the boxed `IoWrite` it returns is `'static`.
#[derive(Clone)]
pub struct Gcs {
    bucket: String,
    endpoint: String,
    auth: GcsAuth,
    agent: ureq::Agent,
}

impl Gcs {
    /// Build a `Gcs` backend from `config`, constructing a fresh
    /// [`ureq::Agent`].
    #[must_use]
    pub fn new(config: GcsConfig) -> Self {
        Self::with_agent(config, ureq::agent())
    }

    /// Build a `Gcs` backend with a caller-supplied [`ureq::Agent`].
    #[must_use]
    pub fn with_agent(config: GcsConfig, agent: ureq::Agent) -> Self {
        let endpoint = config
            .endpoint
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
            .trim_end_matches('/')
            .to_string();
        Self {
            bucket: config.bucket,
            endpoint,
            auth: GcsAuth::Token(config.token),
            agent,
        }
    }

    /// Configured endpoint base URL (trailing slash trimmed). Useful for tests.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Configured bucket. Useful for tests / diagnostics.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Full request URL for object `key`: `<endpoint>/<bucket>/<key>`.
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint, self.bucket, key)
    }

    /// Bucket-level URL used for listing: `<endpoint>/<bucket>`.
    fn bucket_url(&self) -> String {
        format!("{}/{}", self.endpoint, self.bucket)
    }

    /// Build the `Authorization` header `(name, value)` pair for the configured
    /// auth mechanism. Factored out so the bearer-token formatting is unit
    /// testable without a live request.
    fn auth_header(&self) -> (String, String) {
        match &self.auth {
            GcsAuth::Token(token) => ("Authorization".to_string(), format!("Bearer {token}")),
        }
    }

    /// Translate a `Path` into a GCS object key. Backend-relative: any leading
    /// `/` is stripped, and Windows-style separators are normalised to `/`.
    fn key_for(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let normalised = raw.replace('\\', "/");
        normalised.trim_start_matches('/').to_string()
    }
}

/// Map an HTTP status code to a [`StorageError`]. Pure so it can be unit-tested:
/// `404 -> NotFound`, `401`/`403 -> PermissionDenied`, any other non-2xx ->
/// `Backend`.
///
/// `2xx` is the success range and must not be passed here; callers only invoke
/// this for non-success statuses. It is mapped to `Backend` defensively.
#[must_use]
pub fn status_to_error(code: u16, path: &Path) -> StorageError {
    match code {
        404 => StorageError::NotFound {
            path: path.to_path_buf(),
        },
        401 | 403 => StorageError::PermissionDenied {
            path: path.to_path_buf(),
        },
        other => StorageError::Backend {
            path: path.to_path_buf(),
            message: format!("unexpected http status {other}"),
        },
    }
}

/// One entry parsed out of an XML API list response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListEntry {
    key: String,
    size: u64,
    modified: Option<i64>,
}

/// Parse a GCS XML API list response body into its `<Contents>` entries.
///
/// The GCS XML API returns an S3-compatible `ListBucketResult` document:
/// `<ListBucketResult><Contents><Key>..</Key><Size>..</Size>`
/// `<LastModified>..</LastModified></Contents>…</ListBucketResult>`.
fn parse_list_objects(xml: &str) -> Result<Vec<ListEntry>, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut entries = Vec::new();
    let mut in_contents = false;
    let mut cur_tag: Option<String> = None;
    let mut key = String::new();
    let mut size: u64 = 0;
    let mut modified: Option<i64> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let name = e.local_name();
                let name = String::from_utf8_lossy(name.as_ref()).into_owned();
                if name == "Contents" {
                    in_contents = true;
                    key.clear();
                    size = 0;
                    modified = None;
                }
                cur_tag = Some(name);
            }
            Ok(Event::Text(e)) => {
                if !in_contents {
                    continue;
                }
                let text = e.xml_content().map_err(|err| err.to_string())?.into_owned();
                match cur_tag.as_deref() {
                    Some("Key") => key = text,
                    Some("Size") => size = text.trim().parse().unwrap_or(0),
                    Some("LastModified") => modified = parse_rfc3339_secs(&text),
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let name = e.local_name();
                let name = String::from_utf8_lossy(name.as_ref()).into_owned();
                if name == "Contents" {
                    in_contents = false;
                    entries.push(ListEntry {
                        key: std::mem::take(&mut key),
                        size,
                        modified,
                    });
                }
                cur_tag = None;
            }
            Ok(Event::Eof) => break,
            Err(err) => return Err(err.to_string()),
            _ => {}
        }
    }

    Ok(entries)
}

/// Parse an RFC-3339 / ISO-8601 timestamp (e.g. `2009-10-12T17:50:30.000Z`)
/// into Unix epoch seconds. Best-effort: returns `None` on any parse failure.
/// Only the `YYYY-MM-DDТHH:MM:SS` prefix is consulted; fractional seconds and
/// the trailing `Z` are ignored — matching `storageGcsCvtTime` in the C driver,
/// which discards milliseconds.
fn parse_rfc3339_secs(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    let year: i64 = text.get(0..4)?.parse().ok()?;
    let month: i64 = text.get(5..7)?.parse().ok()?;
    let day: i64 = text.get(8..10)?.parse().ok()?;
    let hour: i64 = text.get(11..13)?.parse().ok()?;
    let minute: i64 = text.get(14..16)?.parse().ok()?;
    let second: i64 = text.get(17..19)?.parse().ok()?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    // Days from the Unix epoch to the start of `year-month-day`, via the
    // civil-from-days algorithm (Howard Hinnant). Valid for the proleptic
    // Gregorian calendar across the range GCS ever produces.
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Best-effort parse of an HTTP `Last-Modified` date (RFC-1123, e.g.
/// `Wed, 12 Oct 2009 17:50:30 GMT`) into Unix epoch seconds.
fn parse_http_date_secs(text: &str) -> Option<i64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let day: i64 = parts[1].parse().ok()?;
    let month = match parts[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year: i64 = parts[3].parse().ok()?;
    let time: Vec<&str> = parts[4].split(':').collect();
    if time.len() != 3 {
        return None;
    }
    let hour: i64 = time[0].parse().ok()?;
    let minute: i64 = time[1].parse().ok()?;
    let second: i64 = time[2].parse().ok()?;

    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let epoch_days = era * 146_097 + doe - 719_468;
    Some(epoch_days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Adapter exposing an owned byte buffer (a fetched object body) as [`IoRead`].
struct GcsRead {
    data: Vec<u8>,
    pos: usize,
}

impl IoRead for GcsRead {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
        let remaining = self.data.len() - self.pos;
        let n = remaining.min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn eof(&self) -> bool {
        self.pos >= self.data.len()
    }
}

/// Adapter that buffers writes and PUTs the whole object on [`IoWrite::close`].
///
/// A simple GCS object upload is not streaming-friendly without resumable
/// uploads, so this collects the body in memory and uploads it once on close
/// (matching the C driver's behaviour for small objects).
struct GcsWrite {
    gcs: Gcs,
    key: String,
    buffer: Vec<u8>,
    closed: bool,
}

impl IoWrite for GcsWrite {
    fn write(&mut self, buf: &[u8]) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        self.buffer.extend_from_slice(buf);
        Ok(())
    }

    fn flush(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Err(IoError::Closed);
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), IoError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.gcs
            .put_object(&self.key, &self.buffer)
            .map_err(|err| IoError::Backend(err.to_string()))
    }
}

impl Gcs {
    /// PUT an object body to `key`.
    fn put_object(&self, key: &str, body: &[u8]) -> Result<(), StorageError> {
        let url = self.object_url(key);
        let (auth_name, auth_value) = self.auth_header();
        let req = self.agent.put(&url).set(&auth_name, &auth_value);
        match req.send_bytes(body) {
            Ok(_) => Ok(()),
            Err(err) => Err(map_ureq_error(err, key)),
        }
    }
}

/// Map a [`ureq::Error`] to a [`StorageError`], honouring HTTP status codes via
/// [`status_to_error`] and treating transport failures as `Backend`.
fn map_ureq_error(err: ureq::Error, key: &str) -> StorageError {
    let path = PathBuf::from(key);
    match err {
        ureq::Error::Status(code, _) => status_to_error(code, &path),
        ureq::Error::Transport(transport) => StorageError::Backend {
            path,
            message: transport.to_string(),
        },
    }
}

impl Storage for Gcs {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        match self.info(path) {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let key = Self::key_for(path);
        let url = self.object_url(&key);
        let (auth_name, auth_value) = self.auth_header();
        let req = self.agent.head(&url).set(&auth_name, &auth_value);
        match req.call() {
            Ok(resp) => {
                let size = resp.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                let modified = resp.header("last-modified").and_then(parse_http_date_secs);
                Ok(StorageInfo {
                    path: path.to_path_buf(),
                    kind: StorageKind::File,
                    size,
                    modified,
                })
            }
            Err(err) => Err(map_ureq_error(err, &key)),
        }
    }

    fn list(&self, path: &Path) -> Result<Vec<StorageInfo>, StorageError> {
        let mut prefix = Self::key_for(path);
        if !prefix.is_empty() && !prefix.ends_with('/') {
            prefix.push('/');
        }

        let url = self.bucket_url();
        let (auth_name, auth_value) = self.auth_header();
        let mut req = self.agent.get(&url).set(&auth_name, &auth_value);
        if !prefix.is_empty() {
            // ureq percent-encodes the query value for the wire request.
            req = req.query("prefix", &prefix);
        }

        let body = match req.call() {
            Ok(resp) => resp.into_string().map_err(|err| StorageError::Backend {
                path: path.to_path_buf(),
                message: err.to_string(),
            })?,
            Err(err) => return Err(map_ureq_error(err, &prefix)),
        };

        let parsed = parse_list_objects(&body).map_err(|message| StorageError::Backend {
            path: path.to_path_buf(),
            message,
        })?;

        let mut entries: Vec<StorageInfo> = parsed
            .into_iter()
            .map(|e| StorageInfo {
                path: PathBuf::from(e.key),
                kind: StorageKind::File,
                size: e.size,
                modified: e.modified,
            })
            .collect();
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        let key = Self::key_for(path);
        let url = self.object_url(&key);
        let (auth_name, auth_value) = self.auth_header();
        let req = self.agent.get(&url).set(&auth_name, &auth_value);
        match req.call() {
            Ok(resp) => {
                let mut data = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut data)
                    .map_err(|err| StorageError::Backend {
                        path: path.to_path_buf(),
                        message: err.to_string(),
                    })?;
                Ok(Box::new(GcsRead { data, pos: 0 }))
            }
            Err(err) => Err(map_ureq_error(err, &key)),
        }
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let key = Self::key_for(path);
        Ok(Box::new(GcsWrite {
            gcs: self.clone(),
            key,
            buffer: Vec::new(),
            closed: false,
        }))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        let key = Self::key_for(path);
        let url = self.object_url(&key);
        let (auth_name, auth_value) = self.auth_header();
        let req = self.agent.delete(&url).set(&auth_name, &auth_value);
        match req.call() {
            Ok(_) => Ok(()),
            Err(err) => match map_ureq_error(err, &key) {
                StorageError::NotFound { .. } if !error_on_missing => Ok(()),
                other => Err(other),
            },
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        // GCS has no atomic rename. Emulate copy-then-delete via read+write,
        // mirroring the S3 / Azure backends.
        let mut reader = self.open_read(source)?;
        let data = reader.read_all().map_err(StorageError::Io)?;
        let mut writer = self.open_write(target)?;
        writer.write(&data).map_err(StorageError::Io)?;
        writer.close().map_err(StorageError::Io)?;
        self.remove(source, false)
    }

    fn create_path(&self, _path: &Path, _recursive: bool) -> Result<(), StorageError> {
        // GCS has no real directories: objects with a common prefix are a
        // "path". Creating one is a no-op (the prefix springs into existence
        // with the first object written under it).
        Ok(())
    }

    fn remove_path(&self, path: &Path, recursive: bool, error_on_missing: bool) -> Result<(), StorageError> {
        let entries = match self.list(path) {
            Ok(entries) => entries,
            Err(StorageError::NotFound { .. }) if !error_on_missing => return Ok(()),
            Err(other) => return Err(other),
        };

        if entries.is_empty() {
            if error_on_missing {
                return Err(StorageError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            return Ok(());
        }

        if !recursive {
            return Err(StorageError::Backend {
                path: path.to_path_buf(),
                message: "non-recursive remove_path on a non-empty prefix".to_string(),
            });
        }

        for entry in entries {
            self.remove(&entry.path, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_config() -> GcsConfig {
        GcsConfig {
            bucket: "examplebucket".to_string(),
            endpoint: None,
            token: "ya29.EXAMPLE_ACCESS_TOKEN".to_string(),
        }
    }

    fn test_gcs() -> Gcs {
        Gcs::new(test_config())
    }

    #[test]
    fn object_url_building() {
        let gcs = test_gcs();
        assert_eq!(gcs.endpoint(), "https://storage.googleapis.com");
        assert_eq!(gcs.bucket(), "examplebucket");
        assert_eq!(
            gcs.object_url("path/to/object.bin"),
            "https://storage.googleapis.com/examplebucket/path/to/object.bin"
        );
        assert_eq!(gcs.bucket_url(), "https://storage.googleapis.com/examplebucket");
    }

    #[test]
    fn explicit_endpoint_overrides_and_trims_trailing_slash() {
        let mut config = test_config();
        config.endpoint = Some("https://gcs.example.com/".to_string());
        let gcs = Gcs::with_agent(config, ureq::agent());
        assert_eq!(gcs.endpoint(), "https://gcs.example.com");
        assert_eq!(gcs.object_url("a/b.bin"), "https://gcs.example.com/examplebucket/a/b.bin");
    }

    #[test]
    fn auth_header_is_bearer_token() {
        let gcs = test_gcs();
        let (name, value) = gcs.auth_header();
        assert_eq!(name, "Authorization");
        assert_eq!(value, "Bearer ya29.EXAMPLE_ACCESS_TOKEN");
    }

    #[test]
    fn key_for_strips_leading_slash_and_normalises() {
        assert_eq!(Gcs::key_for(Path::new("/repo/archive/x")), "repo/archive/x");
        assert_eq!(Gcs::key_for(Path::new("repo/archive/x")), "repo/archive/x");
    }

    #[test]
    fn status_to_error_mapping() {
        let path = Path::new("missing/object");
        assert_eq!(
            status_to_error(404, path),
            StorageError::NotFound {
                path: path.to_path_buf()
            }
        );
        assert_eq!(
            status_to_error(403, path),
            StorageError::PermissionDenied {
                path: path.to_path_buf()
            }
        );
        assert_eq!(
            status_to_error(401, path),
            StorageError::PermissionDenied {
                path: path.to_path_buf()
            }
        );
        match status_to_error(500, path) {
            StorageError::Backend { message, .. } => assert!(message.contains("500")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn list_response_parsing() {
        // The GCS XML API returns an S3-compatible ListBucketResult document.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
    <Name>examplebucket</Name>
    <Prefix>archive/</Prefix>
    <Marker></Marker>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>archive/000000010000000000000001</Key>
        <Generation>1607977586105966</Generation>
        <LastModified>2009-10-12T17:50:30.000Z</LastModified>
        <ETag>&quot;fba9dede5f27731c9771645a39863328&quot;</ETag>
        <Size>16777216</Size>
    </Contents>
    <Contents>
        <Key>archive/000000010000000000000002</Key>
        <Generation>1607977586105967</Generation>
        <LastModified>2009-10-12T17:51:00.000Z</LastModified>
        <ETag>&quot;9b2cf535f27731c9771645a39863328a&quot;</ETag>
        <Size>42</Size>
    </Contents>
</ListBucketResult>"#;

        let entries = parse_list_objects(xml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "archive/000000010000000000000001");
        assert_eq!(entries[0].size, 16_777_216);
        assert_eq!(entries[1].key, "archive/000000010000000000000002");
        assert_eq!(entries[1].size, 42);

        // 2009-10-12T17:50:30Z == 1255369830 epoch seconds.
        assert_eq!(entries[0].modified, Some(1_255_369_830));
    }

    #[test]
    fn list_parses_empty_result() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://doc.s3.amazonaws.com/2006-03-01">
    <Name>examplebucket</Name>
    <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;
        assert!(parse_list_objects(xml).unwrap().is_empty());
    }

    #[test]
    fn rfc3339_parse_handles_fractional_and_z() {
        assert_eq!(parse_rfc3339_secs("2013-05-24T00:00:00Z"), Some(1_369_353_600));
        assert_eq!(parse_rfc3339_secs("2009-10-12T17:50:30.123Z"), Some(1_255_369_830));
        assert_eq!(parse_rfc3339_secs("nope"), None);
    }

    #[test]
    fn http_date_parse() {
        // Mon, 12 Oct 2009 17:50:30 GMT == 1255369830.
        assert_eq!(parse_http_date_secs("Mon, 12 Oct 2009 17:50:30 GMT"), Some(1_255_369_830));
        assert_eq!(parse_http_date_secs("garbage"), None);
    }

    /// Integration test against a real bucket. Skipped unless the `PGBR_GCS_*`
    /// env vars are set. Run with `cargo test -p pgbr-storage -- --ignored`.
    #[test]
    #[ignore = "requires a live GCS bucket and PGBR_GCS_* env vars"]
    fn gcs_round_trip() {
        let config = GcsConfig {
            bucket: std::env::var("PGBR_GCS_TEST_BUCKET").expect("PGBR_GCS_TEST_BUCKET"),
            endpoint: std::env::var("PGBR_GCS_TEST_ENDPOINT").ok(),
            token: std::env::var("PGBR_GCS_TEST_TOKEN").expect("PGBR_GCS_TEST_TOKEN"),
        };
        let gcs = Gcs::new(config);

        let key = Path::new("pgbr-storage-round-trip.txt");
        {
            let mut writer = gcs.open_write(key).unwrap();
            writer.write(b"hello gcs").unwrap();
            writer.close().unwrap();
        }

        assert!(gcs.exists(key).unwrap());
        let info = gcs.info(key).unwrap();
        assert_eq!(info.size, 9);

        let mut reader = gcs.open_read(key).unwrap();
        assert_eq!(reader.read_all().unwrap(), b"hello gcs");

        gcs.remove(key, true).unwrap();
        assert!(!gcs.exists(key).unwrap());
    }
}

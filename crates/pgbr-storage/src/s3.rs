//! S3 storage backend.
//!
//! Implements the [`Storage`] trait over the S3 REST API using a synchronous
//! [`ureq`] HTTP client (blocking, no async runtime). The correctness-critical
//! piece is AWS Signature Version 4 request signing, which is fully unit-tested
//! against AWS's published test vectors so the implementation is anchored even
//! without a live endpoint.
//!
//! ## Addressing style
//!
//! This backend uses **path-style** addressing: an object with key `k` lives at
//! `<endpoint>/<bucket>/<key>`. Virtual-hosted-style (`<bucket>.<host>/<key>`)
//! is not used because path-style works against every endpoint (including
//! `s3.<region>.amazonaws.com` and `S3`-compatible stores like `MinIO`) without
//! DNS gymnastics. The configured `endpoint` is expected to include the scheme,
//! e.g. `https://s3.us-east-1.amazonaws.com`.
//!
//! ## Error mapping
//!
//! HTTP responses are mapped to [`StorageError`] via [`status_to_error`]:
//! `404 -> NotFound`, `403 -> PermissionDenied`, any other non-2xx -> `Backend`.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use pgbr_io::{IoError, IoRead, IoWrite};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha2::{Digest, Sha256};

use crate::http::HttpOptions;
use crate::{Storage, StorageError, StorageInfo, StorageKind};

type HmacSha256 = Hmac<Sha256>;

/// SHA-256 hash of an empty payload, hex-encoded. AWS uses this as the
/// `x-amz-content-sha256` value for requests with no body (GET/HEAD/DELETE).
const EMPTY_PAYLOAD_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The `SigV4` algorithm identifier.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// S3 bucket addressing style (`repo-s3-uri-style`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum S3UriStyle {
    /// Virtual-hosted-style: the bucket is part of the hostname
    /// (`<bucket>.<endpoint-host>/<key>`). The C default (`repo-s3-uri-style=host`).
    #[default]
    Host,
    /// Path-style: the bucket is the first path segment
    /// (`<endpoint>/<bucket>/<key>`). Required by most S3-compatible stores.
    Path,
}

impl S3UriStyle {
    /// Parse the `repo-s3-uri-style` option value (`host` / `path`).
    ///
    /// # Errors
    ///
    /// Returns the unrecognised value as an error string for the caller to wrap.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "host" => Ok(Self::Host),
            "path" => Ok(Self::Path),
            other => Err(format!("unrecognised repo-s3-uri-style `{other}` (expected host or path)")),
        }
    }
}

/// Server-side-encryption request settings (`repo-s3-kms-key-id` /
/// `repo-s3-sse-customer-key`). Grouped so the credential struct does not sprout
/// several mutually-related optional fields.
#[derive(Debug, Clone, Default)]
pub enum S3Encryption {
    /// No server-side encryption headers (the default).
    #[default]
    None,
    /// SSE-KMS: `x-amz-server-side-encryption: aws:kms` plus the KMS key id in
    /// `x-amz-server-side-encryption-aws-kms-key-id` (`repo-s3-kms-key-id`).
    Kms(String),
    /// SSE-C: customer-provided AES-256 key (`repo-s3-sse-customer-key`). The
    /// stored value is the raw key string; the request headers carry its base64
    /// encoding and an MD5 digest.
    CustomerKey(String),
}

/// Immutable configuration for an [`S3`] backend.
///
/// Mirrors the credential / addressing inputs the C `storage/s3` driver takes,
/// minus the live HTTP agent (which [`S3::new`] constructs). The non-credential
/// fields default to their documented `config.yaml` defaults, so existing
/// callers can build with [`S3Config::default`]-style `..` spreads.
#[derive(Debug, Clone)]
pub struct S3Config {
    /// Endpoint base URL including scheme, e.g. `https://s3.us-east-1.amazonaws.com`.
    pub endpoint: String,
    /// AWS region, e.g. `us-east-1`. Used in the `SigV4` credential scope.
    pub region: String,
    /// Bucket name (path-style: appears as the first path segment).
    pub bucket: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key.
    pub secret_key: String,
    /// Optional session token (`x-amz-security-token`) for temporary credentials.
    pub token: Option<String>,
    /// Bucket addressing style (`repo-s3-uri-style`).
    pub uri_style: S3UriStyle,
    /// Server-side-encryption settings (`repo-s3-kms-key-id` / `-sse-customer-key`).
    pub encryption: S3Encryption,
    /// Send `x-amz-request-payer: requester` on every request
    /// (`repo-s3-requester-pays`).
    pub requester_pays: bool,
    /// Object tags applied on upload (`repo-storage-tag`), sent as the
    /// `x-amz-tagging` header (`k1=v1&k2=v2`).
    pub tags: BTreeMap<String, String>,
    /// Shared HTTPS-client transport options (`repo-storage-*`).
    pub http: HttpOptions,
}

impl S3Config {
    /// Build a config with only the required credential / addressing inputs and
    /// every optional field at its default (matches the prior constructor shape).
    #[must_use]
    pub fn new(
        endpoint: String,
        region: String,
        bucket: String,
        access_key: String,
        secret_key: String,
        token: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            region,
            bucket,
            access_key,
            secret_key,
            token,
            uri_style: S3UriStyle::default(),
            encryption: S3Encryption::default(),
            requester_pays: false,
            tags: BTreeMap::new(),
            http: HttpOptions::default(),
        }
    }
}

/// S3 storage backend speaking the REST API over a synchronous [`ureq`] client.
///
/// Cloning is cheap: [`ureq::Agent`] clones share the underlying connection
/// pool, and the remaining fields are short strings. The `open_write` writer
/// holds an owned clone so the boxed `IoWrite` it returns is `'static`.
#[derive(Clone)]
pub struct S3 {
    endpoint: String,
    region: String,
    bucket: String,
    access_key: String,
    secret_key: String,
    token: Option<String>,
    uri_style: S3UriStyle,
    encryption: S3Encryption,
    requester_pays: bool,
    tags: BTreeMap<String, String>,
    agent: ureq::Agent,
}

impl S3 {
    /// Build an `S3` backend from `config`, constructing a [`ureq::Agent`] from
    /// the config's [`HttpOptions`] (custom CA / verify-tls when set).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] if the configured TLS options
    /// (`repo-storage-ca-file` / `-ca-path`) cannot be loaded into a client
    /// config.
    pub fn new(config: S3Config) -> Result<Self, StorageError> {
        let agent = config.http.build_agent()?;
        Ok(Self::with_agent(config, agent))
    }

    /// Build an `S3` backend with a caller-supplied [`ureq::Agent`], ignoring the
    /// config's [`HttpOptions`] TLS settings (the agent is taken as-is).
    #[must_use]
    pub fn with_agent(config: S3Config, agent: ureq::Agent) -> Self {
        let endpoint = config.endpoint.trim_end_matches('/').to_string();
        Self {
            endpoint,
            region: config.region,
            bucket: config.bucket,
            access_key: config.access_key,
            secret_key: config.secret_key,
            token: config.token,
            uri_style: config.uri_style,
            encryption: config.encryption,
            requester_pays: config.requester_pays,
            tags: config.tags,
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

    /// The bare host portion of the configured endpoint (no scheme, no trailing
    /// slash, no port stripping). The `SigV4` `host` header and request URL are
    /// derived from this, possibly with the bucket prepended (host-style).
    fn endpoint_host(&self) -> &str {
        let no_scheme = self
            .endpoint
            .strip_prefix("https://")
            .or_else(|| self.endpoint.strip_prefix("http://"))
            .unwrap_or(&self.endpoint);
        no_scheme.split('/').next().unwrap_or(no_scheme)
    }

    /// The scheme of the configured endpoint (`http` or `https`), defaulting to
    /// `https` when the endpoint carries no explicit scheme.
    fn scheme(&self) -> &str {
        if self.endpoint.starts_with("http://") {
            "http"
        } else {
            "https"
        }
    }

    /// The `host` header value for `SigV4` signing and the wire request: the bare
    /// endpoint host for path-style, or `<bucket>.<endpoint-host>` for host-style.
    fn host(&self) -> String {
        match self.uri_style {
            S3UriStyle::Path => self.endpoint_host().to_string(),
            S3UriStyle::Host => format!("{}.{}", self.bucket, self.endpoint_host()),
        }
    }

    /// Canonical (percent-encoded) request URI for `key`, per the `S3` `SigV4`
    /// canonical-URI rules. Path-style prepends the bucket
    /// (`/<bucket>/<encoded key>`); host-style omits it (`/<encoded key>`) since
    /// the bucket is in the hostname. Each path segment is percent-encoded but
    /// the `/` separators are preserved.
    fn canonical_uri(&self, key: &str) -> String {
        let mut uri = String::from("/");
        if matches!(self.uri_style, S3UriStyle::Path) {
            uri.push_str(&uri_encode(&self.bucket, false));
            uri.push('/');
        }
        uri.push_str(&uri_encode(key, false));
        uri
    }

    /// The canonical request URI used for a bucket-level (list) request: `/` for
    /// host-style, `/<bucket>` for path-style.
    fn bucket_canonical_uri(&self) -> String {
        match self.uri_style {
            S3UriStyle::Host => "/".to_string(),
            S3UriStyle::Path => format!("/{}", uri_encode(&self.bucket, false)),
        }
    }

    /// Base request URL (scheme + host + bucket-path-prefix) without any object
    /// key — `<scheme>://<host>` for host-style or `<scheme>://<host>/<bucket>`
    /// for path-style.
    fn base_url(&self) -> String {
        match self.uri_style {
            S3UriStyle::Host => format!("{}://{}", self.scheme(), self.host()),
            S3UriStyle::Path => format!("{}://{}/{}", self.scheme(), self.host(), uri_encode(&self.bucket, false)),
        }
    }

    /// Full request URL for `key`: the [`Self::base_url`] joined with the
    /// percent-encoded key.
    fn object_url(&self, key: &str) -> String {
        format!("{}/{}", self.base_url(), uri_encode(key, false))
    }

    /// Build the `SigV4` `Authorization` header value for a request.
    ///
    /// `headers` is the set of headers to sign as `(lowercased-name, value)`
    /// pairs; it must include `host` and `x-amz-content-sha256` (and
    /// `x-amz-date`). `timestamp` is in the `YYYYMMDDTHHMMSSZ` ISO-8601 basic
    /// form; the scope date is its first 8 characters.
    fn sign_request(
        &self,
        method: &str,
        canonical_uri: &str,
        query: &str,
        headers: &[(String, String)],
        payload_hash: &str,
        timestamp: &str,
    ) -> String {
        let date = &timestamp[..8];
        let scope = format!("{date}/{}/s3/aws4_request", self.region);

        // Canonical headers must be sorted by lowercased name; values trimmed.
        let mut sorted = headers.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));

        let mut canonical_headers = String::new();
        let mut signed_headers = String::new();
        for (idx, (name, value)) in sorted.iter().enumerate() {
            canonical_headers.push_str(name);
            canonical_headers.push(':');
            canonical_headers.push_str(value.trim());
            canonical_headers.push('\n');
            if idx > 0 {
                signed_headers.push(';');
            }
            signed_headers.push_str(name);
        }

        let canonical_request =
            format!("{method}\n{canonical_uri}\n{query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

        let string_to_sign = format!(
            "{ALGORITHM}\n{timestamp}\n{scope}\n{}",
            hex_sha256(canonical_request.as_bytes())
        );

        let signing_key = derive_signing_key(&self.secret_key, date, &self.region, "s3");
        let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        format!(
            "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        )
    }

    /// Assemble the standard signed headers for a request and return the
    /// `(header pairs, authorization)` needed to dispatch it. `payload_hash`
    /// is the hex SHA-256 of the request body (or [`EMPTY_PAYLOAD_SHA256`]).
    ///
    /// `extra` carries request-type-specific `x-amz-*` headers (server-side
    /// encryption, object tags, requester-pays) that must participate in the
    /// `SigV4` signature; see [`Self::request_extra_headers`].
    fn signed_headers(
        &self,
        method: &str,
        canonical_uri: &str,
        query: &str,
        timestamp: &str,
        payload_hash: &str,
        extra: &[(String, String)],
    ) -> Vec<(String, String)> {
        let mut headers = vec![
            ("host".to_string(), self.host()),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-date".to_string(), timestamp.to_string()),
        ];
        if let Some(token) = &self.token {
            headers.push(("x-amz-security-token".to_string(), token.clone()));
        }
        headers.extend(extra.iter().cloned());

        let authorization = self.sign_request(method, canonical_uri, query, &headers, payload_hash, timestamp);
        headers.push(("authorization".to_string(), authorization));
        headers
    }

    /// Build the request-type-specific `x-amz-*` headers to sign and send.
    ///
    /// `is_upload` selects whether upload-only headers (SSE-KMS, object tags)
    /// apply. The requester-pays header (`x-amz-request-payer: requester`) and
    /// SSE-C headers are sent on every request type, since SSE-C must be repeated
    /// on reads to decrypt the object. Returned `(name, value)` pairs are
    /// lowercase-named so they sort correctly into the canonical headers.
    fn request_extra_headers(&self, is_upload: bool) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        if self.requester_pays {
            headers.push(("x-amz-request-payer".to_string(), "requester".to_string()));
        }
        match &self.encryption {
            S3Encryption::None => {}
            S3Encryption::Kms(key_id) => {
                if is_upload {
                    headers.push(("x-amz-server-side-encryption".to_string(), "aws:kms".to_string()));
                    headers.push(("x-amz-server-side-encryption-aws-kms-key-id".to_string(), key_id.clone()));
                }
            }
            S3Encryption::CustomerKey(key) => headers.extend(sse_customer_headers(key)),
        }
        if is_upload && !self.tags.is_empty() {
            headers.push(("x-amz-tagging".to_string(), encode_tagging(&self.tags)));
        }
        headers
    }

    /// Translate a `Path` into an S3 object key. Backend-relative: any leading
    /// `/` is stripped, and Windows-style separators are normalised to `/`.
    fn key_for(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let normalised = raw.replace('\\', "/");
        normalised.trim_start_matches('/').to_string()
    }
}

/// Map an HTTP status code to a [`StorageError`]. Pure so it can be unit-tested:
/// `404 -> NotFound`, `403 -> PermissionDenied`, any other non-2xx -> `Backend`.
///
/// `2xx` is the success range and must not be passed here; callers only invoke
/// this for non-success statuses. It is mapped to `Backend` defensively.
#[must_use]
pub fn status_to_error(code: u16, path: &Path) -> StorageError {
    match code {
        404 => StorageError::NotFound {
            path: path.to_path_buf(),
        },
        403 => StorageError::PermissionDenied {
            path: path.to_path_buf(),
        },
        other => StorageError::Backend {
            path: path.to_path_buf(),
            message: format!("unexpected http status {other}"),
        },
    }
}

/// One entry parsed out of a `ListObjectsV2` response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListEntry {
    key: String,
    size: u64,
    modified: Option<i64>,
}

/// A single parsed page of a `ListObjectsV2` response: the `<Contents>` entries
/// plus the pagination state needed to fetch the next page.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ListPage {
    entries: Vec<ListEntry>,
    /// `true` when the result was truncated and a further request is required.
    is_truncated: bool,
    /// The `<NextContinuationToken>` to re-inject as `continuation-token` on the
    /// next request. Present only when `is_truncated` is `true`.
    next_continuation_token: Option<String>,
}

/// Parse a `ListObjectsV2` XML response body into one [`ListPage`]: the
/// `<Contents>` entries plus the `<IsTruncated>` / `<NextContinuationToken>`
/// pagination markers.
fn parse_list_objects_v2(xml: &str) -> Result<ListPage, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut page = ListPage::default();
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
                let text = e.xml_content().map_err(|err| err.to_string())?.into_owned();
                if in_contents {
                    match cur_tag.as_deref() {
                        Some("Key") => key = text,
                        Some("Size") => size = text.trim().parse().unwrap_or(0),
                        Some("LastModified") => modified = parse_rfc3339_secs(&text),
                        _ => {}
                    }
                } else {
                    // Top-level pagination markers live outside <Contents>.
                    match cur_tag.as_deref() {
                        Some("IsTruncated") => page.is_truncated = text.trim().eq_ignore_ascii_case("true"),
                        Some("NextContinuationToken") => {
                            let token = text.trim();
                            if !token.is_empty() {
                                page.next_continuation_token = Some(token.to_string());
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = e.local_name();
                let name = String::from_utf8_lossy(name.as_ref()).into_owned();
                if name == "Contents" {
                    in_contents = false;
                    page.entries.push(ListEntry {
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

    Ok(page)
}

/// Parse an RFC-3339 / ISO-8601 timestamp (e.g. `2009-10-12T17:50:30.000Z`)
/// into Unix epoch seconds. Best-effort: returns `None` on any parse failure.
/// Only the `YYYY-MM-DDТHH:MM:SS` prefix is consulted; fractional seconds and
/// the trailing `Z` are ignored.
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
    // Gregorian calendar across the range S3 ever produces.
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Derive the `SigV4` signing key:
/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`.
fn derive_signing_key(secret: &str, date: &str, region: &str, service: &str) -> [u8; 32] {
    let mut key = Vec::with_capacity(4 + secret.len());
    key.extend_from_slice(b"AWS4");
    key.extend_from_slice(secret.as_bytes());

    let k_date = hmac_sha256(&key, date.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// HMAC-SHA256 of `data` under `key`, returned as 32 bytes.
///
/// `new_from_slice` is infallible for HMAC — it accepts keys of any length, so
/// the `InvalidLength` error can never occur here. The scoped allow documents
/// that the `expect` is dead code in practice rather than a latent panic.
#[allow(clippy::expect_used)]
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// SHA-256 of `data`, hex-encoded (lowercase).
fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex(&hasher.finalize())
}

/// Lowercase hex-encode a byte slice.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// RFC-3986 percent-encoding as required by `SigV4`. Unreserved characters
/// (`A-Z a-z 0-9 - _ . ~`) pass through; everything else is `%XX`-encoded.
/// When `encode_slash` is `false`, `/` is left intact (used for object keys in
/// the canonical URI, where path separators must be preserved).
fn uri_encode(input: &str, encode_slash: bool) -> String {
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') || (b == b'/' && !encode_slash);
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(UPPER[(b >> 4) as usize] as char);
            out.push(UPPER[(b & 0x0f) as usize] as char);
        }
    }
    out
}

/// Build the SSE-C (customer-provided key) request headers for the raw key
/// string `key`: the AES-256 algorithm marker, the base64-encoded key, and the
/// base64-encoded MD5 of the key, per the AWS SSE-C protocol. Returned with
/// lowercase header names so they sort into the canonical signed headers.
fn sse_customer_headers(key: &str) -> Vec<(String, String)> {
    use base64::Engine as _;
    use md5::{Digest as _, Md5};
    let b64 = base64::engine::general_purpose::STANDARD.encode(key.as_bytes());
    let digest = Md5::digest(key.as_bytes());
    let md5_b64 = base64::engine::general_purpose::STANDARD.encode(digest);
    vec![
        (
            "x-amz-server-side-encryption-customer-algorithm".to_string(),
            "AES256".to_string(),
        ),
        ("x-amz-server-side-encryption-customer-key".to_string(), b64),
        ("x-amz-server-side-encryption-customer-key-md5".to_string(), md5_b64),
    ]
}

/// Encode object tags as the `x-amz-tagging` header value: a URL-query-style
/// `k1=v1&k2=v2` string with each key and value percent-encoded. Keys are sorted
/// (the map is a [`BTreeMap`]) so the output is deterministic.
fn encode_tagging(tags: &BTreeMap<String, String>) -> String {
    tags.iter()
        .map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Adapter exposing an owned byte buffer (a fetched object body) as [`IoRead`].
struct S3Read {
    data: Vec<u8>,
    pos: usize,
}

impl IoRead for S3Read {
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
/// S3 PUT is not streaming-friendly without multipart upload, so this collects
/// the body in memory and uploads it once on close (matching the C driver's
/// behaviour for small objects).
struct S3Write {
    s3: S3,
    key: String,
    buffer: Vec<u8>,
    closed: bool,
}

impl IoWrite for S3Write {
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
        self.s3
            .put_object(&self.key, &self.buffer)
            .map_err(|err| IoError::Backend(err.to_string()))
    }
}

impl S3 {
    /// Current `SigV4` timestamp in `YYYYMMDDTHHMMSSZ` form, derived from the
    /// system clock. Kept tiny and dependency-free.
    fn now_timestamp() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        format_timestamp(secs)
    }

    /// PUT an object body to `key`.
    fn put_object(&self, key: &str, body: &[u8]) -> Result<(), StorageError> {
        let timestamp = Self::now_timestamp();
        let canonical_uri = self.canonical_uri(key);
        let payload_hash = hex_sha256(body);
        let extra = self.request_extra_headers(true);
        let headers = self.signed_headers("PUT", &canonical_uri, "", &timestamp, &payload_hash, &extra);

        let url = self.object_url(key);
        let mut req = self.agent.put(&url);
        for (name, value) in &headers {
            req = req.set(name, value);
        }
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

impl Storage for S3 {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        match self.info(path) {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let key = Self::key_for(path);
        let timestamp = Self::now_timestamp();
        let canonical_uri = self.canonical_uri(&key);
        let extra = self.request_extra_headers(false);
        let headers = self.signed_headers("HEAD", &canonical_uri, "", &timestamp, EMPTY_PAYLOAD_SHA256, &extra);

        let url = self.object_url(&key);
        let mut req = self.agent.head(&url);
        for (name, value) in &headers {
            req = req.set(name, value);
        }
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

        let canonical_uri = self.bucket_canonical_uri();
        let mut entries: Vec<StorageInfo> = Vec::new();
        // Follow `IsTruncated` / `NextContinuationToken` until the listing is
        // exhausted, so a listing larger than the per-response cap (1000 keys)
        // is returned in full rather than silently truncated to the first page.
        let mut continuation_token: Option<String> = None;

        loop {
            let timestamp = Self::now_timestamp();
            // Canonical query string: params sorted by name, both name and value
            // percent-encoded (slashes too). `continuation-token` sorts before
            // both `list-type` and `prefix`.
            let mut query = String::new();
            if let Some(token) = &continuation_token {
                query.push_str("continuation-token=");
                query.push_str(&uri_encode(token, true));
                query.push('&');
            }
            query.push_str("list-type=2");
            if !prefix.is_empty() {
                query.push_str("&prefix=");
                query.push_str(&uri_encode(&prefix, true));
            }

            let extra = self.request_extra_headers(false);
            let headers = self.signed_headers("GET", &canonical_uri, &query, &timestamp, EMPTY_PAYLOAD_SHA256, &extra);

            let url = format!("{}?{}", self.base_url(), query);
            let mut req = self.agent.get(&url);
            for (name, value) in &headers {
                req = req.set(name, value);
            }

            let body = match req.call() {
                Ok(resp) => resp.into_string().map_err(|err| StorageError::Backend {
                    path: path.to_path_buf(),
                    message: err.to_string(),
                })?,
                Err(err) => return Err(map_ureq_error(err, &prefix)),
            };

            let page = parse_list_objects_v2(&body).map_err(|message| StorageError::Backend {
                path: path.to_path_buf(),
                message,
            })?;

            entries.extend(page.entries.into_iter().map(|e| StorageInfo {
                path: PathBuf::from(e.key),
                kind: StorageKind::File,
                size: e.size,
                modified: e.modified,
            }));

            // A truncated response without a usable token would loop forever;
            // stop rather than spin.
            match (page.is_truncated, page.next_continuation_token) {
                (true, Some(token)) => continuation_token = Some(token),
                _ => break,
            }
        }

        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    fn open_read(&self, path: &Path) -> Result<Box<dyn IoRead>, StorageError> {
        let key = Self::key_for(path);
        let timestamp = Self::now_timestamp();
        let canonical_uri = self.canonical_uri(&key);
        let extra = self.request_extra_headers(false);
        let headers = self.signed_headers("GET", &canonical_uri, "", &timestamp, EMPTY_PAYLOAD_SHA256, &extra);

        let url = self.object_url(&key);
        let mut req = self.agent.get(&url);
        for (name, value) in &headers {
            req = req.set(name, value);
        }

        match req.call() {
            Ok(resp) => {
                let mut data = Vec::new();
                resp.into_reader()
                    .read_to_end(&mut data)
                    .map_err(|err| StorageError::Backend {
                        path: path.to_path_buf(),
                        message: err.to_string(),
                    })?;
                Ok(Box::new(S3Read { data, pos: 0 }))
            }
            Err(err) => Err(map_ureq_error(err, &key)),
        }
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let key = Self::key_for(path);
        Ok(Box::new(S3Write {
            s3: self.clone(),
            key,
            buffer: Vec::new(),
            closed: false,
        }))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        let key = Self::key_for(path);
        let timestamp = Self::now_timestamp();
        let canonical_uri = self.canonical_uri(&key);
        let extra = self.request_extra_headers(false);
        let headers = self.signed_headers("DELETE", &canonical_uri, "", &timestamp, EMPTY_PAYLOAD_SHA256, &extra);

        let url = self.object_url(&key);
        let mut req = self.agent.delete(&url);
        for (name, value) in &headers {
            req = req.set(name, value);
        }
        match req.call() {
            // S3 DELETE returns 204 whether or not the object existed.
            Ok(_) => Ok(()),
            Err(err) => match map_ureq_error(err, &key) {
                StorageError::NotFound { .. } if !error_on_missing => Ok(()),
                other => Err(other),
            },
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        // S3 has no atomic rename. Emulate copy-then-delete via read+write.
        let mut reader = self.open_read(source)?;
        let data = reader.read_all().map_err(StorageError::Io)?;
        let mut writer = self.open_write(target)?;
        writer.write(&data).map_err(StorageError::Io)?;
        writer.close().map_err(StorageError::Io)?;
        self.remove(source, false)
    }

    fn create_path(&self, _path: &Path, _recursive: bool) -> Result<(), StorageError> {
        // S3 has no real directories: keys with a common prefix are a "path".
        // Creating one is a no-op (the prefix springs into existence with the
        // first object written under it), mirroring the C posix-vs-object split.
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

/// Format Unix epoch `secs` as a `SigV4` timestamp `YYYYMMDDTHHMMSSZ` (UTC).
fn format_timestamp(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z")
}

/// Inverse of the days-from-civil computation: turn a day count since the Unix
/// epoch into `(year, month, day)` in the proleptic Gregorian calendar.
const fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Best-effort parse of an HTTP `Last-Modified` date (RFC-1123, e.g.
/// `Wed, 12 Oct 2009 17:50:00 GMT`) into Unix epoch seconds.
fn parse_http_date_secs(text: &str) -> Option<i64> {
    // "Wed, 12 Oct 2009 17:50:00 GMT"
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Path-style test config (bucket as first path segment), preserving the
    /// addressing the URL-building / canonical-URI assertions below expect.
    fn test_config() -> S3Config {
        S3Config {
            uri_style: S3UriStyle::Path,
            ..S3Config::new(
                "https://s3.us-east-1.amazonaws.com".to_string(),
                "us-east-1".to_string(),
                "examplebucket".to_string(),
                "AKIAIOSFODNN7EXAMPLE".to_string(),
                "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
                None,
            )
        }
    }

    /// Build the path-style test backend, unwrapping the (infallible for the
    /// default `HttpOptions`) `S3::new` result.
    fn test_s3() -> S3 {
        S3::new(test_config()).unwrap()
    }

    /// Anchor #1: AWS's published signing-key intermediate value.
    ///
    /// From the AWS docs "Deriving the signing key with HMAC" example:
    /// secret `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, date `20150830`,
    /// region `us-east-1`, service `iam`. The published signing key bytes are
    /// reproduced below; this pins the four-stage HMAC derivation exactly.
    #[test]
    fn derive_signing_key_matches_aws_intermediate() {
        let key = derive_signing_key("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1", "iam");
        // 2c94c0cf5378ada6887f09bb697df8fc0affdb34ba1cdd5bda32b664bd55b73c
        let expected: [u8; 32] = [
            0x2c, 0x94, 0xc0, 0xcf, 0x53, 0x78, 0xad, 0xa6, 0x88, 0x7f, 0x09, 0xbb, 0x69, 0x7d, 0xf8, 0xfc, 0x0a, 0xff, 0xdb, 0x34,
            0xba, 0x1c, 0xdd, 0x5b, 0xda, 0x32, 0xb6, 0x64, 0xbd, 0x55, 0xb7, 0x3c,
        ];
        assert_eq!(hex(&key), "2c94c0cf5378ada6887f09bb697df8fc0affdb34ba1cdd5bda32b664bd55b73c");
        assert_eq!(key, expected);
    }

    /// Anchor #2: the full `SigV4` "GET Object" request signature from the AWS
    /// docs "Examples of signed Signature Version 4 requests" (the "GET Object"
    /// example). This is a complete request vector — canonical request,
    /// string-to-sign, derived signing key and final signature — so it
    /// exercises `sign_request` end to end against published expected output.
    ///
    /// The published example is virtual-hosted-style: the bucket is part of the
    /// host (`examplebucket.s3.amazonaws.com`) so the canonical URI is just
    /// `/test.txt`. We feed those exact inputs to `sign_request`.
    ///
    /// Published expected signature:
    /// `f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41`
    #[test]
    fn sigv4_matches_aws_test_vector() {
        let s3 = test_s3();
        let timestamp = "20130524T000000Z";
        // GET /test.txt with a Range header, per the AWS GET Object example.
        let canonical_uri = "/test.txt";
        let payload_hash = EMPTY_PAYLOAD_SHA256;
        let headers = vec![
            ("host".to_string(), "examplebucket.s3.amazonaws.com".to_string()),
            ("range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-date".to_string(), timestamp.to_string()),
        ];

        let authorization = s3.sign_request("GET", canonical_uri, "", &headers, payload_hash, timestamp);

        let expected_signature = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
        assert!(
            authorization.ends_with(&format!("Signature={expected_signature}")),
            "got authorization: {authorization}"
        );
        assert!(authorization.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature="
        ));
    }

    #[test]
    fn empty_payload_constant_is_sha256_of_empty() {
        assert_eq!(hex_sha256(b""), EMPTY_PAYLOAD_SHA256);
    }

    #[test]
    fn object_url_building() {
        let s3 = test_s3();
        assert_eq!(
            s3.object_url("path/to/object.bin"),
            "https://s3.us-east-1.amazonaws.com/examplebucket/path/to/object.bin"
        );
        // The canonical URI percent-encodes special chars but keeps slashes.
        assert_eq!(s3.canonical_uri("a b/c+d"), "/examplebucket/a%20b/c%2Bd");
        assert_eq!(s3.host(), "s3.us-east-1.amazonaws.com");
        assert_eq!(s3.base_url(), "https://s3.us-east-1.amazonaws.com/examplebucket");
        assert_eq!(s3.bucket_canonical_uri(), "/examplebucket");
    }

    #[test]
    fn host_style_addressing() {
        // Host-style: the bucket lives in the hostname, the canonical URI omits
        // it, and the request URL is `<scheme>://<bucket>.<host>/<key>`.
        let cfg = S3Config {
            uri_style: S3UriStyle::Host,
            ..test_config()
        };
        let s3 = S3::new(cfg).unwrap();
        assert_eq!(s3.host(), "examplebucket.s3.us-east-1.amazonaws.com");
        assert_eq!(s3.canonical_uri("path/to/object.bin"), "/path/to/object.bin");
        assert_eq!(
            s3.object_url("path/to/object.bin"),
            "https://examplebucket.s3.us-east-1.amazonaws.com/path/to/object.bin"
        );
        assert_eq!(s3.base_url(), "https://examplebucket.s3.us-east-1.amazonaws.com");
        assert_eq!(s3.bucket_canonical_uri(), "/");
    }

    #[test]
    fn uri_style_parse() {
        assert_eq!(S3UriStyle::parse("host").unwrap(), S3UriStyle::Host);
        assert_eq!(S3UriStyle::parse("path").unwrap(), S3UriStyle::Path);
        assert!(S3UriStyle::parse("dns").is_err());
        // The documented default is host-style.
        assert_eq!(S3UriStyle::default(), S3UriStyle::Host);
    }

    #[test]
    fn requester_pays_header_is_signed_and_sent() {
        // With requester-pays on, every request carries the request-payer header,
        // and it participates in the signature (it appears in SignedHeaders).
        let cfg = S3Config {
            requester_pays: true,
            ..test_config()
        };
        let s3 = S3::new(cfg).unwrap();
        let extra = s3.request_extra_headers(false);
        assert!(extra.iter().any(|(n, v)| n == "x-amz-request-payer" && v == "requester"));

        let headers = s3.signed_headers(
            "GET",
            "/examplebucket/k",
            "",
            "20130524T000000Z",
            EMPTY_PAYLOAD_SHA256,
            &extra,
        );
        let auth = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(auth.contains("x-amz-request-payer"), "auth was {auth}");
    }

    #[test]
    fn sse_kms_headers_on_upload_only() {
        let cfg = S3Config {
            encryption: S3Encryption::Kms("arn:aws:kms:key/abc".to_string()),
            ..test_config()
        };
        let s3 = S3::new(cfg).unwrap();
        // Upload carries the SSE-KMS markers.
        let up = s3.request_extra_headers(true);
        assert!(up.iter().any(|(n, v)| n == "x-amz-server-side-encryption" && v == "aws:kms"));
        assert!(
            up.iter()
                .any(|(n, v)| n == "x-amz-server-side-encryption-aws-kms-key-id" && v == "arn:aws:kms:key/abc")
        );
        // A read request does not (SSE-KMS is server-side; reads need no header).
        let down = s3.request_extra_headers(false);
        assert!(!down.iter().any(|(n, _)| n.starts_with("x-amz-server-side-encryption")));
    }

    #[test]
    fn sse_customer_key_headers_on_read_and_write() {
        // SSE-C key "0123456789012345678901234567890" (raw) -> base64 + md5 b64.
        let headers = sse_customer_headers("0123456789012345678901234567890");
        assert_eq!(headers[0].1, "AES256");
        // base64("0123456789012345678901234567890")
        assert_eq!(headers[1].1, "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MA==");
        // md5 of that string, base64-encoded (computed independently).
        assert_eq!(headers[2].0, "x-amz-server-side-encryption-customer-key-md5");
        assert!(!headers[2].1.is_empty());

        // SSE-C is repeated on reads (needed to decrypt) and writes.
        let cfg = S3Config {
            encryption: S3Encryption::CustomerKey("0123456789012345678901234567890".to_string()),
            ..test_config()
        };
        let s3 = S3::new(cfg).unwrap();
        assert!(
            s3.request_extra_headers(false)
                .iter()
                .any(|(n, _)| n == "x-amz-server-side-encryption-customer-key")
        );
        assert!(
            s3.request_extra_headers(true)
                .iter()
                .any(|(n, _)| n == "x-amz-server-side-encryption-customer-key")
        );
    }

    #[test]
    fn object_tags_only_on_upload() {
        let mut tags = BTreeMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        tags.insert("team".to_string(), "db ops".to_string());
        assert_eq!(encode_tagging(&tags), "env=prod&team=db%20ops");

        let cfg = S3Config { tags, ..test_config() };
        let s3 = S3::new(cfg).unwrap();
        assert!(s3.request_extra_headers(true).iter().any(|(n, _)| n == "x-amz-tagging"));
        assert!(!s3.request_extra_headers(false).iter().any(|(n, _)| n == "x-amz-tagging"));
    }

    #[test]
    fn key_for_strips_leading_slash_and_normalises() {
        assert_eq!(S3::key_for(Path::new("/repo/archive/x")), "repo/archive/x");
        assert_eq!(S3::key_for(Path::new("repo/archive/x")), "repo/archive/x");
    }

    #[test]
    fn uri_encode_rules() {
        assert_eq!(uri_encode("aZ09-_.~", true), "aZ09-_.~");
        assert_eq!(uri_encode("a/b", false), "a/b");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("a b", true), "a%20b");
        assert_eq!(uri_encode("+", true), "%2B");
    }

    #[test]
    fn http_404_maps_to_not_found() {
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
        match status_to_error(500, path) {
            StorageError::Backend { message, .. } => assert!(message.contains("500")),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn list_parses_listobjectsv2_xml() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>examplebucket</Name>
    <Prefix>archive/</Prefix>
    <KeyCount>2</KeyCount>
    <MaxKeys>1000</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>archive/000000010000000000000001</Key>
        <LastModified>2009-10-12T17:50:30.000Z</LastModified>
        <ETag>&quot;fba9dede5f27731c9771645a39863328&quot;</ETag>
        <Size>16777216</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
    <Contents>
        <Key>archive/000000010000000000000002</Key>
        <LastModified>2009-10-12T17:51:00.000Z</LastModified>
        <ETag>&quot;9b2cf535f27731c9771645a39863328a&quot;</ETag>
        <Size>42</Size>
        <StorageClass>STANDARD</StorageClass>
    </Contents>
</ListBucketResult>"#;

        let page = parse_list_objects_v2(xml).unwrap();
        let entries = &page.entries;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "archive/000000010000000000000001");
        assert_eq!(entries[0].size, 16_777_216);
        assert_eq!(entries[1].key, "archive/000000010000000000000002");
        assert_eq!(entries[1].size, 42);

        // 2009-10-12T17:50:30Z == 1255369830 epoch seconds.
        assert_eq!(entries[0].modified, Some(1_255_369_830));

        assert!(!page.is_truncated);
        assert_eq!(page.next_continuation_token, None);
    }

    #[test]
    fn list_parses_empty_result() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>examplebucket</Name>
    <KeyCount>0</KeyCount>
    <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;
        assert!(parse_list_objects_v2(xml).unwrap().entries.is_empty());
    }

    #[test]
    fn list_parses_truncated_page_then_final_page() {
        // First page: truncated, carries a continuation token to fetch more.
        let page1 = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>examplebucket</Name>
    <Prefix>archive/</Prefix>
    <KeyCount>1</KeyCount>
    <MaxKeys>1</MaxKeys>
    <IsTruncated>true</IsTruncated>
    <NextContinuationToken>example-next-page-token</NextContinuationToken>
    <Contents>
        <Key>archive/000000010000000000000001</Key>
        <LastModified>2009-10-12T17:50:30.000Z</LastModified>
        <Size>16</Size>
    </Contents>
</ListBucketResult>"#;
        let parsed1 = parse_list_objects_v2(page1).unwrap();
        assert_eq!(parsed1.entries.len(), 1);
        assert_eq!(parsed1.entries[0].key, "archive/000000010000000000000001");
        assert!(parsed1.is_truncated);
        assert_eq!(parsed1.next_continuation_token.as_deref(), Some("example-next-page-token"));

        // Second page: not truncated, no further token — the loop terminates.
        let page2 = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
    <Name>examplebucket</Name>
    <Prefix>archive/</Prefix>
    <KeyCount>1</KeyCount>
    <MaxKeys>1</MaxKeys>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>archive/000000010000000000000002</Key>
        <LastModified>2009-10-12T17:51:00.000Z</LastModified>
        <Size>42</Size>
    </Contents>
</ListBucketResult>"#;
        let parsed2 = parse_list_objects_v2(page2).unwrap();
        assert_eq!(parsed2.entries.len(), 1);
        assert_eq!(parsed2.entries[0].key, "archive/000000010000000000000002");
        assert!(!parsed2.is_truncated);
        assert_eq!(parsed2.next_continuation_token, None);
    }

    #[test]
    fn timestamp_round_trips_through_civil() {
        // 2013-05-24T00:00:00Z == 1369353600 epoch seconds.
        assert_eq!(format_timestamp(1_369_353_600), "20130524T000000Z");
        // 2009-10-12T17:50:30Z.
        assert_eq!(format_timestamp(1_255_369_830), "20091012T175030Z");
    }

    #[test]
    fn rfc3339_parse_handles_fractional_and_z() {
        assert_eq!(parse_rfc3339_secs("2013-05-24T00:00:00Z"), Some(1_369_353_600));
        assert_eq!(parse_rfc3339_secs("2009-10-12T17:50:30.123Z"), Some(1_255_369_830));
        assert_eq!(parse_rfc3339_secs("nope"), None);
    }

    #[test]
    fn http_date_parse() {
        // Wed, 12 Oct 2009 17:50:30 GMT == 1255369830.
        assert_eq!(parse_http_date_secs("Wed, 12 Oct 2009 17:50:30 GMT"), Some(1_255_369_830));
        assert_eq!(parse_http_date_secs("garbage"), None);
    }

    #[test]
    fn with_agent_trims_trailing_slash() {
        let mut config = test_config();
        config.endpoint = "https://s3.example.com/".to_string();
        let s3 = S3::with_agent(config, ureq::agent());
        assert_eq!(s3.endpoint(), "https://s3.example.com");
        assert_eq!(s3.bucket(), "examplebucket");
    }

    /// Integration test against a real endpoint. Skipped unless the
    /// `PGBR_S3_TEST_BUCKET` / `PGBR_S3_TEST_*` env vars are set. Run with
    /// `cargo test -p pgbr-storage -- --ignored`.
    #[test]
    #[ignore = "requires a live S3 endpoint and PGBR_S3_* env vars"]
    fn s3_round_trip_against_real_endpoint() {
        let bucket = std::env::var("PGBR_S3_TEST_BUCKET").expect("PGBR_S3_TEST_BUCKET");
        let config = S3Config {
            // Path-style is the most portable choice across S3-compatible
            // endpoints (MinIO etc.); host-style is exercised by unit tests.
            uri_style: S3UriStyle::Path,
            ..S3Config::new(
                std::env::var("PGBR_S3_TEST_ENDPOINT").unwrap_or_else(|_| "https://s3.us-east-1.amazonaws.com".to_string()),
                std::env::var("PGBR_S3_TEST_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
                bucket,
                std::env::var("PGBR_S3_TEST_ACCESS_KEY").expect("PGBR_S3_TEST_ACCESS_KEY"),
                std::env::var("PGBR_S3_TEST_SECRET_KEY").expect("PGBR_S3_TEST_SECRET_KEY"),
                std::env::var("PGBR_S3_TEST_TOKEN").ok(),
            )
        };
        let s3 = S3::new(config).unwrap();

        let key = Path::new("pgbr-storage-round-trip.txt");
        {
            let mut writer = s3.open_write(key).unwrap();
            writer.write(b"hello s3").unwrap();
            writer.close().unwrap();
        }

        assert!(s3.exists(key).unwrap());
        let info = s3.info(key).unwrap();
        assert_eq!(info.size, 8);

        let mut reader = s3.open_read(key).unwrap();
        assert_eq!(reader.read_all().unwrap(), b"hello s3");

        s3.remove(key, true).unwrap();
        assert!(!s3.exists(key).unwrap());
    }
}

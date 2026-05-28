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
//! pre-supplied bearer token. This backend implements two of them:
//!
//! - [`GcsAuth::Token`] — a pre-supplied `OAuth2` access token, sent verbatim as
//!   `Authorization: Bearer <token>`.
//! - [`GcsAuth::ServiceAccount`] — a service-account key (client email + RS256
//!   PEM private key). A short-lived JWT assertion is built and signed with the
//!   private key ([`build_signed_jwt`]), exchanged at the `OAuth2` token endpoint
//!   for an access token ([`Gcs::exchange_jwt`]), and the access token is cached
//!   until just before its expiry. Mirrors `storageGcsAuthService` /
//!   `storageGcsAuthJwt` in the C `src/storage/gcs/storage.c`.
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
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use pgbr_io::{IoError, IoRead, IoWrite};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};

use crate::{Storage, StorageError, StorageInfo, StorageKind};

/// Default GCS XML/JSON API endpoint base URL.
const DEFAULT_ENDPOINT: &str = "https://storage.googleapis.com";

/// Default `OAuth2` token-exchange endpoint for the service-account JWT flow.
/// Public so callers building a `GcsAuth::ServiceAccount` can use the standard
/// endpoint without hard-coding the URL.
pub const DEFAULT_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

/// `OAuth2` scope requested for the service-account access token: read/write to
/// Cloud Storage, matching what pgBackRest's gcs driver requests.
const STORAGE_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";

/// Lifetime (seconds) of the signed JWT assertion. Google caps this at one hour.
const JWT_LIFETIME_SECS: i64 = 3600;

/// Refresh the cached access token this many seconds before its stated expiry,
/// to avoid using a token that lapses mid-request.
const TOKEN_REFRESH_SLACK_SECS: i64 = 60;

/// Authentication mechanism for a [`Gcs`] backend.
#[derive(Debug, Clone)]
pub enum GcsAuth {
    /// A pre-acquired `OAuth2` access token, sent verbatim as the bearer token in
    /// the `Authorization: Bearer <token>` header.
    Token(String),
    /// A service-account key. An RS256-signed JWT assertion is built from these
    /// fields, exchanged at `token_uri` for a short-lived `OAuth2` access token,
    /// and the access token is then used as the bearer token (cached to its
    /// expiry).
    ServiceAccount {
        /// Service-account email, used as the JWT `iss` (and `sub`) claim.
        client_email: String,
        /// RS256 PEM private key from the service-account key JSON
        /// (`private_key`), used to sign the JWT assertion.
        private_key_pem: String,
        /// `OAuth2` token-exchange endpoint, usually
        /// `https://oauth2.googleapis.com/token`. Used as the JWT `aud` claim
        /// and as the POST target.
        token_uri: String,
    },
}

/// A cached `OAuth2` access token plus the Unix-epoch second at which it expires.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: i64,
}

/// The subset of the `OAuth2` token-exchange JSON response this backend needs.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    /// Lifetime in seconds from the moment of issue.
    expires_in: i64,
}

/// JWT claims for the service-account `jwt-bearer` assertion.
#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
    iss: &'a str,
    scope: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
}

/// Build and RS256-sign the `OAuth2` JWT assertion for a service account.
///
/// Produces the compact JWS `base64url(header).base64url(claims).base64url(sig)`
/// with header `{"alg":"RS256","typ":"JWT"}` and claims
/// `{iss, scope, aud, iat: now_unix, exp: now_unix + 3600}`. The signature is
/// `RS256` (RSASSA-PKCS1-v1_5 over SHA-256) under `private_key_pem`.
///
/// Pure and deterministic given `now_unix`, so it is unit-testable without any
/// network access.
///
/// # Errors
///
/// Returns [`StorageError::Backend`] if `private_key_pem` is not a valid RSA PEM
/// private key or the JWT cannot be encoded.
pub fn build_signed_jwt(
    client_email: &str,
    scope: &str,
    aud: &str,
    now_unix: i64,
    private_key_pem: &str,
) -> Result<String, StorageError> {
    let header = Header::new(Algorithm::RS256);
    let claims = JwtClaims {
        iss: client_email,
        scope,
        aud,
        iat: now_unix,
        exp: now_unix + JWT_LIFETIME_SECS,
    };
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|err| StorageError::Backend {
        path: PathBuf::new(),
        message: format!("invalid service-account RSA private key: {err}"),
    })?;
    jsonwebtoken::encode(&header, &claims, &key).map_err(|err| StorageError::Backend {
        path: PathBuf::new(),
        message: format!("failed to sign service-account JWT: {err}"),
    })
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
    /// Authentication mechanism (bearer token or service-account key).
    pub auth: GcsAuth,
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
    /// Cached service-account access token, shared across clones so a refresh by
    /// one clone is visible to the others. `None` for the [`GcsAuth::Token`]
    /// path, which never refreshes.
    token_cache: Arc<Mutex<Option<CachedToken>>>,
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
            auth: config.auth,
            agent,
            token_cache: Arc::new(Mutex::new(None)),
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
    /// auth mechanism.
    ///
    /// For [`GcsAuth::Token`] this is infallible string formatting. For
    /// [`GcsAuth::ServiceAccount`] it returns the cached access token, performing
    /// a JWT-bearer token exchange first if the cache is empty or stale.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] if a service-account token exchange is
    /// required and fails (signing, transport, or a non-2xx token response).
    fn auth_header(&self) -> Result<(String, String), StorageError> {
        let token = self.bearer_token()?;
        Ok(("Authorization".to_string(), format!("Bearer {token}")))
    }

    /// Resolve the bearer token to send: the verbatim token for
    /// [`GcsAuth::Token`], or a fresh-enough cached access token for
    /// [`GcsAuth::ServiceAccount`] (refreshed via [`Self::exchange_jwt`] when the
    /// cache is empty or within [`TOKEN_REFRESH_SLACK_SECS`] of expiry).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] if a service-account refresh is needed
    /// and fails.
    fn bearer_token(&self) -> Result<String, StorageError> {
        match &self.auth {
            GcsAuth::Token(token) => Ok(token.clone()),
            GcsAuth::ServiceAccount {
                client_email,
                private_key_pem,
                token_uri,
            } => {
                let now = now_unix();
                // Fast path: a cached token that is still comfortably valid.
                {
                    let cache = self.token_cache.lock().map_err(|_| poisoned_cache_error())?;
                    if let Some(cached) = cache.as_ref().filter(|c| c.expires_at - TOKEN_REFRESH_SLACK_SECS > now) {
                        return Ok(cached.access_token.clone());
                    }
                }

                // Slow path: build + sign a JWT and exchange it for a token.
                let jwt = build_signed_jwt(client_email, STORAGE_SCOPE, token_uri, now, private_key_pem)?;
                let response = self.exchange_jwt(token_uri, &jwt)?;
                let cached = CachedToken {
                    access_token: response.access_token,
                    expires_at: now + response.expires_in,
                };
                let access_token = cached.access_token.clone();
                {
                    let mut cache = self.token_cache.lock().map_err(|_| poisoned_cache_error())?;
                    *cache = Some(cached);
                }
                Ok(access_token)
            }
        }
    }

    /// POST a signed JWT assertion to `token_uri` and parse the access token out
    /// of the `OAuth2` JSON response.
    ///
    /// The body is the standard `urn:ietf:params:oauth:grant-type:jwt-bearer`
    /// form: `grant_type=<grant>&assertion=<jwt>`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] on transport failure, a non-2xx status,
    /// or a response body that cannot be parsed into a [`TokenResponse`].
    fn exchange_jwt(&self, token_uri: &str, jwt: &str) -> Result<TokenResponse, StorageError> {
        let backend = |message: String| StorageError::Backend {
            path: PathBuf::new(),
            message,
        };
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", jwt),
        ];
        match self.agent.post(token_uri).send_form(&form) {
            Ok(resp) => {
                let body = resp
                    .into_string()
                    .map_err(|err| backend(format!("reading token response: {err}")))?;
                serde_json::from_str::<TokenResponse>(&body).map_err(|err| backend(format!("parsing token response: {err}")))
            }
            Err(ureq::Error::Status(code, resp)) => {
                let detail = resp.into_string().unwrap_or_default();
                Err(backend(format!("token exchange failed with status {code}: {detail}")))
            }
            Err(ureq::Error::Transport(transport)) => Err(backend(format!("token exchange transport error: {transport}"))),
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

/// Current wall-clock time as Unix epoch seconds (saturating to 0 before the
/// epoch). Used for JWT `iat`/`exp` and token-cache expiry checks.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Error returned when the shared token-cache mutex has been poisoned (a thread
/// panicked while holding it). Treated as a backend failure rather than a panic.
fn poisoned_cache_error() -> StorageError {
    StorageError::Backend {
        path: PathBuf::new(),
        message: "gcs token cache mutex poisoned".to_string(),
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
        let (auth_name, auth_value) = self.auth_header()?;
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
        let (auth_name, auth_value) = self.auth_header()?;
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
        let (auth_name, auth_value) = self.auth_header()?;
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
        let (auth_name, auth_value) = self.auth_header()?;
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
        let (auth_name, auth_value) = self.auth_header()?;
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
            auth: GcsAuth::Token("ya29.EXAMPLE_ACCESS_TOKEN".to_string()),
        }
    }

    fn test_gcs() -> Gcs {
        Gcs::new(test_config())
    }

    /// A deterministic 2048-bit RSA private key in PKCS#8 PEM, generated solely
    /// for tests (not a real credential). Used to exercise [`build_signed_jwt`]
    /// and signature verification without contacting Google.
    const TEST_RSA_PRIVATE_KEY_PEM: &str = include_str!("../tests/data/test_rsa_private_key.pem");
    const TEST_RSA_PUBLIC_KEY_PEM: &str = include_str!("../tests/data/test_rsa_public_key.pem");

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
        let (name, value) = gcs.auth_header().unwrap();
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

    /// Decode a JWT segment from base64url (no padding) into bytes.
    fn b64url_decode(segment: &str) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segment)
            .expect("valid base64url segment")
    }

    #[test]
    fn jwt_has_three_segments_and_rs256_header() {
        let now = 1_700_000_000;
        let jwt = build_signed_jwt(
            "svc@example.iam.gserviceaccount.com",
            STORAGE_SCOPE,
            DEFAULT_TOKEN_URI,
            now,
            TEST_RSA_PRIVATE_KEY_PEM,
        )
        .unwrap();

        // A compact JWS has exactly three dot-separated base64url segments.
        let segments: Vec<&str> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3, "JWT must have header.claims.signature");
        assert!(!segments[2].is_empty(), "signature segment must be present");

        // Header decodes to {"alg":"RS256","typ":"JWT"}.
        let header: serde_json::Value = serde_json::from_slice(&b64url_decode(segments[0])).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");

        // Claims carry iss/scope/aud and the iat/exp window we set.
        let claims: serde_json::Value = serde_json::from_slice(&b64url_decode(segments[1])).unwrap();
        assert_eq!(claims["iss"], "svc@example.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], STORAGE_SCOPE);
        assert_eq!(claims["aud"], DEFAULT_TOKEN_URI);
        assert_eq!(claims["iat"], now);
        assert_eq!(claims["exp"], now + JWT_LIFETIME_SECS);
    }

    #[test]
    fn jwt_signature_verifies_with_public_key() {
        use jsonwebtoken::{DecodingKey, Validation};

        let now = now_unix();
        let jwt = build_signed_jwt(
            "svc@example.iam.gserviceaccount.com",
            STORAGE_SCOPE,
            DEFAULT_TOKEN_URI,
            now,
            TEST_RSA_PRIVATE_KEY_PEM,
        )
        .unwrap();

        // Verify the RS256 signature against the matching public key. This proves
        // the signing pipeline is correct, not merely self-consistent.
        let decoding_key = DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[DEFAULT_TOKEN_URI]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(&jwt, &decoding_key, &validation).unwrap();
        assert_eq!(decoded.claims["iss"], "svc@example.iam.gserviceaccount.com");
        assert_eq!(decoded.claims["scope"], STORAGE_SCOPE);
    }

    #[test]
    fn jwt_rejects_invalid_private_key() {
        let err = build_signed_jwt(
            "svc@example.iam.gserviceaccount.com",
            STORAGE_SCOPE,
            DEFAULT_TOKEN_URI,
            0,
            "-----BEGIN PRIVATE KEY-----\nnot a real key\n-----END PRIVATE KEY-----\n",
        )
        .unwrap_err();
        match err {
            StorageError::Backend { message, .. } => assert!(message.contains("invalid service-account RSA private key")),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn service_account_config_is_accepted() {
        // A ServiceAccount-configured backend builds without contacting Google;
        // the token exchange is deferred until the first request.
        let config = GcsConfig {
            bucket: "examplebucket".to_string(),
            endpoint: None,
            auth: GcsAuth::ServiceAccount {
                client_email: "svc@example.iam.gserviceaccount.com".to_string(),
                private_key_pem: TEST_RSA_PRIVATE_KEY_PEM.to_string(),
                token_uri: DEFAULT_TOKEN_URI.to_string(),
            },
        };
        let gcs = Gcs::new(config);
        assert_eq!(gcs.bucket(), "examplebucket");
        assert!(matches!(gcs.auth, GcsAuth::ServiceAccount { .. }));
    }

    /// Integration test against a real bucket using a bearer token. Skipped
    /// unless the `PGBR_GCS_*` env vars are set. Run with
    /// `cargo test -p pgbr-storage -- --ignored`.
    #[test]
    #[ignore = "requires a live GCS bucket and PGBR_GCS_* env vars"]
    fn gcs_round_trip() {
        let config = GcsConfig {
            bucket: std::env::var("PGBR_GCS_TEST_BUCKET").expect("PGBR_GCS_TEST_BUCKET"),
            endpoint: std::env::var("PGBR_GCS_TEST_ENDPOINT").ok(),
            auth: GcsAuth::Token(std::env::var("PGBR_GCS_TEST_TOKEN").expect("PGBR_GCS_TEST_TOKEN")),
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

    /// Integration test of the full service-account JWT → access-token →
    /// read/write round trip. Skipped unless the `PGBR_GCS_SA_*` env vars are
    /// set. Run with `cargo test -p pgbr-storage -- --ignored`.
    #[test]
    #[ignore = "requires a live GCS bucket and PGBR_GCS_SA_* env vars"]
    fn gcs_service_account_round_trip() {
        let config = GcsConfig {
            bucket: std::env::var("PGBR_GCS_TEST_BUCKET").expect("PGBR_GCS_TEST_BUCKET"),
            endpoint: std::env::var("PGBR_GCS_TEST_ENDPOINT").ok(),
            auth: GcsAuth::ServiceAccount {
                client_email: std::env::var("PGBR_GCS_SA_CLIENT_EMAIL").expect("PGBR_GCS_SA_CLIENT_EMAIL"),
                private_key_pem: std::env::var("PGBR_GCS_SA_PRIVATE_KEY").expect("PGBR_GCS_SA_PRIVATE_KEY"),
                token_uri: std::env::var("PGBR_GCS_SA_TOKEN_URI").unwrap_or_else(|_| DEFAULT_TOKEN_URI.to_string()),
            },
        };
        let gcs = Gcs::new(config);

        let key = Path::new("pgbr-storage-sa-round-trip.txt");
        {
            let mut writer = gcs.open_write(key).unwrap();
            writer.write(b"hello service account").unwrap();
            writer.close().unwrap();
        }

        assert!(gcs.exists(key).unwrap());
        let mut reader = gcs.open_read(key).unwrap();
        assert_eq!(reader.read_all().unwrap(), b"hello service account");

        gcs.remove(key, true).unwrap();
        assert!(!gcs.exists(key).unwrap());
    }
}

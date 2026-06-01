//! Azure Blob Storage backend.
//!
//! Implements the [`Storage`] trait over the Azure Blob REST API using the same
//! synchronous [`ureq`] HTTP client as the S3 backend (blocking, no async
//! runtime).
//!
//! ## Authentication
//!
//! Two methods are supported, selected by [`AzureAuth`]:
//!
//! - [`AzureAuth::SharedKey`] — the account key signs each request. This is the
//!   correctness-critical path: it is unit-tested both for the exact
//!   `StringToSign` byte layout and for the
//!   `base64(HMAC-SHA256(account_key, …))` pipeline against an independently
//!   computed value.
//! - [`AzureAuth::Sas`] — a user-supplied Shared Access Signature token (a
//!   pre-signed query string). With SAS there is no `Authorization` header to
//!   compute; the SAS token is appended to each request URL's query string
//!   instead (see [`append_sas`]).
//!
//! ## Addressing
//!
//! A blob with key `k` lives at `<endpoint>/<container>/<k>`, where `endpoint`
//! defaults to `https://<account>.blob.core.windows.net`. The endpoint may be
//! overridden (e.g. for the Azurite emulator) via [`AzureConfig::endpoint`].
//!
//! ## Error mapping
//!
//! HTTP responses are mapped to [`StorageError`] via [`status_to_error`]:
//! `404 -> NotFound`, `403 -> PermissionDenied`, any other non-2xx -> `Backend`.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use pgbr_io::{IoError, IoRead, IoWrite};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha2::Sha256;

use crate::http::HttpOptions;
use crate::{Storage, StorageError, StorageInfo, StorageKind};

type HmacSha256 = Hmac<Sha256>;

/// The Azure Storage REST API version this backend speaks. Sent as the
/// mandatory `x-ms-version` header and included in the signature.
const API_VERSION: &str = "2021-08-06";

/// Resolved authentication mechanism for an [`Azure`] backend.
///
/// Mirrors pgBackRust's two azure auth modes: Shared Key (the account key signs
/// requests) and SAS (a pre-signed token appended to request URLs).
#[derive(Debug, Clone)]
pub enum AzureAuth {
    /// The decoded (raw bytes) account key, used to HMAC-sign each request's
    /// `StringToSign` into a `SharedKey <account>:<signature>` header.
    SharedKey(Vec<u8>),
    /// A Shared Access Signature token: the query-string portion of a SAS URL,
    /// e.g. `sv=2021-08-06&ss=b&srt=co&sp=rwdlac&sig=…` (with or without a
    /// leading `?`). It is appended to each request URL instead of computing an
    /// `Authorization` header.
    Sas(String),
}

/// Immutable configuration for an [`Azure`] backend.
///
/// Mirrors the credential / addressing inputs the C `storage/azure` driver
/// takes, minus the live HTTP agent (which [`Azure::new`] constructs). Supply
/// exactly one of `account_key_base64` (Shared Key) or `sas_token` (SAS).
#[derive(Debug, Clone)]
pub struct AzureConfig {
    /// Storage account name, e.g. `myaccount`.
    pub account: String,
    /// Blob container name.
    pub container: String,
    /// Account key, base64-encoded (as Azure presents it in the portal). Used
    /// for Shared Key auth. Mutually exclusive with `sas_token`.
    pub account_key_base64: Option<String>,
    /// A SAS token query string (the part after `?` in a SAS URL). Used for SAS
    /// auth. Mutually exclusive with `account_key_base64`.
    pub sas_token: Option<String>,
    /// Optional endpoint base URL including scheme. Defaults to
    /// `https://<account>.blob.core.windows.net`.
    pub endpoint: Option<String>,
    /// Blob tags applied on upload (`repo-storage-tag`), sent as the
    /// `x-ms-tags` header (`k1=v1&k2=v2`).
    pub tags: BTreeMap<String, String>,
    /// Shared HTTPS-client transport options (`repo-storage-*`).
    pub http: HttpOptions,
}

impl AzureConfig {
    /// Build a config with only the required credential / addressing inputs and
    /// every optional field at its default (matches the prior constructor shape).
    #[must_use]
    pub fn new(
        account: String,
        container: String,
        account_key_base64: Option<String>,
        sas_token: Option<String>,
        endpoint: Option<String>,
    ) -> Self {
        Self {
            account,
            container,
            account_key_base64,
            sas_token,
            endpoint,
            tags: BTreeMap::new(),
            http: HttpOptions::default(),
        }
    }
}

/// Azure Blob storage backend speaking the REST API over a synchronous
/// [`ureq`] client.
///
/// Cloning is cheap: [`ureq::Agent`] clones share the underlying connection
/// pool, and the remaining fields are short strings / a decoded key. The
/// `open_write` writer holds an owned clone so the boxed `IoWrite` it returns
/// is `'static`.
#[derive(Clone)]
pub struct Azure {
    account: String,
    container: String,
    auth: AzureAuth,
    endpoint: String,
    tags: BTreeMap<String, String>,
    agent: ureq::Agent,
}

impl Azure {
    /// Build an `Azure` backend from `config`, constructing a [`ureq::Agent`]
    /// from the config's [`HttpOptions`] (custom CA / verify-tls when set).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] if neither (or both) of
    /// `account_key_base64` / `sas_token` is supplied, if `account_key_base64`
    /// is not valid base64, or if the configured TLS options cannot be loaded.
    pub fn new(config: AzureConfig) -> Result<Self, StorageError> {
        let agent = config.http.build_agent()?;
        Self::with_agent(config, agent)
    }

    /// Build an `Azure` backend with a caller-supplied [`ureq::Agent`].
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] if neither (or both) of
    /// `account_key_base64` / `sas_token` is supplied, or if
    /// `account_key_base64` is not valid base64.
    pub fn with_agent(config: AzureConfig, agent: ureq::Agent) -> Result<Self, StorageError> {
        let backend = |message: String| StorageError::Backend {
            path: PathBuf::new(),
            message,
        };
        let auth = match (config.account_key_base64, config.sas_token) {
            (Some(key_b64), None) => {
                let key = BASE64
                    .decode(key_b64.trim())
                    .map_err(|err| backend(format!("invalid base64 account key: {err}")))?;
                AzureAuth::SharedKey(key)
            }
            (None, Some(sas)) => AzureAuth::Sas(sas),
            (Some(_), Some(_)) => {
                return Err(backend(
                    "exactly one of account_key_base64 or sas_token must be set, not both".to_string(),
                ));
            }
            (None, None) => {
                return Err(backend("one of account_key_base64 or sas_token must be set".to_string()));
            }
        };
        let endpoint = config
            .endpoint
            .unwrap_or_else(|| format!("https://{}.blob.core.windows.net", config.account))
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            account: config.account,
            container: config.container,
            auth,
            endpoint,
            tags: config.tags,
            agent,
        })
    }

    /// Configured endpoint base URL (trailing slash trimmed). Useful for tests.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Configured container. Useful for tests / diagnostics.
    #[must_use]
    pub fn container(&self) -> &str {
        &self.container
    }

    /// Configured account name. Useful for tests / diagnostics.
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }

    /// Full request URL for blob `key`: `<endpoint>/<container>/<key>`.
    fn blob_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.endpoint, self.container, key)
    }

    /// Build the canonicalized resource component of the `StringToSign`:
    /// `/<account>/<container>/<blob>` followed, for each query parameter
    /// (sorted by lowercased name), by `\n<name>:<value>`.
    ///
    /// `query` is the set of `(name, value)` query parameters in the request;
    /// for a plain blob operation it is empty.
    fn canonicalized_resource(&self, key: &str, query: &[(String, String)]) -> String {
        let mut resource = format!("/{}/{}", self.account, self.container);
        if !key.is_empty() {
            resource.push('/');
            resource.push_str(key);
        }

        let mut params = query.to_vec();
        params.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, value) in params {
            resource.push('\n');
            resource.push_str(&name.to_lowercase());
            resource.push(':');
            resource.push_str(&value);
        }
        resource
    }

    /// Assemble the Shared Key `StringToSign` for a request.
    ///
    /// `ms_headers` is the set of `x-ms-*` headers to canonicalize (lowercased
    /// name + value); it must include `x-ms-date` and `x-ms-version`.
    /// `canonicalized_resource` is produced by [`Self::canonicalized_resource`].
    /// `content_length` is the request body length (empty string for a zero or
    /// absent body, per the Shared Key rules for newer API versions).
    fn string_to_sign(
        method: &str,
        content_length: &str,
        content_type: &str,
        ms_headers: &[(String, String)],
        canonicalized_resource: &str,
    ) -> String {
        // Canonicalized x-ms-* headers: lowercased names, sorted, "name:value\n".
        let mut sorted = ms_headers.to_vec();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let mut canonicalized_headers = String::new();
        for (name, value) in &sorted {
            canonicalized_headers.push_str(&name.to_lowercase());
            canonicalized_headers.push(':');
            canonicalized_headers.push_str(value.trim());
            canonicalized_headers.push('\n');
        }

        // The blob-service StringToSign: VERB, then the fixed standard-header
        // block (most fields empty for our requests), then canonicalized x-ms-*
        // headers, then the canonicalized resource. Note: there is NO trailing
        // newline after the standard-header block — the last fixed field
        // (Range) is followed by '\n', then the canonicalized headers begin.
        format!(
            "{method}\n\
             \n\
             \n\
             {content_length}\n\
             \n\
             {content_type}\n\
             \n\
             \n\
             \n\
             \n\
             \n\
             \n\
             {canonicalized_headers}{canonicalized_resource}"
        )
    }

    /// Compute the `Authorization: SharedKey <account>:<signature>` header value
    /// for a request, or `None` when SAS auth is in effect (SAS carries its
    /// signature in the URL, so no `Authorization` header is sent).
    fn authorization(
        &self,
        method: &str,
        content_length: &str,
        content_type: &str,
        ms_headers: &[(String, String)],
        canonicalized_resource: &str,
    ) -> Option<String> {
        match &self.auth {
            AzureAuth::SharedKey(key) => {
                let to_sign = Self::string_to_sign(method, content_length, content_type, ms_headers, canonicalized_resource);
                let signature = BASE64.encode(hmac_sha256(key, to_sign.as_bytes()));
                Some(format!("SharedKey {}:{signature}", self.account))
            }
            AzureAuth::Sas(_) => None,
        }
    }

    /// Final request URL for `base_url`: unchanged for Shared Key auth, or with
    /// the SAS token appended to the query string for SAS auth.
    fn request_url(&self, base_url: &str) -> String {
        match &self.auth {
            AzureAuth::SharedKey(_) => base_url.to_string(),
            AzureAuth::Sas(sas) => append_sas(base_url, sas),
        }
    }

    /// Build the mandatory `x-ms-date` + `x-ms-version` headers for "now".
    fn ms_base_headers() -> Vec<(String, String)> {
        vec![
            ("x-ms-date".to_string(), Self::now_http_date()),
            ("x-ms-version".to_string(), API_VERSION.to_string()),
        ]
    }

    /// Translate a `Path` into an Azure blob key. Backend-relative: any leading
    /// `/` is stripped, and Windows-style separators are normalised to `/`.
    fn key_for(path: &Path) -> String {
        let raw = path.to_string_lossy();
        let normalised = raw.replace('\\', "/");
        normalised.trim_start_matches('/').to_string()
    }

    /// Current time formatted as an RFC-1123 / HTTP date (`x-ms-date`).
    fn now_http_date() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        format_http_date(secs)
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

/// One entry parsed out of a List Blobs response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ListEntry {
    name: String,
    size: u64,
    modified: Option<i64>,
}

/// Parse a List Blobs XML response body into its `<Blob>` entries.
///
/// The relevant shape is:
/// `<EnumerationResults><Blobs><Blob><Name>..</Name>`
/// `<Properties><Content-Length>..</Content-Length>`
/// `<Last-Modified>..</Last-Modified></Properties></Blob>…</Blobs>…`.
fn parse_list_blobs(xml: &str) -> Result<Vec<ListEntry>, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut entries = Vec::new();
    let mut in_blob = false;
    let mut cur_tag: Option<String> = None;
    let mut name = String::new();
    let mut size: u64 = 0;
    let mut modified: Option<i64> = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = e.local_name();
                let tag = String::from_utf8_lossy(tag.as_ref()).into_owned();
                if tag == "Blob" {
                    in_blob = true;
                    name.clear();
                    size = 0;
                    modified = None;
                }
                cur_tag = Some(tag);
            }
            Ok(Event::Text(e)) => {
                if !in_blob {
                    continue;
                }
                let text = e.xml_content().map_err(|err| err.to_string())?.into_owned();
                match cur_tag.as_deref() {
                    Some("Name") => name = text,
                    Some("Content-Length") => size = text.trim().parse().unwrap_or(0),
                    Some("Last-Modified") => modified = parse_http_date_secs(&text),
                    _ => {}
                }
            }
            Ok(Event::End(e)) => {
                let tag = e.local_name();
                let tag = String::from_utf8_lossy(tag.as_ref()).into_owned();
                if tag == "Blob" {
                    in_blob = false;
                    entries.push(ListEntry {
                        name: std::mem::take(&mut name),
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

/// Append a SAS token query string to `base_url`.
///
/// Chooses the correct separator: `?` if the URL has no query yet, `&` if it
/// already does (e.g. the list operation carries `?restype=container&comp=list`).
/// Any leading `?` on the SAS token is stripped so it is not duplicated. Pure so
/// the join logic is unit-testable without a live request.
#[must_use]
pub fn append_sas(base_url: &str, sas_token: &str) -> String {
    let sas = sas_token.trim().trim_start_matches('?');
    if sas.is_empty() {
        return base_url.to_string();
    }
    let separator = if base_url.contains('?') { '&' } else { '?' };
    format!("{base_url}{separator}{sas}")
}

/// Percent-encode a query-parameter value (RFC 3986 `pchar`-safe set). Only the
/// unreserved characters `A-Z a-z 0-9 - _ . ~` are passed through; everything
/// else — including `/` in a blob prefix — is `%XX`-encoded. Matches how a URL
/// query value must be escaped on the wire.
fn percent_encode_query(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// Encode blob tags as the `x-ms-tags` header value: a URL-query-style
/// `k1=v1&k2=v2` string with each key and value percent-encoded. Keys are sorted
/// (the map is a [`BTreeMap`]) so the output is deterministic.
fn encode_blob_tags(tags: &BTreeMap<String, String>) -> String {
    tags.iter()
        .map(|(k, v)| format!("{}={}", percent_encode_query(k), percent_encode_query(v)))
        .collect::<Vec<_>>()
        .join("&")
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

/// Adapter exposing an owned byte buffer (a fetched blob body) as [`IoRead`].
struct AzureRead {
    data: Vec<u8>,
    pos: usize,
}

impl IoRead for AzureRead {
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

/// Adapter that buffers writes and PUTs the whole blob on [`IoWrite::close`].
///
/// A block-blob PUT is not streaming-friendly without staged blocks, so this
/// collects the body in memory and uploads it once on close (matching the C
/// driver's behaviour for small objects).
struct AzureWrite {
    azure: Azure,
    key: String,
    buffer: Vec<u8>,
    closed: bool,
}

impl IoWrite for AzureWrite {
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
        self.azure
            .put_blob(&self.key, &self.buffer)
            .map_err(|err| IoError::Backend(err.to_string()))
    }
}

impl Azure {
    /// PUT a block blob body to `key`.
    fn put_blob(&self, key: &str, body: &[u8]) -> Result<(), StorageError> {
        let mut ms_headers = Self::ms_base_headers();
        ms_headers.push(("x-ms-blob-type".to_string(), "BlockBlob".to_string()));
        // Object tags (`repo-storage-tag`) are sent as the signed `x-ms-tags`
        // header (`k1=v1&k2=v2`, percent-encoded). Only on upload.
        if !self.tags.is_empty() {
            ms_headers.push(("x-ms-tags".to_string(), encode_blob_tags(&self.tags)));
        }

        let content_length = body.len().to_string();
        let resource = self.canonicalized_resource(key, &[]);
        let authorization = self.authorization("PUT", &content_length, "", &ms_headers, &resource);

        let url = self.request_url(&self.blob_url(key));
        let mut req = self.agent.put(&url).set("Content-Length", &content_length);
        for (name, value) in &ms_headers {
            req = req.set(name, value);
        }
        if let Some(authorization) = &authorization {
            req = req.set("Authorization", authorization);
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

impl Storage for Azure {
    fn exists(&self, path: &Path) -> Result<bool, StorageError> {
        match self.info(path) {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    fn info(&self, path: &Path) -> Result<StorageInfo, StorageError> {
        let key = Self::key_for(path);
        let ms_headers = Self::ms_base_headers();
        let resource = self.canonicalized_resource(&key, &[]);
        let authorization = self.authorization("HEAD", "", "", &ms_headers, &resource);

        let url = self.request_url(&self.blob_url(&key));
        let mut req = self.agent.head(&url);
        for (name, value) in &ms_headers {
            req = req.set(name, value);
        }
        if let Some(authorization) = &authorization {
            req = req.set("Authorization", authorization);
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

        let ms_headers = Self::ms_base_headers();
        // Query params that participate in the canonicalized resource. The
        // List Blobs operation is keyed on the container (empty blob name).
        let mut query: Vec<(String, String)> = vec![
            ("comp".to_string(), "list".to_string()),
            ("restype".to_string(), "container".to_string()),
        ];
        if !prefix.is_empty() {
            query.push(("prefix".to_string(), prefix.clone()));
        }
        let resource = self.canonicalized_resource("", &query);
        let authorization = self.authorization("GET", "", "", &ms_headers, &resource);

        // Build the wire URL with the operation query string ourselves so the
        // SAS token (if any) can be appended after it via `request_url`. The
        // prefix value is percent-encoded the same way ureq's `.query()` would.
        let mut base_url = format!("{}/{}?restype=container&comp=list", self.endpoint, self.container);
        if !prefix.is_empty() {
            base_url.push_str("&prefix=");
            base_url.push_str(&percent_encode_query(&prefix));
        }
        let url = self.request_url(&base_url);
        let mut req = self.agent.get(&url);
        for (name, value) in &ms_headers {
            req = req.set(name, value);
        }
        if let Some(authorization) = &authorization {
            req = req.set("Authorization", authorization);
        }

        let body = match req.call() {
            Ok(resp) => resp.into_string().map_err(|err| StorageError::Backend {
                path: path.to_path_buf(),
                message: err.to_string(),
            })?,
            Err(err) => return Err(map_ureq_error(err, &prefix)),
        };

        let parsed = parse_list_blobs(&body).map_err(|message| StorageError::Backend {
            path: path.to_path_buf(),
            message,
        })?;

        let mut entries: Vec<StorageInfo> = parsed
            .into_iter()
            .map(|e| StorageInfo {
                path: PathBuf::from(e.name),
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
        let ms_headers = Self::ms_base_headers();
        let resource = self.canonicalized_resource(&key, &[]);
        let authorization = self.authorization("GET", "", "", &ms_headers, &resource);

        let url = self.request_url(&self.blob_url(&key));
        let mut req = self.agent.get(&url);
        for (name, value) in &ms_headers {
            req = req.set(name, value);
        }
        if let Some(authorization) = &authorization {
            req = req.set("Authorization", authorization);
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
                Ok(Box::new(AzureRead { data, pos: 0 }))
            }
            Err(err) => Err(map_ureq_error(err, &key)),
        }
    }

    fn open_write(&self, path: &Path) -> Result<Box<dyn IoWrite>, StorageError> {
        let key = Self::key_for(path);
        Ok(Box::new(AzureWrite {
            azure: self.clone(),
            key,
            buffer: Vec::new(),
            closed: false,
        }))
    }

    fn remove(&self, path: &Path, error_on_missing: bool) -> Result<(), StorageError> {
        let key = Self::key_for(path);
        let ms_headers = Self::ms_base_headers();
        let resource = self.canonicalized_resource(&key, &[]);
        let authorization = self.authorization("DELETE", "", "", &ms_headers, &resource);

        let url = self.request_url(&self.blob_url(&key));
        let mut req = self.agent.delete(&url);
        for (name, value) in &ms_headers {
            req = req.set(name, value);
        }
        if let Some(authorization) = &authorization {
            req = req.set("Authorization", authorization);
        }

        match req.call() {
            Ok(_) => Ok(()),
            Err(err) => match map_ureq_error(err, &key) {
                StorageError::NotFound { .. } if !error_on_missing => Ok(()),
                other => Err(other),
            },
        }
    }

    fn rename(&self, source: &Path, target: &Path) -> Result<(), StorageError> {
        // Azure Blob has no atomic rename. Emulate copy-then-delete via
        // read+write, mirroring the S3 backend.
        let mut reader = self.open_read(source)?;
        let data = reader.read_all().map_err(StorageError::Io)?;
        let mut writer = self.open_write(target)?;
        writer.write(&data).map_err(StorageError::Io)?;
        writer.close().map_err(StorageError::Io)?;
        self.remove(source, false)
    }

    fn create_path(&self, _path: &Path, _recursive: bool) -> Result<(), StorageError> {
        // Azure Blob has no real directories: blobs with a common prefix are a
        // "path". Creating one is a no-op (the prefix springs into existence
        // with the first blob written under it).
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

/// Number-of-days-since-epoch → `(year, month, day)` in the proleptic
/// Gregorian calendar (Howard Hinnant's civil-from-days algorithm).
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

/// Format Unix epoch `secs` as an RFC-1123 / HTTP date in GMT, e.g.
/// `Wed, 12 Oct 2009 17:50:30 GMT` — the form Azure's `x-ms-date` requires.
fn format_http_date(secs: u64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let days = secs / 86_400;
    let rem = secs % 86_400;
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;

    // 1970-01-01 was a Thursday; index into WEEKDAYS accordingly.
    let weekday = WEEKDAYS[(days % 7) as usize];

    let (year, month, day) = civil_from_days(i64::try_from(days).unwrap_or(0));
    let month_index = usize::try_from(month).unwrap_or(1).saturating_sub(1).min(11);
    let month_name = MONTHS[month_index];

    format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_config() -> AzureConfig {
        AzureConfig::new(
            "devstoreaccount1".to_string(),
            "mycontainer".to_string(),
            // "0123456789" base64-encoded — a deterministic, non-secret test key.
            Some("MDEyMzQ1Njc4OQ==".to_string()),
            None,
            None,
        )
    }

    /// A SAS-configured test config (no account key). The token is a fixed,
    /// non-secret fixture; the `sig` value is illustrative, not a real HMAC.
    fn sas_config() -> AzureConfig {
        AzureConfig::new(
            "devstoreaccount1".to_string(),
            "mycontainer".to_string(),
            None,
            Some("sv=2021-08-06&ss=b&srt=co&sp=rwdlac&sig=ABC%2Bdef123".to_string()),
            None,
        )
    }

    fn test_azure() -> Azure {
        Azure::new(test_config()).unwrap()
    }

    /// Extract the decoded Shared Key bytes from a backend, panicking if it is
    /// not Shared-Key-configured. Test-only helper.
    fn shared_key_bytes(azure: &Azure) -> &[u8] {
        match &azure.auth {
            AzureAuth::SharedKey(key) => key,
            AzureAuth::Sas(_) => panic!("expected SharedKey auth"),
        }
    }

    /// Anchor #1: pin the exact `StringToSign` byte layout for a fixed request.
    /// This catches accidental format drift (a missing/extra newline silently
    /// corrupts every signature).
    ///
    /// Anchor #2: prove the `base64(HMAC-SHA256(key, msg))` pipeline is correct
    /// (not merely self-consistent) by checking against a value computed
    /// independently in the dev container:
    ///
    /// ```text
    /// python3 -c "import hmac,hashlib,base64;
    ///   k=base64.b64decode('MDEyMzQ1Njc4OQ==');
    ///   print(base64.b64encode(hmac.new(k, b'hello', hashlib.sha256).digest()).decode())"
    /// => p1l1ggO/CZANAwoL/KMDTa3KSMTQnQJ3Tv67ZE9SXZQ=
    /// ```
    #[test]
    fn shared_key_signature_is_stable() {
        let azure = test_azure();

        // (a) Self-consistency: the StringToSign for a fixed GET blob request.
        let ms_headers = vec![
            ("x-ms-date".to_string(), "Fri, 01 Jan 2021 00:00:00 GMT".to_string()),
            ("x-ms-version".to_string(), "2021-08-06".to_string()),
        ];
        let resource = azure.canonicalized_resource("path/to/blob.bin", &[]);
        let to_sign = Azure::string_to_sign("GET", "", "", &ms_headers, &resource);

        let expected = "GET\n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        \n\
                        x-ms-date:Fri, 01 Jan 2021 00:00:00 GMT\n\
                        x-ms-version:2021-08-06\n\
                        /devstoreaccount1/mycontainer/path/to/blob.bin";
        assert_eq!(to_sign, expected);

        // (b) Independently-verified HMAC + base64 pipeline.
        let signature = BASE64.encode(hmac_sha256(shared_key_bytes(&azure), b"hello"));
        assert_eq!(signature, "p1l1ggO/CZANAwoL/KMDTa3KSMTQnQJ3Tv67ZE9SXZQ=");

        // And the full Authorization header is well-formed.
        let auth = azure
            .authorization("GET", "", "", &ms_headers, &resource)
            .expect("Shared Key auth produces an Authorization header");
        assert!(auth.starts_with("SharedKey devstoreaccount1:"));
    }

    #[test]
    fn canonicalized_resource_building() {
        let azure = test_azure();

        // Plain blob: /<account>/<container>/<blob>.
        assert_eq!(
            azure.canonicalized_resource("dir/blob.txt", &[]),
            "/devstoreaccount1/mycontainer/dir/blob.txt"
        );

        // Container-level op with sorted query params, each on its own line.
        let query = vec![
            ("restype".to_string(), "container".to_string()),
            ("comp".to_string(), "list".to_string()),
            ("prefix".to_string(), "archive/".to_string()),
        ];
        assert_eq!(
            azure.canonicalized_resource("", &query),
            "/devstoreaccount1/mycontainer\ncomp:list\nprefix:archive/\nrestype:container"
        );
    }

    #[test]
    fn blob_url_uses_default_endpoint() {
        let azure = test_azure();
        assert_eq!(azure.endpoint(), "https://devstoreaccount1.blob.core.windows.net");
        assert_eq!(
            azure.blob_url("a/b/c.bin"),
            "https://devstoreaccount1.blob.core.windows.net/mycontainer/a/b/c.bin"
        );

        // Explicit endpoint overrides the default and trims the trailing slash.
        let mut config = test_config();
        config.endpoint = Some("http://127.0.0.1:10000/devstoreaccount1/".to_string());
        let emulator = Azure::new(config).unwrap();
        assert_eq!(emulator.endpoint(), "http://127.0.0.1:10000/devstoreaccount1");
        assert_eq!(emulator.container(), "mycontainer");
        assert_eq!(emulator.account(), "devstoreaccount1");
    }

    #[test]
    fn invalid_base64_key_is_rejected() {
        let mut config = test_config();
        config.account_key_base64 = Some("not valid base64!!!".to_string());
        match Azure::new(config).err() {
            Some(StorageError::Backend { message, .. }) => assert!(message.contains("invalid base64")),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn requires_exactly_one_auth_method() {
        // Neither set.
        let mut none_config = test_config();
        none_config.account_key_base64 = None;
        none_config.sas_token = None;
        match Azure::new(none_config).err() {
            Some(StorageError::Backend { message, .. }) => assert!(message.contains("must be set")),
            other => panic!("expected Backend error, got {other:?}"),
        }

        // Both set.
        let mut both_config = test_config();
        both_config.sas_token = Some("sv=2021-08-06&sig=x".to_string());
        match Azure::new(both_config).err() {
            Some(StorageError::Backend { message, .. }) => assert!(message.contains("not both")),
            other => panic!("expected Backend error, got {other:?}"),
        }
    }

    #[test]
    fn shared_key_path_still_works() {
        // Regression guard: a Shared-Key backend resolves to SharedKey auth,
        // produces an Authorization header, and appends nothing to the URL.
        let azure = test_azure();
        assert!(matches!(azure.auth, AzureAuth::SharedKey(_)));

        let ms_headers = fixed_ms_headers();
        let resource = azure.canonicalized_resource("dir/blob.bin", &[]);
        assert!(azure.authorization("GET", "", "", &ms_headers, &resource).is_some());

        // Shared Key leaves the request URL untouched (no SAS appended).
        let base = azure.blob_url("dir/blob.bin");
        assert_eq!(azure.request_url(&base), base);
    }

    /// Fixed `x-ms-*` headers for tests that don't care about the live clock.
    fn fixed_ms_headers() -> Vec<(String, String)> {
        vec![
            ("x-ms-date".to_string(), "Fri, 01 Jan 2021 00:00:00 GMT".to_string()),
            ("x-ms-version".to_string(), "2021-08-06".to_string()),
        ]
    }

    #[test]
    fn sas_url_appends_token() {
        // No existing query → join with '?'.
        let plain = "https://devstoreaccount1.blob.core.windows.net/mycontainer/blob.bin";
        assert_eq!(
            append_sas(plain, "sv=2021-08-06&sig=abc"),
            "https://devstoreaccount1.blob.core.windows.net/mycontainer/blob.bin?sv=2021-08-06&sig=abc"
        );

        // Existing query (the list op) → join with '&'.
        let listing = "https://devstoreaccount1.blob.core.windows.net/mycontainer?restype=container&comp=list";
        assert_eq!(
            append_sas(listing, "sv=2021-08-06&sig=abc"),
            "https://devstoreaccount1.blob.core.windows.net/mycontainer?restype=container&comp=list&sv=2021-08-06&sig=abc"
        );

        // A leading '?' on the SAS token is stripped, not duplicated.
        assert_eq!(
            append_sas(plain, "?sv=2021-08-06&sig=abc"),
            format!("{plain}?sv=2021-08-06&sig=abc")
        );

        // An empty SAS token leaves the URL unchanged.
        assert_eq!(append_sas(plain, ""), plain);
    }

    #[test]
    fn sas_auth_appends_to_request_urls_and_skips_authorization() {
        let azure = Azure::new(sas_config()).unwrap();
        assert!(matches!(azure.auth, AzureAuth::Sas(_)));

        // SAS auth produces no Authorization header.
        let ms_headers = fixed_ms_headers();
        let resource = azure.canonicalized_resource("dir/blob.bin", &[]);
        assert!(azure.authorization("GET", "", "", &ms_headers, &resource).is_none());

        // A plain blob URL gets the SAS token after a '?'.
        let blob = azure.request_url(&azure.blob_url("dir/blob.bin"));
        assert_eq!(
            blob,
            "https://devstoreaccount1.blob.core.windows.net/mycontainer/dir/blob.bin\
             ?sv=2021-08-06&ss=b&srt=co&sp=rwdlac&sig=ABC%2Bdef123"
        );

        // A URL that already carries a query gets the SAS token after a '&'.
        let listing = azure.request_url(&format!(
            "{}/{}?restype=container&comp=list",
            azure.endpoint(),
            azure.container()
        ));
        assert_eq!(
            listing,
            "https://devstoreaccount1.blob.core.windows.net/mycontainer\
             ?restype=container&comp=list&sv=2021-08-06&ss=b&srt=co&sp=rwdlac&sig=ABC%2Bdef123"
        );
    }

    #[test]
    fn percent_encode_query_escapes_slash() {
        assert_eq!(percent_encode_query("archive/sub/"), "archive%2Fsub%2F");
        assert_eq!(percent_encode_query("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(percent_encode_query("x y+z"), "x%20y%2Bz");
    }

    #[test]
    fn blob_tags_encode_deterministically() {
        let mut tags = BTreeMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        tags.insert("team".to_string(), "db ops".to_string());
        // Sorted by key (BTreeMap), values percent-encoded.
        assert_eq!(encode_blob_tags(&tags), "env=prod&team=db%20ops");
    }

    #[test]
    fn tags_set_signed_x_ms_tags_on_upload() {
        // A tagged config carries the tags through to the backend; the put path
        // adds them as the `x-ms-tags` header (verified via the field here, the
        // header assembly is exercised by the put method).
        let mut tags = BTreeMap::new();
        tags.insert("k".to_string(), "v".to_string());
        let config = AzureConfig {
            tags: tags.clone(),
            ..test_config()
        };
        let azure = Azure::new(config).unwrap();
        assert_eq!(azure.tags, tags);
        assert_eq!(encode_blob_tags(&azure.tags), "k=v");
    }

    #[test]
    fn key_for_strips_leading_slash_and_normalises() {
        assert_eq!(Azure::key_for(Path::new("/repo/archive/x")), "repo/archive/x");
        assert_eq!(Azure::key_for(Path::new("repo/archive/x")), "repo/archive/x");
    }

    #[test]
    fn status_to_error_mapping() {
        let path = Path::new("missing/blob");
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
    fn list_parses_blob_xml() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="https://devstoreaccount1.blob.core.windows.net/" ContainerName="mycontainer">
    <Prefix>archive/</Prefix>
    <Blobs>
        <Blob>
            <Name>archive/000000010000000000000001</Name>
            <Properties>
                <Last-Modified>Mon, 12 Oct 2009 17:50:30 GMT</Last-Modified>
                <Content-Length>16777216</Content-Length>
                <Content-Type>application/octet-stream</Content-Type>
                <BlobType>BlockBlob</BlobType>
            </Properties>
        </Blob>
        <Blob>
            <Name>archive/000000010000000000000002</Name>
            <Properties>
                <Last-Modified>Mon, 12 Oct 2009 17:51:00 GMT</Last-Modified>
                <Content-Length>42</Content-Length>
                <BlobType>BlockBlob</BlobType>
            </Properties>
        </Blob>
    </Blobs>
    <NextMarker />
</EnumerationResults>"#;

        let entries = parse_list_blobs(xml).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "archive/000000010000000000000001");
        assert_eq!(entries[0].size, 16_777_216);
        assert_eq!(entries[1].name, "archive/000000010000000000000002");
        assert_eq!(entries[1].size, 42);
        // Mon, 12 Oct 2009 17:50:30 GMT == 1255369830 epoch seconds.
        assert_eq!(entries[0].modified, Some(1_255_369_830));
    }

    #[test]
    fn list_parses_empty_result() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ContainerName="mycontainer">
    <Blobs />
    <NextMarker />
</EnumerationResults>"#;
        assert!(parse_list_blobs(xml).unwrap().is_empty());
    }

    #[test]
    fn http_date_round_trips() {
        // Wed, 12 Oct 2009 17:50:30 GMT == 1255369830.
        assert_eq!(format_http_date(1_255_369_830), "Mon, 12 Oct 2009 17:50:30 GMT");
        assert_eq!(parse_http_date_secs("Mon, 12 Oct 2009 17:50:30 GMT"), Some(1_255_369_830));
        // 2021-01-01T00:00:00Z == 1609459200, a Friday.
        assert_eq!(format_http_date(1_609_459_200), "Fri, 01 Jan 2021 00:00:00 GMT");
        assert_eq!(parse_http_date_secs("garbage"), None);
    }

    /// Integration test against a real account. Skipped unless the
    /// `PGBR_AZURE_*` env vars are set. Run with
    /// `cargo test -p pgbr-storage -- --ignored`.
    #[test]
    #[ignore = "requires a live Azure account and PGBR_AZURE_* env vars"]
    fn azure_round_trip() {
        let config = AzureConfig::new(
            std::env::var("PGBR_AZURE_ACCOUNT").expect("PGBR_AZURE_ACCOUNT"),
            std::env::var("PGBR_AZURE_CONTAINER").expect("PGBR_AZURE_CONTAINER"),
            Some(std::env::var("PGBR_AZURE_KEY").expect("PGBR_AZURE_KEY")),
            None,
            std::env::var("PGBR_AZURE_ENDPOINT").ok(),
        );
        let azure = Azure::new(config).unwrap();

        let key = Path::new("pgbr-storage-round-trip.txt");
        {
            let mut writer = azure.open_write(key).unwrap();
            writer.write(b"hello azure").unwrap();
            writer.close().unwrap();
        }

        assert!(azure.exists(key).unwrap());
        let info = azure.info(key).unwrap();
        assert_eq!(info.size, 11);

        let mut reader = azure.open_read(key).unwrap();
        assert_eq!(reader.read_all().unwrap(), b"hello azure");

        azure.remove(key, true).unwrap();
        assert!(!azure.exists(key).unwrap());
    }

    /// Integration test against a real account using a SAS token. Skipped unless
    /// the `PGBR_AZURE_*` + `PGBR_AZURE_SAS` env vars are set. Run with
    /// `cargo test -p pgbr-storage -- --ignored`.
    #[test]
    #[ignore = "requires a live Azure account and PGBR_AZURE_SAS env var"]
    fn azure_sas_round_trip() {
        let config = AzureConfig::new(
            std::env::var("PGBR_AZURE_ACCOUNT").expect("PGBR_AZURE_ACCOUNT"),
            std::env::var("PGBR_AZURE_CONTAINER").expect("PGBR_AZURE_CONTAINER"),
            None,
            Some(std::env::var("PGBR_AZURE_SAS").expect("PGBR_AZURE_SAS")),
            std::env::var("PGBR_AZURE_ENDPOINT").ok(),
        );
        let azure = Azure::new(config).unwrap();

        let key = Path::new("pgbr-storage-sas-round-trip.txt");
        {
            let mut writer = azure.open_write(key).unwrap();
            writer.write(b"hello sas").unwrap();
            writer.close().unwrap();
        }

        assert!(azure.exists(key).unwrap());
        let mut reader = azure.open_read(key).unwrap();
        assert_eq!(reader.read_all().unwrap(), b"hello sas");

        azure.remove(key, true).unwrap();
        assert!(!azure.exists(key).unwrap());
    }
}

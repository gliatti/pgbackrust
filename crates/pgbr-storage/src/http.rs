//! Shared HTTPS-client configuration for the object-store backends
//! ([`crate::S3`], [`crate::Azure`], [`crate::Gcs`]).
//!
//! pgBackRust's cloud drivers all share a small family of transport options that
//! are independent of the storage protocol on top: the `repo-storage-verify-tls`
//! toggle (skip certificate verification), `repo-storage-ca-file` /
//! `repo-storage-ca-path` (extra CA roots to trust), `repo-storage-port`
//! (override the TLS port) and `repo-storage-upload-chunk-size` (the multipart /
//! chunked upload threshold). C reference: the `HttpClient` construction shared
//! by `src/storage/{s3,azure,gcs}/storage.c` via `src/common/io/http/`.
//!
//! [`HttpOptions`] carries those settings and [`HttpOptions::build_agent`]
//! turns them into a configured [`ureq::Agent`] (the synchronous HTTP client all
//! three backends use). The CA / verify-tls handling builds a custom
//! [`rustls::ClientConfig`]; the pure parts (root-store assembly, the
//! no-verification verifier) are unit-tested without a live endpoint.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::StorageError;

/// Transport-level (HTTPS-client) options shared by the cloud backends, mirroring
/// pgBackRust's `repo-storage-*` family.
///
/// The defaults reproduce a stock HTTPS client: certificate verification on, no
/// extra CA roots, the protocol default port, and the backend's own default
/// upload-chunk size.
#[derive(Debug, Clone)]
pub struct HttpOptions {
    /// Verify the server's TLS certificate against the trusted roots. When
    /// `false` (the `repo-storage-verify-tls=n` case) every certificate is
    /// accepted — insecure, but pgBackRust supports it for self-signed
    /// endpoints. Defaults to `true`.
    pub verify_tls: bool,
    /// Path to a PEM file of additional CA certificates to trust
    /// (`repo-storage-ca-file`). Each certificate in the file is added to the
    /// trust store on top of the webpki defaults.
    pub ca_file: Option<PathBuf>,
    /// Directory of PEM CA-certificate files to trust (`repo-storage-ca-path`).
    /// Every `*.pem`/`*.crt` file directly inside it is loaded.
    pub ca_path: Option<PathBuf>,
    /// Override TLS port (`repo-storage-port`). `None` keeps the URL's implicit
    /// port (443 for `https`).
    pub port: Option<u16>,
    /// Multipart / chunked upload size in bytes (`repo-storage-upload-chunk-size`).
    /// `None` leaves the backend's own default in force.
    pub upload_chunk_size: Option<u64>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            verify_tls: true,
            ca_file: None,
            ca_path: None,
            port: None,
            upload_chunk_size: None,
        }
    }
}

impl HttpOptions {
    /// `true` when no TLS customisation is requested, so the backend can keep its
    /// plain [`ureq::agent`] default rather than building a config. Port and
    /// upload-chunk-size are applied separately by the backend and do not force a
    /// custom TLS config.
    #[must_use]
    pub const fn is_default_tls(&self) -> bool {
        self.verify_tls && self.ca_file.is_none() && self.ca_path.is_none()
    }

    /// Build a [`ureq::Agent`] honouring the TLS settings.
    ///
    /// When [`Self::is_default_tls`] holds, the stock [`ureq::agent`] is returned
    /// unchanged (webpki roots, verification on). Otherwise a custom
    /// [`rustls::ClientConfig`] is assembled: extra CA roots from
    /// `ca_file`/`ca_path` are trusted, and when `verify_tls` is `false` a no-op
    /// certificate verifier disables validation entirely.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Backend`] if a configured CA file/path cannot be
    /// read or parsed, or the rustls config cannot be built.
    pub fn build_agent(&self) -> Result<ureq::Agent, StorageError> {
        if self.is_default_tls() {
            return Ok(ureq::agent());
        }
        let tls_config = self.build_client_config()?;
        Ok(ureq::AgentBuilder::new().tls_config(Arc::new(tls_config)).build())
    }

    /// Assemble the [`rustls::ClientConfig`] for the configured CA roots and
    /// verification mode. Separated from [`Self::build_agent`] so the
    /// config-building logic is unit-testable.
    ///
    /// # Errors
    ///
    /// As [`Self::build_agent`].
    pub fn build_client_config(&self) -> Result<ClientConfig, StorageError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|err| backend_err(format!("rustls protocol versions: {err}")))?;

        let config = if self.verify_tls {
            builder.with_root_certificates(self.root_store()?).with_no_client_auth()
        } else {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertVerification(provider)))
                .with_no_client_auth()
        };
        Ok(config)
    }

    /// Build the trust store: the webpki default roots plus every certificate in
    /// the configured `ca_file` and `ca_path`.
    fn root_store(&self) -> Result<RootCertStore, StorageError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        if let Some(ca_file) = &self.ca_file {
            add_pem_file(&mut roots, ca_file)?;
        }
        if let Some(ca_path) = &self.ca_path {
            for entry in pem_files_in_dir(ca_path)? {
                add_pem_file(&mut roots, &entry)?;
            }
        }
        Ok(roots)
    }
}

/// Add every certificate in the PEM file at `path` to `roots`.
fn add_pem_file(roots: &mut RootCertStore, path: &Path) -> Result<(), StorageError> {
    for cert in load_pem_certs(path)? {
        roots
            .add(cert)
            .map_err(|err| backend_err(format!("add CA from {}: {err}", path.display())))?;
    }
    Ok(())
}

/// Construct a [`StorageError::Backend`] carrying `message` with an empty path
/// (transport-level configuration errors are not tied to a single object).
const fn backend_err(message: String) -> StorageError {
    StorageError::Backend {
        path: PathBuf::new(),
        message,
    }
}

/// Load every PEM certificate in the file at `path`.
fn load_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, StorageError> {
    let pem = std::fs::read(path).map_err(|err| backend_err(format!("read CA file {}: {err}", path.display())))?;
    let mut reader = &pem[..];
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| backend_err(format!("parse CA file {}: {err}", path.display())))
}

/// Enumerate the `*.pem` / `*.crt` files directly inside the directory `dir`,
/// sorted for determinism.
fn pem_files_in_dir(dir: &Path) -> Result<Vec<PathBuf>, StorageError> {
    let read = std::fs::read_dir(dir).map_err(|err| backend_err(format!("read CA path {}: {err}", dir.display())))?;
    let mut files = Vec::new();
    for entry in read {
        let entry = entry.map_err(|err| backend_err(format!("read CA path {}: {err}", dir.display())))?;
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("crt"))
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

/// A [`ServerCertVerifier`] that accepts any certificate, used for
/// `repo-storage-verify-tls=n`. Signature verification still runs (delegated to
/// the crypto provider) so the handshake remains well-formed; only the chain /
/// name validation is skipped.
#[derive(Debug)]
struct NoCertVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_tls_is_detected() {
        assert!(HttpOptions::default().is_default_tls());

        let opts = HttpOptions {
            port: Some(8443),
            upload_chunk_size: Some(8 * 1024 * 1024),
            ..HttpOptions::default()
        };
        // Port / chunk-size alone don't force a custom TLS config.
        assert!(opts.is_default_tls());

        let no_verify = HttpOptions {
            verify_tls: false,
            ..HttpOptions::default()
        };
        assert!(!no_verify.is_default_tls());

        let with_ca = HttpOptions {
            ca_file: Some(PathBuf::from("/etc/ssl/ca.pem")),
            ..HttpOptions::default()
        };
        assert!(!with_ca.is_default_tls());
    }

    #[test]
    fn default_options_build_a_default_agent() {
        // A default HttpOptions builds without touching rustls at all.
        assert!(HttpOptions::default().build_agent().is_ok());
    }

    #[test]
    fn verify_tls_off_builds_a_client_config() {
        // Disabling verification builds a ClientConfig with the no-op verifier.
        let opts = HttpOptions {
            verify_tls: false,
            ..HttpOptions::default()
        };
        assert!(opts.build_client_config().is_ok());
        assert!(opts.build_agent().is_ok());
    }

    #[test]
    fn verify_on_with_default_roots_builds() {
        // verify_tls=true with no extra CA still builds against the webpki roots.
        assert!(HttpOptions::default().build_client_config().is_ok());
    }

    #[test]
    fn missing_ca_file_is_a_backend_error() {
        let opts = HttpOptions {
            ca_file: Some(PathBuf::from("/no/such/ca.pem")),
            ..HttpOptions::default()
        };
        match opts.build_client_config() {
            Err(StorageError::Backend { message, .. }) => assert!(message.contains("read CA file"), "msg was {message}"),
            other => panic!("expected Backend(read CA file), got {other:?}"),
        }
    }

    #[test]
    fn empty_ca_file_parses_to_no_extra_roots() {
        // A readable PEM file with no certificates parses cleanly (zero certs)
        // and the config still builds atop the webpki defaults.
        let dir = tempfile::tempdir().unwrap();
        let pem_path = dir.path().join("empty.pem");
        std::fs::write(&pem_path, b"# no certificates here\n").unwrap();
        assert!(load_pem_certs(&pem_path).unwrap().is_empty());

        let opts = HttpOptions {
            ca_file: Some(pem_path),
            ..HttpOptions::default()
        };
        assert!(opts.build_client_config().is_ok());
    }

    #[test]
    fn ca_path_scans_only_pem_and_crt_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("root.pem"), b"# pem\n").unwrap();
        std::fs::write(dir.path().join("inter.crt"), b"# crt\n").unwrap();
        // A non-cert file in the same dir is ignored.
        std::fs::write(dir.path().join("notes.txt"), b"ignore me").unwrap();

        let files = pem_files_in_dir(dir.path()).unwrap();
        assert_eq!(files.len(), 2, "only the .pem and .crt files are scanned");
        // Sorted: inter.crt before root.pem.
        assert!(files[0].ends_with("inter.crt"));
        assert!(files[1].ends_with("root.pem"));

        let opts = HttpOptions {
            ca_path: Some(dir.path().to_path_buf()),
            ..HttpOptions::default()
        };
        assert!(opts.build_client_config().is_ok());
    }
}

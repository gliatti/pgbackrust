//! Cryptographic helpers used throughout the pgBackRust workspace.
//!
//! Two submodules:
//!
//! - [`xxhash3`] — XXH3-128 (`xxHash`) hashing used to identify backup blocks during incremental
//!   backups. The 128-bit canonical representation matches the upstream xxHash
//!   `XXH128_canonicalFromHash` byte order: high 64 bits first, low 64 bits next, both
//!   big-endian.
//! - [`common`] — OpenSSL initialization, error-stack inspection, and RNG helpers ported from
//!   `src/common/crypto/common.c`. Routes through the `openssl` and `openssl-sys` crates so that
//!   error codes and RNG output are byte-identical to the legacy direct libcrypto calls.

pub mod common {
    //! OpenSSL initialization, error-stack draining, RNG helpers — ported from
    //! `src/common/crypto/common.c`.

    use core::ffi::CStr;

    /// Bit mask for `OPENSSL_init_ssl` — load the default OpenSSL config file. The constant is
    /// defined in `openssl/crypto.h` but `openssl-sys` 0.9 does not re-export it under this name,
    /// so hard-code the documented value.
    const OPENSSL_INIT_LOAD_CONFIG: u64 = 0x0000_0040;

    /// Initialize the OpenSSL crypto and SSL stacks once for the process. Idempotent.
    ///
    /// Mirrors `cryptoInit` in the legacy C code: loads the default config in addition to the
    /// crypto algorithms / strings registered by `openssl::init`. Calling this multiple times is
    /// a no-op after the first invocation, matching the `cryptoInitDone` guard in the C wrapper.
    pub fn init() {
        // The high-level safe init covers `OPENSSL_init_crypto` + `OPENSSL_init_ssl`.
        openssl::init();
        // Match the legacy `OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL)` so per-platform
        // OpenSSL config overrides keep applying. Idempotent — OpenSSL serializes init internally.
        // SAFETY: `OPENSSL_init_ssl` is documented as thread-safe and idempotent, accepts a null
        // settings pointer, and returns 1 on success / 0 on failure (which we ignore to mirror
        // the C wrapper's fire-and-forget behaviour).
        unsafe {
            openssl_sys::OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, core::ptr::null());
        }
    }

    /// Drain one error from the calling thread's OpenSSL error queue and return its numeric
    /// code. Returns `0` if the queue is empty.
    ///
    /// Direct equivalent of `ERR_get_error()` — the same call the legacy `cryptoError` made.
    #[must_use]
    pub fn last_error_get() -> u64 {
        // SAFETY: `ERR_get_error` is thread-safe, takes no arguments, and returns the numeric
        // error code (0 when the queue is empty). It is the same call the C wrapper made.
        unsafe { openssl_sys::ERR_get_error() }
    }

    /// Fill `dst` with the OpenSSL reason string for `code`. Writes "no details available" when
    /// `ERR_reason_error_string` returns null (which is what the C wrapper substitutes).
    ///
    /// Returns the number of bytes written excluding the trailing NUL. The output is always
    /// NUL-terminated provided `dst.len() >= 1`. If `dst` is empty, returns 0.
    pub fn error_reason_into(code: u64, dst: &mut [u8]) -> usize {
        if dst.is_empty() {
            return 0;
        }
        // SAFETY: `ERR_reason_error_string` is thread-safe and returns either null or a pointer
        // to a static, NUL-terminated string with lifetime equal to the process.
        let reason_ptr = unsafe { openssl_sys::ERR_reason_error_string(code) };
        let reason: &[u8] = if reason_ptr.is_null() {
            b"no details available"
        } else {
            // SAFETY: documented as a NUL-terminated static string when non-null.
            unsafe { CStr::from_ptr(reason_ptr) }.to_bytes()
        };
        let copy_len = (dst.len() - 1).min(reason.len());
        dst[..copy_len].copy_from_slice(&reason[..copy_len]);
        dst[copy_len] = 0;
        copy_len
    }

    /// Fill `dst` with cryptographically strong random bytes.
    ///
    /// Mirrors `cryptoRandomBytes` (`RAND_bytes`). Returns `Ok(())` on success and propagates
    /// the OpenSSL error stack on failure so the FFI shim can re-emit it as `CryptoError`.
    ///
    /// # Errors
    ///
    /// Returns the captured [`openssl::error::ErrorStack`] when `RAND_bytes` fails — typically
    /// only when the kernel RNG is unavailable on a hardened platform.
    pub fn random_bytes(dst: &mut [u8]) -> Result<(), openssl::error::ErrorStack> {
        if dst.is_empty() {
            return Ok(());
        }
        openssl::rand::rand_bytes(dst)
    }
}

pub mod hash {
    //! MD5 / SHA1 / SHA256 hashing + HMAC, ported from `src/common/crypto/hash.c`.
    //!
    //! SHA1 and SHA256 go through the safe `openssl::hash` wrappers (FIPS-respecting EVP). MD5
    //! uses the pure-Rust `md-5` crate so MD5 keeps working when the linked OpenSSL is built in
    //! FIPS mode, mirroring the legacy approach of bundling a vendor MD5 implementation in the
    //! C code.

    use md5::Digest;
    use openssl::hash::{Hasher, MessageDigest};

    /// Discrete hash type accepted across this module.
    ///
    /// Discriminants match the codes used by the FFI shim in `pgbr-ffi` (0 = MD5, 1 = SHA1,
    /// 2 = SHA256) so the C side can pass an `i32` derived from the legacy `HashType`
    /// `StringId` without needing a separate mapping table on the Rust side.
    #[repr(i32)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum HashType {
        /// MD5, 16 bytes — bundled implementation, FIPS-bypassing.
        Md5 = 0,
        /// SHA1, 20 bytes.
        Sha1 = 1,
        /// SHA256, 32 bytes.
        Sha256 = 2,
    }

    impl HashType {
        /// Number of bytes a finalized digest occupies.
        #[must_use]
        pub const fn size(self) -> usize {
            match self {
                Self::Md5 => 16,
                Self::Sha1 => 20,
                Self::Sha256 => 32,
            }
        }

        /// Return the variant whose discriminant equals `code`, or `None`.
        #[must_use]
        pub const fn from_code(code: i32) -> Option<Self> {
            match code {
                0 => Some(Self::Md5),
                1 => Some(Self::Sha1),
                2 => Some(Self::Sha256),
                _ => None,
            }
        }

        fn openssl_md(self) -> MessageDigest {
            match self {
                Self::Md5 => MessageDigest::md5(),
                Self::Sha1 => MessageDigest::sha1(),
                Self::Sha256 => MessageDigest::sha256(),
            }
        }
    }

    enum Backend {
        Md5(md5::Md5),
        Evp(Hasher),
    }

    /// Streaming hasher.
    ///
    /// Mirrors the legacy `CryptoHash` object: holds an opaque per-algorithm context, accepts
    /// repeated [`update`](Self::update) calls, and produces a finalized digest exactly once
    /// via [`finalize_into`](Self::finalize_into) (subsequent finalize attempts return the
    /// cached digest, matching the C wrapper which caches the result on first call).
    pub struct State {
        ty: HashType,
        backend: Backend,
        finalized: Option<Vec<u8>>,
    }

    impl State {
        /// Construct a new streaming hasher for the given algorithm.
        ///
        /// # Errors
        ///
        /// Propagates the OpenSSL error stack when [`HashType::Sha1`] / [`HashType::Sha256`]
        /// initialization fails. MD5 uses the pure-Rust backend and never fails here.
        pub fn new(ty: HashType) -> Result<Self, openssl::error::ErrorStack> {
            let backend = match ty {
                HashType::Md5 => Backend::Md5(md5::Md5::new()),
                HashType::Sha1 | HashType::Sha256 => Backend::Evp(Hasher::new(ty.openssl_md())?),
            };
            Ok(Self {
                ty,
                backend,
                finalized: None,
            })
        }

        /// Feed `data` into the hasher. No-op once [`finalize_into`](Self::finalize_into) has
        /// been called and the digest is cached.
        ///
        /// # Errors
        ///
        /// Propagates the OpenSSL error stack on `EVP_DigestUpdate` failure.
        pub fn update(&mut self, data: &[u8]) -> Result<(), openssl::error::ErrorStack> {
            if self.finalized.is_some() {
                return Ok(());
            }
            match &mut self.backend {
                Backend::Md5(h) => {
                    h.update(data);
                    Ok(())
                }
                Backend::Evp(h) => h.update(data),
            }
        }

        /// Finalize and write up to `dst.len()` bytes of the digest into `dst`. Returns the
        /// number of bytes written (the algorithm's full digest size, possibly truncated to
        /// `dst.len()`).
        ///
        /// Idempotent — repeated calls return the cached result, matching the legacy
        /// `cryptoHash()` getter.
        ///
        /// # Errors
        ///
        /// Propagates the OpenSSL error stack on `EVP_DigestFinal_ex` failure.
        pub fn finalize_into(&mut self, dst: &mut [u8]) -> Result<usize, openssl::error::ErrorStack> {
            if self.finalized.is_none() {
                let bytes: Vec<u8> = match core::mem::replace(&mut self.backend, Backend::Md5(md5::Md5::new())) {
                    Backend::Md5(h) => h.finalize().to_vec(),
                    Backend::Evp(mut h) => h.finish()?.to_vec(),
                };
                self.finalized = Some(bytes);
            }
            // The block above unconditionally populates `self.finalized`, so the cache is
            // guaranteed to be `Some` here. Use a fallible match instead of `expect` to satisfy
            // the workspace's `clippy::expect_used` lint.
            let Some(cached) = self.finalized.as_ref() else {
                return Ok(0);
            };
            let copy = dst.len().min(cached.len());
            dst[..copy].copy_from_slice(&cached[..copy]);
            Ok(copy)
        }

        /// The hash type this state was constructed for.
        #[must_use]
        pub const fn ty(&self) -> HashType {
            self.ty
        }
    }

    /// Single-shot hash. Equivalent to constructing a [`State`], updating with `message`, and
    /// finalizing into `dst`. Mirrors the legacy `cryptoHashOne`.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Propagates the OpenSSL error stack from initialization, update, or finalize.
    pub fn one_shot(ty: HashType, message: &[u8], dst: &mut [u8]) -> Result<usize, openssl::error::ErrorStack> {
        let mut state = State::new(ty)?;
        if !message.is_empty() {
            state.update(message)?;
        }
        state.finalize_into(dst)
    }

    /// HMAC of `message` keyed by `key` using `ty`. Mirrors the legacy `cryptoHmacOne` (which
    /// itself wraps OpenSSL's `HMAC()` one-shot helper).
    ///
    /// Returns the number of bytes written into `dst` (the digest size of `ty`).
    ///
    /// # Errors
    ///
    /// Propagates the OpenSSL error stack on `PKey::hmac` / `Signer` failure.
    pub fn hmac_one(ty: HashType, key: &[u8], message: &[u8], dst: &mut [u8]) -> Result<usize, openssl::error::ErrorStack> {
        use openssl::pkey::PKey;
        use openssl::sign::Signer;
        let pkey = PKey::hmac(key)?;
        let mut signer = Signer::new(ty.openssl_md(), &pkey)?;
        signer.update(message)?;
        let mac = signer.sign_to_vec()?;
        let copy = dst.len().min(mac.len());
        dst[..copy].copy_from_slice(&mac[..copy]);
        Ok(copy)
    }
}

pub mod xxhash3 {
    //! 128-bit XXH3 hashing (single-shot and incremental).

    use xxhash_rust::xxh3::Xxh3;

    /// Maximum number of canonical bytes produced by [`one_128`] / [`State::digest_into`].
    pub const HASH_SIZE_MAX: usize = 16;

    /// Compute the 128-bit XXH3 hash of `data` and write up to `dst.len()` canonical bytes
    /// (high 64 first, low 64 next, big-endian) into `dst`.
    pub fn one_128(data: &[u8], dst: &mut [u8]) {
        let canonical = xxhash_rust::xxh3::xxh3_128(data).to_be_bytes();
        let copy = dst.len().min(canonical.len());
        dst[..copy].copy_from_slice(&canonical[..copy]);
    }

    /// Streaming XXH3-128 hasher. Wraps the inner state so the FFI layer can pass an opaque
    /// pointer to the C side without exposing `xxhash-rust` types.
    pub struct State(Xxh3);

    impl State {
        /// New hasher initialized to the default XXH3 seed (matches the C `XXH3_128bits_reset`).
        #[must_use]
        #[allow(clippy::missing_const_for_fn)] // `xxhash_rust::xxh3::Xxh3::new` is not const.
        pub fn new() -> Self {
            Self(Xxh3::new())
        }

        /// Feed more bytes into the hasher.
        pub fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }

        /// Finalize the hash and write up to `dst.len()` canonical bytes.
        pub fn digest_into(&self, dst: &mut [u8]) {
            let canonical = self.0.digest128().to_be_bytes();
            let copy = dst.len().min(canonical.len());
            dst[..copy].copy_from_slice(&canonical[..copy]);
        }
    }

    impl Default for State {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common_tests {
    use super::common::*;

    #[test]
    fn init_is_idempotent() {
        init();
        init();
        init();
    }

    #[test]
    fn random_bytes_fills_buffer_and_zero_size_is_noop() {
        init();
        let mut buf = [0u8; 64];
        random_bytes(&mut buf).expect("rand_bytes must succeed on a healthy system");
        // Statistically, at least one of 64 random bytes should be non-zero.
        assert!(buf.iter().any(|&b| b != 0), "random_bytes produced an all-zero buffer");

        // Zero-sized requests must short-circuit and not invoke OpenSSL.
        let mut empty: [u8; 0] = [];
        random_bytes(&mut empty).expect("zero-length random must succeed without calling OpenSSL");
    }

    #[test]
    fn random_bytes_two_calls_differ() {
        init();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a).unwrap();
        random_bytes(&mut b).unwrap();
        assert_ne!(a, b, "two consecutive random buffers should not collide");
    }

    #[test]
    fn last_error_get_returns_zero_on_clean_queue() {
        init();
        // Drain anything residual from earlier tests sharing the thread.
        while last_error_get() != 0 {}
        assert_eq!(last_error_get(), 0);
    }

    #[test]
    fn error_reason_into_writes_no_details_for_zero_code() {
        let mut buf = [0u8; 64];
        let len = error_reason_into(0, &mut buf);
        assert_eq!(&buf[..len], b"no details available");
        assert_eq!(buf[len], 0, "must be NUL-terminated");
    }

    #[test]
    fn error_reason_into_truncates_to_buffer() {
        let mut buf = [0u8; 8];
        let len = error_reason_into(0, &mut buf);
        assert_eq!(len, 7, "must leave room for NUL");
        assert_eq!(&buf[..len], b"no deta");
        assert_eq!(buf[len], 0);
    }

    #[test]
    fn error_reason_into_empty_buffer_is_noop() {
        let mut empty: [u8; 0] = [];
        assert_eq!(error_reason_into(123, &mut empty), 0);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod hash_tests {
    use super::common as crypto_common;
    use super::hash::*;

    fn hex(bytes: &[u8]) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn known_vectors_md5() {
        crypto_common::init();
        let mut buf = [0u8; HashType::Md5.size()];
        one_shot(HashType::Md5, b"", &mut buf).unwrap();
        assert_eq!(hex(&buf), "d41d8cd98f00b204e9800998ecf8427e");

        one_shot(HashType::Md5, b"abc", &mut buf).unwrap();
        assert_eq!(hex(&buf), "900150983cd24fb0d6963f7d28e17f72");
    }

    #[test]
    fn known_vectors_sha1() {
        crypto_common::init();
        let mut buf = [0u8; HashType::Sha1.size()];
        one_shot(HashType::Sha1, b"", &mut buf).unwrap();
        assert_eq!(hex(&buf), "da39a3ee5e6b4b0d3255bfef95601890afd80709");

        one_shot(HashType::Sha1, b"12345", &mut buf).unwrap();
        assert_eq!(hex(&buf), "8cb2237d0679ca88db6464eac60da96345513964");
    }

    #[test]
    fn known_vectors_sha256() {
        crypto_common::init();
        let mut buf = [0u8; HashType::Sha256.size()];
        one_shot(HashType::Sha256, b"", &mut buf).unwrap();
        assert_eq!(hex(&buf), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

        one_shot(HashType::Sha256, b"abc", &mut buf).unwrap();
        assert_eq!(hex(&buf), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn streaming_matches_one_shot() {
        crypto_common::init();
        for ty in [HashType::Md5, HashType::Sha1, HashType::Sha256] {
            let chunks: &[&[u8]] = &[b"the quick ", b"brown fox ", b"jumps over ", b"the lazy ", b"dog"];

            let mut state = State::new(ty).unwrap();
            for c in chunks {
                state.update(c).unwrap();
            }
            let mut streamed = vec![0u8; ty.size()];
            state.finalize_into(&mut streamed).unwrap();

            let mut joined: Vec<u8> = Vec::new();
            for c in chunks {
                joined.extend_from_slice(c);
            }
            let mut one = vec![0u8; ty.size()];
            one_shot(ty, &joined, &mut one).unwrap();

            assert_eq!(streamed, one, "streaming/one-shot disagree for {ty:?}");
        }
    }

    #[test]
    fn finalize_is_idempotent() {
        crypto_common::init();
        let mut state = State::new(HashType::Sha1).unwrap();
        state.update(b"hello").unwrap();
        let mut a = [0u8; HashType::Sha1.size()];
        state.finalize_into(&mut a).unwrap();
        let mut b = [0u8; HashType::Sha1.size()];
        state.finalize_into(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_known_vector() {
        crypto_common::init();
        let mut buf = [0u8; HashType::Sha256.size()];
        let n = hmac_one(
            HashType::Sha256,
            b"AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            b"20170412",
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, HashType::Sha256.size());
        assert_eq!(hex(&buf), "8b05c497afe9e1f42c8ada4cb88392e118649db1e5c98f0f0fb0a158bdd2dd76");
    }

    #[test]
    fn from_code_round_trip() {
        for ty in [HashType::Md5, HashType::Sha1, HashType::Sha256] {
            assert_eq!(HashType::from_code(ty as i32), Some(ty));
        }
        assert_eq!(HashType::from_code(99), None);
    }

    /// Random differential between the openssl-backed sha1 and the standalone md-5 backend on
    /// 10 000 deterministic inputs — guards against accidental regressions in the wrapper /
    /// state-machine logic by re-hashing each input through both a streaming `State` and a
    /// `one_shot` call and asserting agreement.
    #[test]
    fn streaming_vs_one_shot_random() {
        crypto_common::init();
        let mut state: u64 = 0xabad_cafe_face_b00c;
        let mut buf = Vec::with_capacity(257);
        for _ in 0..10_000 {
            for ty in [HashType::Md5, HashType::Sha1, HashType::Sha256] {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let len = ((state >> 32) as usize) % 257;
                buf.clear();
                for _ in 0..len {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1_442_695_040_888_963_407);
                    buf.push((state >> 56) as u8);
                }

                let mut one = vec![0u8; ty.size()];
                one_shot(ty, &buf, &mut one).unwrap();

                let mut s = State::new(ty).unwrap();
                if !buf.is_empty() {
                    s.update(&buf).unwrap();
                }
                let mut streamed = vec![0u8; ty.size()];
                s.finalize_into(&mut streamed).unwrap();

                assert_eq!(one, streamed);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::xxhash3::*;

    #[test]
    fn one_128_matches_xxhash_rust_reference() {
        let mut buf = [0u8; HASH_SIZE_MAX];

        one_128(b"", &mut buf);
        let empty = u128::from_be_bytes(buf);
        assert_eq!(empty, xxhash_rust::xxh3::xxh3_128(b""));

        one_128(b"abc", &mut buf);
        let abc = u128::from_be_bytes(buf);
        assert_eq!(abc, xxhash_rust::xxh3::xxh3_128(b"abc"));
    }

    #[test]
    fn truncation_returns_canonical_prefix() {
        let mut full = [0u8; HASH_SIZE_MAX];
        one_128(b"hello", &mut full);

        let mut short = [0u8; 8];
        one_128(b"hello", &mut short);
        assert_eq!(&full[..8], &short[..]);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut hasher = State::new();
        hasher.update(b"the quick brown ");
        hasher.update(b"fox jumps over ");
        hasher.update(b"the lazy dog");
        let mut streamed = [0u8; HASH_SIZE_MAX];
        hasher.digest_into(&mut streamed);

        let mut one_shot = [0u8; HASH_SIZE_MAX];
        one_128(b"the quick brown fox jumps over the lazy dog", &mut one_shot);
        assert_eq!(streamed, one_shot);
    }

    #[test]
    fn round_trip_random_inputs_streaming_vs_one_shot() {
        // Deterministic LCG over a fixed seed — 10 000 inputs covering 0..=200 byte lengths,
        // plus interleaved chunked updates. Confirms streaming and one-shot agree, which is the
        // closest Rust-only equivalent to the legacy C differential.
        let mut state: u64 = 0xfeed_face_dead_beef;
        let mut buf = Vec::with_capacity(257);
        for iter in 0..10_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = if iter < 257 { iter } else { ((state >> 32) as usize) % 257 };
            buf.clear();
            for _ in 0..len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                buf.push((state >> 56) as u8);
            }

            let mut one = [0u8; HASH_SIZE_MAX];
            one_128(&buf, &mut one);

            let mut hasher = State::new();
            let mut offset = 0;
            while offset < buf.len() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let chunk = (((state >> 40) as usize) % 32).max(1).min(buf.len() - offset);
                hasher.update(&buf[offset..offset + chunk]);
                offset += chunk;
            }
            let mut streamed = [0u8; HASH_SIZE_MAX];
            hasher.digest_into(&mut streamed);

            assert_eq!(one, streamed, "iter {iter} len {len}");
        }
    }
}

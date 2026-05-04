//! Cryptographic helpers used throughout the pgBackRust workspace.
//!
//! Currently exposes a single algorithm: XXH3-128 (`xxHash`) used to identify backup blocks
//! during incremental backups. The 128-bit canonical representation matches the upstream xxHash
//! `XXH128_canonicalFromHash` byte order: high 64 bits first, low 64 bits next, both
//! big-endian.
//!
//! The XXH3 maths come from the maintained `xxhash-rust` crate (a Rust port of the reference
//! implementation). This module wraps it to return the canonical byte representation expected
//! by the C side and hides the streaming state behind an opaque type so the FFI layer can pass
//! it as a raw pointer.

#![cfg_attr(not(test), forbid(unsafe_code))]

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

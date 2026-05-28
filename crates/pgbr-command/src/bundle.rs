//! File-bundling helpers (`repo-bundle=y`).
//!
//! C reference: `src/command/backup/backup.c` (the `manifestBundle*` /
//! bundle-packing pass) and `src/info/manifest.c` (the `bni` / `bno` per-file
//! keys).
//!
//! With bundling on, small files (size ≤ `repo-bundle-limit`, default 2 MiB) are
//! packed together into shared *bundle* objects (each up to `repo-bundle-size`,
//! default 20 MiB) stored at `backup/<stanza>/<label>/bundle/<bundle-id>`, rather
//! than one repo object per file. Each bundled file records its `bundle-id` (`bni`)
//! and byte `offset` (`bno`) in the manifest so restore can slice it back out.
//! Files larger than the limit stay as individual objects (the unbundled
//! behaviour), so the per-object overhead is only avoided where it matters.
//!
//! The packing policy is a pure, unit-testable function ([`BundlePacker`]). The
//! backup driver feeds it each small file's *post-transform* repo size (bundling
//! packs the bytes that actually land in the repo) and gets back the assigned
//! bundle id + offset; it appends the bytes to the open bundle object itself.

/// Subdirectory under a backup root that holds bundle objects.
pub const BUNDLE_DIR: &str = "bundle";

/// Repository-relative path of bundle object `id` within `backup_root`.
#[must_use]
pub fn bundle_object_path(backup_root: &str, id: u64) -> String {
    format!("{backup_root}/{BUNDLE_DIR}/{id}")
}

/// Where one file's bytes were placed inside a bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleSlot {
    /// Identifier of the bundle object the bytes were appended to.
    pub bundle_id: u64,
    /// Byte offset within that bundle object where the bytes begin.
    pub offset: u64,
}

/// Accumulates files into bundle objects up to a configured size cap.
///
/// Construct with [`BundlePacker::new`], then call [`BundlePacker::place`] for
/// each file (in the order they will be written) passing the number of bytes the
/// file occupies in the repo (post-transform). The packer returns the
/// [`BundleSlot`] (bundle id + offset) the bytes belong at and advances its
/// internal cursor.
///
/// Sizing rule (mirrors pgBackRest): a file is appended to the current bundle
/// unless doing so would push the bundle past `bundle_size` **and** the current
/// bundle already holds at least one file — in that case a new bundle is started
/// first. A single file larger than `bundle_size` still gets its own bundle (it
/// cannot be split, so it occupies one oversized bundle alone), matching the C
/// behaviour where an over-cap file simply ends the current bundle.
#[derive(Debug, Clone)]
pub struct BundlePacker {
    /// Maximum bytes per bundle object (`repo-bundle-size`).
    bundle_size: u64,
    /// Id of the bundle currently being filled. Bundle ids start at 1.
    current_id: u64,
    /// Bytes already written into the current bundle (the next file's offset).
    current_offset: u64,
    /// Whether the current bundle already holds at least one file.
    has_file: bool,
}

impl BundlePacker {
    /// Create a packer whose bundles cap at `bundle_size` bytes. A `bundle_size`
    /// of zero is clamped to one byte so every file lands in its own bundle (the
    /// packer never divides by, or loops on, zero).
    #[must_use]
    pub const fn new(bundle_size: u64) -> Self {
        Self {
            bundle_size: if bundle_size == 0 { 1 } else { bundle_size },
            current_id: 1,
            current_offset: 0,
            has_file: false,
        }
    }

    /// The id of the bundle currently being filled.
    #[must_use]
    pub const fn current_id(&self) -> u64 {
        self.current_id
    }

    /// Place a file of `repo_bytes` bytes, returning the bundle id + offset its
    /// bytes belong at and advancing the cursor past them.
    ///
    /// Starts a fresh bundle first when the current one is non-empty and adding
    /// this file would exceed the cap, so each bundle stays within `bundle_size`
    /// (except a lone over-cap file, which unavoidably exceeds it on its own).
    pub const fn place(&mut self, repo_bytes: u64) -> BundleSlot {
        if self.has_file && self.current_offset.saturating_add(repo_bytes) > self.bundle_size {
            // Close the current bundle and open the next.
            self.current_id += 1;
            self.current_offset = 0;
            self.has_file = false;
        }
        let slot = BundleSlot {
            bundle_id: self.current_id,
            offset: self.current_offset,
        };
        self.current_offset = self.current_offset.saturating_add(repo_bytes);
        self.has_file = true;
        slot
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn packs_small_files_into_one_bundle() {
        let mut packer = BundlePacker::new(100);
        let a = packer.place(30);
        let b = packer.place(40);
        let c = packer.place(20);
        assert_eq!(a, BundleSlot { bundle_id: 1, offset: 0 });
        assert_eq!(
            b,
            BundleSlot {
                bundle_id: 1,
                offset: 30
            }
        );
        assert_eq!(
            c,
            BundleSlot {
                bundle_id: 1,
                offset: 70
            }
        );
    }

    #[test]
    fn starts_new_bundle_when_cap_exceeded() {
        let mut packer = BundlePacker::new(100);
        let a = packer.place(60); // bundle 1: [0,60)
        let b = packer.place(60); // would be 120 > 100 -> bundle 2: [0,60)
        let c = packer.place(30); // bundle 2: [60,90)
        assert_eq!(a, BundleSlot { bundle_id: 1, offset: 0 });
        assert_eq!(b, BundleSlot { bundle_id: 2, offset: 0 });
        assert_eq!(
            c,
            BundleSlot {
                bundle_id: 2,
                offset: 60
            }
        );
    }

    #[test]
    fn exact_fit_stays_in_bundle() {
        let mut packer = BundlePacker::new(100);
        let a = packer.place(60);
        let b = packer.place(40); // exactly fills to 100 (not > cap) -> same bundle
        let c = packer.place(1); // now over -> new bundle
        assert_eq!(a.bundle_id, 1);
        assert_eq!(b.bundle_id, 1);
        assert_eq!(b.offset, 60);
        assert_eq!(c.bundle_id, 2);
        assert_eq!(c.offset, 0);
    }

    #[test]
    fn lone_oversize_file_gets_its_own_bundle() {
        let mut packer = BundlePacker::new(100);
        let a = packer.place(250); // over cap, but it is the first file: bundle 1
        let b = packer.place(10); // adding would exceed cap -> bundle 2
        assert_eq!(a, BundleSlot { bundle_id: 1, offset: 0 });
        assert_eq!(b, BundleSlot { bundle_id: 2, offset: 0 });
    }

    #[test]
    fn zero_bundle_size_is_one_file_per_bundle() {
        let mut packer = BundlePacker::new(0);
        let a = packer.place(5);
        let b = packer.place(5);
        assert_eq!(a.bundle_id, 1);
        assert_eq!(b.bundle_id, 2);
    }

    #[test]
    fn object_path_uses_bundle_subdir() {
        assert_eq!(
            bundle_object_path("backup/demo/20240101-120000F", 3),
            "backup/demo/20240101-120000F/bundle/3"
        );
    }
}

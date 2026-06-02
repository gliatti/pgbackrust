# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This is the **Rust rewrite** of pgBackRest (the original C project ended at
release `2.58.0`). Versioning restarts at `0.x` for the rewrite and is
independent of the upstream C version numbering. The on-disk repository format
this port reads and writes remains pinned to the pgBackRest `2.58` format
(`backrest-format` 5) for compatibility with existing repositories — that
format version is distinct from the product version tracked here.

## [Unreleased]

## [0.1.0] - 2026-06-02

First tagged release of the Rust rewrite (epic
[#238](https://github.com/gliatti/pgbackrust/issues/238)). The entire codebase
was rewritten from the C tree into an idiomatic, cargo-only Rust workspace.
This is a **pre-production** release: see *Known limitations* below.

### Added

- **Cargo-only workspace.** `cargo build --workspace --release` produces the
  `pgbackrust` binary (from `pgbr-cli`). The C tree, Meson build, cbindgen FFI
  header generator, and transitional `pgbr-ffi` shim have all been removed.
- **Crates** covering the full stack:
  - `pgbr-core` — string/blob/memory primitives, log formatting, debug, stack
    trace, object base.
  - `pgbr-error` — typed `Error` / `ErrorType` generated from `error.yaml`.
  - `pgbr-encode` — hex / base64 encoders.
  - `pgbr-crypto` — OpenSSL-backed crypto: init + secure random, MD5/SHA1/SHA256
    + HMAC (MD5 via the pure-Rust `md-5` crate to survive a FIPS OpenSSL),
    symmetric cipher, and XXH3-128 for incremental block identity.
  - `pgbr-compress` — gz / bz2 / lz4 / zstd compress + decompress as
    `pgbr_io::Filter` adapters.
  - `pgbr-regex` — regex wrapper.
  - `pgbr-build` — typed parsers for the four pgBackRust definition files,
    embedded at compile time.
  - `pgbr-config` — full configuration pipeline (CLI > ENV > stanza:cmd >
    stanza > global:cmd > global > default precedence, with allow-list /
    allow-range / depend validation and per-flavor defaults).
  - `pgbr-io` — `IoRead` / `IoWrite` traits, mem/file backends, filter chain
    (`Sha1`, `Sha256`, `Size`, AES-256-CBC `Cipher`).
  - `pgbr-storage` — `Storage` trait with `Posix`, `Cifs`, `S3` (SigV4),
    `Azure` (Shared Key), `Gcs` (bearer token), and `Sftp` (ssh2) backends.
  - `pgbr-db` — safe libpq wrapper.
  - `pgbr-protocol` — JSON-line request / response codec.
  - `pgbr-postgres` — `crc32c`, version registry (PG 9.6 … 18), `pg_control`
    parsing, page checksums.
  - `pgbr-info` — on-disk `InfoArchive`, `InfoBackup`, `Manifest` (INI + SHA-1).
  - `pgbr-command` — every command plus the dispatch router.
  - `pgbr-cli` — the `pgbackrust` binary.
- **Command set:** `backup` (full / diff / incr), `restore` (+ delta +
  reference resolution), `archive-push`, `archive-get`, `expire`, `verify`,
  `check`, `info`, `stanza-create`, `stanza-delete`, `stanza-upgrade`,
  `repo-ls`, `repo-get`, `repo-put`, `repo-rm`, `annotate`, `manifest`,
  `start`, `stop`, `server`, `server-ping`, `help`, `version`.
- **PostgreSQL support:** versions 9.6 through 18.
- **Integration harness** (`integration/`) driving the release binary
  end-to-end against live PostgreSQL over Docker and Vagrant topologies, with
  11 numbered scenarios (local, remote-pull SSH, PITR, encryption, standby,
  tablespaces, async queuing, multi-repo, TLS, bundling/block, S3).
- **CHANGELOG.md** (this file).

### Changed

- The `version` command now reports the product version from the cargo
  workspace (`pgBackRust 0.1.0`) instead of a hard-coded string.

### Fixed

- **Thread-safe logging.** The log subsystem kept its process-global state (the
  shared format scratch buffer and the in-memory capture buffer) behind an
  `unsafe impl Sync` justified by a "pgBackRust forks, never threads" invariant
  carried over from the C original — which is false in the threaded Rust port
  (the test harness and the server / parallel-dispatch paths use real threads).
  Concurrent log emission could race the capture buffer's `Vec` reallocation and
  abort the process with `free(): invalid next size`. Log emission and the
  capture buffer are now serialized by a `Mutex`, and the configuration setters
  share the same lock. The stale "single-threaded" safety notes on the
  (currently unused) `stack_trace` / `mem_context` globals were corrected to
  warn against the same trap.
- Corrected the `repository` URL typo (`pgbakrest` → `pgbackrust`) in the
  workspace manifest.

### Known limitations

- **Not a drop-in production replacement yet.** Do not rely on it for
  production backups.
- The local/remote protocol and parallel job dispatch exist as message types
  and a dispatcher but are not yet a full drop-in replacement for the C
  protocol.
- Block-level incremental backup is not yet implemented.
- End-to-end validation against live PostgreSQL is ongoing via the
  `integration/` harness.

[Unreleased]: https://github.com/gliatti/pgbackrust/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/gliatti/pgbackrust/releases/tag/v0.1.0

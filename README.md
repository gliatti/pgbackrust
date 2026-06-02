# pgBackRust <br/> A Rust rewrite of the PostgreSQL backup & restore tool

## About this fork

[pgBackRust](https://github.com/pgbackrust/pgbackrust) is a reliable backup and
restore solution for PostgreSQL. The upstream project is **no longer
maintained** — [release 2.58.0](https://github.com/pgbackrust/pgbackrust/releases/tag/release/2.58.0)
is the final C release (see the original notice below).

This fork is a **from-scratch rewrite of pgBackRust in Rust**. The original C
sources (everything that lived under `src/`), the Meson build, and the
transitional cbindgen/FFI scaffolding have been removed. The repository is now a
**cargo-only Rust workspace**: `cargo build --workspace --release` produces the
`pgbackrust` binary. There is no C left to build.

The rewrite preserves pgBackRust's on-disk formats, configuration model, and
command set so that it can read existing repositories, while replacing the
manual memory contexts and FFI ceremony of the C code with idiomatic Rust
(`Result`, `Drop`, lifetimes, safe wrappers around the few C libraries that are
still linked).

> **Heads up:** this is a rewrite in progress. Most subsystems are fully ported,
> but a few are simplified relative to upstream — see [Porting status](#porting-status).
> Do not treat it as a drop-in replacement for production backups yet.

## Workspace layout

The build is driven entirely by Cargo. The `pgbackrust` binary is produced by
`crates/pgbr-cli`; everything else is a library crate under `crates/`.

| Crate | Responsibility |
| --- | --- |
| `pgbr-core` | String, blob, memory primitives; log formatting, debug, stack trace, object base. |
| `pgbr-error` | Typed `Error` / `ErrorType` (generated from `error.yaml` by `build.rs`), format, retry. |
| `pgbr-encode` | Hex / base64 encoders. |
| `pgbr-crypto` | OpenSSL-backed crypto: OpenSSL init + secure random (`common`), MD5/SHA1/SHA256 hashing + HMAC (`hash`; MD5 via the pure-Rust `md-5` crate to survive a FIPS OpenSSL), a symmetric cipher (`cipher`), and XXH3-128 (`xxhash3`, used to identify backup blocks for incremental). |
| `pgbr-compress` | gz / bz2 / lz4 / zstd compress + decompress, exposed as `pgbr_io::Filter` adapters. |
| `pgbr-regex` | Regex wrapper. |
| `pgbr-build` | Typed parsers for the four pgBackRust definition files, embedded at compile time and exposed as `pgbr_build::inputs::{CONFIG_YAML, ERROR_YAML, HELP_XML, POSTGRES_YAML}`. The files live in `crates/pgbr-build/inputs/`. |
| `pgbr-config` | Full configuration pipeline: option model, compile/inheritance, value parsing, CLI tokenizer, `PGBACKRUST_<OPTION>` environment-variable source, `pgbackrust.conf` ini parsing, and `load_config` with the CLI > ENV > stanza:cmd > stanza > global:cmd > global > default precedence plus allow-list / allow-range / depend validation. |
| `pgbr-io` | `IoRead` / `IoWrite` traits, in-memory and file-backed implementations, `FilterChain`, and built-in filters (`Sha1`, `Sha256`, `Size`, `Cipher` AES-256-CBC). |
| `pgbr-storage` | `Storage` trait + backends: `Posix`, `Cifs`, `S3` (SigV4), `Azure` (Shared Key), `Gcs` (bearer token), `Sftp` (ssh2). |
| `pgbr-db` | Safe libpq wrapper (`Connection`, `QueryResult`). |
| `pgbr-protocol` | JSON-line `Request` / `Response` message types + codec. |
| `pgbr-postgres` | `crc32c_one`, version registry (PG 9.6 .. 18), `pg_control` header parsing, and `pg_checksum_page`. |
| `pgbr-info` | On-disk info files: `InfoArchive`, `InfoBackup`, `Manifest`, shared INI+SHA-1 format. |
| `pgbr-command` | Every command implementation plus the dispatch entry point — `dispatch_multi` (the real router over all configured repositories) and its single-repo wrapper `dispatch` (see below). |
| `pgbr-cli` | The `pgbackrust` binary: parse argv → load config → resolve → `pgbr_command::dispatch`. |

`pgbr-command` implements: backup (full / differential / incremental), restore
(with delta and reference resolution), archive-push / archive-get, expire
(backup + WAL retention), verify, check, info, stanza-create / delete / upgrade,
repo-ls / get / put / rm, annotate, manifest, start / stop, server / server-ping
(TCP + TLS), help, and version.

## Building

**Rust is not installed on the host.** All compilation goes through the
`pgbackrust-dev` Docker image (`Dockerfile.dev`, orchestrated by
`docker-compose.yml`). See `CLAUDE.md` for the full dev-environment notes and the
pinned toolchain versions.

```
docker compose build dev                                # build the image (first time only)
docker compose run --rm cargo build --workspace --release
```

The release binary is written to the `rust-target` volume under
`target/release/pgbackrust`. Run a command directly with:

```
docker compose run --rm cargo run -p pgbr-cli -- info
```

## Testing

```
docker compose run --rm cargo test --workspace
```

Unit tests live in `#[cfg(test)] mod tests` inside each crate. Cloud-backend and
live-database tests are `#[ignore]`d and gated on environment variables
(`PGBR_S3_*`, `PGBR_AZURE_*`, `PGBR_GCS_*`, `PGBR_SFTP_*`, `DATABASE_URL`).

## The gate

Run the same checks CI runs before committing:

```
docker compose run --rm cargo fmt --check
docker compose run --rm cargo clippy --workspace --all-targets -- -D warnings
docker compose run --rm cargo test --workspace
```

`--all-targets` is required so clippy also lints `#[cfg(test)]` code. See
`CODING.md` for the coding standards and `CONTRIBUTING.md` for the contribution
flow.

## Porting status

- **Fully ported:** the configuration pipeline, I/O and filter chain, all
  compression filters, the storage backends (Posix, Cifs, S3, Azure, GCS, Sftp),
  the on-disk info/manifest formats, the PostgreSQL version registry / control
  file parsing / page checksums, and the full command set listed above.
- **Simplified relative to upstream:** the local/remote protocol and parallel
  job dispatch are present as message types and a dispatcher but are not yet a
  full drop-in replacement for the C protocol; some advanced backup features
  (e.g. block-level incremental) are not yet implemented. Consult `CLAUDE.md` and
  the crate docs for the current state of any given subsystem.

## License

pgBackRust is released under the MIT license. See [`LICENSE`](LICENSE) for the
full text. The original copyright and attribution are preserved:

> Portions Copyright (c) 2015-2026, The PostgreSQL Global Development Group
> Portions Copyright (c) 2013-2026, David Steele

This rewrite builds on that work and remains under the same MIT license.

## Recognition

[Armchair](https://thenounproject.com/icon/armchair-129971) graphic by
[Alexander Skowalsky](https://thenounproject.com/sandorsz).

---

## Original notice of obsolescence

> TL;DR: pgBackRust is no longer being maintained. If you fork pgBackRust, please select a new name for your project.
>
> After a lot of thought, I have decided to stop working on pgBackRust. I did not come to this decision lightly. pgBackRust has been my passion project for the last thirteen years, and I was fortunate to have corporate sponsorship for much of this time, but there were also many late nights and weekends as I worked to make pgBackRust the project it is today, aided by numerous contributors. Every open-source developer knows exactly what I mean and how much of your life gets devoted to a special project.
>
> Since Crunchy Data was sold, I have been maintaining pgBackRust and looking for a position that would allow me to continue the work, but so far I have not been successful. Likewise, my efforts to secure sponsorship have also fallen far short of what I need to make the project viable.
>
> Again, many thanks to all the pgBackRust contributors over the years. It was a pleasure working with you!

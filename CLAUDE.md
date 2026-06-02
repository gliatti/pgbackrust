# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

pgBackRust is **no longer being maintained** as of release 2.58.0 (see `README.md`). This fork (`gliatti/pgbackrust`) **rewrote the codebase entirely in Rust** under `crates/`. PRs target `main`. The work is tracked by a single epic: [#238](https://github.com/gliatti/pgbackrust/issues/238).

The original C tree (`src/`), the Meson build, the cbindgen FFI header generator, and the transitional `pgbr-ffi` shim crate have all been **removed**. The workspace is now **cargo-only**: `cargo build --workspace --release` produces the `pgbackrust` binary (from `crates/pgbr-cli`). There is no C left to build.

The top-level docs (`README.md`, `CODING.md`, `CONTRIBUTING.md`) have all been rewritten for the Rust workspace, and the C-era `doc/` toolchain has been removed. What remains before the migration is fully "done" is end-to-end validation against live PostgreSQL — the job of the `integration/` harness (see **Integration testing** below) — plus a handful of subsystems still simplified relative to upstream (the local/remote protocol + parallel job dispatch, block-level incremental backup); see `README.md` "Porting status".

## Docker dev environment (REQUIRED — Rust is not installed locally)

All `cargo` commands run through the `pgbackrust-dev` Docker image defined in `Dockerfile.dev` and orchestrated by `docker-compose.yml`. **Do not install Rust on the host.**

Pinned versions (refresh deliberately, not silently):

- Debian 13 trixie (13.4)
- Rust 1.95.0 stable (rustup, components: rustfmt, clippy)
- Native libs linked by crates: libpq (pgbr-db), libssh2 (pgbr-storage sftp), zlib/bz2/lz4/zstd (pgbr-compress)

Common invocations (all from repo root):

```
docker compose build dev                                          # build the image (first time only)
docker compose run --rm cargo check --workspace                   # quick type-check
docker compose run --rm cargo test --workspace                    # run all tests
docker compose run --rm cargo fmt --check                         # rustfmt verify
docker compose run --rm cargo clippy --workspace --all-targets -- -D warnings
docker compose run --rm cargo run -p pgbr-cli -- info             # run the pgbackrust binary
```

The first build of the image takes a few minutes. Cargo registry, git cache and `target/` live in named volumes (`cargo-registry`, `cargo-git`, `rust-target`) so subsequent `cargo` runs are fast. To wipe them: `docker compose down -v`. The `dev` service stays up (`sleep infinity`) so you can `docker compose exec dev bash` for an interactive shell.

`docker-compose.yml` defines three services off the same image: **`cargo`** (entrypoint `cargo`, so `docker compose run --rm cargo <args>` == `cargo <args>`), **`dev`** (runs `sleep infinity`; use `docker compose run --rm dev <cmd>` for an arbitrary command, e.g. `dev cargo fmt --check`, or `docker compose exec dev bash` for a shell), and **`build`** (a separate Debian 12 bookworm release builder — see **Integration testing**). The `cargo …` and `dev cargo …` forms used in this file are interchangeable for cargo commands.

## The gate (run before every commit)

```
docker compose run --rm dev cargo fmt --check
docker compose run --rm dev cargo clippy --workspace --all-targets -- -D warnings
docker compose run --rm dev cargo test --workspace
```

**Use `--all-targets`** — without it clippy skips `#[cfg(test)]` code and test-only lint regressions slip through. The workspace lints (`[workspace.lints]` in the root `Cargo.toml`) deny `clippy::all` and warn `pedantic` + `nursery`, all hardened to errors by `-D warnings`. `unwrap_used` / `expect_used` / `panic` / `todo` / `unimplemented` are warned in production code (and `unused_must_use` is denied); every crate root carries `#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]` so tests may use those idioms freely. Config lives in `rustfmt.toml` and `clippy.toml`.

## Rust workspace

`cargo build --workspace --release` builds everything; the `pgbackrust` binary comes from `crates/pgbr-cli`. Crates:

- `pgbr-core` — string, blob, memory primitives, log formatting, debug, stack trace, object base
- `pgbr-error` — typed `Error` / `ErrorType` (generated from `error.yaml` by `build.rs`), format, retry
- `pgbr-encode` — hex / base64 encoders
- `pgbr-crypto` — OpenSSL-backed crypto: `common` (OpenSSL init + `random_bytes`), `hash` (MD5/SHA1/SHA256 + HMAC; MD5 via the pure-Rust `md-5` crate so it survives a FIPS OpenSSL), `cipher` (symmetric `State` + `derive_key_iv`), and `xxhash3` (XXH3-128, used to identify backup blocks for incremental)
- `pgbr-compress` — gz / bz2 / lz4 / zst compress + decompress, exposed as `pgbr_io::Filter` adapters (`filter` module)
- `pgbr-regex` — regex wrapper
- `pgbr-build` — typed parsers for the four pgBackRust definition files, which are embedded at compile time and exposed as `pgbr_build::inputs::{CONFIG_YAML, ERROR_YAML, HELP_XML, POSTGRES_YAML}`. The files themselves live in `crates/pgbr-build/inputs/`
- `pgbr-config` — full configuration pipeline: `types`, `command` (`CfgCommand`), `option` (`CfgOption`), `compile` (`Cfg`, inheritance + `+role`/`+inherit`/`-command` expansion), `value` (`OptionValue`, `parse_value`), `cli` (`parse_cli` + `resolve_cli`), `env` (`PGBACKRUST_<OPTION>` environment-variable source, `collect_env`), `ini` (`parse_ini`), `merge` (`load_config` / `load_config_with_context` with **CLI > ENV > stanza:cmd > stanza > global:cmd > global > default** precedence + allow-list/allow-range/depend validation + dynamic & per-flavor defaults)
- `pgbr-io` — `IoRead`/`IoWrite` traits (with `Box<dyn>`/`&mut` blanket impls + `copy`), `MemRead`/`MemWrite`, `FileRead`/`FileWrite`, `FilterChain`, and the `filter` module (`Sha1`, `Sha256`, `Size`, `Cipher` AES-256-CBC)
- `pgbr-storage` — `Storage` trait + backends: `Posix`, `Cifs`, `S3` (SigV4), `Azure` (Shared Key), `Gcs` (bearer token), `Sftp` (ssh2)
- `pgbr-db` — safe libpq wrapper (`Connection`, `QueryResult`); `Connection` is `!Send`
- `pgbr-protocol` — JSON-line `Request` / `Response` message types + `read_message`/`write_message` codec
- `pgbr-postgres` — `crc32c_one`, `version` registry (PG 9.6 .. 18), `control` (`pg_control` header + per-version field offsets), `page` (`pg_checksum_page`)
- `pgbr-info` — on-disk info files: `InfoArchive`, `InfoBackup`, `Manifest`, shared INI+SHA-1 `format`
- `pgbr-command` — every command + the dispatch entry (`dispatch_multi` is the real router, taking all configured repositories; `dispatch` is the single-repo convenience wrapper that calls it with `[(1, repo)]`): backup (full/diff/incr), restore (+ delta + reference resolution), archive-push/get, expire (backup + WAL retention), verify, check, info, stanza-create/delete/upgrade, repo-ls/get/put/rm, annotate, manifest, start/stop, server/server-ping (TCP + TLS), help, version; plus the shared `pipeline::RepoTransform` (compress + encrypt)
- `pgbr-cli` — the `pgbackrust` binary: parse argv → load `config.yaml` + `pgbackrust.conf` → resolve → `pgbr_command::dispatch`

## Adding a configuration option

Two hand-written files under `crates/pgbr-build/inputs/`:

1. `config.yaml` — defines the option (type, commands, command-roles, group, defaults, allow-list, secrets). Command-line-only options omit `section:`; config-file options set `section: global` or `stanza`. Group options like `repo` index to `repo1-foo`, `repo2-foo`, etc.
2. `help.xml` — an `<option>` entry with `<summary>` (ending in a period), `<text>`, `<example>`.

These are embedded into `pgbr-build` at compile time, so a plain `cargo build` picks up the change. `pgbr-config` (option model) and the `help` command consume them automatically; add tests in `pgbr-config` for new resolution behavior.

## Testing

`cargo test --workspace` runs all unit + integration tests. Per-module tests live in `#[cfg(test)] mod tests` inside the owning crate. Cloud-backend and DB round-trip tests that need a live endpoint are `#[ignore]`d and gated on env vars (`PGBR_S3_*`, `PGBR_AZURE_*`, `PGBR_GCS_*`, `PGBR_SFTP_*`, `DATABASE_URL`).

Scope the run while iterating (everything still goes through the `cargo` service):

```
docker compose run --rm cargo test -p pgbr-config                       # one crate
docker compose run --rm cargo test -p pgbr-config merge::tests          # one module
docker compose run --rm cargo test -p pgbr-config -- --exact merge::tests::precedence_cli_wins   # one test
docker compose run --rm cargo test -p pgbr-config -- --nocapture        # show stdout/println!
```

To run the `#[ignore]`d endpoint tests, pass `-- --ignored` and inject the required env vars with `docker compose run -e` (they are read inside the container, so host exports don't reach them):

```
docker compose run --rm -e DATABASE_URL=postgres://... cargo test -p pgbr-db -- --ignored
```

The same `-p <crate>` / name-filter scoping works for clippy (`cargo clippy -p pgbr-config --all-targets -- -D warnings`) and for running the binary (`cargo run -p pgbr-cli -- <command>`).

## Integration testing (`integration/`)

Beyond the in-crate `cargo test` suite, `integration/` drives the **release binary** end-to-end against live PostgreSQL clusters. Two topologies share one binary artifact and one scenario matrix:

- **Build the artifact first:** `./integration/build-binary.sh` compiles `pgbr-cli` in the **`build`** docker-compose service (Debian 12 bookworm, glibc 2.36 — *not* the trixie `dev`/`cargo` image) and drops a portable ELF at `integration/artifacts/pgbackrust`. glibc is backward- but not forward-compatible, so building on the lowest supported glibc yields **one** binary that runs on both the bookworm Vagrant VMs and the trixie Docker nodes. A trixie-built binary dies on the VMs with `GLIBC_2.39 not found`, so don't build the integration artifact with `dev`/`cargo`.
- **Docker topology** (`integration/docker/docker-compose.yml`) — a 3-node cluster (`principal` primary / `secondaire` standby / `depot` repo) plus a `minio` S3 endpoint, sharing an SSH key so the `postgres` user can hop between nodes. The binary is **bind-mounted** into each node (not COPYed — under Docker Desktop's WSL2 image store the COPYed layer is intermittently not materialised). This is what local/CI validation uses.
- **Scenarios** (`integration/scenarios/`) — 11 numbered scripts (`01-local-minimal` … `11-s3`: local, remote-pull SSH, PITR, encryption, standby, tablespaces, async queuing, multi-repo, TLS, bundling/block, S3) over shared helpers in `_lib.sh`. Run them with `./integration/scenarios/run-all.sh` (optionally filter: `run-all.sh 01 03`). Each scenario runs against a freshly `down -v`'d topology for isolation; a failing scenario is recorded and the loop continues rather than aborting.
- **Vagrant topology** (`integration/vagrant/`) — the same KB scenario matrix against VirtualBox VMs via `run-validation.sh` (run after `vagrant up`); an alternative to Docker that exercises real systemd/SSH. Provisioning scripts live in `integration/vagrant/provision/`.

## CI gating

`.github/workflows/test.yml` runs the Rust gate (fmt check, clippy `--all-targets -D warnings`, `cargo test --workspace`) on pushes/PRs to `main` and on `**-ci` / `**-cig` branches. Pull requests target **`main`**.

## Tip: branches ending in `-cig` push to GitHub Actions

Renaming a branch to end in `-cig` (or `-ci`) and pushing it to your fork triggers the CI workflow — useful for running the gate without opening a PR.

## History

The C source this was ported from lived under `src/` (removed in the dismantling commits; recoverable from git history). The original plan was a 215-phase incremental port behind an FFI shim with C↔Rust differential tests; that was retired after ~50 phases in favour of a single big-bang rewrite (epic #238). If you need to consult the original C for behavioural reference, check out a pre-dismantling commit or pgBackRust 2.58.0 upstream.
